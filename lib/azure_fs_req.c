/*
 * Copyright (C) SUSE LINUX GmbH 2012-2016, all rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) version 3.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

/* for encoding */
#include <event2/http.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "exml.h"
#include "data.h"
#include "op.h"
#include "sign.h"
#include "azure_req.h"
#include "azure_fs_path.h"
#include "azure_fs_req.h"

/*
 * primary Elasto-Backend Op structure for Azure File Service requests
 */
struct az_fs_ebo {
	enum az_fs_opcode opcode;
	struct az_fs_req req;
	struct az_fs_rsp rsp;
	struct op op;
};

static void
az_fs_req_free(struct op *op);
static void
az_fs_rsp_free(struct op *op);
static int
az_fs_rsp_process(struct op *op);

static void
az_fs_ebo_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	free(ebo);
}

static int
az_fs_ebo_init(enum az_fs_opcode opcode,
	       struct az_fs_ebo **_ebo)
{
	struct az_fs_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_free = az_fs_req_free;
	ebo->op.rsp_free = az_fs_rsp_free;
	ebo->op.rsp_process = az_fs_rsp_process;
	ebo->op.ebo_free = az_fs_ebo_free;
	/* sign callback set conditionally per-op */
	*_ebo = ebo;
	return 0;
}

int
az_fs_req_hostname_get(char *acc,
		       char **_hostname)
{
	int ret;
	char *hostname;

	if ((acc == NULL) || (_hostname== NULL)) {
		return -EINVAL;
	}

	ret = asprintf(&hostname, "%s.file.core.windows.net", acc);
	if (ret < 0) {
		return -ENOMEM;
	}

	*_hostname = hostname;
	return 0;
}

static int
az_fs_req_url_encode(const struct az_fs_path *path,
		     const char *url_params,
		     char **_url_host,
		     char **_url_path)
{
	int ret;
	char *url_host;
	char *url_path;
	const char *params_str = url_params ? url_params : "";

	ret = az_fs_req_hostname_get(path->acc, &url_host);
	if (ret < 0) {
		goto err_out;
	}

	if (AZ_FS_PATH_IS_ACC(path)) {
		ret = asprintf(&url_path, "/%s", params_str);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_uhost_free;
		}
	} else if (AZ_FS_PATH_IS_SHARE(path)) {
		ret = asprintf(&url_path, "/%s%s", path->share, params_str);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_uhost_free;
		}
	} else if (AZ_FS_PATH_IS_ENT(path)) {
		/* file or dir path below share */
		char *parent_encoded = NULL;
		char *ent_encoded = NULL;

		if (path->parent_dir != NULL) {
			parent_encoded = evhttp_encode_uri(path->parent_dir);
			if (parent_encoded == NULL) {
				ret = -ENOMEM;
				goto err_uhost_free;
			}
		}
		ent_encoded = evhttp_encode_uri(path->fs_ent);
		if (ent_encoded == NULL) {
			free(parent_encoded);
			ret = -ENOMEM;
			goto err_uhost_free;
		}
		ret = asprintf(&url_path, "/%s/%s%s%s%s",
			       path->share,
			       (parent_encoded ? parent_encoded : ""),
			       (parent_encoded ? "/" : ""), ent_encoded,
			       params_str);
		free(parent_encoded);
		free(ent_encoded);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_uhost_free;
		}
	} else {
		dbg(0, "can't encode path\n");
		ret = -EINVAL;
		goto err_uhost_free;
	}

	*_url_host = url_host;
	*_url_path = url_path;
	return 0;

err_uhost_free:
	free(url_host);
err_out:
	return ret;
}

static void
az_fs_share_free(struct az_fs_share **_share)
{
	struct az_fs_share *share = *_share;

	free(share->name);
	free(share);
}

static void
az_fs_rsp_shares_list_free(struct az_fs_rsp_shares_list *shares_list_rsp)
{
	struct az_fs_share *share;
	struct az_fs_share *share_n;

	if (shares_list_rsp->num_shares == 0) {
		return;
	}

	list_for_each_safe(&shares_list_rsp->shares, share, share_n, list) {
		az_fs_share_free(&share);
	}
}

int
az_fs_req_shares_list(const struct az_fs_path *path,
		      struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ACC(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARES_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?comp=list",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_rsp_share_iter_process(struct xml_doc *xdoc,
			     const char *path,
			     const char *val,
			     void *cb_data)
{
	int ret;
	struct az_fs_rsp_shares_list *shares_list_rsp
				= (struct az_fs_rsp_shares_list *)cb_data;
	struct az_fs_share *share;

	/* request callback for subsequent share descriptors */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Shares/Share", false,
				az_fs_rsp_share_iter_process,
				shares_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	share = malloc(sizeof(*share));
	if (share == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(share, 0, sizeof(*share));

	ret = exml_str_want(xdoc, "./Name", true, &share->name, NULL);
	if (ret < 0) {
		goto err_share_free;
	}

	ret = exml_date_time_want(xdoc, "./Properties/Last-Modified", true,
				  &share->last_mod, NULL);
	if (ret < 0) {
		goto err_share_free;
	}

	list_add_tail(&shares_list_rsp->shares, &share->list);
	shares_list_rsp->num_shares++;

	return 0;

err_share_free:
	free(share);
err_out:
	return ret;
}

static int
az_fs_rsp_shares_list_process(struct op *op,
			      struct az_fs_rsp_shares_list *shares_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct az_fs_share *share;
	struct az_fs_share *share_n;

	assert(op->opcode == AOP_FS_SHARES_LIST);

	if ((op->rsp.data == NULL) || (op->rsp.data->type != ELASTO_DATA_IOV)) {
		dbg(1, "invalid data buffer in 0x%x response\n", op->opcode);
		ret = -EIO;
		goto err_out;
	}

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&shares_list_rsp->shares);

	/* request callback for first share */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Shares/Share", false,
				az_fs_rsp_share_iter_process,
				shares_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		/* need to walk list in case cb fired */
		goto err_shares_free;
	}

	exml_free(xdoc);
	return 0;

err_shares_free:
	list_for_each_safe(&shares_list_rsp->shares, share, share_n, list) {
		az_fs_share_free(&share);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static int
az_fs_req_share_create_hdr_fill(struct az_fs_req_share_create *share_create_req,
				struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "%" PRIu64, share_create_req->quota_gb);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-share-quota", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_fs_req_share_create(const struct az_fs_path *path,
		       uint64_t quota_gb,
		       struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_create *share_create_req;

	if (!AZ_FS_PATH_IS_SHARE(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	if ((quota_gb == 0) || (quota_gb > AZ_FS_SHARE_QUOTA_MAX_GB)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	share_create_req = &ebo->req.share_create;
	share_create_req->quota_gb = quota_gb;
	op->method = REQ_METHOD_PUT;

	ret = az_fs_req_url_encode(path, "?restype=share",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_share_create_hdr_fill(share_create_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_fs_req_share_del(const struct az_fs_path *path,
		    struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_SHARE(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_DELETE;

	ret = az_fs_req_url_encode(path, "?restype=share",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_fs_req_share_prop_get(const struct az_fs_path *path,
			 struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_SHARE(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?restype=share",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_rsp_share_prop_get_process(struct op *op,
			struct az_fs_rsp_share_prop_get *share_prop_get_rsp)
{
	int ret;

	assert(op->opcode == AOP_FS_SHARE_PROP_GET);

	ret = op_hdr_date_time_val_lookup(&op->rsp.hdrs, "Last-Modified",
					  &share_prop_get_rsp->last_mod);
	if (ret < 0) {
		/* mandatory header, error if not present */
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

static void
az_fs_ent_free(struct az_fs_ent **pent)
{
	struct az_fs_ent *ent = *pent;

	if (ent->type == AZ_FS_ENT_TYPE_FILE) {
		free(ent->file.name);
	} else if (ent->type == AZ_FS_ENT_TYPE_DIR) {
		free(ent->dir.name);
	}
	free(ent);
}

static void
az_fs_rsp_dirs_files_list_free(struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp)
{
	struct az_fs_ent *ent;
	struct az_fs_ent *ent_n;

	if (dirs_files_list_rsp->num_ents == 0) {
		return;
	}

	list_for_each_safe(&dirs_files_list_rsp->ents, ent, ent_n, list) {
		az_fs_ent_free(&ent);
	}
}

int
az_fs_req_dirs_files_list(const struct az_fs_path *path,
			  struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_SHARE(path) && !AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIRS_FILES_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?restype=directory&comp=list",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_rsp_ent_file_iter_process(struct xml_doc *xdoc,
				const char *path,
				const char *val,
				void *cb_data)
{
	int ret;
	struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp
				= (struct az_fs_rsp_dirs_files_list *)cb_data;
	struct az_fs_ent *ent;

	/* request callback for subsequent file descriptors */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Entries/File", false,
				az_fs_rsp_ent_file_iter_process,
				dirs_files_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ent = malloc(sizeof(*ent));
	if (ent == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(ent, 0, sizeof(*ent));
	ent->type = AZ_FS_ENT_TYPE_FILE;

	ret = exml_str_want(xdoc, "./Name", true, &ent->file.name, NULL);
	if (ret < 0) {
		goto err_ent_free;
	}

	ret = exml_uint64_want(xdoc, "./Properties/Content-Length", true,
			       &ent->file.size, NULL);
	if (ret < 0) {
		goto err_ent_free;
	}

	list_add_tail(&dirs_files_list_rsp->ents, &ent->list);
	dirs_files_list_rsp->num_ents++;

	return 0;

err_ent_free:
	free(ent);
err_out:
	return ret;
}

static int
az_fs_rsp_ent_dir_iter_process(struct xml_doc *xdoc,
			       const char *path,
			       const char *val,
			       void *cb_data)
{
	int ret;
	struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp
				= (struct az_fs_rsp_dirs_files_list *)cb_data;
	struct az_fs_ent *ent;

	/* request callback for subsequent dir descriptors */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Entries/Directory", false,
				az_fs_rsp_ent_dir_iter_process,
				dirs_files_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ent = malloc(sizeof(*ent));
	if (ent == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(ent, 0, sizeof(*ent));
	ent->type = AZ_FS_ENT_TYPE_DIR;

	ret = exml_str_want(xdoc, "./Name", true, &ent->file.name, NULL);
	if (ret < 0) {
		goto err_ent_free;
	}

	list_add_tail(&dirs_files_list_rsp->ents, &ent->list);
	dirs_files_list_rsp->num_ents++;

	return 0;

err_ent_free:
	free(ent);
err_out:
	return ret;
}

static int
az_fs_rsp_dirs_files_list_process(struct op *op,
			struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct az_fs_ent *ent;
	struct az_fs_ent *ent_n;

	assert(op->opcode == AOP_FS_DIRS_FILES_LIST);

	if ((op->rsp.data == NULL) || (op->rsp.data->type != ELASTO_DATA_IOV)) {
		dbg(1, "invalid data buffer in 0x%x response\n", op->opcode);
		ret = -EIO;
		goto err_out;
	}

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&dirs_files_list_rsp->ents);

	/* request callback for first file descriptor */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Entries/File", false,
				az_fs_rsp_ent_file_iter_process,
				dirs_files_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Entries/Directory", false,
				az_fs_rsp_ent_dir_iter_process,
				dirs_files_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		/* need to walk list in case cb fired */
		goto err_ents_free;
	}

	exml_free(xdoc);
	return 0;

err_ents_free:
	list_for_each_safe(&dirs_files_list_rsp->ents, ent, ent_n, list) {
		az_fs_ent_free(&ent);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

int
az_fs_req_dir_create(const struct az_fs_path *path,
		     struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?restype=directory",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_fs_req_dir_del(const struct az_fs_path *path,
		  struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_DELETE;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?restype=directory",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_fs_req_dir_prop_get(const struct az_fs_path *path,
		       struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?restype=directory",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_rsp_dir_prop_get_process(struct op *op,
			       struct az_fs_rsp_dir_prop_get *dir_prop_get_rsp)
{
	int ret;

	assert(op->opcode == AOP_FS_DIR_PROP_GET);

	ret = op_hdr_date_time_val_lookup(&op->rsp.hdrs, "Last-Modified",
					  &dir_prop_get_rsp->last_mod);
	if (ret < 0) {
		/* mandatory header, error if not present */
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

static int
az_fs_req_file_create_hdr_fill(struct az_fs_req_file_create *file_create_req,
			       struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "%" PRIu64, file_create_req->max_size_bytes);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-content-length", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	ret = op_req_hdr_add(op, "x-ms-type", "file");
	if (ret < 0) {
		goto err_hdrs_free;
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_fs_req_file_create(const struct az_fs_path *path,
		      uint64_t max_size_bytes,
		      struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_create *file_create_req;

	if (!AZ_FS_PATH_IS_ENT(path) || (max_size_bytes > BYTES_IN_TB)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	file_create_req = &ebo->req.file_create;
	file_create_req->max_size_bytes = max_size_bytes;

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, NULL,
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_file_create_hdr_fill(file_create_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_fs_req_file_del(const struct az_fs_path *path,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	op->method = REQ_METHOD_DELETE;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, NULL,
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_req_file_get_hdr_fill(struct az_fs_req_file_get *file_get_req,
			    struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (file_get_req->len > 0) {
		ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
			       file_get_req->off,
			       (file_get_req->off + file_get_req->len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * pretty similar to blob_get
 * if @len is zero then ignore @off and retrieve entire blob
 */
int
az_fs_req_file_get(const struct az_fs_path *path,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *dest_data,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_get *file_get_req;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	file_get_req = &ebo->req.file_get;
	if (len > 0) {
		file_get_req->off = off;
		file_get_req->len = len;
	}

	if (dest_data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = dest_data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, NULL,
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_file_get_hdr_fill(file_get_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_req_file_put_hdr_fill(struct az_fs_req_file_put *file_put_req,
			    struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (file_put_req->len > 0) {
		ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
			       file_put_req->off,
			       (file_put_req->off + file_put_req->len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (file_put_req->clear_data) {
		ret = op_req_hdr_add(op, "x-ms-write", "clear");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else {
		ret = op_req_hdr_add(op, "x-ms-write", "update");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * pretty similar to blob_put
 * update or clear @len bytes of data at @off.
 * if @src_data is null then clear the byte range, otherwise update.
 */
int
az_fs_req_file_put(const struct az_fs_path *path,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *src_data,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_put *file_put_req;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	file_put_req = &ebo->req.file_put;
	if (len > 0) {
		file_put_req->off = off;
		file_put_req->len = len;
	}

	if (src_data == NULL) {
		file_put_req->clear_data = true;
	} else {
		file_put_req->clear_data = false;
		op->req.data = src_data;
		/* TODO add a foreign flag so @req.data is not freed with @op */
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?comp=range",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_file_put_hdr_fill(file_put_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_file_cp_free(struct az_fs_req_file_cp *file_cp_req)
{
	az_fs_path_free(&file_cp_req->src_path);
}

static int
az_fs_req_file_cp_hdr_fill(struct az_fs_req_file_cp *file_cp_req,
			   struct op *op)
{
	int ret;
	char *hdr_str;
	char *src_url_host = NULL;
	char *src_url_path = NULL;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_req_url_encode(&file_cp_req->src_path, NULL,
				   &src_url_host, &src_url_path);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	/*
	 * tell server to always use https when dealing with the src file
	 * TODO: support copying from the blob service
	 */
	ret = asprintf(&hdr_str, "https://%s%s", src_url_host, src_url_path);
	free(src_url_host);
	free(src_url_path);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-copy-source", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}
	/* common headers and signature added later */

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_fs_req_file_cp(const struct az_fs_path *src_path,
		  const struct az_fs_path *dst_path,
		  struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_cp *file_cp_req;

	if (!AZ_FS_PATH_IS_ENT(src_path) || !AZ_FS_PATH_IS_ENT(dst_path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_CP, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(dst_path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	file_cp_req = &ebo->req.file_cp;
	ret = az_fs_path_dup(src_path, &file_cp_req->src_path);
	if (ret < 0) {
		goto err_dst_path_free;
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(dst_path, NULL,
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_src_path_free;
	}

	ret = az_fs_req_file_cp_hdr_fill(file_cp_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_src_path_free:
	az_fs_path_free(&file_cp_req->src_path);
err_dst_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_rsp_file_cp_free(struct az_fs_rsp_file_cp *file_cp_rsp)
{
	free(file_cp_rsp->cp_id);
}

static int
az_fs_rsp_file_cp_process(struct op *op,
			  struct az_fs_rsp_file_cp *file_cp_rsp)
{
	int ret;
	char *hdr_val;

	assert(op->opcode == AOP_FS_FILE_CP);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-copy-id",
				&file_cp_rsp->cp_id);
	if (ret < 0) {
		/* mandatory header, error if not present */
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-copy-status",
				&hdr_val);
	if (ret < 0) {
		goto err_cid_free;
	}

	ret = az_rsp_cp_status_map(hdr_val, &file_cp_rsp->cp_status);
	free(hdr_val);
	if (ret < 0) {
		goto err_cid_free;
	}

	return 0;

err_cid_free:
	free(file_cp_rsp->cp_id);
err_out:
	return ret;
}

int
az_fs_req_file_prop_get(const struct az_fs_path *path,
			struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, NULL, &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_rsp_file_prop_get_free(struct az_fs_rsp_file_prop_get *file_prop_get_rsp)
{
	free(file_prop_get_rsp->content_type);
	free(file_prop_get_rsp->cp_id);
}

static int
az_fs_rsp_file_prop_get_process(struct op *op,
			struct az_fs_rsp_file_prop_get *file_prop_get_rsp)
{
	int ret;
	char *hdr_val;

	assert(op->opcode == AOP_FS_FILE_PROP_GET);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "Content-Length",
				    &file_prop_get_rsp->len);
	if (ret < 0) {
		/* mandatory header, error if not present */
		goto err_out;
	}
	file_prop_get_rsp->relevant |= AZ_FS_FILE_PROP_LEN;

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"Content-Type",
				&file_prop_get_rsp->content_type);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	} else if (ret == 0) {
		/* optional header is present */
		file_prop_get_rsp->relevant |= AZ_FS_FILE_PROP_CTYPE;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-id",
				&file_prop_get_rsp->cp_id);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_ctype_free;
	} else if (ret == 0) {
		file_prop_get_rsp->relevant |= AZ_FS_FILE_PROP_CP_ID;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-status",
				&hdr_val);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_cid_free;
	} else if (ret == 0) {
		ret = az_rsp_cp_status_map(hdr_val,
					   &file_prop_get_rsp->cp_status);
		free(hdr_val);
		if (ret < 0) {
			goto err_cid_free;
		}
		file_prop_get_rsp->relevant |= AZ_FS_FILE_PROP_CP_STATUS;
	}

	return 0;

err_cid_free:
	free(file_prop_get_rsp->cp_id);
err_ctype_free:
	free(file_prop_get_rsp->content_type);
err_out:
	return ret;
}

static void
az_fs_req_file_prop_set_free(struct az_fs_req_file_prop_set *file_prop_set_req)
{
	free(file_prop_set_req->content_type);
}

static int
az_fs_req_file_prop_set_hdr_fill(
			struct az_fs_req_file_prop_set *file_prop_set_req,
			struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (file_prop_set_req->relevant & AZ_FS_FILE_PROP_LEN) {
		char *hdr_str;
		ret = asprintf(&hdr_str, "%" PRIu64, file_prop_set_req->len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-content-length", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (file_prop_set_req->relevant & AZ_FS_FILE_PROP_CTYPE) {
		ret = op_req_hdr_add(op, "x-ms-content-type",
				     file_prop_set_req->content_type);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_fs_req_file_prop_set(const struct az_fs_path *path,
			uint64_t relevant,
			uint64_t len,
			const char *content_type,
			struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_prop_set *file_prop_set_req;

	if (!AZ_FS_PATH_IS_ENT(path)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PROP_SET, &ebo);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op = &ebo->op;
	file_prop_set_req = &ebo->req.file_prop_set;

	if (relevant & AZ_FS_FILE_PROP_LEN) {
		relevant &= (~AZ_FS_FILE_PROP_LEN);
		file_prop_set_req->relevant |= AZ_FS_FILE_PROP_LEN;
		file_prop_set_req->len = len;
	}

	if (relevant & AZ_FS_FILE_PROP_CTYPE) {
		relevant &= (~AZ_FS_FILE_PROP_CTYPE);
		file_prop_set_req->relevant |= AZ_FS_FILE_PROP_CTYPE;
		file_prop_set_req->content_type = strdup(content_type);
		if (file_prop_set_req->content_type == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

	if (relevant != 0) {
		dbg(0, "invalid remainint property relevance flags: %" PRIu64
		       "\n", relevant);
		ret = -EINVAL;
		goto err_ctype_free;
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;

	ret = az_fs_req_url_encode(path, "?comp=properties",
				   &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_file_prop_set_hdr_fill(file_prop_set_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_ctype_free:
	free(file_prop_set_req->content_type);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_fs_req_file_ranges_list_hdr_fill(
			struct az_fs_req_file_ranges_list *file_ranges_list_req,
			struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
		       file_ranges_list_req->off,
		(file_ranges_list_req->off + file_ranges_list_req->len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_fs_req_file_ranges_list(const struct az_fs_path *path,
			   uint64_t off,
			   uint64_t len,
			   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct az_fs_req_file_ranges_list *file_ranges_list_req;
	struct op *op;

	if (!AZ_FS_PATH_IS_ENT(path) || (_op == NULL) || (len == 0)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_RANGES_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_ranges_list_req = &ebo->req.file_ranges_list;

	ret = az_fs_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	file_ranges_list_req->off = off;
	file_ranges_list_req->len = len;

	op->method = REQ_METHOD_GET;
	ret = az_fs_req_url_encode(path, "?comp=rangelist",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_fs_req_file_ranges_list_hdr_fill(file_ranges_list_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_fs_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_rsp_file_ranges_list_free(
			struct az_fs_rsp_file_ranges_list *file_ranges_list_rsp)
{
	struct az_file_range *range;
	struct az_file_range *range_n;

	if (file_ranges_list_rsp->num_ranges == 0) {
		return;
	}

	list_for_each_safe(&file_ranges_list_rsp->ranges,
			   range, range_n, list) {
		free(range);
	}
}

static int
az_rsp_range_iter_process(struct xml_doc *xdoc,
			  const char *path,
			  const char *val,
			  void *cb_data)
{
	struct az_fs_rsp_file_ranges_list *file_ranges_list_rsp
			= (struct az_fs_rsp_file_ranges_list *)cb_data;
	int ret;
	struct az_file_range *range;

	/* request callback for subsequent Range entries */
	ret = exml_path_cb_want(xdoc, "/Ranges/Range", false,
				az_rsp_range_iter_process, file_ranges_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	range = malloc(sizeof(*range));
	if (range == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(range, 0, sizeof(*range));

	ret = exml_uint64_want(xdoc, "./Start", true, &range->start_byte, NULL);
	if (ret < 0) {
		goto err_range_free;
	}

	ret = exml_uint64_want(xdoc, "./End", true, &range->end_byte, NULL);
	if (ret < 0) {
		goto err_range_free;
	}

	list_add_tail(&file_ranges_list_rsp->ranges, &range->list);
	file_ranges_list_rsp->num_ranges++;

	return 0;

err_range_free:
	free(range);
err_out:
	return ret;
}

static int
az_fs_rsp_file_ranges_list_process(struct op *op,
			struct az_fs_rsp_file_ranges_list *file_ranges_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_FS_FILE_RANGES_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "x-ms-content-length",
				    &file_ranges_list_rsp->file_len);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&file_ranges_list_rsp->ranges);

	/* trigger path callback for first Range */
	ret = exml_path_cb_want(xdoc, "/Ranges/Range", false,
				az_rsp_range_iter_process, file_ranges_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_ranges_free;
	}

	exml_free(xdoc);

	return 0;

err_ranges_free:
	az_fs_rsp_file_ranges_list_free(file_ranges_list_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_fs_req_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	az_fs_path_free(&ebo->req.path);

	switch (ebo->opcode) {
	case AOP_FS_FILE_CP:
		az_fs_req_file_cp_free(&ebo->req.file_cp);
		break;
	case AOP_FS_FILE_PROP_SET:
		az_fs_req_file_prop_set_free(&ebo->req.file_prop_set);
		break;
	case AOP_FS_SHARES_LIST:
	case AOP_FS_SHARE_CREATE:
	case AOP_FS_SHARE_DEL:
	case AOP_FS_SHARE_PROP_GET:
	case AOP_FS_DIRS_FILES_LIST:
	case AOP_FS_DIR_CREATE:
	case AOP_FS_DIR_DEL:
	case AOP_FS_DIR_PROP_GET:
	case AOP_FS_FILE_CREATE:
	case AOP_FS_FILE_DEL:
	case AOP_FS_FILE_GET:
	case AOP_FS_FILE_PUT:
	case AOP_FS_FILE_PROP_GET:
	case AOP_FS_FILE_RANGES_LIST:
		/* nothing more to free */
		break;
	default:
		assert(false);
		break;
	};
}

static void
az_fs_rsp_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	switch (ebo->opcode) {
	case AOP_FS_SHARES_LIST:
		az_fs_rsp_shares_list_free(&ebo->rsp.shares_list);
		break;
	case AOP_FS_DIRS_FILES_LIST:
		az_fs_rsp_dirs_files_list_free(&ebo->rsp.dirs_files_list);
		break;
	case AOP_FS_FILE_CP:
		az_fs_rsp_file_cp_free(&ebo->rsp.file_cp);
		break;
	case AOP_FS_FILE_PROP_GET:
		az_fs_rsp_file_prop_get_free(&ebo->rsp.file_prop_get);
		break;
	case AOP_FS_FILE_RANGES_LIST:
		az_fs_rsp_file_ranges_list_free(&ebo->rsp.file_ranges_list);
		break;
	case AOP_FS_SHARE_CREATE:
	case AOP_FS_SHARE_DEL:
	case AOP_FS_SHARE_PROP_GET:
	case AOP_FS_DIR_CREATE:
	case AOP_FS_DIR_DEL:
	case AOP_FS_DIR_PROP_GET:
	case AOP_FS_FILE_CREATE:
	case AOP_FS_FILE_DEL:
	case AOP_FS_FILE_GET:
	case AOP_FS_FILE_PUT:
	case AOP_FS_FILE_PROP_SET:
		/* nothing to do */
		break;
	default:
		assert(false);
		break;
	};
}

/*
 * unmarshall response data
 */
int
az_fs_rsp_process(struct op *op)
{
	int ret;
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_FS_SHARES_LIST:
		ret = az_fs_rsp_shares_list_process(op,
						    &ebo->rsp.shares_list);
		break;
	case AOP_FS_SHARE_PROP_GET:
		ret = az_fs_rsp_share_prop_get_process(op,
						      &ebo->rsp.share_prop_get);
		break;
	case AOP_FS_DIRS_FILES_LIST:
		ret = az_fs_rsp_dirs_files_list_process(op,
						&ebo->rsp.dirs_files_list);
		break;
	case AOP_FS_DIR_PROP_GET:
		ret = az_fs_rsp_dir_prop_get_process(op,
						     &ebo->rsp.dir_prop_get);
		break;
	case AOP_FS_FILE_CP:
		ret = az_fs_rsp_file_cp_process(op, &ebo->rsp.file_cp);
		break;
	case AOP_FS_FILE_PROP_GET:
		ret = az_fs_rsp_file_prop_get_process(op,
						      &ebo->rsp.file_prop_get);
		break;
	case AOP_FS_FILE_RANGES_LIST:
		ret = az_fs_rsp_file_ranges_list_process(op,
						&ebo->rsp.file_ranges_list);
		break;
	case AOP_FS_SHARE_CREATE:
	case AOP_FS_SHARE_DEL:
	case AOP_FS_DIR_CREATE:
	case AOP_FS_DIR_DEL:
	case AOP_FS_FILE_CREATE:
	case AOP_FS_FILE_DEL:
	case AOP_FS_FILE_GET:
	case AOP_FS_FILE_PUT:
	case AOP_FS_FILE_PROP_SET:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}

struct az_fs_rsp_shares_list *
az_fs_rsp_shares_list(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.shares_list;
}

struct az_fs_rsp_share_prop_get *
az_fs_rsp_share_prop_get(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.share_prop_get;
}

struct az_fs_rsp_dirs_files_list *
az_fs_rsp_dirs_files_list(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.dirs_files_list;
}

struct az_fs_rsp_dir_prop_get *
az_fs_rsp_dir_prop_get(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.dir_prop_get;
}

struct az_fs_rsp_file_cp *
az_fs_rsp_file_cp(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.file_cp;
}

struct az_fs_rsp_file_prop_get *
az_fs_rsp_file_prop_get(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.file_prop_get;
}

struct az_fs_rsp_file_ranges_list *
az_fs_rsp_file_ranges_list(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.file_ranges_list;
}
