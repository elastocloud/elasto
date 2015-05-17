/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "exml.h"
#include "data_api.h"
#include "op.h"
#include "sign.h"
#include "azure_req.h"
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

static void
az_fs_req_shares_list_free(struct az_fs_req_shares_list *shares_list_req)
{
	free(shares_list_req->acc);
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
az_fs_req_shares_list(const char *acc,
		      struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_shares_list *shares_list_req;

	if (acc == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARES_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	shares_list_req = &ebo->req.shares_list;

	shares_list_req->acc = strdup(acc);
	if (shares_list_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}
	ret = asprintf(&op->url_path, "/?comp=list");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_acc_free:
	free(shares_list_req->acc);
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
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
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

static void
az_fs_req_share_create_free(struct az_fs_req_share_create *share_create_req)
{
	free(share_create_req->acc);
	free(share_create_req->share);
}

int
az_fs_req_share_create(const char *acc,
		       const char *share,
		       struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_create *share_create_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	share_create_req = &ebo->req.share_create;

	share_create_req->acc = strdup(acc);
	if (share_create_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	share_create_req->share = strdup(share);
	if (share_create_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_share_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=share",
		       share);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_share_free:
	free(share_create_req->share);
err_acc_free:
	free(share_create_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_share_del_free(struct az_fs_req_share_del *share_del_req)
{
	free(share_del_req->acc);
	free(share_del_req->share);
}

int
az_fs_req_share_del(const char *acc,
		    const char *share,
		    struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_del *share_del_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	share_del_req = &ebo->req.share_del;

	share_del_req->acc = strdup(acc);
	if (share_del_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	share_del_req->share = strdup(share);
	if (share_del_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_share_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=share",
		       share);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_share_free:
	free(share_del_req->share);
err_acc_free:
	free(share_del_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_share_prop_get_free(struct az_fs_req_share_prop_get *share_prop_get_req)
{
	free(share_prop_get_req->acc);
	free(share_prop_get_req->share);
}

int
az_fs_req_share_prop_get(const char *acc,
			 const char *share,
			 struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_prop_get *share_prop_get_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	share_prop_get_req = &ebo->req.share_prop_get;

	share_prop_get_req->acc = strdup(acc);
	if (share_prop_get_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	share_prop_get_req->share = strdup(share);
	if (share_prop_get_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_share_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=share",
		       share);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_share_free:
	free(share_prop_get_req->share);
err_acc_free:
	free(share_prop_get_req->acc);
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
az_fs_req_dirs_files_list_free(
			struct az_fs_req_dirs_files_list *dirs_files_list_req)
{
	free(dirs_files_list_req->acc);
	free(dirs_files_list_req->share);
	free(dirs_files_list_req->dir_path);
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
az_fs_req_dirs_files_list(const char *acc,
			  const char *share,
			  const char *dir_path,
			  struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_dirs_files_list *dirs_files_list_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIRS_FILES_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	dirs_files_list_req = &ebo->req.dirs_files_list;

	dirs_files_list_req->acc = strdup(acc);
	if (dirs_files_list_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	dirs_files_list_req->share = strdup(share);
	if (dirs_files_list_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (dir_path != NULL) {
		dirs_files_list_req->dir_path = strdup(dir_path);
		if (dirs_files_list_req->dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dir_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s?restype=directory&comp=list",
		       share, (dir_path ? dir_path : ""));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dir_free:
	free(dirs_files_list_req->dir_path);
err_share_free:
	free(dirs_files_list_req->share);
err_acc_free:
	free(dirs_files_list_req->acc);
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
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
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

static void
az_fs_req_dir_create_free(struct az_fs_req_dir_create *dir_create_req)
{
	free(dir_create_req->acc);
	free(dir_create_req->share);
	free(dir_create_req->parent_dir_path);
	free(dir_create_req->dir);
}

int
az_fs_req_dir_create(const char *acc,
		     const char *share,
		     const char *parent_dir_path,	/* optional */
		     const char *dir,
		     struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_dir_create *dir_create_req;

	if ((acc == NULL) || (share == NULL) || (dir == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	dir_create_req = &ebo->req.dir_create;

	dir_create_req->acc = strdup(acc);
	if (dir_create_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	dir_create_req->share = strdup(share);
	if (dir_create_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		dir_create_req->parent_dir_path = strdup(parent_dir_path);
		if (dir_create_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	dir_create_req->dir = strdup(dir);
	if (dir_create_req->dir == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dir_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s?restype=directory",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), dir);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dir_free:
	free(dir_create_req->dir);
err_path_free:
	free(dir_create_req->parent_dir_path);
err_share_free:
	free(dir_create_req->share);
err_acc_free:
	free(dir_create_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_dir_del_free(struct az_fs_req_dir_del *dir_del_req)
{
	free(dir_del_req->acc);
	free(dir_del_req->share);
	free(dir_del_req->parent_dir_path);
	free(dir_del_req->dir);
}

int
az_fs_req_dir_del(const char *acc,
		  const char *share,
		  const char *parent_dir_path,	/* optional */
		  const char *dir,
		  struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_dir_del *dir_del_req;

	if ((acc == NULL) || (share == NULL) || (dir == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	dir_del_req = &ebo->req.dir_del;

	dir_del_req->acc = strdup(acc);
	if (dir_del_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	dir_del_req->share = strdup(share);
	if (dir_del_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		dir_del_req->parent_dir_path = strdup(parent_dir_path);
		if (dir_del_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	dir_del_req->dir = strdup(dir);
	if (dir_del_req->dir == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	op->method = REQ_METHOD_DELETE;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dir_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s?restype=directory",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), dir);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dir_free:
	free(dir_del_req->dir);
err_path_free:
	free(dir_del_req->parent_dir_path);
err_share_free:
	free(dir_del_req->share);
err_acc_free:
	free(dir_del_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_dir_prop_get_free(struct az_fs_req_dir_prop_get *dir_prop_get_req)
{
	free(dir_prop_get_req->acc);
	free(dir_prop_get_req->share);
	free(dir_prop_get_req->parent_dir_path);
	free(dir_prop_get_req->dir);
}

int
az_fs_req_dir_prop_get(const char *acc,
		       const char *share,
		       const char *parent_dir_path,	/* optional */
		       const char *dir,
		       struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_dir_prop_get *dir_prop_get_req;

	if ((acc == NULL) || (share == NULL) || (dir == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_DIR_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	dir_prop_get_req = &ebo->req.dir_prop_get;

	dir_prop_get_req->acc = strdup(acc);
	if (dir_prop_get_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	dir_prop_get_req->share = strdup(share);
	if (dir_prop_get_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		dir_prop_get_req->parent_dir_path = strdup(parent_dir_path);
		if (dir_prop_get_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	dir_prop_get_req->dir = strdup(dir);
	if (dir_prop_get_req->dir == NULL) {
		ret = -ENOMEM;
		goto err_parent_free;
	}

	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dir_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s?restype=directory",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), dir);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dir_free:
	free(dir_prop_get_req->dir);
err_parent_free:
	free(dir_prop_get_req->parent_dir_path);
err_share_free:
	free(dir_prop_get_req->share);
err_acc_free:
	free(dir_prop_get_req->acc);
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

static void
az_fs_req_file_create_free(struct az_fs_req_file_create *file_create_req)
{
	free(file_create_req->acc);
	free(file_create_req->share);
	free(file_create_req->parent_dir_path);
	free(file_create_req->file);
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
az_fs_req_file_create(const char *acc,
		      const char *share,
		      const char *parent_dir_path,	/* optional */
		      const char *file,
		      uint64_t max_size_bytes,
		      struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_create *file_create_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)
					|| (max_size_bytes > BYTES_IN_TB)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_create_req = &ebo->req.file_create;

	file_create_req->acc = strdup(acc);
	if (file_create_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_create_req->share = strdup(share);
	if (file_create_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_create_req->parent_dir_path = strdup(parent_dir_path);
		if (file_create_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_create_req->file = strdup(file);
	if (file_create_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	file_create_req->max_size_bytes = max_size_bytes;

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_file_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_fs_req_file_create_hdr_fill(file_create_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_file_free:
	free(file_create_req->file);
err_path_free:
	free(file_create_req->parent_dir_path);
err_share_free:
	free(file_create_req->share);
err_acc_free:
	free(file_create_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_file_del_free(struct az_fs_req_file_del *file_del_req)
{
	free(file_del_req->acc);
	free(file_del_req->share);
	free(file_del_req->parent_dir_path);
	free(file_del_req->file);
}

int
az_fs_req_file_del(const char *acc,
		   const char *share,
		   const char *parent_dir_path,	/* optional */
		   const char *file,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_del *file_del_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_del_req = &ebo->req.file_del;

	file_del_req->acc = strdup(acc);
	if (file_del_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_del_req->share = strdup(share);
	if (file_del_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_del_req->parent_dir_path = strdup(parent_dir_path);
		if (file_del_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_del_req->file = strdup(file);
	if (file_del_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	op->method = REQ_METHOD_DELETE;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_file_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_file_free:
	free(file_del_req->file);
err_path_free:
	free(file_del_req->parent_dir_path);
err_share_free:
	free(file_del_req->share);
err_acc_free:
	free(file_del_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_file_get_free(struct az_fs_req_file_get *file_get_req)
{
	free(file_get_req->acc);
	free(file_get_req->share);
	free(file_get_req->parent_dir_path);
	free(file_get_req->file);
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
az_fs_req_file_get(const char *acc,
		   const char *share,
		   const char *parent_dir_path,
		   const char *file,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *dest_data,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_get *file_get_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_get_req = &ebo->req.file_get;

	file_get_req->acc = strdup(acc);
	if (file_get_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_get_req->share = strdup(share);
	if (file_get_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_get_req->parent_dir_path = strdup(parent_dir_path);
		if (file_get_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_get_req->file = strdup(file);
	if (file_get_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

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
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_file_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_fs_req_file_get_hdr_fill(file_get_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_file_free:
	free(file_get_req->file);
err_path_free:
	free(file_get_req->parent_dir_path);
err_share_free:
	free(file_get_req->share);
err_acc_free:
	free(file_get_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_file_put_free(struct az_fs_req_file_put *file_put_req)
{
	free(file_put_req->acc);
	free(file_put_req->share);
	free(file_put_req->parent_dir_path);
	free(file_put_req->file);
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
az_fs_req_file_put(const char *acc,
		   const char *share,
		   const char *parent_dir_path,
		   const char *file,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *src_data,
		   struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_put *file_put_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_put_req = &ebo->req.file_put;

	file_put_req->acc = strdup(acc);
	if (file_put_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_put_req->share = strdup(share);
	if (file_put_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_put_req->parent_dir_path = strdup(parent_dir_path);
		if (file_put_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_put_req->file = strdup(file);
	if (file_put_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

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
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_file_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s?comp=range",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_fs_req_file_put_hdr_fill(file_put_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_file_free:
	free(file_put_req->file);
err_path_free:
	free(file_put_req->parent_dir_path);
err_share_free:
	free(file_put_req->share);
err_acc_free:
	free(file_put_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_file_prop_get_free(struct az_fs_req_file_prop_get *file_prop_get_req)
{
	free(file_prop_get_req->acc);
	free(file_prop_get_req->share);
	free(file_prop_get_req->parent_dir_path);
	free(file_prop_get_req->file);
}

int
az_fs_req_file_prop_get(const char *acc,
			const char *share,
			const char *parent_dir_path,
			const char *file,
			struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_prop_get *file_prop_get_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_prop_get_req = &ebo->req.file_prop_get;

	file_prop_get_req->acc = strdup(acc);
	if (file_prop_get_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_prop_get_req->share = strdup(share);
	if (file_prop_get_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_prop_get_req->parent_dir_path = strdup(parent_dir_path);
		if (file_prop_get_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_prop_get_req->file = strdup(file);
	if (file_prop_get_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	op->method = REQ_METHOD_HEAD;
	op->url_https_only = false;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_file_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_file_free:
	free(file_prop_get_req->file);
err_path_free:
	free(file_prop_get_req->parent_dir_path);
err_share_free:
	free(file_prop_get_req->share);
err_acc_free:
	free(file_prop_get_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_rsp_file_prop_get_free(struct az_fs_rsp_file_prop_get *file_prop_get_rsp)
{
	free(file_prop_get_rsp->content_type);
}

static int
az_fs_rsp_file_prop_get_process(struct op *op,
			struct az_fs_rsp_file_prop_get *file_prop_get_rsp)
{
	int ret;

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

	return 0;

err_out:
	return ret;
}

static void
az_fs_req_file_prop_set_free(struct az_fs_req_file_prop_set *file_prop_set_req)
{
	free(file_prop_set_req->acc);
	free(file_prop_set_req->share);
	free(file_prop_set_req->parent_dir_path);
	free(file_prop_set_req->file);
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
az_fs_req_file_prop_set(const char *acc,
			const char *share,
			const char *parent_dir_path,
			const char *file,
			uint64_t relevant,
			uint64_t len,
			const char *content_type,
			struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_file_prop_set *file_prop_set_req;

	if ((acc == NULL) || (share == NULL) || (file == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_FILE_PROP_SET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	file_prop_set_req = &ebo->req.file_prop_set;

	file_prop_set_req->acc = strdup(acc);
	if (file_prop_set_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	file_prop_set_req->share = strdup(share);
	if (file_prop_set_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	if (parent_dir_path != NULL) {
		file_prop_set_req->parent_dir_path = strdup(parent_dir_path);
		if (file_prop_set_req->parent_dir_path == NULL) {
			ret = -ENOMEM;
			goto err_share_free;
		}
	}

	file_prop_set_req->file = strdup(file);
	if (file_prop_set_req->file == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

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
			goto err_file_free;
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
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctype_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s%s%s?comp=properties",
		       share,
		       (parent_dir_path ? parent_dir_path : ""),
		       (parent_dir_path ? "/" : ""), file);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_fs_req_file_prop_set_hdr_fill(file_prop_set_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_ctype_free:
	free(file_prop_set_req->content_type);
err_file_free:
	free(file_prop_set_req->file);
err_path_free:
	free(file_prop_set_req->parent_dir_path);
err_share_free:
	free(file_prop_set_req->share);
err_acc_free:
	free(file_prop_set_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	switch (ebo->opcode) {
	case AOP_FS_SHARES_LIST:
		az_fs_req_shares_list_free(&ebo->req.shares_list);
		break;
	case AOP_FS_SHARE_CREATE:
		az_fs_req_share_create_free(&ebo->req.share_create);
		break;
	case AOP_FS_SHARE_DEL:
		az_fs_req_share_del_free(&ebo->req.share_del);
		break;
	case AOP_FS_SHARE_PROP_GET:
		az_fs_req_share_prop_get_free(&ebo->req.share_prop_get);
		break;
	case AOP_FS_DIRS_FILES_LIST:
		az_fs_req_dirs_files_list_free(&ebo->req.dirs_files_list);
		break;
	case AOP_FS_DIR_CREATE:
		az_fs_req_dir_create_free(&ebo->req.dir_create);
		break;
	case AOP_FS_DIR_DEL:
		az_fs_req_dir_del_free(&ebo->req.dir_del);
		break;
	case AOP_FS_DIR_PROP_GET:
		az_fs_req_dir_prop_get_free(&ebo->req.dir_prop_get);
		break;
	case AOP_FS_FILE_CREATE:
		az_fs_req_file_create_free(&ebo->req.file_create);
		break;
	case AOP_FS_FILE_DEL:
		az_fs_req_file_del_free(&ebo->req.file_del);
		break;
	case AOP_FS_FILE_GET:
		az_fs_req_file_get_free(&ebo->req.file_get);
		break;
	case AOP_FS_FILE_PUT:
		az_fs_req_file_put_free(&ebo->req.file_put);
		break;
	case AOP_FS_FILE_PROP_GET:
		az_fs_req_file_prop_get_free(&ebo->req.file_prop_get);
		break;
	case AOP_FS_FILE_PROP_SET:
		az_fs_req_file_prop_set_free(&ebo->req.file_prop_set);
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
	case AOP_FS_FILE_PROP_GET:
		az_fs_rsp_file_prop_get_free(&ebo->rsp.file_prop_get);
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
	case AOP_FS_FILE_PROP_GET:
		ret = az_fs_rsp_file_prop_get_process(op,
						      &ebo->rsp.file_prop_get);
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

struct az_fs_rsp_file_prop_get *
az_fs_rsp_file_prop_get(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);
	return &ebo->rsp.file_prop_get;
}
