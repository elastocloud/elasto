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
#include "azure_mgmt_req.h"

/*
 * primary Elasto-Backend Op structure for Azure service management requests
 */
struct az_mgmt_ebo {
	enum az_mgmt_opcode opcode;
	struct az_mgmt_req req;
	struct az_mgmt_rsp rsp;
	struct op op;
};

static void
az_mgmt_req_free(struct op *op);
static void
az_mgmt_rsp_free(struct op *op);
static int
az_mgmt_rsp_process(struct op *op);

static void
az_mgmt_ebo_free(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);

	free(ebo);
}

static int
az_mgmt_ebo_init(enum az_mgmt_opcode opcode,
		 struct az_mgmt_ebo **_ebo)
{
	struct az_mgmt_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_free = az_mgmt_req_free;
	ebo->op.rsp_free = az_mgmt_rsp_free;
	ebo->op.rsp_process = az_mgmt_rsp_process;
	ebo->op.ebo_free = az_mgmt_ebo_free;
	/* sign callback set conditionally per-op */
	*_ebo = ebo;
	return 0;
}

#define REQ_HOST_AZURE_MGMT "management.core.windows.net"

int
az_mgmt_req_hostname_get(char **_hostname)
{
	char *hostname;

	if (_hostname== NULL) {
		return -EINVAL;
	}

	hostname = strdup(REQ_HOST_AZURE_MGMT);
	if (hostname == NULL) {
		return -ENOMEM;
	}

	*_hostname = hostname;
	return 0;
}

static void
az_mgmt_req_acc_keys_get_free(struct az_mgmt_req_acc_keys_get *acc_keys_get_req)
{
	free(acc_keys_get_req->sub_id);
	free(acc_keys_get_req->service_name);
}

static void
az_mgmt_rsp_acc_keys_get_free(struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp)
{
	free(acc_keys_get_rsp->primary);
	free(acc_keys_get_rsp->secondary);
}

int
az_mgmt_req_acc_keys_get(const char *sub_id,
			 const char *service_name,
			 struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_acc_keys_get *acc_keys_get_req;

	if ((sub_id == NULL) || (service_name == NULL) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_ACC_KEYS_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	acc_keys_get_req = &ebo->req.acc_keys_get;

	acc_keys_get_req->sub_id = strdup(sub_id);
	if (acc_keys_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	acc_keys_get_req->service_name = strdup(service_name);
	if (acc_keys_get_req->service_name == NULL) {
		ret = -ENOMEM;
		goto err_free_sub;
	}
	op->method = REQ_METHOD_GET;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_free_svc;
	}

	ret = asprintf(&op->url_path,
		       "/%s/services/storageservices/%s/keys",
		       sub_id, service_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, true);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_free_svc:
	free(acc_keys_get_req->service_name);
err_free_sub:
	free(acc_keys_get_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_mgmt_rsp_acc_keys_get_process(struct op *op,
			struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_MGMT_ACC_KEYS_GET);

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

	ret = exml_str_want(xdoc, "/StorageService/StorageServiceKeys/Primary",
			    true, &acc_keys_get_rsp->primary, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}
	ret = exml_str_want(xdoc,
			    "/StorageService/StorageServiceKeys/Secondary",
			    true, &acc_keys_get_rsp->secondary, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_rsp_free;
	}
	dbg(5, "primary key: %s, secondary key: %s\n",
	    acc_keys_get_rsp->primary, acc_keys_get_rsp->secondary);

	exml_free(xdoc);
	return 0;

err_rsp_free:
	az_mgmt_rsp_acc_keys_get_free(acc_keys_get_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_mgmt_req_acc_list_free(struct az_mgmt_req_acc_list *acc_list_req)
{
	free(acc_list_req->sub_id);
}

static void
azure_acc_free(struct azure_account *acc)
{
	free(acc->svc_name);
	free(acc->label);
	free(acc->url);
	free(acc->affin_grp);
	free(acc->location);
	free(acc->desc);
}

static void
az_mgmt_rsp_acc_list_free(struct az_mgmt_rsp_acc_list *acc_list_rsp)
{
	struct azure_account *acc;
	struct azure_account *acc_n;

	if (acc_list_rsp->num_accs == 0) {
		return;
	}

	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(acc);
		free(acc);
	}
}

int
az_mgmt_req_acc_list(const char *sub_id,
		     struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_acc_list *acc_list_req;

	if ((sub_id == NULL) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_ACC_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	acc_list_req = &ebo->req.acc_list;

	acc_list_req->sub_id = strdup(sub_id);
	if (acc_list_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	ret = asprintf(&op->url_path,
		       "/%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, true);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_sub_free:
	free(acc_list_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int az_mgmt_rsp_acc_want(struct xml_doc *xdoc,
				struct azure_account *acc)
{
	int ret;

	ret = exml_str_want(xdoc, "./ServiceName", true, &acc->svc_name, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "./Url", true, &acc->url, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/Description",
			    false, &acc->desc, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/AffinityGroup",
			    false, &acc->affin_grp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_base64_want(xdoc, "./StorageServiceProperties/Label",
			       false, &acc->label, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/Location",
			    false, &acc->location, NULL);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static int az_mgmt_rsp_acc_iter_process(struct xml_doc *xdoc,
					const char *path,
					const char *val,
					void *cb_data)
{
	int ret;
	struct az_mgmt_rsp_acc_list *acc_list_rsp
				= (struct az_mgmt_rsp_acc_list *)cb_data;
	struct azure_account *acc;

	/* request callback for subsequent storage account descriptions */
	ret = exml_path_cb_want(xdoc,
				"/StorageServices/StorageService", false,
				az_mgmt_rsp_acc_iter_process, acc_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	acc = malloc(sizeof(*acc));
	if (acc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(acc, 0, sizeof(*acc));

	ret = az_mgmt_rsp_acc_want(xdoc, acc);
	if (ret < 0) {
		goto err_acc_free;
	}

	list_add_tail(&acc_list_rsp->accs, &acc->list);
	acc_list_rsp->num_accs++;

	return 0;

err_acc_free:
	free(acc);
err_out:
	return ret;
}

static int
az_mgmt_rsp_acc_list_process(struct op *op,
			     struct az_mgmt_rsp_acc_list *acc_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_account *acc;
	struct azure_account *acc_n;

	assert(op->opcode == AOP_MGMT_ACC_LIST);

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

	list_head_init(&acc_list_rsp->accs);

	/* request callback for first storage account description */
	ret = exml_path_cb_want(xdoc,
				"/StorageServices/StorageService", false,
				az_mgmt_rsp_acc_iter_process, acc_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		/* need to walk list in case cb fired */
		goto err_accs_free;
	}

	exml_free(xdoc);
	return 0;

err_accs_free:
	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(acc);
		free(acc);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_mgmt_req_acc_create_free(struct az_mgmt_req_acc_create *acc_create_req)
{
	free(acc_create_req->sub_id);
	azure_acc_free(&acc_create_req->acc);
}

static int
az_mgmt_req_acc_create_hdr_fill(struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, true);
	if (ret < 0) {
		goto err_out;
	}
	ret = op_req_hdr_add(op,
			"Content-Type", "application/xml; charset=utf-8");
	if (ret < 0) {
		goto err_hdrs_free;
	}
	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * The order of the elements in the request body is significant!
 */
static int
az_mgmt_req_acc_create_body_fill(struct azure_account *acc,
				 struct elasto_data **req_data_out)
{
	int ret;
	char *b64_label;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	/* 2k buf, should be strlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = base64_encode(acc->label, strlen(acc->label), &b64_label);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_buf_free;
	}

	xml_data = (char *)req_data->iov.buf;
	ret = snprintf(xml_data, buf_remain,
		       "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		       "<CreateStorageServiceInput "
			  "xmlns=\"http://schemas.microsoft.com/windowsazure\">"
				"<ServiceName>%s</ServiceName>"
				"<Description>%s</Description>"
				"<Label>%s</Label>",
		       acc->svc_name,
		       (acc->desc ? acc->desc : ""),
		       b64_label);
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	if (acc->affin_grp != NULL) {
		ret = snprintf(xml_data, buf_remain,
					"<AffinityGroup>%s</AffinityGroup>"
			       "</CreateStorageServiceInput>",
			       acc->affin_grp);

	} else {
		ret = snprintf(xml_data, buf_remain,
					"<Location>%s</Location>"
			       "</CreateStorageServiceInput>",
			       acc->location);
	}

	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending account creation req data: %s\n",
	    (char *)req_data->iov.buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_free(req_data);
err_out:
	return ret;
}

/*
 * either @affin_grp or @location must be set, but not both.
 */
int
az_mgmt_req_acc_create(const char *sub_id,
		       const char *svc_name,
		       const char *label,
		       const char *desc,
		       const char *affin_grp,
		       const char *location,
		       struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_acc_create *acc_create_req;

	if ((sub_id == NULL) || (svc_name == NULL) || (label == NULL)) {
		return -EINVAL;
	} else if ((affin_grp == NULL) && (location == NULL)) {
		return -EINVAL;
	} else if ((affin_grp != NULL) && (location != NULL)) {
		return -EINVAL;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_ACC_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	acc_create_req = &ebo->req.acc_create;

	acc_create_req->sub_id = strdup(sub_id);
	if (acc_create_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	acc_create_req->acc.svc_name = strdup(svc_name);
	if (acc_create_req->acc.svc_name == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}
	acc_create_req->acc.label = strdup(label);
	if (acc_create_req->acc.label == NULL) {
		ret = -ENOMEM;
		goto err_svc_name_free;
	}

	if (desc != NULL) {
		acc_create_req->acc.desc = strdup(desc);
		if (acc_create_req->acc.desc == NULL) {
			ret = -ENOMEM;
			goto err_label_free;
		}
	}
	if (affin_grp != NULL) {
		assert(location == NULL);
		acc_create_req->acc.affin_grp = strdup(affin_grp);
		if (acc_create_req->acc.affin_grp == NULL) {
			ret = -ENOMEM;
			goto err_desc_free;
		}
	} else {
		assert(location != NULL);
		acc_create_req->acc.location = strdup(location);
		if (acc_create_req->acc.location == NULL) {
			ret = -ENOMEM;
			goto err_desc_free;
		}
	}

	op->method = REQ_METHOD_POST;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_loc_free;
	}

	ret = asprintf(&op->url_path,
		       "/%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_mgmt_req_acc_create_hdr_fill(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = az_mgmt_req_acc_create_body_fill(&acc_create_req->acc,
					       &op->req.data);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	*_op = op;
	return 0;
err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_loc_free:
	free(acc_create_req->acc.location);
	free(acc_create_req->acc.affin_grp);
err_desc_free:
	free(acc_create_req->acc.desc);
err_label_free:
	free(acc_create_req->acc.label);
err_svc_name_free:
	free(acc_create_req->acc.svc_name);
err_sub_free:
	free(acc_create_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_mgmt_req_acc_del_free(struct az_mgmt_req_acc_del *acc_del_req)
{
	free(acc_del_req->sub_id);
	free(acc_del_req->acc);
}

static int
az_mgmt_req_acc_del_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, true);
}

int
az_mgmt_req_acc_del(const char *sub_id,
		    const char *acc,
		    struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_acc_del *acc_del_req;

	if ((sub_id == NULL) || (acc == NULL) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_ACC_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	acc_del_req = &ebo->req.acc_del;

	acc_del_req->sub_id = strdup(sub_id);
	if (acc_del_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	acc_del_req->acc = strdup(acc);
	if (acc_del_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	op->method = REQ_METHOD_DELETE;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	ret = asprintf(&op->url_path,
		       "/%s/services/storageservices/%s",
		       sub_id, acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_mgmt_req_acc_del_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_acc_free:
	free(acc_del_req->acc);
err_sub_free:
	free(acc_del_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_mgmt_req_acc_prop_get_free(struct az_mgmt_req_acc_prop_get *acc_prop_get_req)
{
	free(acc_prop_get_req->sub_id);
	free(acc_prop_get_req->acc);
}

static void
az_mgmt_rsp_acc_prop_get_free(struct az_mgmt_rsp_acc_prop_get *acc_prop_get_rsp)
{
	azure_acc_free(&acc_prop_get_rsp->acc_desc);
}

int
az_mgmt_req_acc_prop_get(const char *sub_id,
			 const char *acc,
			 struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_acc_prop_get *acc_prop_get_req;

	if ((sub_id == NULL) || (acc == NULL) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_ACC_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	acc_prop_get_req = &ebo->req.acc_prop_get;

	acc_prop_get_req->sub_id = strdup(sub_id);
	if (acc_prop_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	acc_prop_get_req->acc = strdup(acc);
	if (acc_prop_get_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	ret = asprintf(&op->url_path, "/%s/services/storageservices/%s",
		       sub_id, acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, true);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_acc_free:
	free(acc_prop_get_req->acc);
err_sub_free:
	free(acc_prop_get_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int az_mgmt_rsp_acc_svc_process(struct xml_doc *xdoc,
				       const char *path,
				       const char *val,
				       void *cb_data)
{
	struct az_mgmt_rsp_acc_prop_get *acc_prop_get_rsp
				= (struct az_mgmt_rsp_acc_prop_get *)cb_data;

	return az_mgmt_rsp_acc_want(xdoc, &acc_prop_get_rsp->acc_desc);
}

static int
az_mgmt_rsp_acc_prop_get_process(struct op *op,
			      struct az_mgmt_rsp_acc_prop_get *acc_prop_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_MGMT_ACC_PROP_GET);

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

	ret = exml_path_cb_want(xdoc,
				"/StorageService", true,
				az_mgmt_rsp_acc_svc_process,
				acc_prop_get_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = 0;
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_mgmt_req_status_get_free(struct az_mgmt_req_status_get *sts_get_req)
{
	free(sts_get_req->sub_id);
	free(sts_get_req->req_id);
}

static void
az_mgmt_rsp_status_get_free(struct az_mgmt_rsp_status_get *sts_get_rsp)
{
	if (sts_get_rsp->status == AOP_STATUS_FAILED) {
		free(sts_get_rsp->err.msg);
	}
}

int
az_mgmt_req_status_get(const char *sub_id,
		       const char *req_id,
		       struct op **_op)
{
	int ret;
	struct az_mgmt_ebo *ebo;
	struct op *op;
	struct az_mgmt_req_status_get *sts_get_req;

	if ((sub_id == NULL) || (req_id == NULL) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_ebo_init(AOP_MGMT_STATUS_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	sts_get_req = &ebo->req.sts_get;

	sts_get_req->sub_id = strdup(sub_id);
	if (sts_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	sts_get_req->req_id = strdup(req_id);
	if (sts_get_req->req_id == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	op->method = REQ_METHOD_GET;
	op->url_https_only = true;
	op->url_host = strdup(REQ_HOST_AZURE_MGMT);
	if (op->url_host == NULL) {
		ret = -ENOMEM;
		goto err_req_free;
	}

	ret = asprintf(&op->url_path,
		       "/%s/operations/%s",
		       sub_id, req_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, true);
	if (ret < 0)
		goto err_upath_free;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_req_free:
	free(sts_get_req->req_id);
err_sub_free:
	free(sts_get_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_mgmt_rsp_status_val_process(struct xml_doc *xdoc,
			       const char *path,
			       const char *val,
			       void *cb_data)
{
	struct az_mgmt_rsp_status_get *sts_get_rsp
			= (struct az_mgmt_rsp_status_get *)cb_data;
	int ret;

	if (strcmp(val, "InProgress") == 0) {
		sts_get_rsp->status = AOP_STATUS_IN_PROGRESS;
	} else if (strcmp(val, "Succeeded") == 0) {
		sts_get_rsp->status = AOP_STATUS_SUCCEEDED;
		ret = exml_int32_want(xdoc, "/Operation/HttpStatusCode", true,
				      &sts_get_rsp->ok.http_code, NULL);
		if (ret < 0) {
			goto err_out;
		}
	} else if (strcmp(val, "Failed") == 0) {
		sts_get_rsp->status = AOP_STATUS_FAILED;
		ret = exml_int32_want(xdoc, "/Operation/HttpStatusCode", true,
				      &sts_get_rsp->ok.http_code, NULL);
		if (ret < 0) {
			goto err_out;
		}
		ret = exml_int32_want(xdoc, "/Operation/Error/Code", true,
				      &sts_get_rsp->err.code, NULL);
		if (ret < 0) {
			goto err_out;
		}
		ret = exml_str_want(xdoc, "/Operation/Error/Message", true,
				    &sts_get_rsp->err.msg, NULL);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		dbg(0, "unexpected op status: %s\n", val);
		ret = -EINVAL;
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static int
az_mgmt_rsp_status_get_process(struct op *op,
			       struct az_mgmt_rsp_status_get *sts_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_MGMT_STATUS_GET);

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

	ret = exml_val_cb_want(xdoc, "/Operation/Status", true,
			       az_mgmt_rsp_status_val_process, sts_get_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_rsp_free;
	}

	exml_free(xdoc);
	return 0;

err_rsp_free:
	az_mgmt_rsp_status_get_free(sts_get_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_mgmt_req_free(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);

	switch (ebo->opcode) {
	case AOP_MGMT_ACC_KEYS_GET:
		az_mgmt_req_acc_keys_get_free(&ebo->req.acc_keys_get);
		break;
	case AOP_MGMT_ACC_LIST:
		az_mgmt_req_acc_list_free(&ebo->req.acc_list);
		break;
	case AOP_MGMT_ACC_CREATE:
		az_mgmt_req_acc_create_free(&ebo->req.acc_create);
		break;
	case AOP_MGMT_ACC_DEL:
		az_mgmt_req_acc_del_free(&ebo->req.acc_del);
		break;
	case AOP_MGMT_ACC_PROP_GET:
		az_mgmt_req_acc_prop_get_free(&ebo->req.acc_prop_get);
		break;
	case AOP_MGMT_STATUS_GET:
		az_mgmt_req_status_get_free(&ebo->req.sts_get);
		break;
	default:
		assert(false);
		break;
	};
}

static void
az_mgmt_rsp_free(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);

	switch (ebo->opcode) {
	case AOP_MGMT_ACC_KEYS_GET:
		az_mgmt_rsp_acc_keys_get_free(&ebo->rsp.acc_keys_get);
		break;
	case AOP_MGMT_ACC_LIST:
		az_mgmt_rsp_acc_list_free(&ebo->rsp.acc_list);
		break;
	case AOP_MGMT_ACC_PROP_GET:
		az_mgmt_rsp_acc_prop_get_free(&ebo->rsp.acc_prop_get);
		break;
	case AOP_MGMT_STATUS_GET:
		az_mgmt_rsp_status_get_free(&ebo->rsp.sts_get);
		break;
	case AOP_MGMT_ACC_CREATE:
	case AOP_MGMT_ACC_DEL:
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
az_mgmt_rsp_process(struct op *op)
{
	int ret;
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_MGMT_ACC_KEYS_GET:
		ret = az_mgmt_rsp_acc_keys_get_process(op,
						       &ebo->rsp.acc_keys_get);
		break;
	case AOP_MGMT_ACC_LIST:
		ret = az_mgmt_rsp_acc_list_process(op, &ebo->rsp.acc_list);
		break;
	case AOP_MGMT_ACC_PROP_GET:
		ret = az_mgmt_rsp_acc_prop_get_process(op,
						       &ebo->rsp.acc_prop_get);
		break;
	case AOP_MGMT_STATUS_GET:
		ret = az_mgmt_rsp_status_get_process(op, &ebo->rsp.sts_get);
		break;
	case AOP_MGMT_ACC_CREATE:
	case AOP_MGMT_ACC_DEL:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}

struct az_mgmt_rsp_acc_keys_get *
az_mgmt_rsp_acc_keys_get(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);
	return &ebo->rsp.acc_keys_get;
}

struct az_mgmt_rsp_acc_list *
az_mgmt_rsp_acc_list(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);
	return &ebo->rsp.acc_list;
}

struct az_mgmt_rsp_acc_prop_get *
az_mgmt_rsp_acc_prop_get(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);
	return &ebo->rsp.acc_prop_get;
}

struct az_mgmt_rsp_status_get *
az_mgmt_rsp_status_get(struct op *op)
{
	struct az_mgmt_ebo *ebo = container_of(op, struct az_mgmt_ebo, op);
	return &ebo->rsp.sts_get;
}
