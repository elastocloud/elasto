/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2014, all rights reserved.
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
#define _GNU_SOURCE
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

/*
 * primary Elasto-Backend Op structure for Azure requests
 */
struct az_ebo {
	enum az_opcode opcode;
	struct az_req req;
	struct az_rsp rsp;
	struct op op;
};

static int
az_req_sign(const char *acc,
	    const uint8_t *key,
	    int key_len,
	    struct op *op)
{
	int ret;
	char *sig_str;
	char *hdr_str;

	if (key == NULL) {
		return -EINVAL;
	}

	ret = sign_gen_lite_azure(acc, key, key_len,
				  op, &op->sig_src, &sig_str);
	if (ret < 0) {
		dbg(0, "Azure signing failed: %s\n",
		    strerror(-ret));
		return ret;
	}
	ret = asprintf(&hdr_str, "SharedKeyLite %s:%s",
		       acc, sig_str);
	free(sig_str);
	if (ret < 0) {
		return -ENOMEM;
	}

	ret = op_req_hdr_add(op, "Authorization", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static void
az_req_free(struct op *op);
static void
az_rsp_free(struct op *op);
static int
az_rsp_process(struct op *op);

static void
az_ebo_free(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);

	free(ebo);
}

static int
az_ebo_init(enum az_opcode opcode,
	    struct az_ebo **_ebo)
{
	struct az_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_free = az_req_free;
	ebo->op.rsp_free = az_rsp_free;
	ebo->op.rsp_process = az_rsp_process;
	ebo->op.ebo_free = az_ebo_free;
	/* sign callback set conditionally per-op */
	*_ebo = ebo;
	return 0;
}

static char *
gen_date_str(void)
{
	char buf[200];
	time_t now;
	struct tm utc_tm;
	size_t ret;

	time(&now);
	gmtime_r(&now, &utc_tm);
	/* Sun, 11 Oct 2009 21:49:13 GMT */
	ret = strftime(buf, sizeof(buf), "%a, %d %b %Y %T GMT", &utc_tm);
	if (ret == 0)
		return NULL;
	return strdup(buf);
}

static int
az_req_common_hdr_fill(struct op *op, bool mgmt)
{
	int ret;
	char *date_str;

	if (mgmt) {
		ret = op_req_hdr_add(op, "x-ms-version", "2012-03-01");
		if (ret < 0) {
			goto err_out;
		}
		return 0;
	}

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = op_req_hdr_add(op, "x-ms-date", date_str);
	free(date_str);
	if (ret < 0) {
		goto err_out;
	}
	/* different to the version in management */
	ret = op_req_hdr_add(op, "x-ms-version", "2012-02-12");
	if (ret < 0) {
		goto err_hdrs_free;
	}
	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

static void
az_req_acc_keys_get_free(struct az_req_acc_keys_get *acc_keys_get_req)
{
	free(acc_keys_get_req->sub_id);
	free(acc_keys_get_req->service_name);
}
static void
az_rsp_acc_keys_get_free(struct az_rsp_acc_keys_get *acc_keys_get_rsp)
{
	free(acc_keys_get_rsp->primary);
	free(acc_keys_get_rsp->secondary);
}

static int
az_req_acc_keys_get_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, true);
}

int
az_req_acc_keys_get(const char *sub_id,
		    const char *service_name,
		    struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_acc_keys_get *acc_keys_get_req;

	ret = az_ebo_init(AOP_ACC_KEYS_GET, &ebo);
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

	ret = az_req_acc_keys_get_hdr_fill(op);
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
az_rsp_acc_keys_get_process(struct op *op,
			    struct az_rsp_acc_keys_get *acc_keys_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_ACC_KEYS_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
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
	az_rsp_acc_keys_get_free(acc_keys_get_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_acc_list_free(struct az_req_acc_list *acc_list_req)
{
	free(acc_list_req->sub_id);
}

static void
azure_acc_free(struct azure_account **pacc)
{
	struct azure_account *acc = *pacc;

	free(acc->svc_name);
	free(acc->label);
	free(acc->url);
	free(acc->affin_grp);
	free(acc->location);
	free(acc->desc);
	free(acc);
}

static void
az_rsp_acc_list_free(struct az_rsp_acc_list *acc_list_rsp)
{
	struct azure_account *acc;
	struct azure_account *acc_n;

	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(&acc);
	}
}

static int
az_req_acc_list_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, true);
}

int
az_req_acc_list(const char *sub_id,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_acc_list *acc_list_req;

	/* TODO input validation */

	ret = az_ebo_init(AOP_ACC_LIST, &ebo);
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

	ret = az_req_acc_list_hdr_fill(op);
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

static int az_rsp_acc_iter_process(struct xml_doc *xdoc,
				   const char *path,
				   const char *val,
				   void *cb_data)
{
	int ret;
	struct az_rsp_acc_list *acc_list_rsp
					= (struct az_rsp_acc_list *)cb_data;
	struct azure_account *acc;

	/* request callback for subsequent storage account descriptions */
	ret = exml_path_cb_want(xdoc,
				"/StorageServices/StorageService", false,
				az_rsp_acc_iter_process, acc_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	acc = malloc(sizeof(*acc));
	if (acc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(acc, 0, sizeof(*acc));

	ret = exml_str_want(xdoc, "./ServiceName", true, &acc->svc_name, NULL);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = exml_str_want(xdoc, "./Url", true, &acc->url, NULL);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/Description",
			    false, &acc->desc, NULL);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/AffinityGroup",
			    false, &acc->affin_grp, NULL);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = exml_base64_want(xdoc, "./StorageServiceProperties/Label",
			       false, &acc->label, NULL);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = exml_str_want(xdoc, "./StorageServiceProperties/Location",
			    false, &acc->location, NULL);
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
az_rsp_acc_list_process(struct op *op,
			struct az_rsp_acc_list *acc_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_account *acc;
	struct azure_account *acc_n;

	assert(op->opcode == AOP_ACC_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&acc_list_rsp->accs);

	/* request callback for first storage account description */
	ret = exml_path_cb_want(xdoc,
				"/StorageServices/StorageService", false,
				az_rsp_acc_iter_process, acc_list_rsp, NULL);
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
		azure_acc_free(&acc);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_acc_create_free(struct az_req_acc_create *acc_create_req)
{
	free(acc_create_req->sub_id);
	azure_acc_free(&acc_create_req->acc);
}

static int
az_req_acc_create_hdr_fill(struct op *op)
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
az_req_acc_create_body_fill(struct azure_account *acc,
			    struct elasto_data **req_data_out)
{
	int ret;
	char *b64_label;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	/* 2k buf, should be strlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, 0, true, &req_data);
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
az_req_acc_create(const char *sub_id,
		  const char *svc_name,
		  const char *label,
		  const char *desc,
		  const char *affin_grp,
		  const char *location,
		  struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_acc_create *acc_create_req;

	if ((sub_id == NULL) || (svc_name == NULL) || (label == NULL)) {
		return -EINVAL;
	} else if ((affin_grp == NULL) && (location == NULL)) {
		return -EINVAL;
	} else if ((affin_grp != NULL) && (location != NULL)) {
		return -EINVAL;
	}

	ret = az_ebo_init(AOP_ACC_CREATE, &ebo);
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

	acc_create_req->acc = malloc(sizeof(*acc_create_req->acc));
	if (acc_create_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}
	memset(acc_create_req->acc, 0, sizeof(*acc_create_req->acc));

	acc_create_req->acc->svc_name = strdup(svc_name);
	if (acc_create_req->acc->svc_name == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}
	acc_create_req->acc->label = strdup(label);
	if (acc_create_req->acc->label == NULL) {
		ret = -ENOMEM;
		goto err_svc_name_free;
	}

	if (desc != NULL) {
		acc_create_req->acc->desc = strdup(desc);
		if (acc_create_req->acc->desc == NULL) {
			ret = -ENOMEM;
			goto err_label_free;
		}
	}
	if (affin_grp != NULL) {
		assert(location == NULL);
		acc_create_req->acc->affin_grp = strdup(affin_grp);
		if (acc_create_req->acc->affin_grp == NULL) {
			ret = -ENOMEM;
			goto err_desc_free;
		}
	} else {
		assert(location != NULL);
		acc_create_req->acc->location = strdup(location);
		if (acc_create_req->acc->location == NULL) {
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

	ret = az_req_acc_create_hdr_fill(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = az_req_acc_create_body_fill(acc_create_req->acc,
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
	free(acc_create_req->acc->location);
	free(acc_create_req->acc->affin_grp);
err_desc_free:
	free(acc_create_req->acc->desc);
err_label_free:
	free(acc_create_req->acc->label);
err_svc_name_free:
	free(acc_create_req->acc->svc_name);
err_acc_free:
	free(acc_create_req->acc);
err_sub_free:
	free(acc_create_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_acc_del_free(struct az_req_acc_del *acc_del_req)
{
	free(acc_del_req->sub_id);
	free(acc_del_req->account);
}

static int
az_req_acc_del_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, true);
}

int
az_req_acc_del(const char *sub_id,
	       const char *account,
	       struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_acc_del *acc_del_req;

	ret = az_ebo_init(AOP_ACC_DEL, &ebo);
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

	acc_del_req->account = strdup(account);
	if (acc_del_req->account == NULL) {
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
		       sub_id, account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_acc_del_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_acc_free:
	free(acc_del_req->account);
err_sub_free:
	free(acc_del_req->sub_id);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_ctnr_list_free(struct az_req_ctnr_list *ctnr_list_req)
{
	free(ctnr_list_req->account);
}
static void
az_rsp_ctnr_list_free(struct az_rsp_ctnr_list *ctnr_list_rsp)
{
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	if (ctnr_list_rsp->num_ctnrs <= 0)
		return;

	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
}

static int
az_req_ctnr_list_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

int
az_req_ctnr_list(const char *account,
		 struct op **_op)
{

	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_ctnr_list *ctnr_list_req;

	/* TODO input validation */

	ret = az_ebo_init(AOP_CONTAINER_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	ctnr_list_req = &ebo->req.ctnr_list;

	ctnr_list_req->account = strdup(account);
	if (ctnr_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}
	ret = asprintf(&op->url_path, "/?comp=list");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = az_req_ctnr_list_hdr_fill(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_buf_free:
	elasto_data_free(op->rsp.data);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_acc_free:
	free(ctnr_list_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_ctnr_iter_process(struct xml_doc *xdoc,
			 const char *path,
			 const char *val,
			 void *cb_data)
{
	int ret;
	struct az_rsp_ctnr_list *ctnr_list_rsp =
					(struct az_rsp_ctnr_list *)cb_data;
	struct azure_ctnr *ctnr;

	/* request callback for subsequent containers */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Containers/Container",
				false, az_rsp_ctnr_iter_process, ctnr_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	ctnr = malloc(sizeof(*ctnr));
	if (ctnr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(ctnr, 0, sizeof(*ctnr));

	ret = exml_str_want(xdoc, "./Name", true, &ctnr->name, NULL);
	if (ret < 0) {
		goto err_ctnr_free;
	}

	list_add_tail(&ctnr_list_rsp->ctnrs, &ctnr->list);
	ctnr_list_rsp->num_ctnrs++;

	return 0;

err_ctnr_free:
	free(ctnr);
err_out:
	return ret;
}

static int
az_rsp_ctnr_list_process(struct op *op,
			 struct az_rsp_ctnr_list *ctnr_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	assert(op->opcode == AOP_CONTAINER_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&ctnr_list_rsp->ctnrs);

	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Containers/Container",
				false, az_rsp_ctnr_iter_process, ctnr_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	/*
	 * Returns up to 5000 records (maxresults default),
	 */
	ret = exml_parse(xdoc);
	if (ret < 0) {
		/* need to walk list in case cb fired */
		goto err_ctnrs_free;
	}

	exml_free(xdoc);
	return 0;

err_ctnrs_free:
	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_ctnr_create_free(struct az_req_ctnr_create *ctnr_create_req)
{
	free(ctnr_create_req->account);
	free(ctnr_create_req->ctnr);
}

static int
az_req_ctnr_create_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

int
az_req_ctnr_create(const char *account,
		   const char *ctnr,
		   struct op **_op)
{

	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_ctnr_create *ctnr_create_req;

	/* TODO input validation */

	ret = az_ebo_init(AOP_CONTAINER_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	ctnr_create_req = &ebo->req.ctnr_create;

	ctnr_create_req->account = strdup(account);
	if (ctnr_create_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	ctnr_create_req->ctnr = strdup(ctnr);
	if (ctnr_create_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=container",
		       ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_ctnr_create_hdr_fill(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_ctnr_free:
	free(ctnr_create_req->ctnr);
err_acc_free:
	free(ctnr_create_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_ctnr_del_free(struct az_req_ctnr_del *ctnr_del_req)
{
	free(ctnr_del_req->account);
	free(ctnr_del_req->container);
}

static int
az_req_ctnr_del_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

int
az_req_ctnr_del(const char *account,
		const char *container,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_ctnr_del *ctnr_del_req;

	ret = az_ebo_init(AOP_CONTAINER_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	ctnr_del_req = &ebo->req.ctnr_del;

	ctnr_del_req->account = strdup(account);
	if (ctnr_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	ctnr_del_req->container = strdup(container);
	if (ctnr_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_container;
	}
	ret = asprintf(&op->url_path, "/%s?restype=container",
		       container);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_ctnr_del_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_free_container:
	free(ctnr_del_req->container);
err_free_account:
	free(ctnr_del_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_list_free(struct az_req_blob_list *blob_list_req)
{
	free(blob_list_req->account);
	free(blob_list_req->ctnr);
}
static void
az_rsp_blob_list_free(struct az_rsp_blob_list *blob_list_rsp)
{
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	if (blob_list_rsp->num_blobs <= 0)
		return;

	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob);
	}
}

static int
az_req_blob_list_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

int
az_req_blob_list(const char *account,
		 const char *ctnr,
		 struct op **_op)
{

	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_list *blob_list_req;

	/* TODO input validation */

	ret = az_ebo_init(AOP_BLOB_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_list_req = &ebo->req.blob_list;

	blob_list_req->account = strdup(account);
	if (blob_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_list_req->ctnr = strdup(ctnr);
	if (blob_list_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=container&comp=list",
		       ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = az_req_blob_list_hdr_fill(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_buf_free:
	elasto_data_free(op->rsp.data);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_ctnr_free:
	free(blob_list_req->ctnr);
err_acc_free:
	free(blob_list_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blob_iter_type_process(struct xml_doc *xdoc,
			      const char *path,
			      const char *val,
			      void *cb_data)
{
	struct azure_blob *blob = (struct azure_blob *)cb_data;

	if (val == NULL) {
		return -EINVAL;
	}
	blob->is_page = (strcmp(val, BLOB_TYPE_PAGE) == 0);
	return 0;
}

/*
 * process a single blob list iteration at @iter, return -ENOENT if no such
 * iteration exists
 */
static int
az_rsp_blob_iter_process(struct xml_doc *xdoc,
			 const char *path,
			 const char *val,
			 void *cb_data)
{
	int ret;
	struct az_rsp_blob_list *blob_list_rsp
				= (struct az_rsp_blob_list *)cb_data;
	struct azure_blob *blob;

	/* request callback for subsequent blobs */
	ret = exml_path_cb_want(xdoc, "/EnumerationResults/Blobs/Blob",
				false, az_rsp_blob_iter_process,
				blob_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	blob = malloc(sizeof(*blob));
	if (blob == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(blob, 0, sizeof(*blob));

	ret = exml_str_want(xdoc, "./Name", true, &blob->name, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_uint64_want(xdoc, "./Properties/Content-Length", true,
			       &blob->len, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_val_cb_want(xdoc, "./Properties/BlobType", true,
			       az_rsp_blob_iter_type_process, blob, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	list_add_tail(&blob_list_rsp->blobs, &blob->list);
	blob_list_rsp->num_blobs++;

	return 0;

err_blob_free:
	free(blob);
err_out:
	return ret;
}

static int
az_rsp_blob_list_process(struct op *op,
			 struct az_rsp_blob_list *blob_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	assert(op->opcode == AOP_BLOB_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&blob_list_rsp->blobs);

	ret = exml_path_cb_want(xdoc, "/EnumerationResults/Blobs/Blob",
				false, az_rsp_blob_iter_process,
				blob_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_blobs_free;
	}

	exml_free(xdoc);
	return 0;

err_blobs_free:
	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_blob_put_free(struct az_req_blob_put *blob_put_req)
{
	free(blob_put_req->account);
	free(blob_put_req->container);
	free(blob_put_req->bname);
}

static int
az_req_blob_put_hdr_fill(struct az_req_blob_put *blob_put_req,
			 struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}
	if (strcmp(blob_put_req->type, BLOB_TYPE_PAGE) == 0) {
		char *hdr_str;
		ret = op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = asprintf(&hdr_str, "%" PRIu64,
			       blob_put_req->pg_len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-blob-content-length",
					   hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
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
 * if @data is NULL, then @page_len corresponds to the page blob length,
 * otherwise it is ignored and @data is uploaded as a block blob.
 */
int
az_req_blob_put(const char *account,
		const char *container,
		const char *bname,
		struct elasto_data *data,
		uint64_t page_len,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_put *blob_put_req;

	if ((data == NULL)
	 && (((page_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != page_len)) {
		ret = -EINVAL;
		goto err_out;
	} else if ((data != NULL) && (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_ebo_init(AOP_BLOB_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_put_req = &ebo->req.blob_put;

	blob_put_req->account = strdup(account);
	if (blob_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_put_req->container = strdup(container);
	if (blob_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	blob_put_req->bname = strdup(bname);
	if (blob_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (data == NULL) {
		blob_put_req->type = BLOB_TYPE_PAGE;
		blob_put_req->pg_len = page_len;
	} else {
		blob_put_req->type = BLOB_TYPE_BLOCK;
		op->req.data = data;
		/* TODO add a foreign flag so @req.data is not freed with @op */
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}
	ret = asprintf(&op->url_path, "/%s/%s",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_put_hdr_fill(blob_put_req, op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_free_bname:
	free(blob_put_req->bname);
err_free_container:
	free(blob_put_req->container);
err_free_account:
	free(blob_put_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_get_free(struct az_req_blob_get *blob_get_req)
{
	free(blob_get_req->account);
	free(blob_get_req->container);
	free(blob_get_req->bname);
}

static int
az_req_blob_get_hdr_fill(struct az_req_blob_get *blob_get_req,
			 struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (blob_get_req->len > 0) {
		char *hdr_str;
		ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
			       blob_get_req->off,
			       (blob_get_req->off + blob_get_req->len - 1));
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

	if (strcmp(blob_get_req->type, BLOB_TYPE_PAGE) == 0) {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
	} else {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
	}
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
 * if @src_len is zero then ignore @req_off and retrieve entire blob
 */
int
az_req_blob_get(const char *account,
		const char *container,
		const char *bname,
		bool is_page,
		struct elasto_data *dest_data,
		uint64_t src_off,
		uint64_t src_len,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_get *blob_get_req;

	/* check for correct alignment */
	if (is_page
	 && ((((src_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != src_len)
	  || (((src_off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != src_off))) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_ebo_init(AOP_BLOB_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_get_req = &ebo->req.blob_get;

	blob_get_req->account = strdup(account);
	if (blob_get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_get_req->container = strdup(container);
	if (blob_get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	blob_get_req->bname = strdup(bname);
	if (blob_get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	if (is_page) {
		blob_get_req->type = BLOB_TYPE_PAGE;
	} else {
		blob_get_req->type = BLOB_TYPE_BLOCK;
	}
	if (src_len > 0) {
		/* retrieve a specific range */
		blob_get_req->off = src_off;
		blob_get_req->len = src_len;
	}

	if (dest_data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = dest_data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_get_hdr_fill(blob_get_req, op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_bname_free:
	free(blob_get_req->bname);
err_ctnr_free:
	free(blob_get_req->container);
err_acc_free:
	free(blob_get_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_page_put_free(struct az_req_page_put *page_put_req)
{
	free(page_put_req->account);
	free(page_put_req->container);
	free(page_put_req->bname);
}

static int
az_req_page_put_hdr_fill(struct az_req_page_put *page_put_req,
			 struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
		       page_put_req->off,
		       (page_put_req->off + page_put_req->len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	if (page_put_req->clear_data) {
		ret = op_req_hdr_add(op, "x-ms-page-write", "clear");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else {
		ret = op_req_hdr_add(op, "x-ms-page-write", "update");
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
 * update or clear @dest_len bytes of page data at @dest_off.
 * if @src_data is null then clear the byte range, otherwise update.
 */
int
az_req_page_put(const char *account,
		const char *container,
		const char *bname,
		struct elasto_data *src_data,
		uint64_t dest_off,
		uint64_t dest_len,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_page_put *page_put_req;

	/* check for correct alignment */
	if (((dest_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != dest_len) {
		ret = -EINVAL;
		goto err_out;
	}
	if (((dest_off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != dest_off) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_ebo_init(AOP_BLOB_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	page_put_req = &ebo->req.page_put;

	page_put_req->account = strdup(account);
	if (page_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	if (container == NULL) {
		page_put_req->container = NULL;
	} else {
		page_put_req->container = strdup(container);
		if (page_put_req->container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	page_put_req->bname = strdup(bname);
	if (page_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	page_put_req->off = dest_off;
	page_put_req->len = dest_len;
	if (src_data == NULL) {
		page_put_req->clear_data = true;
	} else {
		page_put_req->clear_data = false;
		op->req.data = src_data;
		/* TODO add a foreign flag so @req.data is not freed with @op */
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}
	ret = asprintf(&op->url_path, "/%s/%s?comp=page",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_page_put_hdr_fill(page_put_req, op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data = NULL;
	}
	free(page_put_req->bname);
err_free_container:
	free(page_put_req->container);
err_free_account:
	free(page_put_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_block_put_free(struct az_req_block_put *blk_put_req)
{
	free(blk_put_req->account);
	free(blk_put_req->container);
	free(blk_put_req->bname);
	free(blk_put_req->blk_id);
}

static int
az_req_block_put_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 * Note: For a given blob, the length of the value specified for the blockid
 *	 parameter must be the same size for each block.
 */
int
az_req_block_put(const char *account,
		 const char *container,
		 const char *bname,
		 const char *blk_id,
		 struct elasto_data *data,
		 struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_block_put *blk_put_req;
	char *b64_blk_id;

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (strlen(blk_id) > 64) {
		/*
		 * Prior to encoding, the string must be less than or equal to
		 * 64 bytes in size.
		 */
		ret = -EINVAL;
		goto err_out;
	}
	if (data->len > BLOB_BLOCK_MAX) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_ebo_init(AOP_BLOCK_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blk_put_req = &ebo->req.block_put;

	blk_put_req->account = strdup(account);
	if (blk_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blk_put_req->container = strdup(container);
	if (blk_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_put_req->bname = strdup(bname);
	if (blk_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	blk_put_req->blk_id = strdup(blk_id);
	if (blk_put_req->blk_id == NULL) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	ret = base64_html_encode(blk_id, strlen(blk_id), &b64_blk_id);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_data_close;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		free(b64_blk_id);
		goto err_data_close;
	}
	ret = asprintf(&op->url_path, "/%s/%s?comp=block&blockid=%s",
		       container, bname, b64_blk_id);
	free(b64_blk_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_block_put_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_data_close:
	op->req.data = NULL;
	free(blk_put_req->blk_id);
err_bname_free:
	free(blk_put_req->bname);
err_container_free:
	free(blk_put_req->container);
err_account_free:
	free(blk_put_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_block_list_put_free(struct az_req_block_list_put *blk_list_put_req)
{
	struct azure_block *blk;
	struct azure_block *blk_n;
	free(blk_list_put_req->account);
	free(blk_list_put_req->container);
	free(blk_list_put_req->bname);
	list_for_each_safe(blk_list_put_req->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
	free(blk_list_put_req->blks);
}

static int
az_req_block_list_put_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

static int
az_req_block_list_put_body_fill(struct list_head *blks,
				struct elasto_data **req_data_out)
{
	int ret;
	struct azure_block *blk;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	/* 2k buf, should be listlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, 0, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	xml_data = (char *)req_data->iov.buf;
	ret = snprintf(xml_data, buf_remain,
		       "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		       "<BlockList>");
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	list_for_each(blks, blk, list) {
		const char *state;
		char *b64_id;

		switch(blk->state) {
		case BLOCK_STATE_COMMITED:
			state = "Committed";
			break;
		case BLOCK_STATE_UNCOMMITED:
			state = "Uncommitted";
			break;
		case BLOCK_STATE_LATEST:
			state = "Latest";
			break;
		default:
			ret = -EINVAL;
			goto err_buf_free;
			break;
		}
		ret = base64_encode(blk->id, strlen(blk->id), &b64_id);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_buf_free;
		}
		ret = snprintf(xml_data, buf_remain,
			       "<%s>%s</%s>", state, b64_id, state);
		free(b64_id);
		if ((ret < 0) || (ret >= buf_remain)) {
			ret = -E2BIG;
			goto err_buf_free;
		}

		xml_data += ret;
		buf_remain -= ret;
	}

	ret = snprintf(xml_data, buf_remain,
		       "</BlockList>");
	if ((ret < 0) || (ret >= buf_remain)) {
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
 * @blks is a list of blocks to commit, items in the list are not duped
 */
int
az_req_block_list_put(const char *account,
		      const char *container,
		      const char *bname,
		      struct list_head *blks,
		      struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_block_list_put *blk_list_put_req;

	ret = az_ebo_init(AOP_BLOCK_LIST_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blk_list_put_req = &ebo->req.block_list_put;

	blk_list_put_req->account = strdup(account);
	if (blk_list_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blk_list_put_req->container = strdup(container);
	if (blk_list_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_list_put_req->bname = strdup(bname);
	if (blk_list_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s?comp=blocklist",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_block_list_put_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	ret = az_req_block_list_put_body_fill(blks, &op->req.data);
	if (ret < 0)
		goto err_hdrs_free;

	blk_list_put_req->blks = blks;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_bname_free:
	free(blk_list_put_req->bname);
err_container_free:
	free(blk_list_put_req->container);
err_account_free:
	free(blk_list_put_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_block_list_get_free(struct az_req_block_list_get *blk_list_get_req)
{
	free(blk_list_get_req->account);
	free(blk_list_get_req->container);
	free(blk_list_get_req->bname);
}
static void
az_rsp_block_list_get_free(struct az_rsp_block_list_get *blk_list_get_rsp)
{
	struct azure_block *blk;
	struct azure_block *blk_n;
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
}

static int
az_req_block_list_get_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

/* request a list of all committed and uncommited blocks for @bname */
int
az_req_block_list_get(const char *account,
		      const char *container,
		      const char *bname,
		      struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_block_list_get *blk_list_get_req;

	ret = az_ebo_init(AOP_BLOCK_LIST_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blk_list_get_req = &ebo->req.block_list_get;

	blk_list_get_req->account = strdup(account);
	if (blk_list_get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blk_list_get_req->container = strdup(container);
	if (blk_list_get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_list_get_req->bname = strdup(bname);
	if (blk_list_get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s?comp=blocklist&blocklisttype=all",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = az_req_block_list_get_hdr_fill(op);
	if (ret < 0)
		goto err_buf_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_buf_free:
	elasto_data_free(op->rsp.data);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_bname_free:
	free(blk_list_get_req->bname);
err_container_free:
	free(blk_list_get_req->container);
err_account_free:
	free(blk_list_get_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blk_iter_process(struct xml_doc *xdoc,
			const char *path,
			const char *val,
			void *cb_data)
{
	struct az_rsp_block_list_get *blk_list_get_rsp
			= (struct az_rsp_block_list_get *)cb_data;
	int ret;
	struct azure_block *blk;

	/* request callback for subsequent Block descriptors */
	ret = exml_path_cb_want(xdoc, "/BlockList/*/Block", false,
				az_rsp_blk_iter_process, blk_list_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	blk = malloc(sizeof(*blk));
	if (blk == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(blk, 0, sizeof(*blk));

	if (strstr(path, "/CommittedBlocks[") != NULL) {
		blk->state = BLOCK_STATE_COMMITED;
	} else if (strstr(path, "/UncommittedBlocks[") != NULL) {
		blk->state = BLOCK_STATE_UNCOMMITED;
	} else {
		dbg(0, "Unknown block state: %s\n", path);
		ret = -EINVAL;
		goto err_blk_free;
	}

	ret = exml_base64_want(xdoc, "./Name", true, &blk->id, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	ret = exml_uint64_want(xdoc, "./Size", true, &blk->len, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	list_add_tail(&blk_list_get_rsp->blks, &blk->list);
	blk_list_get_rsp->num_blks++;

	return 0;

err_blk_free:
	free(blk);
err_out:
	return ret;
}

static int
az_rsp_block_list_get_process(struct op *op,
			      struct az_rsp_block_list_get *blk_list_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_block *blk;
	struct azure_block *blk_n;

	assert(op->opcode == AOP_BLOCK_LIST_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&blk_list_get_rsp->blks);

	/* trigger path callback for CommittedBlocks and UncommittedBlocks */
	ret = exml_path_cb_want(xdoc, "/BlockList/*/Block", false,
				az_rsp_blk_iter_process, blk_list_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_blks_free;
	}

	exml_free(xdoc);

	return 0;

err_blks_free:
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_blob_del_free(struct az_req_blob_del *blob_del_req)
{
	free(blob_del_req->account);
	free(blob_del_req->container);
	free(blob_del_req->bname);
}

static int
az_req_blob_del_hdr_fill(struct op *op)
{
	return az_req_common_hdr_fill(op, false);
}

int
az_req_blob_del(const char *account,
		const char *container,
		const char *bname,
		struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_del *blob_del_req;

	ret = az_ebo_init(AOP_BLOB_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_del_req = &ebo->req.blob_del;

	blob_del_req->account = strdup(account);
	if (blob_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_del_req->container = strdup(container);
	if (blob_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	blob_del_req->bname = strdup(bname);
	if (blob_del_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}
	ret = asprintf(&op->url_path, "/%s/%s",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_del_hdr_fill(op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_free_bname:
	free(blob_del_req->bname);
err_free_container:
	free(blob_del_req->container);
err_free_account:
	free(blob_del_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_cp_free(struct az_req_blob_cp *blob_cp_req)
{
	free(blob_cp_req->src.account);
	free(blob_cp_req->src.container);
	free(blob_cp_req->src.bname);
	free(blob_cp_req->dst.account);
	free(blob_cp_req->dst.container);
	free(blob_cp_req->dst.bname);
}

static int
az_req_blob_cp_hdr_fill(struct az_req_blob_cp *blob_cp_req,
			struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	/* tell server to always use https when dealing with the src blob */
	ret = asprintf(&hdr_str,
		       "https://%s.blob.core.windows.net/%s/%s",
		       blob_cp_req->src.account,
		       blob_cp_req->src.container,
		       blob_cp_req->src.bname);
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
az_req_blob_cp(const char *src_account,
	       const char *src_container,
	       const char *src_bname,
	       const char *dst_account,
	       const char *dst_container,
	       const char *dst_bname,
	       struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_cp *blob_cp_req;

	ret = az_ebo_init(AOP_BLOB_CP, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_cp_req = &ebo->req.blob_cp;

	blob_cp_req->src.account = strdup(src_account);
	if (blob_cp_req->src.account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_cp_req->src.container = strdup(src_container);
	if (blob_cp_req->src.container == NULL) {
		ret = -ENOMEM;
		goto err_src_acc_free;
	}

	blob_cp_req->src.bname = strdup(src_bname);
	if (blob_cp_req->src.bname == NULL) {
		ret = -ENOMEM;
		goto err_src_ctnr_free;
	}

	blob_cp_req->dst.account = strdup(dst_account);
	if (blob_cp_req->dst.account == NULL) {
		ret = -ENOMEM;
		goto err_src_blb_free;
	}

	blob_cp_req->dst.container = strdup(dst_container);
	if (blob_cp_req->dst.container == NULL) {
		ret = -ENOMEM;
		goto err_dst_acc_free;
	}

	blob_cp_req->dst.bname = strdup(dst_bname);
	if (blob_cp_req->dst.bname == NULL) {
		ret = -ENOMEM;
		goto err_dst_ctnr_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", dst_account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dst_blb_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s",
		       dst_container, dst_bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_cp_hdr_fill(blob_cp_req, op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dst_blb_free:
	free(blob_cp_req->dst.bname);
err_dst_ctnr_free:
	free(blob_cp_req->dst.container);
err_dst_acc_free:
	free(blob_cp_req->dst.account);
err_src_blb_free:
	free(blob_cp_req->src.bname);
err_src_ctnr_free:
	free(blob_cp_req->src.container);
err_src_acc_free:
	free(blob_cp_req->src.account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_prop_get_free(struct az_req_blob_prop_get *blob_prop_get_req)
{
	free(blob_prop_get_req->account);
	free(blob_prop_get_req->container);
	free(blob_prop_get_req->bname);
}

static void
az_rsp_blob_prop_get_free(struct az_rsp_blob_prop_get *blob_prop_get_rsp)
{
	free(blob_prop_get_rsp->cp_id);
	free(blob_prop_get_rsp->content_type);
}

int
az_req_blob_prop_get(const char *account,
		     const char *container,
		     const char *bname,
		     struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_prop_get *blob_prop_get_req;

	ret = az_ebo_init(AOP_BLOB_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_prop_get_req = &ebo->req.blob_prop_get;

	blob_prop_get_req->account = strdup(account);
	if (blob_prop_get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_prop_get_req->container = strdup(container);
	if (blob_prop_get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	blob_prop_get_req->bname = strdup(bname);
	if (blob_prop_get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	op->method = REQ_METHOD_HEAD;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_bname_free:
	free(blob_prop_get_req->bname);
err_ctnr_free:
	free(blob_prop_get_req->container);
err_acc_free:
	free(blob_prop_get_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static const struct {
	const char *state_str;
	enum az_lease_state state;
} az_rsp_blob_prop_lease_state_map[] = {
	{"available", AOP_LEASE_STATE_AVAILABLE},
	{"leased", AOP_LEASE_STATE_LEASED},
	{"expired", AOP_LEASE_STATE_EXPIRED},
	{"breaking", AOP_LEASE_STATE_BREAKING},
	{"broken", AOP_LEASE_STATE_BROKEN},
};
int
az_rsp_blob_prop_lease_state(const char *state_str,
			     enum az_lease_state *_state)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(az_rsp_blob_prop_lease_state_map); i++) {
		if (!strcmp(state_str,
			    az_rsp_blob_prop_lease_state_map[i].state_str)) {
			*_state = az_rsp_blob_prop_lease_state_map[i].state;
			return 0;
		}
	}
	dbg(1, "invalid lease state string: %s\n", state_str);
	return -EINVAL;
}

static const struct {
	const char *status_str;
	enum az_lease_status status;
} az_rsp_blob_prop_lease_status_map[] = {
	{"locked", AOP_LEASE_STATUS_LOCKED},
	{"unlocked", AOP_LEASE_STATUS_UNLOCKED},
};
int
az_rsp_blob_prop_lease_status(const char *status_str,
			      enum az_lease_status *_status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(az_rsp_blob_prop_lease_status_map); i++) {
		if (!strcmp(status_str,
			    az_rsp_blob_prop_lease_status_map[i].status_str)) {
			*_status = az_rsp_blob_prop_lease_status_map[i].status;
			return 0;
		}
	}
	dbg(1, "invalid lease status string: %s\n", status_str);
	return -EINVAL;
}

static const struct {
	const char *status_str;
	enum az_cp_status status;
} az_rsp_blob_prop_cp_status_map[] = {
	{"pending", AOP_CP_STATUS_PENDING},
	{"success", AOP_CP_STATUS_SUCCESS},
	{"aborted", AOP_CP_STATUS_ABORTED},
	{"failed", AOP_CP_STATUS_FAILED},
};
int
az_rsp_blob_prop_cp_status(const char *status_str,
			   enum az_cp_status *_status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(az_rsp_blob_prop_cp_status_map); i++) {
		if (!strcmp(status_str,
			    az_rsp_blob_prop_cp_status_map[i].status_str)) {
			*_status = az_rsp_blob_prop_cp_status_map[i].status;
			return 0;
		}
	}
	dbg(1, "invalid copy status string: %s\n", status_str);
	return -EINVAL;
}

static int
az_rsp_blob_prop_get_process(struct op *op,
			     struct az_rsp_blob_prop_get *blob_prop_get_rsp)
{
	int ret;
	char *hdr_val;

	assert(op->opcode == AOP_BLOB_PROP_GET);
	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-blob-type",
				&hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	if (!strcmp(hdr_val, BLOB_TYPE_BLOCK)) {
		blob_prop_get_rsp->is_page = false;
	} else if (!strcmp(hdr_val, BLOB_TYPE_PAGE)) {
		blob_prop_get_rsp->is_page = true;
	} else {
		dbg(0, "unknown blob type %s\n", hdr_val);
		free(hdr_val);
		ret = -ENOTSUP;
		goto err_out;
	}

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "Content-Length",
				    &blob_prop_get_rsp->len);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"Content-Type",
				&blob_prop_get_rsp->content_type);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-state",
				&hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = az_rsp_blob_prop_lease_state(hdr_val,
					   &blob_prop_get_rsp->lease_state);
	free(hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-status",
				&hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = az_rsp_blob_prop_lease_status(hdr_val,
					    &blob_prop_get_rsp->lease_status);
	free(hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-id",
				&blob_prop_get_rsp->cp_id);
	if (ret == -ENOENT) {
		/* cp ID only present if blob was a cp destination */
		goto done;
	} else if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-status",
				&hdr_val);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_cid_free;
	} else if (ret == 0) {
		ret = az_rsp_blob_prop_cp_status(hdr_val,
						 &blob_prop_get_rsp->cp_status);
		free(hdr_val);
		if (ret < 0) {
			goto err_cid_free;
		}
	}
done:
	return 0;

err_cid_free:
	free(blob_prop_get_rsp->cp_id);
err_ctype_free:
	free(blob_prop_get_rsp->content_type);
err_out:
	return ret;
}

static void
az_req_blob_prop_set_free(struct az_req_blob_prop_set *blob_prop_set_req)
{
	free(blob_prop_set_req->account);
	free(blob_prop_set_req->container);
	free(blob_prop_set_req->bname);
}

static int
az_req_blob_prop_set_hdr_fill(struct az_req_blob_prop_set *blob_prop_set_req,
			      struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (blob_prop_set_req->is_page) {
		ret = asprintf(&hdr_str, "%" PRIu64, blob_prop_set_req->len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-blob-content-length", hdr_str);
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

/* page blob truncated to @len if @is_page is set, otherwise ignored */
int
az_req_blob_prop_set(const char *account,
		     const char *container,
		     const char *bname,
		     bool is_page,
		     uint64_t len,
		     struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_prop_set *blob_prop_set_req;

	if (!is_page && (len != 0)) {
		dbg(0, "non-zero len for block blob invalid\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_ebo_init(AOP_BLOB_PROP_SET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_prop_set_req = &ebo->req.blob_prop_set;

	blob_prop_set_req->account = strdup(account);
	if (blob_prop_set_req->account == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_prop_set_req->container = strdup(container);
	if (blob_prop_set_req->container == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	blob_prop_set_req->bname = strdup(bname);
	if (blob_prop_set_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	blob_prop_set_req->is_page = is_page;
	blob_prop_set_req->len = len;

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.blob.core.windows.net", account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}
	ret = asprintf(&op->url_path, "/%s/%s?comp=properties",
		       container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_prop_set_hdr_fill(blob_prop_set_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_bname_free:
	free(blob_prop_set_req->bname);
err_ctnr_free:
	free(blob_prop_set_req->container);
err_acc_free:
	free(blob_prop_set_req->account);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_lease_free(struct az_req_blob_lease *blob_lease_req)
{
	free(blob_lease_req->acc);
	free(blob_lease_req->ctnr);
	free(blob_lease_req->blob);
	free(blob_lease_req->lid);
}

static void
az_rsp_blob_lease_free(struct az_rsp_blob_lease *blob_lease_rsp)
{
	free(blob_lease_rsp->lid);
}

static struct {
	enum az_lease_action action_enum;
	const char *action_str;
} action_enum_name_map[] = {
	{AOP_LEASE_ACTION_ACQUIRE, "acquire"},
	{AOP_LEASE_ACTION_RENEW, "renew"},
	{AOP_LEASE_ACTION_CHANGE, "change"},
	{AOP_LEASE_ACTION_RELEASE, "release"},
	{AOP_LEASE_ACTION_BREAK, "break"},
};

static const char *
az_req_blob_lease_actn_enum_map(enum az_lease_action action_enum)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(action_enum_name_map); i++) {
		if (action_enum_name_map[i].action_enum == action_enum) {
			return action_enum_name_map[i].action_str;
		}
	}
	dbg(0, "invalid lease action enum: %u\n", action_enum);
	return NULL;
}

static int
az_req_blob_lease_hdr_fill(struct az_req_blob_lease *blob_lease_req,
			   const char *action_str,
			   struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_req_hdr_add(op, "x-ms-lease-action", action_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	if (blob_lease_req->action == AOP_LEASE_ACTION_ACQUIRE) {
		ret = asprintf(&hdr_str, "%d", blob_lease_req->duration);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-duration", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else if (blob_lease_req->action == AOP_LEASE_ACTION_BREAK) {
		ret = asprintf(&hdr_str, "%d", blob_lease_req->break_period);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-break-period", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (blob_lease_req->lid != NULL) {
		ret = op_req_hdr_add(op, "x-ms-lease-id", blob_lease_req->lid);
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
 * @duration is the lease duration if @action=AOP_LEASE_ACTION_ACQUIRE.
 * It can either be -1 (indefinite), or between 15 and 60 seconds.
 * For @action=AOP_LEASE_ACTION_BREAK, @duration corresponds to the number of
 * seconds that the lease should continue before it is broken.
 */
int
az_req_blob_lease(const char *acc,
		  const char *ctnr,
		  const char *blob,
		  const char *lid,
		  const char *lid_proposed,
		  enum az_lease_action action,
		  int32_t duration,
		  struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_blob_lease *blob_lease_req;
	const char *action_str;

	action_str = az_req_blob_lease_actn_enum_map(action);
	if (action_str == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	/* duration is only valid for AQUIRE and BREAK (as break period) */
	if ((action == AOP_LEASE_ACTION_ACQUIRE)
	 && ((duration != -1) && ((duration < 15) || (duration > 60)))) {
		dbg(1, "invalid lease duration: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	/* break period must be between 0 and 60 */
	if ((action == AOP_LEASE_ACTION_BREAK)
	 && ((duration < 0) || (duration > 60))) {
		dbg(1, "invalid break period: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	if ((action == AOP_LEASE_ACTION_CHANGE) && (lid_proposed == NULL)) {
		dbg(1, "proposed lease ID required with action=change\n");
		ret = -EINVAL;
		goto err_out;
	} else if ((action != AOP_LEASE_ACTION_CHANGE)
			&& (action != AOP_LEASE_ACTION_ACQUIRE)
			&& (lid_proposed != NULL)) {
		dbg(1, "proposed lease ID only valid with "
		    "action=aquire|change\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (((action == AOP_LEASE_ACTION_RENEW)
			|| (action == AOP_LEASE_ACTION_CHANGE)
			|| (action == AOP_LEASE_ACTION_RELEASE))
							&& (lid == NULL)) {
		dbg(1, "lease ID required with action=renew|change|release\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* TODO validate lid GUID format */

	ret = az_ebo_init(AOP_BLOB_LEASE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_lease_req = &ebo->req.blob_lease;

	blob_lease_req->acc = strdup(acc);
	if (blob_lease_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	blob_lease_req->ctnr = strdup(ctnr);
	if (blob_lease_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	blob_lease_req->blob = strdup(blob);
	if (blob_lease_req->blob == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	if (lid != NULL) {
		blob_lease_req->lid = strdup(lid);
		if (blob_lease_req->lid == NULL) {
			ret = -ENOMEM;
			goto err_blob_free;
		}
	}

	if (lid_proposed != NULL) {
		blob_lease_req->lid_proposed = strdup(lid_proposed);
		if (blob_lease_req->lid_proposed == NULL) {
			ret = -ENOMEM;
			goto err_lid_free;
		}
	}

	blob_lease_req->action = action;
	if (action == AOP_LEASE_ACTION_ACQUIRE) {
		blob_lease_req->duration = duration;
	} else if (action == AOP_LEASE_ACTION_BREAK) {
		blob_lease_req->break_period = duration;
	} else if (duration != 0) {
		dbg(0, "ignoring lease duration %d with action %s\n",
		    duration, action_str);
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;
	ret = asprintf(&op->url_host, "%s.blob.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_lid_prop_free;
	}

	ret = asprintf(&op->url_path, "/%s/%s?comp=lease", ctnr, blob);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_blob_lease_hdr_fill(blob_lease_req, action_str, op);
	if (ret < 0)
		goto err_upath_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_lid_prop_free:
	free(blob_lease_req->lid_proposed);
err_lid_free:
	free(blob_lease_req->lid);
err_blob_free:
	free(blob_lease_req->blob);
err_ctnr_free:
	free(blob_lease_req->ctnr);
err_acc_free:
	free(blob_lease_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blob_lease_process(struct op *op,
			  struct az_rsp_blob_lease *blob_lease_rsp)
{
	int ret;

	assert(op->opcode == AOP_BLOB_LEASE);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "x-ms-lease-time",
				    &blob_lease_rsp->time_remaining);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}
	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-id",
				&blob_lease_rsp->lid);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static void
az_req_status_get_free(struct az_req_status_get *sts_get_req)
{
	free(sts_get_req->sub_id);
	free(sts_get_req->req_id);
}

static void
az_rsp_status_get_free(struct az_rsp_status_get *sts_get_rsp)
{
	if (sts_get_rsp->status == AOP_STATUS_FAILED) {
		free(sts_get_rsp->err.msg);
	}
}

int
az_req_status_get(const char *sub_id,
		  const char *req_id,
		  struct op **_op)
{
	int ret;
	struct az_ebo *ebo;
	struct op *op;
	struct az_req_status_get *sts_get_req;

	ret = az_ebo_init(AOP_STATUS_GET, &ebo);
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
az_rsp_status_val_process(struct xml_doc *xdoc,
			  const char *path,
			  const char *val,
			  void *cb_data)
{
	struct az_rsp_status_get *sts_get_rsp
			= (struct az_rsp_status_get *)cb_data;
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
az_rsp_status_get_process(struct op *op,
			  struct az_rsp_status_get *sts_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_STATUS_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_val_cb_want(xdoc, "/Operation/Status", true,
			       az_rsp_status_val_process, sts_get_rsp, NULL);
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
	az_rsp_status_get_free(sts_get_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_req_free(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);

	switch (ebo->opcode) {
	case AOP_ACC_KEYS_GET:
		az_req_acc_keys_get_free(&ebo->req.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		az_req_acc_list_free(&ebo->req.acc_list);
		break;
	case AOP_ACC_CREATE:
		az_req_acc_create_free(&ebo->req.acc_create);
		break;
	case AOP_ACC_DEL:
		az_req_acc_del_free(&ebo->req.acc_del);
		break;
	case AOP_CONTAINER_LIST:
		az_req_ctnr_list_free(&ebo->req.ctnr_list);
		break;
	case AOP_CONTAINER_CREATE:
		az_req_ctnr_create_free(&ebo->req.ctnr_create);
		break;
	case AOP_CONTAINER_DEL:
		az_req_ctnr_del_free(&ebo->req.ctnr_del);
		break;
	case AOP_BLOB_LIST:
		az_req_blob_list_free(&ebo->req.blob_list);
		break;
	case AOP_BLOB_PUT:
		az_req_blob_put_free(&ebo->req.blob_put);
		break;
	case AOP_BLOB_GET:
		az_req_blob_get_free(&ebo->req.blob_get);
		break;
	case AOP_PAGE_PUT:
		az_req_page_put_free(&ebo->req.page_put);
		break;
	case AOP_BLOCK_PUT:
		az_req_block_put_free(&ebo->req.block_put);
		break;
	case AOP_BLOCK_LIST_PUT:
		az_req_block_list_put_free(&ebo->req.block_list_put);
		break;
	case AOP_BLOCK_LIST_GET:
		az_req_block_list_get_free(&ebo->req.block_list_get);
		break;
	case AOP_BLOB_DEL:
		az_req_blob_del_free(&ebo->req.blob_del);
		break;
	case AOP_BLOB_CP:
		az_req_blob_cp_free(&ebo->req.blob_cp);
		break;
	case AOP_BLOB_PROP_GET:
		az_req_blob_prop_get_free(&ebo->req.blob_prop_get);
		break;
	case AOP_BLOB_PROP_SET:
		az_req_blob_prop_set_free(&ebo->req.blob_prop_set);
		break;
	case AOP_BLOB_LEASE:
		az_req_blob_lease_free(&ebo->req.blob_lease);
		break;
	case AOP_STATUS_GET:
		az_req_status_get_free(&ebo->req.sts_get);
		break;
	default:
		assert(false);
		break;
	};
}

static void
az_rsp_free(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);

	switch (ebo->opcode) {
	case AOP_ACC_KEYS_GET:
		az_rsp_acc_keys_get_free(&ebo->rsp.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		az_rsp_acc_list_free(&ebo->rsp.acc_list);
		break;
	case AOP_CONTAINER_LIST:
		az_rsp_ctnr_list_free(&ebo->rsp.ctnr_list);
		break;
	case AOP_BLOB_LIST:
		az_rsp_blob_list_free(&ebo->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		az_rsp_block_list_get_free(&ebo->rsp.block_list_get);
		break;
	case AOP_BLOB_PROP_GET:
		az_rsp_blob_prop_get_free(&ebo->rsp.blob_prop_get);
		break;
	case AOP_BLOB_LEASE:
		az_rsp_blob_lease_free(&ebo->rsp.blob_lease);
		break;
	case AOP_STATUS_GET:
		az_rsp_status_get_free(&ebo->rsp.sts_get);
		break;
	case AOP_ACC_CREATE:
	case AOP_ACC_DEL:
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
	case AOP_BLOB_CP:
	case AOP_BLOB_PROP_SET:
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
az_rsp_process(struct op *op)
{
	int ret;
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		ret = az_rsp_acc_keys_get_process(op, &ebo->rsp.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		ret = az_rsp_acc_list_process(op, &ebo->rsp.acc_list);
		break;
	case AOP_CONTAINER_LIST:
		ret = az_rsp_ctnr_list_process(op, &ebo->rsp.ctnr_list);
		break;
	case AOP_BLOB_LIST:
		ret = az_rsp_blob_list_process(op, &ebo->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		ret = az_rsp_block_list_get_process(op, &ebo->rsp.block_list_get);
		break;
	case AOP_BLOB_PROP_GET:
		ret = az_rsp_blob_prop_get_process(op, &ebo->rsp.blob_prop_get);
		break;
	case AOP_BLOB_LEASE:
		ret = az_rsp_blob_lease_process(op, &ebo->rsp.blob_lease);
		break;
	case AOP_STATUS_GET:
		ret = az_rsp_status_get_process(op, &ebo->rsp.sts_get);
		break;
	case AOP_ACC_CREATE:
	case AOP_ACC_DEL:
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
	case AOP_BLOB_CP:
	case AOP_BLOB_PROP_SET:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}

struct az_rsp_acc_keys_get *
az_rsp_acc_keys_get(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.acc_keys_get;
}

struct az_rsp_acc_list *
az_rsp_acc_list(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.acc_list;
}

struct az_rsp_ctnr_list *
az_rsp_ctnr_list(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.ctnr_list;
}

struct az_rsp_blob_list *
az_rsp_blob_list(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.blob_list;
}

struct az_rsp_block_list_get *
az_rsp_block_list_get(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.block_list_get;
}

struct az_rsp_blob_prop_get *
az_rsp_blob_prop_get(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.blob_prop_get;
}

struct az_rsp_blob_lease *
az_rsp_blob_lease_get(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.blob_lease;
}

struct az_rsp_status_get *
az_rsp_status_get(struct op *op)
{
	struct az_ebo *ebo = container_of(op, struct az_ebo, op);
	return &ebo->rsp.sts_get;
}
