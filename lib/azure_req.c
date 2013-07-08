/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2013, all rights reserved.
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

#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "azure_xml.h"
#include "data.h"
#include "azure_req.h"

static int
azure_op_hdr_add(struct list_head *hdrs,
		 const char *key,
		 const char *val)
{
	int ret;
	struct azure_op_hdr *hdr = malloc(sizeof(*hdr));
	if (hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	hdr->key = strdup(key);
	if (hdr->key == NULL) {
		ret = -ENOMEM;
		goto err_hdr_free;
	}

	hdr->val = strdup(val);
	if (hdr->val == NULL) {
		ret = -ENOMEM;
		goto err_key_free;
	}

	list_add_tail(hdrs, &hdr->list);

	return 0;

err_key_free:
	free(hdr->key);
err_hdr_free:
	free(hdr);
err_out:
	return ret;
}

int
azure_op_req_hdr_add(struct azure_op *op,
		     const char *key,
		     const char *val)
{
	int ret = azure_op_hdr_add(&op->req.hdrs, key, val);
	if (ret < 0) {
		return ret;
	}
	op->req.num_hdrs++;
	dbg(4, "added req hdr(%u): \"%s: %s\"\n", op->req.num_hdrs, key, val);

	return 0;
}

int
azure_op_rsp_hdr_add(struct azure_op *op,
		     const char *key,
		     const char *val)
{
	int ret = azure_op_hdr_add(&op->rsp.hdrs, key, val);
	if (ret < 0) {
		return ret;
	}
	op->rsp.num_hdrs++;
	dbg(4, "added rsp hdr(%u): \"%s: %s\"\n", op->rsp.num_hdrs, key, val);

	return 0;
}

static int
azure_op_hdr_val_lookup(struct list_head *hdrs,
			const char *key,
			char **_val)
{
	struct azure_op_hdr *hdr;

	list_for_each(hdrs, hdr, list) {
		if (strcmp(hdr->key, key) == 0) {
			char *val;
			val = strdup(hdr->val);
			if (val == NULL) {
				return -ENOMEM;
			}
			*_val = val;
			return 0;
		}
	}
	dbg(3, "hdr with key \"%s\" not found\n", key);
	return -ENOENT;
}

void
azure_op_hdrs_free(struct list_head *hdrs)
{
	struct azure_op_hdr *hdr;
	struct azure_op_hdr *hdr_n;

	list_for_each_safe(hdrs, hdr, hdr_n, list) {
		free(hdr->key);
		free(hdr->val);
		free(hdr);
	}
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
azure_op_fill_hdr_common(struct azure_op *op, bool mgmt)
{
	int ret;
	char *date_str;

	if (mgmt) {
		ret = azure_op_req_hdr_add(op, "x-ms-version", "2012-03-01");
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
	ret = azure_op_req_hdr_add(op, "x-ms-date", date_str);
	free(date_str);
	if (ret < 0) {
		goto err_out;
	}
	/* different to the version in management */
	ret = azure_op_req_hdr_add(op, "x-ms-version", "2012-02-12");
	if (ret < 0) {
		goto err_out;
	}
	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

static void
azure_req_acc_keys_get_free(struct azure_req_acc_keys_get *acc_keys_get_req)
{
	free(acc_keys_get_req->sub_id);
	free(acc_keys_get_req->service_name);
}
static void
azure_rsp_acc_keys_get_free(struct azure_rsp_acc_keys_get *acc_keys_get_rsp)
{
	free(acc_keys_get_rsp->primary);
	free(acc_keys_get_rsp->secondary);
}

static int
azure_op_acc_keys_get_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, true);
}

int
azure_op_acc_keys_get(const char *sub_id,
		      const char *service_name,
		      struct azure_op *op)
{
	int ret;
	struct azure_req_acc_keys_get *acc_keys_get_req;

	/* TODO input validation */

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_ACC_KEYS_GET;
	acc_keys_get_req = &op->req.acc_keys_get;

	/* we may not need to keep these, as they're only used in the URL */
	acc_keys_get_req->sub_id = strdup(sub_id);
	if (acc_keys_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	acc_keys_get_req->service_name = strdup(service_name);
	if (acc_keys_get_req->service_name == NULL) {
		ret = -ENOMEM;
		goto err_free_sub;
	}
	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s/keys",
		       sub_id, service_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_svc;
	}

	ret = azure_op_acc_keys_get_fill_hdr(op);
	if (ret < 0) {
		goto err_free_url;
	}

	return 0;
err_free_url:
	free(op->url);
err_free_svc:
	free(acc_keys_get_req->service_name);
err_free_sub:
	free(acc_keys_get_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_acc_keys_get_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_acc_keys_get *acc_keys_get_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;

	assert(op->opcode == AOP_ACC_KEYS_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	acc_keys_get_rsp = &op->rsp.acc_keys_get;

	ret = azure_xml_path_get(xdoc->root,
				 "/StorageService/StorageServiceKeys/Primary",
				 &acc_keys_get_rsp->primary);
	if (ret < 0) {
		goto err_pool_free;
	}
	ret = azure_xml_path_get(xdoc->root,
				 "/StorageService/StorageServiceKeys/Secondary",
				 &acc_keys_get_rsp->secondary);
	if (ret < 0) {
		free(acc_keys_get_rsp->primary);
		goto err_pool_free;
	}
	dbg(5, "primary key: %s, secondary key: %s\n",
	    acc_keys_get_rsp->primary, acc_keys_get_rsp->secondary);
	ret = 0;

err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_req_acc_list_free(struct azure_req_acc_list *acc_list_req)
{
	free(acc_list_req->sub_id);
}

static void
azure_acc_free(struct azure_account **pacc)
{
	struct azure_account *acc = *pacc;

	free(acc->svc_name);
	free(acc->url);
	free(acc->affin_grp);
	free(acc->location);
	free(acc->desc);
	free(acc);
}

static void
azure_rsp_acc_list_free(struct azure_rsp_acc_list *acc_list_rsp)
{
	struct azure_account *acc;
	struct azure_account *acc_n;

	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(&acc);
	}
}

static int
azure_op_acc_list_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, true);
}

int
azure_op_acc_list(const char *sub_id,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_acc_list *acc_list_req;

	/* TODO input validation */

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_ACC_LIST;
	acc_list_req = &op->req.acc_list;

	acc_list_req->sub_id = strdup(sub_id);
	if (acc_list_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	ret = azure_op_acc_list_fill_hdr(op);
	if (ret < 0) {
		goto err_url_free;
	}

	return 0;
err_url_free:
	free(op->url);
err_sub_free:
	free(acc_list_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_acc_iter_process(struct apr_xml_elem *xel,
			   struct azure_account **acc_ret)
{
	int ret;
	struct azure_account *acc;

	acc = malloc(sizeof(*acc));
	if (acc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(acc, 0, sizeof(*acc));

	ret = azure_xml_path_get(xel, "ServiceName", &acc->svc_name);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = azure_xml_path_get(xel, "Url", &acc->url);
	if (ret < 0) {
		goto err_name_free;
	}

	ret = azure_xml_path_get(xel, "StorageServiceProperties/Description",
				 &acc->desc);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_url_free;
	}

	ret = azure_xml_path_get(xel, "StorageServiceProperties/AffinityGroup",
				 &acc->affin_grp);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_desc_free;
	}

	ret = azure_xml_path_get(xel, "StorageServiceProperties/Location",
				 &acc->location);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_affin_free;
	}
	*acc_ret = acc;

	return 0;

err_affin_free:
	free(acc->affin_grp);
err_desc_free:
	free(acc->desc);
err_url_free:
	free(acc->url);
err_name_free:
	free(acc->svc_name);
err_acc_free:
	free(acc);
err_out:
	return ret;
}

static int
azure_rsp_acc_list_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_acc_list *acc_list_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct azure_account *acc;
	struct azure_account *acc_n;

	assert(op->opcode == AOP_ACC_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	acc_list_rsp = &op->rsp.acc_list;
	list_head_init(&acc_list_rsp->accs);

	/* get the first, if present */
	ret = azure_xml_path_el_get(xdoc->root,
				    "/StorageServices/StorageService", &xel);
	if (ret == -ENOENT) {
		goto done;
	} else if (ret < 0) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "StorageService") == 0)) {
		ret = azure_rsp_acc_iter_process(xel->first_child, &acc);
		if (ret < 0) {
			goto err_accs_free;
		}
		list_add_tail(&acc_list_rsp->accs, &acc->list);
		acc_list_rsp->num_accs++;

		xel = xel->next;
	}
done:
	apr_pool_destroy(pool);
	return 0;

err_accs_free:
	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(&acc);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_req_acc_create_free(struct azure_req_acc_create *acc_create_req)
{
	free(acc_create_req->sub_id);
	azure_acc_free(&acc_create_req->acc);
}

static int
azure_op_acc_create_fill_hdr(struct azure_op *op)
{
	int ret;

	ret = azure_op_fill_hdr_common(op, true);
	if (ret < 0) {
		return ret;
	}
	ret = azure_op_req_hdr_add(op,
			"Content-Type", "application/xml; charset=utf-8");
	if (ret < 0) {
		return ret;
	}
	return 0;
}

/*
 * The order of the elements in the request body is significant!
 */
static int
azure_op_acc_create_fill_body(struct azure_account *acc,
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

	xml_data = (char *)req_data->buf;
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
	    (char *)req_data->buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_destroy(&req_data);
err_out:
	return ret;
}

/*
 * either @affin_grp or @location must be set, but not both.
 */
int
azure_op_acc_create(const char *sub_id,
		    const char *svc_name,
		    const char *label,
		    const char *desc,
		    const char *affin_grp,
		    const char *location,
		    struct azure_op *op)
{
	int ret;
	struct azure_req_acc_create *acc_create_req;

	if ((sub_id == NULL) || (svc_name == NULL) || (label == NULL)) {
		return -EINVAL;
	} else if ((affin_grp == NULL) && (location == NULL)) {
		return -EINVAL;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_ACC_CREATE;
	acc_create_req = &op->req.acc_create;

	acc_create_req->sub_id = strdup(sub_id);
	if (acc_create_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
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
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_loc_free;
	}

	ret = azure_op_acc_create_fill_hdr(op);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_acc_create_fill_body(acc_create_req->acc,
					    &op->req.data);
	if (ret < 0) {
		goto err_url_free;
	}

	return 0;
err_url_free:
	free(op->url);
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
err_out:
	return ret;
}

static void
azure_req_acc_del_free(struct azure_req_acc_del *acc_del_req)
{
	free(acc_del_req->sub_id);
	free(acc_del_req->account);
}

static int
azure_op_acc_del_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, true);
}

int
azure_op_acc_del(const char *sub_id,
		 const char *account,
		 struct azure_op *op)
{
	int ret;
	struct azure_req_acc_del *acc_del_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_ACC_DEL;
	acc_del_req = &op->req.acc_del;


	acc_del_req->sub_id = strdup(sub_id);
	if (acc_del_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	acc_del_req->account = strdup(account);
	if (acc_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url,
		       "https://management.core.windows.net/%s"
		       "/services/storageservices/%s",
		       sub_id, account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	/* mandatory headers */
	ret = azure_op_acc_del_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	return 0;
err_url_free:
	free(op->url);
err_acc_free:
	free(acc_del_req->account);
err_sub_free:
	free(acc_del_req->sub_id);
err_out:
	return ret;
}

static void
azure_req_ctnr_list_free(struct azure_req_ctnr_list *ctnr_list_req)
{
	free(ctnr_list_req->account);
}
static void
azure_rsp_ctnr_list_free(struct azure_rsp_ctnr_list *ctnr_list_rsp)
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
azure_op_ctnr_list_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

int
azure_op_ctnr_list(const char *account,
		   bool insecure_http,
		   struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_list *ctnr_list_req;

	/* TODO input validation */

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_CONTAINER_LIST;
	ctnr_list_req = &op->req.ctnr_list;

	ctnr_list_req->account = strdup(account);
	if (ctnr_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/?comp=list",
		       (insecure_http ? "http" : "https"),
		       account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_ctnr_list_fill_hdr(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_buf_free:
	elasto_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_acc_free:
	free(ctnr_list_req->account);
err_out:
	return ret;
}

static int
azure_rsp_ctnr_iter_process(struct apr_xml_elem *xel,
			    struct azure_ctnr **ctnr)
{
	int ret;
	struct azure_ctnr *ictnr;

	ictnr = malloc(sizeof(*ictnr));
	if (ictnr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_path_get(xel, "Name", &ictnr->name);
	if (ret < 0) {
		goto err_ctnr_free;
	}

	*ctnr = ictnr;
	return 0;

err_ctnr_free:
	free(ictnr);
err_out:
	return ret;
}

static int
azure_rsp_ctnr_list_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_ctnr_list *ctnr_list_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	assert(op->opcode == AOP_CONTAINER_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	ctnr_list_rsp = &op->rsp.ctnr_list;
	list_head_init(&ctnr_list_rsp->ctnrs);

	/* get the first container, if present */
	ret = azure_xml_path_el_get(xdoc->root,
				    "/EnumerationResults/Containers/Container",
				    &xel);
	if (ret == -ENOENT) {
		goto done;
	} else if (ret < 0) {
		goto err_pool_free;
	}

	/*
	 * Returns up to 5000 records (maxresults default),
	 */
	while ((xel != NULL) && (strcmp(xel->name, "Container") == 0)) {
		ret = azure_rsp_ctnr_iter_process(xel->first_child, &ctnr);
		if (ret < 0) {
			goto err_ctnrs_free;
		}
		list_add_tail(&ctnr_list_rsp->ctnrs, &ctnr->list);
		ctnr_list_rsp->num_ctnrs++;

		xel = xel->next;
	}
done:
	apr_pool_destroy(pool);
	return 0;

err_ctnrs_free:
	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_req_ctnr_create_free(struct azure_req_ctnr_create *ctnr_create_req)
{
	free(ctnr_create_req->account);
	free(ctnr_create_req->ctnr);
}

static int
azure_op_ctnr_create_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

int
azure_op_ctnr_create(const char *account,
		     const char *ctnr,
		     bool insecure_http,
		     struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_create *ctnr_create_req;

	/* TODO input validation */

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_CONTAINER_CREATE;
	ctnr_create_req = &op->req.ctnr_create;

	ctnr_create_req->account = strdup(account);
	if (ctnr_create_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ctnr_create_req->ctnr = strdup(ctnr);
	if (ctnr_create_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s?restype=container",
		       (insecure_http ? "http" : "https"),
		       account, ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	azure_op_ctnr_create_fill_hdr(op);
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_ctnr_free:
	free(ctnr_create_req->ctnr);
err_acc_free:
	free(ctnr_create_req->account);
err_out:
	return ret;
}

static void
azure_req_ctnr_del_free(struct azure_req_ctnr_del *ctnr_del_req)
{
	free(ctnr_del_req->account);
	free(ctnr_del_req->container);
}

static int
azure_op_ctnr_del_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

int
azure_op_ctnr_del(const char *account,
		  const char *container,
		  bool insecure_http,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_ctnr_del *ctnr_del_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_CONTAINER_DEL;
	ctnr_del_req = &op->req.ctnr_del;

	ctnr_del_req->account = strdup(account);
	if (ctnr_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ctnr_del_req->container = strdup(container);
	if (ctnr_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s?restype=container",
		       (insecure_http ? "http" : "https"),
		       account, container);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	/* mandatory headers */
	ret = azure_op_ctnr_del_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_free_container:
	free(ctnr_del_req->container);
err_free_account:
	free(ctnr_del_req->account);
err_out:
	return ret;
}

static void
azure_req_blob_list_free(struct azure_req_blob_list *blob_list_req)
{
	free(blob_list_req->account);
	free(blob_list_req->ctnr);
}
static void
azure_rsp_blob_list_free(struct azure_rsp_blob_list *blob_list_rsp)
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
azure_op_blob_list_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

int
azure_op_blob_list(const char *account,
		   const char *ctnr,
		   bool insecure_http,
		   struct azure_op *op)
{

	int ret;
	struct azure_req_blob_list *blob_list_req;

	/* TODO input validation */

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_LIST;
	blob_list_req = &op->req.blob_list;

	blob_list_req->account = strdup(account);
	if (blob_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	blob_list_req->ctnr = strdup(ctnr);
	if (blob_list_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net"
		       "/%s?restype=container&comp=list",
		       (insecure_http ? "http" : "https"),
		       account, ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_blob_list_fill_hdr(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_buf_free:
	elasto_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_ctnr_free:
	free(blob_list_req->ctnr);
err_acc_free:
	free(blob_list_req->account);
err_out:
	return ret;
}

/*
 * process a single blob list iteration at @iter, return -ENOENT if no such
 * iteration exists
 */
static int
azure_rsp_blob_iter_process(struct apr_xml_elem *xel,
			    struct azure_blob **blob)
{
	int ret;
	char *type;
	struct azure_blob *iblob;

	iblob = malloc(sizeof(*iblob));
	if (iblob == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_path_get(xel, "Name", &iblob->name);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = azure_xml_path_u64_get(xel, "Properties/Content-Length",
				     &iblob->len);
	if (ret < 0) {
		goto err_name_free;
	}

	ret = azure_xml_path_get(xel, "Properties/BlobType", &type);
	if (ret < 0) {
		goto err_name_free;
	}
	iblob->is_page = (strcmp(type, BLOB_TYPE_PAGE) == 0);

	*blob = iblob;
	free(type);
	return 0;

err_name_free:
	free(iblob->name);
err_blob_free:
	free(iblob);
err_out:
	return ret;
}

static int
azure_rsp_blob_list_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_blob_list *blob_list_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	assert(op->opcode == AOP_BLOB_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	blob_list_rsp = &op->rsp.blob_list;
	list_head_init(&blob_list_rsp->blobs);

	/* get the first blob, if present */
	ret = azure_xml_path_el_get(xdoc->root,
				    "/EnumerationResults/Blobs/Blob", &xel);
	if (ret == -ENOENT) {
		goto done;
	} else if (ret < 0) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "Blob") == 0)) {
		ret = azure_rsp_blob_iter_process(xel->first_child, &blob);
		if (ret < 0) {
			goto err_blobs_free;
		}
		list_add_tail(&blob_list_rsp->blobs, &blob->list);
		blob_list_rsp->num_blobs++;

		xel = xel->next;
	}
done:
	apr_pool_destroy(pool);
	return 0;

err_blobs_free:
	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_req_blob_put_free(struct azure_req_blob_put *blob_put_req)
{
	free(blob_put_req->account);
	free(blob_put_req->container);
	free(blob_put_req->bname);
}

static int
azure_op_blob_put_fill_hdr(struct azure_op *op)
{
	int ret;

	ret = azure_op_fill_hdr_common(op, false);
	if (ret < 0) {
		goto err_out;
	}
	if (strcmp(op->req.blob_put.type, BLOB_TYPE_PAGE) == 0) {
		char *hdr_str;
		ret = azure_op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
		if (ret < 0) {
			goto err_out;
		}
		ret = asprintf(&hdr_str, "%" PRIu64,
			       op->req.blob_put.pg_len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = azure_op_req_hdr_add(op, "x-ms-blob-content-length",
					   hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = azure_op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @data_type is ELASTO_DATA_NONE, then @len corresponds to the page blob
 * length, @buf must be NULL.
 * For a block blob, @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV,
 * or @len bytes from the file at path @buf if @data_type is ELASTO_DATA_FILE.
 */
int
azure_op_blob_put(const char *account,
		  const char *container,
		  const char *bname,
		  enum elasto_data_type data_type,
		  uint8_t *buf,
		  uint64_t len,
		  bool insecure_http,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_blob_put *bl_put_req;

	/* TODO input validation */
	if ((data_type == ELASTO_DATA_NONE)
	 && (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len)) {
		ret = -EINVAL;
		goto err_out;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_PUT;
	bl_put_req = &op->req.blob_put;

	bl_put_req->account = strdup(account);
	if (bl_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	bl_put_req->container = strdup(container);
	if (bl_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	bl_put_req->bname = strdup(bname);
	if (bl_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (data_type == ELASTO_DATA_NONE) {
		bl_put_req->type = BLOB_TYPE_PAGE;
		bl_put_req->pg_len = len;
		assert(buf == NULL);	/* block only */
	} else if (data_type == ELASTO_DATA_IOV) {
		bl_put_req->type = BLOB_TYPE_BLOCK;

		ret = elasto_data_iov_new(buf, len, 0, false, &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}

	} else if (data_type == ELASTO_DATA_FILE) {
		bl_put_req->type = BLOB_TYPE_BLOCK;

		ret = elasto_data_file_new((char *)buf, len, 0, O_RDONLY, 0,
					     &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	/* mandatory headers */
	ret = azure_op_blob_put_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data->buf = NULL;
		elasto_data_destroy(&op->req.data);
	}
err_free_bname:
	free(bl_put_req->bname);
err_free_container:
	free(bl_put_req->container);
err_free_account:
	free(bl_put_req->account);
err_out:
	return ret;
}

static void
azure_req_blob_get_free(struct azure_req_blob_get *blob_get_req)
{
	free(blob_get_req->account);
	free(blob_get_req->container);
	free(blob_get_req->bname);
}

static int
azure_op_blob_get_fill_hdr(struct azure_op *op)
{
	int ret;

	ret = azure_op_fill_hdr_common(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (op->req.blob_get.len > 0) {
		char *hdr_str;
		ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
			       op->req.blob_get.off,
			       (op->req.blob_get.off + op->req.blob_get.len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = azure_op_req_hdr_add(op, "x-ms-range", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_out;
		}
	}

	if (strcmp(op->req.blob_get.type, BLOB_TYPE_PAGE) == 0) {
		ret = azure_op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
	} else {
		ret = azure_op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
	}
	if (ret < 0) {
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @req_len is zero then ignore @req_off and retrieve entire blob
 */
int
azure_op_blob_get(const char *account,
		  const char *container,
		  const char *bname,
		  bool is_page,
		  struct elasto_data *data,
		  uint64_t req_off,
		  uint64_t req_len,
		  bool insecure_http,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_blob_get *get_req;

	/* check for correct alignment */
	if (is_page
	 && ((((req_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != req_len)
	  || (((req_off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != req_off))) {
		ret = -EINVAL;
		goto err_out;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_GET;
	get_req = &op->req.blob_get;

	get_req->account = strdup(account);
	if (get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	get_req->container = strdup(container);
	if (get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	get_req->bname = strdup(bname);
	if (get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	if (is_page) {
		get_req->type = BLOB_TYPE_PAGE;
	} else {
		get_req->type = BLOB_TYPE_BLOCK;
	}
	if (req_len > 0) {
		/* retrieve a specific range */
		get_req->off = req_off;
		get_req->len = req_len;
	}

	if (data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	/* mandatory headers */
	ret = azure_op_blob_get_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_bname_free:
	free(get_req->bname);
err_ctnr_free:
	free(get_req->container);
err_acc_free:
	free(get_req->account);
err_out:
	return ret;
}

static void
azure_req_page_put_free(struct azure_req_page_put *pg_put_req)
{
	free(pg_put_req->account);
	free(pg_put_req->container);
	free(pg_put_req->bname);
}

static int
azure_op_page_put_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;

	ret = azure_op_fill_hdr_common(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
		       op->req.page_put.off,
		       (op->req.page_put.off + op->req.page_put.len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = azure_op_req_hdr_add(op, "x-ms-range", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_out;
	}

	if (op->req.page_put.clear_data) {
		ret = azure_op_req_hdr_add(op, "x-ms-page-write", "clear");
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = azure_op_req_hdr_add(op, "x-ms-page-write", "update");
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}
/*
 * update or clear @len bytes of page data at @off.
 * if @buf is null then clear the byte range, otherwise update.
 */
int
azure_op_page_put(const char *account,
		  const char *container,
		  const char *bname,
		  uint8_t *buf,
		  uint64_t off,
		  uint64_t len,
		  bool insecure_http,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_page_put *pg_put_req;

	/* check for correct alignment */
	if (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len) {
		ret = -EINVAL;
		goto err_out;
	}
	if (((off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != off) {
		ret = -EINVAL;
		goto err_out;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_PUT;
	pg_put_req = &op->req.page_put;

	pg_put_req->account = strdup(account);
	if (pg_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (container == NULL) {
		pg_put_req->container = NULL;
	} else {
		pg_put_req->container = strdup(container);
		if (pg_put_req->container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	pg_put_req->bname = strdup(bname);
	if (pg_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	pg_put_req->off = off;
	pg_put_req->len = len;
	if (buf == NULL) {
		pg_put_req->clear_data = true;
	} else {
		pg_put_req->clear_data = false;
		ret = elasto_data_iov_new(buf, len, 0, false, &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	/* mandatory headers */
	ret = azure_op_page_put_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data->buf = NULL;
		elasto_data_destroy(&op->req.data);
	}
err_free_bname:
	free(pg_put_req->bname);
err_free_container:
	free(pg_put_req->container);
err_free_account:
	free(pg_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_put_free(struct azure_req_block_put *blk_put_req)
{
	free(blk_put_req->account);
	free(blk_put_req->container);
	free(blk_put_req->bname);
	free(blk_put_req->blk_id);
}

static int
azure_op_block_put_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 * Note: For a given blob, the length of the value specified for the blockid
 *	 parameter must be the same size for each block.
 */
int
azure_op_block_put(const char *account,
		   const char *container,
		   const char *bname,
		   const char *blk_id,
		   struct elasto_data *data,
		   bool insecure_http,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_block_put *blk_put_req;
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

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOCK_PUT;
	blk_put_req = &op->req.block_put;

	blk_put_req->account = strdup(account);
	if (blk_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
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
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net"
		       "/%s/%s?comp=block&blockid=%s",
		       (insecure_http ? "http" : "https"),
		       account, container, bname, b64_blk_id);
	free(b64_blk_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_id_free;
	}

	ret = azure_op_block_put_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_data_close:
	op->req.data = NULL;
err_id_free:
	free(blk_put_req->blk_id);
err_bname_free:
	free(blk_put_req->bname);
err_container_free:
	free(blk_put_req->container);
err_account_free:
	free(blk_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_list_put_free(struct azure_req_block_list_put *blk_list_put_req)
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
azure_op_block_list_put_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

static int
azure_op_block_list_put_fill_body(struct list_head *blks,
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

	xml_data = (char *)req_data->buf;
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
	    (char *)req_data->buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_destroy(&req_data);
err_out:
	return ret;
}

/*
 * @blks is a list of blocks to commit, items in the list are not duped
 */
int
azure_op_block_list_put(const char *account,
			const char *container,
			const char *bname,
			struct list_head *blks,
			bool insecure_http,
			struct azure_op *op)
{
	int ret;
	struct azure_req_block_list_put *blk_list_put_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOCK_LIST_PUT;
	blk_list_put_req = &op->req.block_list_put;

	blk_list_put_req->account = strdup(account);
	if (blk_list_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
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
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net"
		       "/%s/%s?comp=blocklist",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	ret = azure_op_block_list_put_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	ret = azure_op_block_list_put_fill_body(blks, &op->req.data);
	if (ret < 0)
		goto err_url_free;

	blk_list_put_req->blks = blks;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_bname_free:
	free(blk_list_put_req->bname);
err_container_free:
	free(blk_list_put_req->container);
err_account_free:
	free(blk_list_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_list_get_free(struct azure_req_block_list_get *blk_list_get_req)
{
	free(blk_list_get_req->account);
	free(blk_list_get_req->container);
	free(blk_list_get_req->bname);
}
static void
azure_rsp_block_list_get_free(struct azure_rsp_block_list_get *blk_list_get_rsp)
{
	struct azure_block *blk;
	struct azure_block *blk_n;
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
}

static int
azure_op_block_list_get_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

/* request a list of all committed and uncommited blocks for @bname */
int
azure_op_block_list_get(const char *account,
			const char *container,
			const char *bname,
			bool insecure_http,
			struct azure_op *op)
{
	int ret;
	struct azure_req_block_list_get *blk_list_get_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOCK_LIST_GET;
	blk_list_get_req = &op->req.block_list_get;

	blk_list_get_req->account = strdup(account);
	if (blk_list_get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
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
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net"
		       "/%s/%s?comp=blocklist&blocklisttype=all",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = elasto_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_block_list_get_fill_hdr(op);
	if (ret < 0)
		goto err_buf_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_buf_free:
	elasto_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_bname_free:
	free(blk_list_get_req->bname);
err_container_free:
	free(blk_list_get_req->container);
err_account_free:
	free(blk_list_get_req->account);
err_out:
	return ret;
}

/*
 * process a single block list get iteration at @iter, return -ENOENT if no
 * such iteration exists
 */
static int
azure_rsp_blk_iter_process(struct apr_xml_elem *xel,
			   enum azure_block_state state,
			   struct azure_block **blk_ret)
{
	int ret;
	char *name;
	struct azure_block *blk;

	blk = malloc(sizeof(*blk));
	if (blk == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_path_get(xel, "Name", &name);
	if (ret < 0) {
		goto err_blk_free;
	}
	blk->id = malloc(strlen(name));
	if (blk->id == NULL) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = base64_decode(name, blk->id);
	if (ret < 0) {
		ret = -EIO;
		goto err_id_free;
	}
	/* zero terminate */
	blk->id[ret] = '\0';

	ret = azure_xml_path_u64_get(xel, "Size", &blk->len);
	if (ret < 0) {
		goto err_id_free;
	}

	blk->state = state;
	*blk_ret = blk;
	free(name);

	return 0;

err_id_free:
	free(blk->id);
err_name_free:
	free(name);
err_blk_free:
	free(blk);
err_out:
	return ret;
}

static int
azure_rsp_block_list_get_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_block_list_get *blk_list_get_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct azure_block *blk;
	struct azure_block *blk_n;

	assert(op->opcode == AOP_BLOCK_LIST_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	blk_list_get_rsp = &op->rsp.block_list_get;
	list_head_init(&blk_list_get_rsp->blks);

	xel = NULL;
	ret = azure_xml_path_el_get(xdoc->root,
				    "/BlockList/CommittedBlocks/Block", &xel);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "Block") == 0)) {
		ret = azure_rsp_blk_iter_process(xel->first_child,
						 BLOCK_STATE_COMMITED,
						 &blk);
		if (ret < 0) {
			goto err_blks_free;
		}
		list_add_tail(&blk_list_get_rsp->blks, &blk->list);
		blk_list_get_rsp->num_blks++;

		xel = xel->next;
	}

	xel = NULL;
	ret = azure_xml_path_el_get(xdoc->root,
				    "BlockList/UncommittedBlocks/Block", &xel);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "Block") == 0)) {
		ret = azure_rsp_blk_iter_process(xel->first_child,
						 BLOCK_STATE_UNCOMMITED,
						 &blk);
		if (ret < 0) {
			goto err_blks_free;
		}
		list_add_tail(&blk_list_get_rsp->blks, &blk->list);
		blk_list_get_rsp->num_blks++;

		xel = xel->next;
	}

	apr_pool_destroy(pool);
	return 0;

err_blks_free:
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_req_blob_del_free(struct azure_req_blob_del *bl_del_req)
{
	free(bl_del_req->account);
	free(bl_del_req->container);
	free(bl_del_req->bname);
}

static int
azure_op_blob_del_fill_hdr(struct azure_op *op)
{
	return azure_op_fill_hdr_common(op, false);
}

int
azure_op_blob_del(const char *account,
		   const char *container,
		   const char *bname,
		   bool insecure_http,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_blob_del *bl_del_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_DEL;
	bl_del_req = &op->req.blob_del;

	bl_del_req->account = strdup(account);
	if (bl_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	bl_del_req->container = strdup(container);
	if (bl_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	bl_del_req->bname = strdup(bname);
	if (bl_del_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}

	/* mandatory headers */
	ret = azure_op_blob_del_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_free_bname:
	free(bl_del_req->bname);
err_free_container:
	free(bl_del_req->container);
err_free_account:
	free(bl_del_req->account);
err_out:
	return ret;
}

static void
azure_req_blob_cp_free(struct azure_req_blob_cp *bl_cp_req)
{
	free(bl_cp_req->src.account);
	free(bl_cp_req->src.container);
	free(bl_cp_req->src.bname);
	free(bl_cp_req->dst.account);
	free(bl_cp_req->dst.container);
	free(bl_cp_req->dst.bname);
}

static int
azure_op_blob_cp_fill_hdr(struct azure_op *op,
			  bool insecure_http)
{
	int ret;
	char *hdr_str;

	ret = azure_op_fill_hdr_common(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       op->req.blob_cp.src.account,
		       op->req.blob_cp.src.container,
		       op->req.blob_cp.src.bname);
	ret = azure_op_req_hdr_add(op, "x-ms-copy-source", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_blob_cp(const char *src_account,
		 const char *src_container,
		 const char *src_bname,
		 const char *dst_account,
		 const char *dst_container,
		 const char *dst_bname,
		 bool insecure_http,
		 struct azure_op *op)
{
	int ret;
	struct azure_req_blob_cp *bl_cp_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_BLOB_CP;
	bl_cp_req = &op->req.blob_cp;

	bl_cp_req->src.account = strdup(src_account);
	if (bl_cp_req->src.account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	bl_cp_req->src.container = strdup(src_container);
	if (bl_cp_req->src.container == NULL) {
		ret = -ENOMEM;
		goto err_src_acc_free;
	}

	bl_cp_req->src.bname = strdup(src_bname);
	if (bl_cp_req->src.bname == NULL) {
		ret = -ENOMEM;
		goto err_src_ctnr_free;
	}

	bl_cp_req->dst.account = strdup(dst_account);
	if (bl_cp_req->dst.account == NULL) {
		ret = -ENOMEM;
		goto err_src_blb_free;
	}

	bl_cp_req->dst.container = strdup(dst_container);
	if (bl_cp_req->dst.container == NULL) {
		ret = -ENOMEM;
		goto err_dst_acc_free;
	}

	bl_cp_req->dst.bname = strdup(dst_bname);
	if (bl_cp_req->dst.bname == NULL) {
		ret = -ENOMEM;
		goto err_dst_ctnr_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "%s://%s.blob.core.windows.net/%s/%s",
		       (insecure_http ? "http" : "https"),
		       dst_account, dst_container, dst_bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dst_blb_free;
	}

	/* mandatory headers */
	ret = azure_op_blob_cp_fill_hdr(op, insecure_http);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_dst_blb_free:
	free(bl_cp_req->dst.bname);
err_dst_ctnr_free:
	free(bl_cp_req->dst.container);
err_dst_acc_free:
	free(bl_cp_req->dst.account);
err_src_blb_free:
	free(bl_cp_req->src.bname);
err_src_ctnr_free:
	free(bl_cp_req->src.container);
err_src_acc_free:
	free(bl_cp_req->src.account);
err_out:
	return ret;
}

static void
azure_req_status_get_free(struct azure_req_status_get *sts_get_req)
{
	free(sts_get_req->sub_id);
	free(sts_get_req->req_id);
}

static void
azure_rsp_status_get_free(struct azure_rsp_status_get *sts_get_rsp)
{
	if (sts_get_rsp->status == AOP_STATUS_FAILED) {
		free(sts_get_rsp->err.msg);
	}
}

int
azure_op_status_get(const char *sub_id,
		    const char *req_id,
		    struct azure_op *op)
{
	int ret;
	struct azure_req_status_get *sts_get_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = AOP_STATUS_GET;
	sts_get_req = &op->req.sts_get;

	sts_get_req->sub_id = strdup(sub_id);
	if (sts_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	sts_get_req->req_id = strdup(req_id);
	if (sts_get_req->req_id == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://management.core.windows.net"
		       "/%s/operations/%s",
		       sub_id, req_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_req_free;
	}

	ret = azure_op_fill_hdr_common(op, true);
	if (ret < 0)
		goto err_url_free;

	return 0;
err_url_free:
	free(op->url);
err_req_free:
	free(sts_get_req->req_id);
err_sub_free:
	free(sts_get_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_status_get_ok_process(struct apr_xml_doc *xdoc,
				struct azure_rsp_status_get *sts_get_rsp)
{
	int ret;

	ret = azure_xml_path_i32_get(xdoc->root,
				     "/Operation/HttpStatusCode",
				     &sts_get_rsp->ok.http_code);
	return ret;
}

static int
azure_rsp_status_get_err_process(struct apr_xml_doc *xdoc,
				 struct azure_rsp_status_get *sts_get_rsp)
{
	int ret;

	ret = azure_xml_path_i32_get(xdoc->root,
				     "/Operation/HttpStatusCode",
				     &sts_get_rsp->err.http_code);
	if (ret < 0) {
		return ret;
	}
	ret = azure_xml_path_i32_get(xdoc->root,
				     "/Operation/Error/Code",
				     &sts_get_rsp->err.code);
	if (ret < 0) {
		return ret;
	}
	ret = azure_xml_path_get(xdoc->root,
				 "/Operation/Error/Message",
				 &sts_get_rsp->err.msg);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int
azure_rsp_status_get_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct azure_rsp_status_get *sts_get_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	char *xml_val;

	assert(op->opcode == AOP_STATUS_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	sts_get_rsp = &op->rsp.sts_get;

	ret = azure_xml_path_get(xdoc->root,
				 "/Operation/Status",
				 &xml_val);
	if (ret < 0) {
		goto err_pool_free;
	}
	if (strcmp(xml_val, "InProgress") == 0) {
		sts_get_rsp->status = AOP_STATUS_IN_PROGRESS;
	} else if (strcmp(xml_val, "Succeeded") == 0) {
		sts_get_rsp->status = AOP_STATUS_SUCCEEDED;
		free(xml_val);
		ret = azure_rsp_status_get_ok_process(xdoc, sts_get_rsp);
		if (ret < 0) {
			goto err_pool_free;
		}
	} else if (strcmp(xml_val, "Failed") == 0) {
		sts_get_rsp->status = AOP_STATUS_FAILED;
		free(xml_val);
		ret = azure_rsp_status_get_err_process(xdoc, sts_get_rsp);
		if (ret < 0) {
			goto err_pool_free;
		}
	} else {
		dbg(0, "unexpected op status: %s\n", xml_val);
		ret = -EINVAL;
		free(xml_val);
		goto err_pool_free;
	}

	apr_pool_destroy(pool);
	return 0;

err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
azure_rsp_error_free(struct azure_rsp_error *err)
{
	free(err->msg);
	free(err->redir_endpoint);
	free(err->buf);
}

/*
 * Check whether @err_code represents an azure error response. Nothing opcode
 * specific yet.
 */
bool
azure_rsp_is_error(enum azure_opcode opcode, int err_code)
{
	if (err_code == 0) {
		return false;
	} else if ((err_code >= 200) && (err_code < 300)) {
		return false;
	}
	return true;
}

static int
azure_rsp_error_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;

	if (op->rsp.err_code == 0) {
		return 0;
	}

	if (op->rsp.err.off == 0) {
		/* no error description XML attached */
		op->rsp.err.msg = strdup("no error description");
		if (op->rsp.err.msg == NULL) {
			return -ENOMEM;
		}
		return 0;
	}

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	ret = azure_xml_slurp(pool, false, op->rsp.err.buf, op->rsp.err.off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	ret = azure_xml_path_get(xdoc->root, "/Error/Message",
				 &op->rsp.err.msg);
	if (ret == -ENOENT) {
		/* data attached, but no error description XML */
		op->rsp.err.msg = strdup("no error description");
		if (op->rsp.err.msg == NULL) {
			ret = -ENOMEM;
			goto err_pool_free;
		}
	} else if (ret < 0) {
		goto err_pool_free;
	}

	dbg(0, "got error msg: %s\n", op->rsp.err.msg);

	if (op->rsp.err_code == 307) {
		/* temporary redirect, fill location */
		ret = azure_xml_path_get(xdoc->root, "/Error/Endpoint",
					 &op->rsp.err.redir_endpoint);
		if (ret == -ENOENT) {
			dbg(1, "got redirect response without endpoint\n");
		} else if (ret < 0) {
			goto err_msg_free;
		} else {
			dbg(3, "redirect response endpoint: %s\n",
			    op->rsp.err.redir_endpoint);
		}
	}

	apr_pool_destroy(pool);
	return 0;

err_msg_free:
	free(op->rsp.err.msg);
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static int
s3_req_fill_hdr_common(struct azure_op *op)
{
	int ret;
	size_t sz;
	char hdr_buf[100];
	time_t t;
	struct tm tm_gmt;

	time(&t);
	gmtime_r(&t, &tm_gmt);
	sz = strftime(hdr_buf, ARRAY_SIZE(hdr_buf),
		      "%a, %d %b %Y %T %z", &tm_gmt);
	if (sz == 0) {
		return -E2BIG;
	}

	ret = azure_op_req_hdr_add(op, "Date", hdr_buf);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

static void
s3_req_svc_list_free(struct s3_req_svc_list *svc_list)
{
	/* nothing to do */
}

static void
s3_bkt_free(struct s3_bucket **pbkt)
{
	struct s3_bucket *bkt = *pbkt;

	free(bkt->name);
	free(bkt->create_date);
	free(bkt);
}

static void
s3_rsp_svc_list_free(struct s3_rsp_svc_list *svc_list_rsp)
{
	struct s3_bucket *bkt;
	struct s3_bucket *bkt_n;

	free(svc_list_rsp->id);
	free(svc_list_rsp->disp_name);
	list_for_each_safe(&svc_list_rsp->bkts, bkt, bkt_n, list) {
		s3_bkt_free(&bkt);
	}
}

int
s3_op_svc_list(bool insecure_http,
	       struct azure_op *op)
{
	int ret;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_SVC_LIST;
	/* no arguments */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "%s://s3.amazonaws.com/",
		       (insecure_http ? "http" : "https"));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_out:
	return ret;
}

static int
s3_rsp_bkt_iter_process(struct apr_xml_elem *xel,
			struct s3_bucket **bkt_ret)
{
	int ret;
	struct s3_bucket *bkt;

	bkt = malloc(sizeof(*bkt));
	if (bkt == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_path_get(xel, "Name", &bkt->name);
	if (ret < 0) {
		goto err_blk_free;
	}

	ret = azure_xml_path_get(xel, "CreationDate", &bkt->create_date);
	if (ret < 0) {
		goto err_name_free;
	}
	*bkt_ret = bkt;

	return 0;

err_name_free:
	free(bkt->name);
err_blk_free:
	free(bkt);
err_out:
	return ret;
}

static int
s3_rsp_svc_list_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct s3_rsp_svc_list *svc_list_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct s3_bucket *bkt;
	struct s3_bucket *bkt_n;

	assert(op->opcode == S3OP_SVC_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);
	svc_list_rsp = &op->rsp.svc_list;

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	ret = azure_xml_path_get(xdoc->root, "/ListAllMyBucketsResult/Owner/ID",
				 &svc_list_rsp->id);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_pool_free;
	}

	ret = azure_xml_path_get(xdoc->root, "/ListAllMyBucketsResult/Owner/DisplayName",
				 &svc_list_rsp->disp_name);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_pool_free;
	}

	list_head_init(&svc_list_rsp->bkts);

	/* get the first, if present */
	ret = azure_xml_path_el_get(xdoc->root,
				    "/ListAllMyBucketsResult/Buckets/Bucket",
				    &xel);
	if (ret == -ENOENT) {
		goto done;
	} else if (ret < 0) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "Bucket") == 0)) {
		ret = s3_rsp_bkt_iter_process(xel->first_child, &bkt);
		if (ret < 0) {
			goto err_bkts_free;
		}
		list_add_tail(&svc_list_rsp->bkts, &bkt->list);
		svc_list_rsp->num_bkts++;

		xel = xel->next;
	}
done:
	apr_pool_destroy(pool);
	return 0;

err_bkts_free:
	list_for_each_safe(&svc_list_rsp->bkts, bkt, bkt_n, list) {
		s3_bkt_free(&bkt);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
s3_req_bkt_list_free(struct s3_req_bkt_list *bkt_list)
{
	free(bkt_list->bkt_name);
}

static void
s3_obj_free(struct s3_object **pobj)
{
	struct s3_object *obj = *pobj;

	free(obj->key);
	free(obj->last_mod);
	free(obj->store_class);
	free(obj);
}

static void
s3_rsp_bkt_list_free(struct s3_rsp_bkt_list *bkt_list_rsp)
{
	struct s3_object *obj;
	struct s3_object *obj_n;

	if (bkt_list_rsp->num_objs <= 0)
		return;
	list_for_each_safe(&bkt_list_rsp->objs, obj, obj_n, list) {
		s3_obj_free(&obj);
	}
}


int
s3_op_bkt_list(const char *bkt_name,
	       bool insecure_http,
	       struct azure_op *op)
{
	int ret;
	struct s3_req_bkt_list *bkt_list_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_BKT_LIST;
	bkt_list_req = &op->req.bkt_list;

	bkt_list_req->bkt_name = strdup(bkt_name);
	if (bkt_list_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/",
		       (insecure_http ? "http" : "https"),
		       bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;

err_url_free:
	free(op->url);
err_name_free:
	free(bkt_list_req->bkt_name);
err_out:
	return ret;
}

static int
s3_rsp_obj_iter_process(struct apr_xml_elem *xel,
			struct s3_object **obj_ret)
{
	int ret;
	struct s3_object *obj;

	obj = malloc(sizeof(*obj));
	if (obj == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_path_get(xel, "Key", &obj->key);
	if (ret < 0) {
		goto err_obj_free;
	}

	ret = azure_xml_path_get(xel, "LastModified", &obj->last_mod);
	if (ret < 0) {
		goto err_key_free;
	}

	ret = azure_xml_path_u64_get(xel, "Size", &obj->size);
	if (ret < 0) {
		goto err_mod_free;
	}

	ret = azure_xml_path_get(xel, "StorageClass", &obj->store_class);
	if (ret < 0) {
		goto err_mod_free;
	}

	*obj_ret = obj;

	return 0;

err_mod_free:
	free(obj->last_mod);
err_key_free:
	free(obj->key);
err_obj_free:
	free(obj);
err_out:
	return ret;
}

static int
s3_rsp_bkt_list_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct s3_rsp_bkt_list *bkt_list_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	struct apr_xml_elem *xel;
	struct s3_object *obj;
	struct s3_object *obj_n;

	assert(op->opcode == S3OP_BKT_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);
	bkt_list_rsp = &op->rsp.bkt_list;

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	ret = azure_xml_path_bool_get(xdoc->root,
				      "/ListBucketResult/IsTruncated",
				      &bkt_list_rsp->truncated);
	if (ret < 0) {
		goto err_pool_free;
	}

	list_head_init(&bkt_list_rsp->objs);

	/* get the first, if present */
	ret = azure_xml_path_el_get(xdoc->root,
				    "/ListBucketResult/Contents",
				    &xel);
	if (ret == -ENOENT) {
		goto done;
	} else if (ret < 0) {
		goto err_pool_free;
	}

	while ((xel != NULL) && (strcmp(xel->name, "Contents") == 0)) {
		ret = s3_rsp_obj_iter_process(xel->first_child, &obj);
		if (ret < 0) {
			goto err_objs_free;
		}
		list_add_tail(&bkt_list_rsp->objs, &obj->list);
		bkt_list_rsp->num_objs++;

		xel = xel->next;
	}
done:
	apr_pool_destroy(pool);
	return 0;

err_objs_free:
	list_for_each_safe(&bkt_list_rsp->objs, obj, obj_n, list) {
		s3_obj_free(&obj);
	}
err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
s3_req_bkt_create_free(struct s3_req_bkt_create *bkt_create)
{
	free(bkt_create->bkt_name);
	free(bkt_create->location);
}

static int
s3_op_bkt_create_fill_body(const char *location,
			   struct elasto_data **req_data_out)
{
	int ret;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	if (location == NULL) {
		dbg(2, "bucket location not specified, using S3 default\n");
		return 0;
	}

	/* 2k buf, should be strlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, 0, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	xml_data = (char *)req_data->buf;
	ret = snprintf(xml_data, buf_remain,
		       "<CreateBucketConfiguration "
			  "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
				"<LocationConstraint>%s</LocationConstraint>"
		       "</CreateBucketConfiguration>",
		       location);
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending bucket creation req data: %s\n",
	    (char *)req_data->buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_destroy(&req_data);
err_out:
	return ret;
}

int
s3_op_bkt_create(const char *bkt_name,
		 const char *location,
		 bool insecure_http,
		 struct azure_op *op)
{
	int ret;
	struct s3_req_bkt_create *bkt_create_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_BKT_CREATE;
	bkt_create_req = &op->req.bkt_create;

	bkt_create_req->bkt_name = strdup(bkt_name);
	if (bkt_create_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (location != NULL) {
		bkt_create_req->location = strdup(location);
		if (bkt_create_req->location == NULL) {
			ret = -ENOMEM;
			goto err_bkt_free;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/",
		       (insecure_http ? "http" : "https"),
		       bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_loc_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = s3_op_bkt_create_fill_body(location, &op->req.data);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;

err_url_free:
	free(op->url);
err_loc_free:
	free(bkt_create_req->location);
err_bkt_free:
	free(bkt_create_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_bkt_del_free(struct s3_req_bkt_del *bkt_del)
{
	free(bkt_del->bkt_name);
}

int
s3_op_bkt_del(const char *bkt_name,
	      bool insecure_http,
	      struct azure_op *op)
{
	int ret;
	struct s3_req_bkt_del *bkt_del_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_BKT_DEL;
	bkt_del_req = &op->req.bkt_del;

	bkt_del_req->bkt_name = strdup(bkt_name);
	if (bkt_del_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/",
		       (insecure_http ? "http" : "https"),
		       bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;

err_url_free:
	free(op->url);
err_name_free:
	free(bkt_del_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_obj_put_free(struct s3_req_obj_put *obj_put)
{
	free(obj_put->bkt_name);
	free(obj_put->obj_name);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 */
int
s3_op_obj_put(const char *bkt_name,
	      const char *obj_name,
	      struct elasto_data *data,
	      bool insecure_http,
	      struct azure_op *op)
{
	int ret;
	struct s3_req_obj_put *obj_put_req;

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_OBJ_PUT;
	obj_put_req = &op->req.obj_put;

	obj_put_req->bkt_name = strdup(bkt_name);
	if (obj_put_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	obj_put_req->obj_name = strdup(obj_name);
	if (obj_put_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s",
		       (insecure_http ? "http" : "https"),
		       bkt_name, obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_data_close:
	op->req.data = NULL;
	free(obj_put_req->obj_name);
err_bkt_free:
	free(obj_put_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_obj_get_free(struct s3_req_obj_get *obj_get)
{
	free(obj_get->bkt_name);
	free(obj_get->obj_name);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 */
int
s3_op_obj_get(const char *bkt_name,
	      const char *obj_name,
	      struct elasto_data *data,
	      bool insecure_http,
	      struct azure_op *op)
{
	int ret;
	struct s3_req_obj_get *obj_get_req;

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_OBJ_GET;
	obj_get_req = &op->req.obj_get;

	obj_get_req->bkt_name = strdup(bkt_name);
	if (obj_get_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	obj_get_req->obj_name = strdup(obj_name);
	if (obj_get_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	if (data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s",
		       (insecure_http ? "http" : "https"),
		       bkt_name, obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_data_close:
	op->req.data = NULL;
	free(obj_get_req->obj_name);
err_bkt_free:
	free(obj_get_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_obj_del_free(struct s3_req_obj_del *obj_del)
{
	free(obj_del->bkt_name);
	free(obj_del->obj_name);
}

int
s3_op_obj_del(const char *bkt_name,
	      const char *obj_name,
	      bool insecure_http,
	      struct azure_op *op)
{
	int ret;
	struct s3_req_obj_del *obj_del_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_OBJ_DEL;
	obj_del_req = &op->req.obj_del;

	obj_del_req->bkt_name = strdup(bkt_name);
	if (obj_del_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	obj_del_req->obj_name = strdup(obj_name);
	if (obj_del_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s",
		       (insecure_http ? "http" : "https"),
		       bkt_name, obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_obj_free:
	free(obj_del_req->obj_name);
err_bkt_free:
	free(obj_del_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_obj_cp_free(struct s3_req_obj_cp *obj_cp)
{
	free(obj_cp->src.bkt_name);
	free(obj_cp->src.obj_name);
	free(obj_cp->dst.bkt_name);
	free(obj_cp->dst.obj_name);
}

static int
s3_req_obj_cp_hdr_fill(struct azure_op *op)
{
	int ret;
	char *hdr_str;

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "/%s/%s",
		       op->req.obj_cp.src.bkt_name,
		       op->req.obj_cp.src.obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = azure_op_req_hdr_add(op, "x-amz-copy-source", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

int
s3_op_obj_cp(const char *src_bkt,
	     const char *src_obj,
	     const char *dst_bkt,
	     const char *dst_obj,
	     bool insecure_http,
	     struct azure_op *op)
{
	int ret;
	struct s3_req_obj_cp *obj_cp_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_OBJ_CP;
	obj_cp_req = &op->req.obj_cp;

	obj_cp_req->src.bkt_name = strdup(src_bkt);
	if (obj_cp_req->src.bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	obj_cp_req->src.obj_name = strdup(src_obj);
	if (obj_cp_req->src.obj_name == NULL) {
		ret = -ENOMEM;
		goto err_src_bkt_free;
	}

	obj_cp_req->dst.bkt_name = strdup(dst_bkt);
	if (obj_cp_req->dst.bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_src_obj_free;
	}

	obj_cp_req->dst.obj_name = strdup(dst_obj);
	if (obj_cp_req->dst.obj_name == NULL) {
		ret = -ENOMEM;
		goto err_dst_bkt_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s",
		       (insecure_http ? "http" : "https"),
		       dst_bkt, dst_obj);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dst_obj_free;
	}

	ret = s3_req_obj_cp_hdr_fill(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_dst_obj_free:
	free(obj_cp_req->dst.obj_name);
err_dst_bkt_free:
	free(obj_cp_req->dst.bkt_name);
err_src_obj_free:
	free(obj_cp_req->src.obj_name);
err_src_bkt_free:
	free(obj_cp_req->src.bkt_name);
err_out:
	return ret;
}

static void
s3_req_mp_start_free(struct s3_req_mp_start *mp_start_req)
{
	free(mp_start_req->bkt_name);
	free(mp_start_req->obj_name);
}

static void
s3_rsp_mp_start_free(struct s3_rsp_mp_start *mp_start_rsp)
{
	free(mp_start_rsp->upload_id);
}

int
s3_op_mp_start(const char *bkt,
	       const char *obj,
	       bool insecure_http,
	       struct azure_op *op)
{
	int ret;
	struct s3_req_mp_start *mp_start_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_MULTIPART_START;
	mp_start_req = &op->req.mp_start;

	mp_start_req->bkt_name = strdup(bkt);
	if (mp_start_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	mp_start_req->obj_name = strdup(obj);
	if (mp_start_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->method = REQ_METHOD_POST;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s?uploads",
		       (insecure_http ? "http" : "https"),
		       bkt, obj);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_obj_free:
	free(mp_start_req->obj_name);
err_bkt_free:
	free(mp_start_req->bkt_name);
err_out:
	return ret;
}

static int
s3_rsp_mp_start_process(struct azure_op *op)
{
	int ret;
	apr_status_t rv;
	struct s3_rsp_mp_start *mp_start_rsp;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;

	assert(op->opcode == S3OP_MULTIPART_START);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);
	mp_start_rsp = &op->rsp.mp_start;

	rv = apr_pool_create(&pool, NULL);
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_out;
	}

	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(pool, false, op->rsp.data->buf, op->rsp.data->off,
			      &xdoc);
	if (ret < 0) {
		goto err_pool_free;
	}

	ret = azure_xml_path_get(xdoc->root, "/InitiateMultipartUploadResult/UploadId",
				 &mp_start_rsp->upload_id);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_pool_free;
	}

	apr_pool_destroy(pool);
	return 0;

err_pool_free:
	apr_pool_destroy(pool);
err_out:
	return ret;
}

static void
s3_part_free(struct s3_part **_part)
{
	struct s3_part *part = *_part;
	free(part->etag);
	free(part);
}

static void
s3_req_mp_done_free(struct s3_req_mp_done *mp_done_req)
{
	struct s3_part *part;
	struct s3_part *part_n;

	free(mp_done_req->bkt_name);
	free(mp_done_req->obj_name);
	free(mp_done_req->upload_id);
	if (mp_done_req->parts == NULL) {
		return;
	}
	list_for_each_safe(mp_done_req->parts, part, part_n, list) {
		s3_part_free(&part);
	}
}

static int
s3_op_mp_done_fill_body(struct list_head *parts,
			struct elasto_data **req_data_out)
{
	int ret;
	struct s3_part *part;
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

	xml_data = (char *)req_data->buf;
	ret = snprintf(xml_data, buf_remain,
		       "<CompleteMultipartUpload>");
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	list_for_each(parts, part, list) {
		ret = snprintf(xml_data, buf_remain,
			       "<Part>"
					"<PartNumber>%u</PartNumber>"
					"<ETag>%s</ETag>"
			       "</Part>",
			       (unsigned int)part->pnum,
			       part->etag);
		if ((ret < 0) || (ret >= buf_remain)) {
			ret = -E2BIG;
			goto err_buf_free;
		}

		xml_data += ret;
		buf_remain -= ret;
	}

	ret = snprintf(xml_data, buf_remain,
		       "</CompleteMultipartUpload>");
	if ((ret < 0) || (ret >= buf_remain)) {
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending multipart upload complete req data: %s\n",
	    (char *)req_data->buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_destroy(&req_data);
err_out:
	return ret;
}

int
s3_op_mp_done(const char *bkt,
	      const char *obj,
	      const char *upload_id,
	      struct list_head *parts,
	      bool insecure_http,
	      struct azure_op *op)
{
	int ret;
	struct s3_req_mp_done *mp_done_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_MULTIPART_DONE;
	mp_done_req = &op->req.mp_done;

	mp_done_req->bkt_name = strdup(bkt);
	if (mp_done_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	mp_done_req->obj_name = strdup(obj);
	if (mp_done_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	mp_done_req->upload_id = strdup(upload_id);
	if (mp_done_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	op->method = REQ_METHOD_POST;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s?uploadId=%s",
		       (insecure_http ? "http" : "https"),
		       bkt, obj, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = s3_op_mp_done_fill_body(parts, &op->req.data);
	if (ret < 0) {
		goto err_hdr_free;
	}
	/* XXX should copy list */
	mp_done_req->parts = parts;

	op->sign = true;

	return 0;

err_hdr_free:
	azure_op_hdrs_free(&op->req.hdrs);
err_url_free:
	free(op->url);
err_obj_free:
	free(mp_done_req->obj_name);
err_bkt_free:
	free(mp_done_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_mp_abort_free(struct s3_req_mp_abort *mp_abort_req)
{
	free(mp_abort_req->bkt_name);
	free(mp_abort_req->obj_name);
	free(mp_abort_req->upload_id);
}

int
s3_op_mp_abort(const char *bkt,
	       const char *obj,
	       const char *upload_id,
	       bool insecure_http,
	       struct azure_op *op)
{
	int ret;
	struct s3_req_mp_abort *mp_abort_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_MULTIPART_ABORT;
	mp_abort_req = &op->req.mp_abort;

	mp_abort_req->bkt_name = strdup(bkt);
	if (mp_abort_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	mp_abort_req->obj_name = strdup(obj);
	if (mp_abort_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	mp_abort_req->upload_id = strdup(upload_id);
	if (mp_abort_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url, "%s://%s.s3.amazonaws.com/%s?uploadId=%s",
		       (insecure_http ? "http" : "https"),
		       bkt, obj, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;

err_url_free:
	free(op->url);
err_obj_free:
	free(mp_abort_req->obj_name);
err_bkt_free:
	free(mp_abort_req->bkt_name);
err_out:
	return ret;
}

static void
s3_req_part_put_free(struct s3_req_part_put *part_put_req)
{
	free(part_put_req->bkt_name);
	free(part_put_req->obj_name);
	free(part_put_req->upload_id);
}

static void
s3_rsp_part_put_free(struct s3_rsp_part_put *part_put_rsp)
{
	free(part_put_rsp->etag);
}

int
s3_op_part_put(const char *bkt,
	       const char *obj,
	       const char *upload_id,
	       uint32_t pnum,
	       struct elasto_data *data,
	       bool insecure_http,
	       struct azure_op *op)
{
	int ret;
	struct s3_req_part_put *part_put_req;

	memset(op, 0, sizeof(*op));
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = S3OP_PART_PUT;
	part_put_req = &op->req.part_put;

	part_put_req->bkt_name = strdup(bkt);
	if (part_put_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	part_put_req->obj_name = strdup(obj);
	if (part_put_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	part_put_req->upload_id = strdup(upload_id);
	if (part_put_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	part_put_req->pnum = pnum;

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "%s://%s.s3.amazonaws.com/%s?partNumber=%u&uploadId=%s",
		       (insecure_http ? "http" : "https"),
		       bkt, obj, (unsigned int)pnum, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uploadid_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_uploadid_free:
	free(part_put_req->upload_id);
err_obj_free:
	free(part_put_req->obj_name);
err_bkt_free:
	free(part_put_req->bkt_name);
err_out:
	return ret;
}

static int
s3_rsp_part_put_process(struct azure_op *op)
{
	int ret;
	struct s3_rsp_part_put *part_put_rsp;

	assert(op->opcode == S3OP_PART_PUT);
	part_put_rsp = &op->rsp.part_put;
	ret = azure_op_hdr_val_lookup(&op->rsp.hdrs, "ETag",
				      &part_put_rsp->etag);
	if (ret < 0) {
		dbg(0, "no etag in response header\n");
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static void
azure_req_free(struct azure_op *op)
{
	azure_op_hdrs_free(&op->req.hdrs);
	elasto_data_destroy(&op->req.data);

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		azure_req_acc_keys_get_free(&op->req.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		azure_req_acc_list_free(&op->req.acc_list);
		break;
	case AOP_ACC_CREATE:
		azure_req_acc_create_free(&op->req.acc_create);
		break;
	case AOP_ACC_DEL:
		azure_req_acc_del_free(&op->req.acc_del);
		break;
	case AOP_CONTAINER_LIST:
		azure_req_ctnr_list_free(&op->req.ctnr_list);
		break;
	case AOP_CONTAINER_CREATE:
		azure_req_ctnr_create_free(&op->req.ctnr_create);
		break;
	case AOP_CONTAINER_DEL:
		azure_req_ctnr_del_free(&op->req.ctnr_del);
		break;
	case AOP_BLOB_LIST:
		azure_req_blob_list_free(&op->req.blob_list);
		break;
	case AOP_BLOB_PUT:
		azure_req_blob_put_free(&op->req.blob_put);
		break;
	case AOP_BLOB_GET:
		azure_req_blob_get_free(&op->req.blob_get);
		break;
	case AOP_PAGE_PUT:
		azure_req_page_put_free(&op->req.page_put);
		break;
	case AOP_BLOCK_PUT:
		azure_req_block_put_free(&op->req.block_put);
		break;
	case AOP_BLOCK_LIST_PUT:
		azure_req_block_list_put_free(&op->req.block_list_put);
		break;
	case AOP_BLOCK_LIST_GET:
		azure_req_block_list_get_free(&op->req.block_list_get);
		break;
	case AOP_BLOB_DEL:
		azure_req_blob_del_free(&op->req.blob_del);
		break;
	case AOP_BLOB_CP:
		azure_req_blob_cp_free(&op->req.blob_cp);
		break;
	case AOP_STATUS_GET:
		azure_req_status_get_free(&op->req.sts_get);
		break;
	/* S3 */
	case S3OP_SVC_LIST:
		s3_req_svc_list_free(&op->req.svc_list);
		break;
	case S3OP_BKT_LIST:
		s3_req_bkt_list_free(&op->req.bkt_list);
		break;
	case S3OP_BKT_CREATE:
		s3_req_bkt_create_free(&op->req.bkt_create);
		break;
	case S3OP_BKT_DEL:
		s3_req_bkt_del_free(&op->req.bkt_del);
		break;
	case S3OP_OBJ_PUT:
		s3_req_obj_put_free(&op->req.obj_put);
		break;
	case S3OP_OBJ_GET:
		s3_req_obj_get_free(&op->req.obj_get);
		break;
	case S3OP_OBJ_DEL:
		s3_req_obj_del_free(&op->req.obj_del);
		break;
	case S3OP_OBJ_CP:
		s3_req_obj_cp_free(&op->req.obj_cp);
		break;
	case S3OP_MULTIPART_START:
		s3_req_mp_start_free(&op->req.mp_start);
		break;
	case S3OP_MULTIPART_DONE:
		s3_req_mp_done_free(&op->req.mp_done);
		break;
	case S3OP_MULTIPART_ABORT:
		s3_req_mp_abort_free(&op->req.mp_abort);
		break;
	case S3OP_PART_PUT:
		s3_req_part_put_free(&op->req.part_put);
		break;
	default:
		assert(true);
		break;
	};
}

static void
azure_rsp_free(struct azure_op *op)
{
	azure_op_hdrs_free(&op->rsp.hdrs);
	elasto_data_destroy(&op->rsp.data);

	if (op->rsp.is_error) {
		/* error response only, no aop data */
		azure_rsp_error_free(&op->rsp.err);
		return;
	}

	free(op->rsp.req_id);

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		azure_rsp_acc_keys_get_free(&op->rsp.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		azure_rsp_acc_list_free(&op->rsp.acc_list);
		break;
	case AOP_CONTAINER_LIST:
		azure_rsp_ctnr_list_free(&op->rsp.ctnr_list);
		break;
	case AOP_BLOB_LIST:
		azure_rsp_blob_list_free(&op->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		azure_rsp_block_list_get_free(&op->rsp.block_list_get);
		break;
	case AOP_STATUS_GET:
		azure_rsp_status_get_free(&op->rsp.sts_get);
		break;
	case S3OP_SVC_LIST:
		s3_rsp_svc_list_free(&op->rsp.svc_list);
		break;
	case S3OP_BKT_LIST:
		s3_rsp_bkt_list_free(&op->rsp.bkt_list);
		break;
	case S3OP_MULTIPART_START:
		s3_rsp_mp_start_free(&op->rsp.mp_start);
		break;
	case S3OP_PART_PUT:
		s3_rsp_part_put_free(&op->rsp.part_put);
		break;
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
	case S3OP_BKT_CREATE:
	case S3OP_BKT_DEL:
	case S3OP_OBJ_PUT:
	case S3OP_OBJ_GET:
	case S3OP_OBJ_DEL:
	case S3OP_OBJ_CP:
	case S3OP_MULTIPART_DONE:
	case S3OP_MULTIPART_ABORT:
		/* nothing to do */
		break;
	default:
		assert(true);
		break;
	};
}

/* Free and zero op data */
void
azure_op_free(struct azure_op *op)
{
	free(op->sig_src);
	free(op->url);
	azure_req_free(op);
	azure_rsp_free(op);
	memset(op, 0, sizeof(*op));
}

/*
 * unmarshall response data
 */
int
azure_rsp_process(struct azure_op *op)
{
	int ret;

	if (op->rsp.is_error) {
		/* set by conn layer, error response only */
		return azure_rsp_error_process(op);
	}

	if (op->opcode < S3OP_SVC_LIST) {
		/* azure op */
		azure_op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
					&op->rsp.req_id);
	} else {
		/* s3 op */
		azure_op_hdr_val_lookup(&op->rsp.hdrs, "x-amz-request-id",
					&op->rsp.req_id);
	}
	if (op->rsp.req_id == NULL) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		ret = azure_rsp_acc_keys_get_process(op);
		break;
	case AOP_ACC_LIST:
		ret = azure_rsp_acc_list_process(op);
		break;
	case AOP_CONTAINER_LIST:
		ret = azure_rsp_ctnr_list_process(op);
		break;
	case AOP_BLOB_LIST:
		ret = azure_rsp_blob_list_process(op);
		break;
	case AOP_BLOCK_LIST_GET:
		ret = azure_rsp_block_list_get_process(op);
		break;
	case AOP_STATUS_GET:
		ret = azure_rsp_status_get_process(op);
		break;
	case S3OP_SVC_LIST:
		ret = s3_rsp_svc_list_process(op);
		break;
	case S3OP_BKT_LIST:
		ret = s3_rsp_bkt_list_process(op);
		break;
	case S3OP_MULTIPART_START:
		ret = s3_rsp_mp_start_process(op);
		break;
	case S3OP_PART_PUT:
		ret = s3_rsp_part_put_process(op);
		break;
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
	case S3OP_BKT_CREATE:
	case S3OP_BKT_DEL:
	case S3OP_OBJ_PUT:
	case S3OP_OBJ_GET:
	case S3OP_OBJ_DEL:
	case S3OP_OBJ_CP:
	case S3OP_MULTIPART_DONE:
	case S3OP_MULTIPART_ABORT:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(true);
		break;
	};

	return ret;
}
