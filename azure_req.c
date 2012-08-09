/*
 * Copyright (C) SUSE LINUX Products GmbH 2012, all rights reserved.
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
 *
 * Author: David Disseldorp <ddiss@suse.de>
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

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ccan/list/list.h"
#include "azure_xml.h"
#include "azure_req.h"

#if 0
char *
azure_op_mgmt_url_list_sas(const char *sub_id)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0)
		return NULL;
	return url;
}

char *
azure_op_mgmt_url_get_sa_props(const char *sub_id, const char *service_name)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s",
		       sub_id, service_name);
	if (ret < 0)
		return NULL;
	return url;
}

char *
azure_op_mgmt_url_check_sa_availability(const char *sub_id, const char *service_name)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices/operations/isavailable/%s",
		       sub_id, service_name);
	if (ret < 0)
		return NULL;
	return url;
}
#endif

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

static void
azure_req_mgmt_get_sa_keys_free(
		struct azure_req_mgmt_get_sa_keys *mgmt_get_sa_keys_req)
{
	free(mgmt_get_sa_keys_req->sub_id);
	free(mgmt_get_sa_keys_req->service_name);
}
static void
azure_rsp_mgmt_get_sa_keys_free(
		struct azure_rsp_mgmt_get_sa_keys *mgmt_get_sa_keys_rsp)
{
	free(mgmt_get_sa_keys_rsp->primary);
	free(mgmt_get_sa_keys_rsp->secondary);
}

static int
azure_op_mgmt_get_sa_keys_fill_hdr(struct azure_op *op)
{
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2012-03-01");
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int
azure_op_mgmt_get_sa_keys(const char *sub_id,
			   const char *service_name,
			   struct azure_op *op)
{
	int ret;
	struct azure_req_mgmt_get_sa_keys *get_sa_keys_req;

	/* TODO input validation */

	op->opcode = AOP_MGMT_GET_SA_KEYS;
	get_sa_keys_req = &op->req.mgmt_get_sa_keys;

	/* we may not need to keep these, as they're only used in the URL */
	get_sa_keys_req->sub_id = strdup(sub_id);
	if (get_sa_keys_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	get_sa_keys_req->service_name = strdup(service_name);
	if (get_sa_keys_req->service_name == NULL) {
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

	ret = azure_op_mgmt_get_sa_keys_fill_hdr(op);
	if (ret < 0) {
		goto err_free_url;
	}

	return 0;
err_free_url:
	free(op->url);
err_free_svc:
	free(get_sa_keys_req->service_name);
err_free_sub:
	free(get_sa_keys_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_mgmt_get_sa_keys_process(struct azure_op *op)
{
	int ret;
	struct azure_rsp_mgmt_get_sa_keys *get_sa_keys_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	/* parse response */
	ret = azure_xml_slurp(false, op->rsp.iov.buf, op->rsp.iov.off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	assert(op->opcode == AOP_MGMT_GET_SA_KEYS);
	get_sa_keys_rsp = &op->rsp.mgmt_get_sa_keys;

	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Primary",
		NULL, &get_sa_keys_rsp->primary);
	if (ret < 0) {
		goto err_xml_free;
	}
	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Secondary",
		NULL, &get_sa_keys_rsp->secondary);
	if (ret < 0) {
		free(get_sa_keys_rsp->primary);
		goto err_xml_free;
	}
	ret = 0;

err_xml_free:
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
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
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_ctnr_list(const char *account,
		    struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_list *ctnr_list_req;

	/* TODO input validation */

	op->opcode = AOP_CONTAINER_LIST;
	ctnr_list_req = &op->req.ctnr_list;

	ctnr_list_req->account = strdup(account);
	if (ctnr_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/?comp=list",
		       account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	op->rsp.iov.buf = malloc(1024 * 1024);	/* XXX determine best size */
	if (op->rsp.iov.buf == NULL) {
		ret = -ENOMEM;
		goto err_url_free;
	}
	op->rsp.iov.buf_len = (1024 * 1024);

	ret = azure_op_ctnr_list_fill_hdr(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_buf_free:
	free(op->rsp.iov.buf);
err_url_free:
	free(op->url);
err_acc_free:
	free(ctnr_list_req->account);
err_out:
	return ret;
}

static int
azure_rsp_ctnr_list_process(struct azure_op *op)
{
	int ret;
	int i;
	struct azure_rsp_ctnr_list *ctnr_list_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	/* parse response */
	ret = azure_xml_slurp(false, op->rsp.iov.buf, op->rsp.iov.off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		return ret;
	}

	assert(op->opcode == AOP_CONTAINER_LIST);
	ctnr_list_rsp = &op->rsp.ctnr_list;

	list_head_init(&ctnr_list_rsp->ctnrs);
	/* returns up to 5000 records (maxresults default) */
	for (i = 1; i <= 5000; i++) {
		char *query;
		char *name;
		struct azure_ctnr *ctnr;
		ret = asprintf(&query, "//Containers/Container[%d]/Name",
			       i);	/* start at 1 for W3C standard? */
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = azure_xml_get_path(xp_ctx, query, NULL, &name);
		free(query);
		if (ret == -ENOENT)
			break;	/* all processed */
		else if (ret < 0) {
			goto err_out;
		}

		ctnr = malloc(sizeof(*ctnr));
		if (ctnr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		ctnr->name = name;
		list_add_tail(&ctnr_list_rsp->ctnrs, &ctnr->list);
		ctnr_list_rsp->num_ctnrs++;
	}
	ret = 0;

err_out:
	/* XXX should unwind out.ctnrs on error */
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);

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
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_ctnr_create(const char *account,
		      const char *ctnr,
		      struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_create *ctnr_create_req;

	/* TODO input validation */

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
		       "https://%s.blob.core.windows.net/%s?restype=container",
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
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (strcmp(op->req.blob_put.type, BLOB_TYPE_PAGE) == 0) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						  "x-ms-blob-type: PageBlob");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = asprintf(&hdr_str, "x-ms-blob-content-length: %lu",
			       op->req.blob_put.pg_len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						  "x-ms-blob-type: BlockBlob");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @is_page is set, then @len corresponds to the page blob length, @buf must
 * be NULL. For a block blob, @len bytes from @buf are put.
 */
int
azure_op_blob_put(const char *account,
		   const char *container,
		   const char *bname,
		   bool is_page,
		   uint8_t *buf,
		   uint64_t len,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_blob_put *bl_put_req;

	/* TODO input validation */
	if (is_page && (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len)) {
		ret = -EINVAL;
		goto err_out;
	}

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

	if (is_page) {
		bl_put_req->type = BLOB_TYPE_PAGE;
		bl_put_req->pg_len = len;
		assert(buf == NULL);	/* block only */
	} else {
		bl_put_req->type = BLOB_TYPE_BLOCK;
		op->req.iov.buf = buf;
		op->req.iov.buf_len = len;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
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
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (op->req.blob_get.len > 0) {
		ret = asprintf(&hdr_str, "x-ms-range: bytes=%lu-%lu",
			       op->req.blob_get.off,
			       (op->req.blob_get.off + op->req.blob_get.len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	if (strcmp(op->req.blob_get.type, BLOB_TYPE_PAGE) == 0) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-blob-type: PageBlob");
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-blob-type: BlockBlob");
	}
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @len is zero then ignore @off and retrieve entire blob
 */
int
azure_op_blob_get(const char *account,
		  const char *container,
		  const char *bname,
		  bool is_page,
		  uint64_t off,
		  uint64_t len,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_blob_get *get_req;

	/* check for correct alignment */
	if (is_page && (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (is_page && (((off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != off)) {
		ret = -EINVAL;
		goto err_out;
	}

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
		goto err_free_account;
	}

	get_req->bname = strdup(bname);
	if (get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (is_page) {
		get_req->type = BLOB_TYPE_PAGE;
	} else {
		get_req->type = BLOB_TYPE_BLOCK;
	}
	if (len > 0) {
		/* retrieve a specific range */
		get_req->off = off;
		get_req->len = len;
	}
	/* recv buffer allocated by conn layer */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}

	/* mandatory headers */
	ret = azure_op_blob_get_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_free_bname:
	free(get_req->bname);
err_free_container:
	free(get_req->container);
err_free_account:
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
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = asprintf(&hdr_str, "x-ms-range: bytes=%lu-%lu",
		       op->req.page_put.off,
		       (op->req.page_put.off + op->req.page_put.len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (op->req.page_put.clear_data) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-page-write: clear");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-page-write: update");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					 "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

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
		op->req.iov.buf = buf;
		op->req.iov.buf_len = len;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
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
azure_rsp_error_free(struct azure_rsp_error *err)
{
	free(err->msg);
}

/*
 * Check whether @err_code represents an azure error response. Nothing opcode
 * specific yet.
 */
static bool
azure_rsp_is_error(int opcode, int err_code)
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
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	if (op->rsp.err_code == 0) {
		return 0;
	}

	ret = azure_xml_slurp(false, op->rsp.iov.buf, op->rsp.iov.off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	ret = azure_xml_get_path(xp_ctx, "/Error/Message", NULL,
				 &op->rsp.err.msg);
	if (ret < 0) {
		goto err_xml_free;
	}
	printf("got error msg: %s\n", op->rsp.err.msg);
	ret = 0;

err_xml_free:
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_free(struct azure_op *op)
{
	free(op->req.iov.buf);
	switch (op->opcode) {
	case AOP_MGMT_GET_SA_KEYS:
		azure_req_mgmt_get_sa_keys_free(&op->req.mgmt_get_sa_keys);
		break;
	case AOP_CONTAINER_LIST:
		azure_req_ctnr_list_free(&op->req.ctnr_list);
		break;
	case AOP_CONTAINER_CREATE:
		azure_req_ctnr_create_free(&op->req.ctnr_create);
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
	default:
		assert(true);
		break;
	};
}

static void
azure_rsp_free(struct azure_op *op)
{
	free(op->rsp.iov.buf);
	if (azure_rsp_is_error(op->opcode, op->rsp.err_code)) {
		/* error response only, no aop data */
		azure_rsp_error_free(&op->rsp.err);
		return;
	}

	switch (op->opcode) {
	case AOP_MGMT_GET_SA_KEYS:
		azure_rsp_mgmt_get_sa_keys_free(&op->rsp.mgmt_get_sa_keys);
		break;
	case AOP_CONTAINER_LIST:
		azure_rsp_ctnr_list_free(&op->rsp.ctnr_list);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
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
	/* CURLOPT_HTTPHEADER must be cleared before doing this */
	curl_slist_free_all(op->http_hdr);
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
	if (azure_rsp_is_error(op->opcode, op->rsp.err_code)) {
		/* error response only */
		return azure_rsp_error_process(op);
	}

	switch (op->opcode) {
	case AOP_MGMT_GET_SA_KEYS:
		ret = azure_rsp_mgmt_get_sa_keys_process(op);
		break;
	case AOP_CONTAINER_LIST:
		ret = azure_rsp_ctnr_list_process(op);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(true);
		break;
	};

	return ret;
}

