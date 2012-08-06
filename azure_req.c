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

int
azure_op_mgmt_get_sa_keys_rsp(struct azure_op *op)
{
	int ret;
	struct azure_rsp_mgmt_get_sa_keys *get_sa_keys_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	/* parse response */
	ret = azure_xml_slurp(false, op->rsp.iov.buf, op->rsp.iov.off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		return ret;
	}

	assert(op->opcode == AOP_MGMT_GET_SA_KEYS);
	get_sa_keys_rsp = &op->rsp.mgmt_get_sa_keys;

	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Primary",
		NULL, &get_sa_keys_rsp->primary);
	if (ret < 0) {
		xmlXPathFreeContext(xp_ctx);
		xmlFreeDoc(xp_doc);
		return ret;
	}
	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Secondary",
		NULL, &get_sa_keys_rsp->secondary);

	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);

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

	ret = azure_op_ctnr_list_fill_hdr(op);
	if (ret < 0) {
		goto err_url_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_url_free:
	free(op->url);
err_acc_free:
	free(ctnr_list_req->account);
err_out:
	return ret;
}

int
azure_op_ctnr_list_rsp(struct azure_op *op)
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
			       op->req.blob_put.content_len_bytes);
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
 * @container may be NULL, in which case the root container is used.
 * @content_len_bytes only valid when @is_page is set, @buf and @len only valid
 * when @is_page is not set. */
int
azure_op_blob_put(const char *account,
		   const char *container,
		   const char *bname,
		   bool is_page,
		   uint64_t content_len_bytes,
		   uint8_t *buf,
		   uint64_t len,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_blob_put *put_req;

	/* TODO input validation */
	if (is_page
	 && (((content_len_bytes / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ)
						!= content_len_bytes)) {
		ret = -EINVAL;
		goto err_out;
	}

	op->opcode = AOP_BLOB_PUT;
	put_req = &op->req.blob_put;

	put_req->account = strdup(account);
	if (put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (container == NULL) {
		put_req->container = NULL;
	} else {
		put_req->container = strdup(container);
		if (put_req->container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	put_req->bname = strdup(bname);
	if (put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (is_page) {
		put_req->type = BLOB_TYPE_PAGE;
		put_req->content_len_bytes = content_len_bytes;
		assert(buf == NULL);	/* block only */
	} else {
		put_req->type = BLOB_TYPE_BLOCK;
		assert(content_len_bytes == 0);	/* page only */
		op->req.iov.buf = buf;
		op->req.iov.buf_len = len;
	}

	op->method = REQ_METHOD_PUT;
	if (container == NULL) {
		ret = asprintf(&op->url,
			       "https://%s.blob.core.windows.net/%s",
			       account, bname);
	} else {
		/* http://myaccount.blob.core.windows.net/mycontainer/myblob */
		ret = asprintf(&op->url,
			       "https://%s.blob.core.windows.net/%s/%s",
			       account, container, bname);
	}
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
	free(put_req->bname);
err_free_container:
	free(put_req->container);
err_free_account:
	free(put_req->account);
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
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-blob-type: BlockBlob");
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

int
azure_op_blob_get(const char *account,
		  const char *container,
		  const char *bname,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_blob_get *get_req;

	/* TODO input validation */

	op->opcode = AOP_BLOB_GET;
	get_req = &op->req.blob_get;

	get_req->account = strdup(account);
	if (get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (container == NULL) {
		get_req->container = NULL;
	} else {
		get_req->container = strdup(container);
		if (get_req->container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	get_req->bname = strdup(bname);
	if (get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	get_req->type = BLOB_TYPE_BLOCK;
	/* recv buffer allocated by conn layer */

	op->method = REQ_METHOD_GET;
	if (container == NULL) {
		ret = asprintf(&op->url,
			       "https://%s.blob.core.windows.net/%s",
			       account, bname);
	} else {
		/* http://myaccount.blob.core.windows.net/mycontainer/myblob */
		ret = asprintf(&op->url,
			       "https://%s.blob.core.windows.net/%s/%s",
			       account, container, bname);
	}
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
	};
}

static void
azure_rsp_free(struct azure_op *op)
{
	free(op->rsp.iov.buf);
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
		/* nothing to do */
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
