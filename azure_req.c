/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
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
azure_req_mgmt_url_list_sas(const char *sub_id)
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
azure_req_mgmt_url_get_sa_props(const char *sub_id, const char *service_name)
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
azure_req_mgmt_url_check_sa_availability(const char *sub_id, const char *service_name)
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
azure_req_mgmt_get_sa_keys_free(struct azure_mgmt_get_sa_keys *get_sa_keys)
{
	free(get_sa_keys->in.sub_id);
	free(get_sa_keys->in.service_name);
	free(get_sa_keys->out.primary);
	free(get_sa_keys->out.secondary);
}

static int
azure_req_mgmt_get_sa_keys_fill_hdr(struct azure_req *req)
{
	req->http_hdr = curl_slist_append(req->http_hdr,
					  "x-ms-version: 2012-03-01");
	if (req->http_hdr == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int
azure_req_mgmt_get_sa_keys_init(const char *sub_id,
				const char *service_name,
			        struct azure_req *req)
{
	int ret;
	struct azure_mgmt_get_sa_keys *get_sa_keys;

	/* TODO input validation */

	req->op = AOP_MGMT_GET_SA_KEYS;
	get_sa_keys = &req->mgmt_get_sa_keys;

	/* we may not need to keep these, as they're only used in the URL */
	get_sa_keys->in.sub_id = strdup(sub_id);
	if (get_sa_keys->in.sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	get_sa_keys->in.service_name = strdup(service_name);
	if (get_sa_keys->in.service_name == NULL) {
		ret = -ENOMEM;
		goto err_free_sub;
	}
	req->method = REQ_METHOD_GET;
	ret = asprintf(&req->url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s/keys",
		       sub_id, service_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_svc;
	}

	/* allocate response buffer, TODO determine appropriate size */
	req->iov.buf_len = (1024 * 1024);
	req->iov.buf = malloc(req->iov.buf_len);
	if (req->iov.buf == NULL) {
		ret = -ENOMEM;
		goto err_free_url;
	}

	ret = azure_req_mgmt_get_sa_keys_fill_hdr(req);
	if (ret < 0) {
		goto err_free_buf;
	}

	return 0;
err_free_buf:
	free(req->iov.buf);
err_free_url:
	free(req->url);
err_free_svc:
	free(get_sa_keys->in.service_name);
err_free_sub:
	free(get_sa_keys->in.sub_id);
err_out:
	return ret;
}

int
azure_req_mgmt_get_sa_keys_rsp(struct azure_req *req)
{
	int ret;
	struct azure_mgmt_get_sa_keys *get_sa_keys;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	/* parse response */
	ret = azure_xml_slurp(req->iov.buf, req->iov.off, &xp_doc, &xp_ctx);
	if (ret < 0) {
		return ret;
	}

	assert(req->op == AOP_MGMT_GET_SA_KEYS);
	get_sa_keys = &req->mgmt_get_sa_keys;

	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Primary",
		&get_sa_keys->out.primary);
	if (ret < 0) {
		xmlXPathFreeContext(xp_ctx);
		xmlFreeDoc(xp_doc);
		return ret;
	}
	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Secondary",
		&get_sa_keys->out.secondary);

	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);

	return ret;
}

static void
azure_req_ctnr_list_free(struct azure_ctnr_list *ctnr_list_req)
{
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;
	free(ctnr_list_req->in.account);

	list_for_each_safe(&ctnr_list_req->out.ctnrs, ctnr, ctnr_n, list) {
		free(ctnr);
	}
}

static int
azure_req_ctnr_list_fill_hdr(struct azure_req *req)
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
	req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
	free(hdr_str);
	if (req->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	req->http_hdr = curl_slist_append(req->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (req->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_req_ctnr_list(const char *account,
		    struct azure_req *req)
{

	int ret;
	struct azure_ctnr_list *ctnr_list_req;

	/* TODO input validation */

	req->op = AOP_CONTAINER_LIST;
	ctnr_list_req = &req->ctnr_list;

	ctnr_list_req->in.account = strdup(account);
	if (ctnr_list_req->in.account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	req->method = REQ_METHOD_GET;
	ret = asprintf(&req->url,
		       "https://%s.blob.core.windows.net/?comp=list",
		       account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	azure_req_ctnr_list_fill_hdr(req);
	/* the connection layer must sign this request before sending */
	req->sign = true;

	/* allocate response buffer, TODO determine appropriate size */
	req->iov.buf_len = (1024 * 1024);
	req->iov.buf = malloc(req->iov.buf_len);
	if (req->iov.buf == NULL) {
		ret = -ENOMEM;
		goto err_url_free;
	}

	list_head_init(&ctnr_list_req->out.ctnrs);

	return 0;

err_url_free:
	free(req->url);
err_acc_free:
	free(ctnr_list_req->in.account);
err_out:
	return ret;
}

/* TODO unmarshall ctnr list response */

static void
azure_req_blob_put_free(struct azure_blob_put *put_req)
{
	free(put_req->in.account);
	free(put_req->in.container);
	free(put_req->in.bname);
}

static int
azure_req_blob_put_fill_hdr(struct azure_req *req)
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
	req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
	free(hdr_str);
	if (req->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "Content-Length: %lu", req->iov.buf_len);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
	free(hdr_str);
	if (req->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (strcmp(req->blob_put.in.type, BLOB_TYPE_PAGE) == 0) {
		req->http_hdr = curl_slist_append(req->http_hdr,
						  "x-ms-blob-type: PageBlob");
		if (req->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = asprintf(&hdr_str, "x-ms-blob-content-length: %lu",
			       req->blob_put.in.content_len_bytes);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
		free(hdr_str);
		if (req->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		req->http_hdr = curl_slist_append(req->http_hdr,
						  "x-ms-blob-type: BlockBlob");
		if (req->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}
	/* different to the version in management */
	req->http_hdr = curl_slist_append(req->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (req->http_hdr == NULL) {
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
azure_req_blob_put_init(const char *account,
			const char *container,
			const char *bname,
			bool is_page,
			uint64_t content_len_bytes,
			uint8_t *buf,
			uint64_t len,
			struct azure_req *req)
{
	int ret;
	struct azure_blob_put *put_req;

	/* TODO input validation */
	if (is_page
	 && (((content_len_bytes / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ)
						!= content_len_bytes)) {
		ret = -EINVAL;
		goto err_out;
	}

	req->op = AOP_BLOB_PUT;
	put_req = &req->blob_put;

	put_req->in.account = strdup(account);
	if (put_req->in.account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (container == NULL) {
		put_req->in.container = NULL;
	} else {
		put_req->in.container = strdup(container);
		if (put_req->in.container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	put_req->in.bname = strdup(bname);
	if (put_req->in.bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (is_page) {
		put_req->in.type = BLOB_TYPE_PAGE;
		put_req->in.content_len_bytes = content_len_bytes;
		assert(buf == NULL);	/* block only */
	} else {
		put_req->in.type = BLOB_TYPE_BLOCK;
		assert(content_len_bytes == 0);	/* page only */
		req->iov.buf = buf;
		req->iov.buf_len = len;
	}

	req->method = REQ_METHOD_PUT;
	if (container == NULL) {
		ret = asprintf(&req->url,
			       "https://%s.blob.core.windows.net/%s",
			       account, bname);
	} else {
		/* http://myaccount.blob.core.windows.net/mycontainer/myblob */
		ret = asprintf(&req->url,
			       "https://%s.blob.core.windows.net/%s/%s",
			       account, container, bname);
	}
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}

	/* mandatory headers */
	ret = azure_req_blob_put_fill_hdr(req);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	req->sign = true;

	return 0;
err_free_url:
	free(req->url);
err_free_bname:
	free(put_req->in.bname);
err_free_container:
	free(put_req->in.container);
err_free_account:
	free(put_req->in.account);
err_out:
	return ret;
}

/* Free and zero request data */
void
azure_req_free(struct azure_req *req)
{
	/* CURLOPT_HTTPHEADER must be cleared before doing this */
	curl_slist_free_all(req->http_hdr);

	free(req->iov.buf);
	free(req->sig_src);
	free(req->url);
	switch (req->op) {
	case AOP_MGMT_GET_SA_KEYS:
		azure_req_mgmt_get_sa_keys_free(&req->mgmt_get_sa_keys);
		break;
	case AOP_CONTAINER_LIST:
		azure_req_ctnr_list_free(&req->ctnr_list);
		break;
	case AOP_BLOB_PUT:
		azure_req_blob_put_free(&req->blob_put);
		break;
	};
	memset(req, 0, sizeof(*req));
}

