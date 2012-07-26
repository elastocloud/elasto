/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

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

static void
azure_req_mgmt_get_sa_keys_free(struct azure_mgmt_get_sa_keys *get_sa_keys)
{
	free(get_sa_keys->in.sub_id);
	free(get_sa_keys->in.service_name);
	xmlFree(get_sa_keys->out.primary);
	xmlFree(get_sa_keys->out.secondary);
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

	return 0;
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

/* does not free curl, allowing for connection reuse */
void
azure_req_free(struct azure_req *req)
{
	/* reset headers, so that the slist can be freed */
	curl_easy_setopt(req->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(req->http_hdr);

	free(req->iov.buf);
	free(req->signature);
	free(req->url);
	switch (req->op) {
	case AOP_MGMT_GET_SA_KEYS:
		azure_req_mgmt_get_sa_keys_free(&req->mgmt_get_sa_keys);
	};
}

