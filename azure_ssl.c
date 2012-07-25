/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
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

#include "azure_req.h"

CURL *
azure_ssl_curl_init(const char *pem_file, const char *pem_pw)
{
	CURL *curl;
	struct curl_slist *chunk = NULL;

	curl = curl_easy_init();
	if (curl == NULL) {
		return NULL;
	}

	chunk = curl_slist_append(chunk, "x-ms-version: 2012-03-01");
	if (chunk == NULL) {
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLCERT, pem_file);
	curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLKEY, pem_file);
	if (pem_pw) {
		curl_easy_setopt(curl, CURLOPT_KEYPASSWD, pem_pw);
	}
	/* XXX chunk cannot be freed yet */

	return curl;
}

size_t
curl_write_cb(char *ptr,
	      size_t size,
	      size_t nmemb,
	      void *userdata)
{
	struct azure_req *req = (struct azure_req *)userdata;
	uint64_t num_bytes = (size * nmemb);

	if (req->iov.off + num_bytes > req->iov.buf_len) {
		printf("fatal: curl_write_cb buffer exceeded, "
		       "len %lu off %lu io_sz %lu\n",
		       req->iov.buf_len, req->iov.off, num_bytes);
		return -1;
	}

	memcpy((void *)(req->iov.buf + req->iov.off), ptr, num_bytes);
	req->iov.off += num_bytes;
	return num_bytes;
}

int
azure_ssl_curl_req_setup(CURL *curl, struct azure_req *req)
{
	req->curl = curl;

	/* XXX we need to clear preset opts when reusing */
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
	curl_easy_setopt(curl, CURLOPT_URL, req->url);
	if (strcmp(req->method, REQ_METHOD_GET) == 0) {
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	}

	return 0;	/* FIXME detect curl_easy_setopt errors */
}

int main(void)
{
	CURLcode res;
	struct azure_req req;
	const char *pem_file = "privateKey.pem";
	const char *pem_pword = "disso";
	const char *subscriber_id = "9baf7f32-66ae-42ca-9ad7-220050765863";
	CURL *curl;
	int ret;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	xmlInitParser();

	memset(&req, 0, sizeof(req));

	curl = azure_ssl_curl_init(pem_file, pem_pword);
	if (curl == NULL) {
		ret = -EINVAL;
		goto err_global_clean;
	}

	ret = azure_req_mgmt_get_sa_keys_init(subscriber_id, "ddiss", &req);
	if (ret < 0) {
		goto err_easy_clean;
	}

	ret = azure_ssl_curl_req_setup(curl, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	/* dispatch */
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		printf("curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		ret = -EBADF;
		goto err_req_free;
	}

	ret = azure_req_mgmt_get_sa_keys_rsp(&req);
	if (ret < 0) {
		goto err_req_free;
	}

	printf("primary key: %s\n"
	       "secondary key: %s\n",
	       req.mgmt_get_sa_keys.out.primary,
	       req.mgmt_get_sa_keys.out.secondary);

	ret = 0;
err_req_free:
	azure_req_free(&req);
err_easy_clean:
	curl_easy_cleanup(curl);
err_global_clean:
	xmlCleanupParser();
	curl_global_cleanup();

	return ret;
}
