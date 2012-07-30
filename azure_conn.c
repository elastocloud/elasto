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

#include "ccan/list/list.h"
#include "base64.h"
#include "azure_req.h"
#include "azure_sign.h"
#include "azure_conn.h"

/* convert base64 encoded key to binary and store in @aconn */
int
azure_conn_sign_setkey(struct azure_conn *aconn,
		       const char *account,
		       const char *key_b64)
{
	int ret;

	free(aconn->sign.key);
	aconn->sign.key = malloc(strlen(key_b64));
	if (aconn->sign.key == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	aconn->sign.account = strdup(account);
	if (aconn->sign.account == NULL) {
		ret = -ENOMEM;
		goto err_key_free;
	}

	ret = base64_decode(key_b64, aconn->sign.key);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_acc_free;
	}
	aconn->sign.key_len = ret;

	return 0;

err_acc_free:
	free(aconn->sign.account);
err_key_free:
	free(aconn->sign.key);
	aconn->sign.key = NULL;
err_out:
	return ret;
}

static size_t
curl_read_cb(char *ptr,
	     size_t size,
	     size_t nmemb,
	     void *userdata)
{
	struct azure_req *req = (struct azure_req *)userdata;
	uint64_t num_bytes = (size * nmemb);

	if (req->iov.off + num_bytes > req->iov.buf_len) {
		printf("curl_read_cb buffer exceeded, "
		       "len %lu off %lu io_sz %lu, capping\n",
		       req->iov.buf_len, req->iov.off, num_bytes);
		num_bytes = num_bytes - req->iov.off;
	}

	memcpy(ptr, (void *)(req->iov.buf + req->iov.off), num_bytes);
	req->iov.off += num_bytes;
	return num_bytes;
}

static size_t
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

static size_t
curl_fail_cb(char *ptr,
	     size_t size,
	     size_t nmemb,
	     void *userdata)
{
	printf("Failure: server body data when not expected!\n");
	return 0;
}

/* a bit ugly, the signature src string is stored in @req for debugging */
static int
azure_conn_send_prepare(struct azure_conn *aconn, struct azure_req *req)
{
	int ret;
	char *hdr_str = NULL;

	curl_easy_setopt(aconn->curl, CURLOPT_CUSTOMREQUEST, req->method);
	curl_easy_setopt(aconn->curl, CURLOPT_URL, req->url);
	/* one-way xfers only so far */
	if (strcmp(req->method, REQ_METHOD_GET) == 0) {
		curl_easy_setopt(aconn->curl, CURLOPT_WRITEDATA, req);
		curl_easy_setopt(aconn->curl, CURLOPT_WRITEFUNCTION,
				 curl_write_cb);
		curl_easy_setopt(aconn->curl, CURLOPT_READFUNCTION,
				 curl_fail_cb);
	} else if (strcmp(req->method, REQ_METHOD_PUT) == 0) {
		curl_easy_setopt(aconn->curl, CURLOPT_UPLOAD, 1);
		curl_easy_setopt(aconn->curl, CURLOPT_INFILESIZE_LARGE,
				 req->iov.buf_len);
		curl_easy_setopt(aconn->curl, CURLOPT_READDATA, req);
		curl_easy_setopt(aconn->curl, CURLOPT_READFUNCTION,
				 curl_read_cb);
		curl_easy_setopt(aconn->curl, CURLOPT_WRITEFUNCTION,
				 curl_fail_cb);
		/* must be set for PUT, TODO ensure not already set */
		ret = asprintf(&hdr_str, "Content-Length: %lu", req->iov.buf_len);
		if (ret < 0) {
			return -ENOMEM;
		}
		req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
		free(hdr_str);
		if (req->http_hdr == NULL) {
			return -ENOMEM;
		}
		req->http_hdr = curl_slist_append(req->http_hdr, "Content-Type: text/plain; charset=UTF-8");
		if (req->http_hdr == NULL) {
			return -ENOMEM;
		}
	}

	if (req->sign) {
		char *sig_str;
		assert(aconn->sign.key != NULL);
		ret = azure_sign_gen_lite(aconn->sign.account,
					  aconn->sign.key, aconn->sign.key_len,
					  req, &req->sig_src, &sig_str);
		if (ret < 0) {
			printf("signing failed: %s\n", strerror(-ret));
			return ret;
		}
		ret = asprintf(&hdr_str, "Authorization: SharedKeyLite %s:%s",
			       aconn->sign.account, sig_str);
		free(sig_str);
		if (ret < 0) {
			return -ENOMEM;
		}
		req->http_hdr = curl_slist_append(req->http_hdr, hdr_str);
		free(hdr_str);
		if (req->http_hdr == NULL) {
			return -ENOMEM;
		}
	}

	curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, req->http_hdr);

	/* TODO remove this later */
	curl_easy_setopt(aconn->curl, CURLOPT_VERBOSE, 1);

	return 0;	/* FIXME detect curl_easy_setopt errors */
}

int
azure_conn_send_req(struct azure_conn *aconn,
		    struct azure_req *req)
{
	int ret;
	CURLcode res;

	ret = azure_conn_send_prepare(aconn, req);
	if (ret < 0) {
		return ret;
	}

	/* dispatch */
	res = curl_easy_perform(aconn->curl);
	if (res != CURLE_OK) {
		printf("curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, NULL);
		return -EBADF;
	}

	/* reset headers, so that req->http_hdr can be freed */
	curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, NULL);

	return 0;
}

int
azure_conn_init(const char *pem_file,
		const char *pem_pw,
		struct azure_conn *aconn)
{
	aconn->curl = curl_easy_init();
	if (aconn->curl == NULL) {
		return -ENOMEM;
	}

//	curl_easy_setopt(aconn->curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(aconn->curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(aconn->curl, CURLOPT_SSLCERT, pem_file);
	curl_easy_setopt(aconn->curl, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(aconn->curl, CURLOPT_SSLKEY, pem_file);
	if (pem_pw) {
		curl_easy_setopt(aconn->curl, CURLOPT_KEYPASSWD, pem_pw);
	}
	memset(&aconn->sign, 0, sizeof(aconn->sign));

	return 0;
}

void
azure_conn_free(struct azure_conn *aconn)
{
	curl_easy_cleanup(aconn->curl);
}

int
azure_conn_subsys_init(void)
{
	CURLcode res;

	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK)
		return -ENOMEM;

	azure_sign_init();

	return 0;
}

void
azure_conn_subsys_deinit(void)
{
	curl_global_cleanup();
	azure_sign_deinit();
}
