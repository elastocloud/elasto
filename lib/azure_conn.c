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
#include <unistd.h>

#include <curl/curl.h>

#include "../ccan/list/list.h"
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

	if (aconn->sign.key_len > 0) {
		free(aconn->sign.key);
		free(aconn->sign.account);
		aconn->sign.key_len = 0;
	}
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
	aconn->sign.key_len = 0;
err_out:
	return ret;
}

#define HDR_PFX_CLEN "Content-Length: "
/*
 * @hdr_str:	single non-null terminated header string.
 * @num_bytes:	length of @hdr_str.
 */
static int
curl_hdr_process(struct azure_op *op,
		 char *hdr_str,
		 uint64_t num_bytes)
{

	if (!strncmp(hdr_str, HDR_PFX_CLEN, sizeof(HDR_PFX_CLEN) - 1)) {
		int64_t clen;
		char *eptr;
		char *loff = hdr_str + sizeof(HDR_PFX_CLEN) - 1;

		if (op->rsp.data.type != AOP_DATA_NONE) {
			/* recv buf already allocated by request */
			return 0;
		}

		clen = strtoll(loff, &eptr, 10);
		if ((eptr == loff) || (eptr > hdr_str + num_bytes)) {
			return -1;
		}
		if (clen == 0) {
			return 0;
		}
		/* TODO check clen isn't too huge */
		op->rsp.data.buf = malloc(clen);
		if (op->rsp.data.buf == NULL) {
			return -1;
		}
		op->rsp.data.len = clen;
		op->rsp.data.iov.off = 0;
		op->rsp.data.type = AOP_DATA_IOV;
	}

	return 0;
}

static size_t
curl_hdr_cb(char *ptr,
	    size_t size,
	    size_t nmemb,
	    void *userdata)
{
	struct azure_op *op = (struct azure_op *)userdata;
	uint64_t num_bytes = (size * nmemb);
	int ret;

	ret = curl_hdr_process(op, ptr, num_bytes);
	if (ret < 0) {
		return 0;
	}

	return num_bytes;
}

static size_t
curl_read_cb(char *ptr,
	     size_t size,
	     size_t nmemb,
	     void *userdata)
{
	struct azure_op *op = (struct azure_op *)userdata;
	uint64_t num_bytes = (size * nmemb);
	uint64_t *off;

	if (op->req.data.type == AOP_DATA_IOV) {
		off = &op->req.data.iov.off;
	} else if (op->req.data.type == AOP_DATA_FILE) {
		off = &op->req.data.file.off;
	} else {
		return -1;	/* not yet supported */
	}
	if (*off + num_bytes > op->req.data.len) {
		printf("curl_read_cb buffer exceeded, "
		       "len %lu off %lu io_sz %lu, capping\n",
		       op->req.data.len, *off, num_bytes);
		num_bytes = op->req.data.len - *off;
	}

	if (op->req.data.type == AOP_DATA_IOV) {
		memcpy(ptr, (void *)(op->req.data.buf + *off), num_bytes);
	} else if (op->req.data.type == AOP_DATA_FILE) {
		ssize_t ret;
		ret = pread(op->req.data.file.fd, ptr, num_bytes, *off);
		if (ret != num_bytes) {
			printf("failed to read from file\n");
			return -1;
		}
	}
	*off += num_bytes;
	return num_bytes;
}

static size_t
curl_write_cb(char *ptr,
	      size_t size,
	      size_t nmemb,
	      void *userdata)
{
	struct azure_op *op = (struct azure_op *)userdata;
	uint64_t num_bytes = (size * nmemb);

	if (op->rsp.data.type != AOP_DATA_IOV) {
		return -1;	/* not yet supported */
	}
	if (op->rsp.data.iov.off + num_bytes > op->rsp.data.len) {
		printf("fatal: curl_write_cb buffer exceeded, "
		       "len %lu off %lu io_sz %lu\n",
		       op->rsp.data.len, op->rsp.data.iov.off, num_bytes);
		return -1;
	}

	memcpy((void *)(op->rsp.data.buf + op->rsp.data.iov.off), ptr,
	       num_bytes);
	op->rsp.data.iov.off += num_bytes;
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

/* a bit ugly, the signature src string is stored in @op for debugging */
static int
azure_conn_send_prepare(struct azure_conn *aconn, struct azure_op *op)
{
	int ret;
	char *hdr_str = NULL;

	curl_easy_setopt(aconn->curl, CURLOPT_CUSTOMREQUEST, op->method);
	curl_easy_setopt(aconn->curl, CURLOPT_URL, op->url);
	curl_easy_setopt(aconn->curl, CURLOPT_HEADERFUNCTION, curl_hdr_cb);
	curl_easy_setopt(aconn->curl, CURLOPT_HEADERDATA, op);
	curl_easy_setopt(aconn->curl, CURLOPT_WRITEDATA, op);
	curl_easy_setopt(aconn->curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	if (strcmp(op->method, REQ_METHOD_GET) == 0) {
		curl_easy_setopt(aconn->curl, CURLOPT_HTTPGET, 1);
		curl_easy_setopt(aconn->curl, CURLOPT_UPLOAD, 0);
		curl_easy_setopt(aconn->curl, CURLOPT_INFILESIZE_LARGE, 0);
		curl_easy_setopt(aconn->curl, CURLOPT_READFUNCTION,
				 curl_fail_cb);
	} else if (strcmp(op->method, REQ_METHOD_PUT) == 0) {
		curl_easy_setopt(aconn->curl, CURLOPT_UPLOAD, 1);
		curl_easy_setopt(aconn->curl, CURLOPT_INFILESIZE_LARGE,
				 op->req.data.len);
		curl_easy_setopt(aconn->curl, CURLOPT_READDATA, op);
		curl_easy_setopt(aconn->curl, CURLOPT_READFUNCTION,
				 curl_read_cb);
		/* must be set for PUT, TODO ensure not already set */
		ret = asprintf(&hdr_str, "Content-Length: %lu", op->req.data.len);
		if (ret < 0) {
			return -ENOMEM;
		}
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			return -ENOMEM;
		}
	}

	if (op->sign) {
		char *sig_str;
		assert(aconn->sign.key != NULL);
		ret = azure_sign_gen_lite(aconn->sign.account,
					  aconn->sign.key, aconn->sign.key_len,
					  op, &op->sig_src, &sig_str);
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
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			return -ENOMEM;
		}
	}

	curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, op->http_hdr);

	/* TODO remove this later */
	curl_easy_setopt(aconn->curl, CURLOPT_VERBOSE, 1);

	return 0;	/* FIXME detect curl_easy_setopt errors */
}

int
azure_conn_send_op(struct azure_conn *aconn,
		   struct azure_op *op)
{
	int ret;
	CURLcode res;

	op->aconn = aconn;
	ret = azure_conn_send_prepare(aconn, op);
	if (ret < 0) {
		op->aconn = NULL;
		return ret;
	}

	/* dispatch */
	res = curl_easy_perform(aconn->curl);
	if (res != CURLE_OK) {
		printf("curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, NULL);
		op->aconn = NULL;
		return -EBADF;
	}

	curl_easy_getinfo(aconn->curl, CURLINFO_RESPONSE_CODE, &op->rsp.err_code);

	/* reset headers, so that op->http_hdr can be freed */
	curl_easy_setopt(aconn->curl, CURLOPT_HTTPHEADER, NULL);
	op->aconn = NULL;

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
	if (aconn->sign.key_len > 0) {
		free(aconn->sign.key);
		free(aconn->sign.account);
	}
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
