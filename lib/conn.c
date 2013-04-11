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

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "azure_req.h"
#include "sign.h"
#include "conn.h"

/* convert base64 encoded key to binary and store in @econn */
int
elasto_conn_sign_setkey(struct elasto_conn *econn,
			const char *account,
			const char *key_b64)
{
	int ret;

	/* signing keys for S3 are set on econn initialisation */
	assert(econn->type == CONN_TYPE_AZURE);

	if (econn->sign.key_len > 0) {
		free(econn->sign.key);
		free(econn->sign.account);
		econn->sign.key_len = 0;
	}
	econn->sign.key = malloc(strlen(key_b64));
	if (econn->sign.key == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	econn->sign.account = strdup(account);
	if (econn->sign.account == NULL) {
		ret = -ENOMEM;
		goto err_key_free;
	}

	ret = base64_decode(key_b64, econn->sign.key);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_acc_free;
	}
	econn->sign.key_len = ret;
	dbg(1, "set account %s signing key: %s\n", account, key_b64);

	return 0;

err_acc_free:
	free(econn->sign.account);
err_key_free:
	free(econn->sign.key);
	econn->sign.key_len = 0;
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

		clen = strtoll(loff, &eptr, 10);
		if ((eptr == loff) || (eptr > hdr_str + num_bytes)) {
			return -1;
		}

		/* allocate recv buffer in write callback */
		op->rsp.clen_recvd = true;
		op->rsp.clen = clen;
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
	uint64_t read_off;

	if ((op->req.data == NULL)
	 || ((op->req.data->type != AOP_DATA_IOV)
	      && (op->req.data->type != AOP_DATA_FILE))) {
		return -1;	/* unsupported */
	}

	op->req.read_cbs++;
	read_off = op->req.data->base_off + op->req.data->off;
	if (op->req.data->off + num_bytes > op->req.data->len) {
		dbg(3, "curl_read_cb buffer exceeded, "
		       "len %lu off %lu io_sz %lu, capping\n",
		       op->req.data->len, op->req.data->off, num_bytes);
		num_bytes = op->req.data->len - op->req.data->off;
	}

	if (op->req.data->type == AOP_DATA_IOV) {
		memcpy(ptr, (void *)(op->req.data->buf + read_off), num_bytes);
	} else if (op->req.data->type == AOP_DATA_FILE) {
		ssize_t ret;
		ret = pread(op->req.data->file.fd, ptr, num_bytes, read_off);
		if (ret != num_bytes) {
			dbg(0, "failed to read from file\n");
			return -1;
		}
	}
	op->req.data->off += num_bytes;
	return num_bytes;
}

static int
curl_write_alloc_err(struct azure_op *op)
{
	op->rsp.err.buf = malloc(op->rsp.clen);
	if (op->rsp.err.buf == NULL) {
		return -ENOMEM;
	}
	op->rsp.err.len = op->rsp.clen;
	op->rsp.err.off = 0;
	return 0;
}

static int
curl_write_alloc_std(struct azure_op *op)
{
	uint64_t clen = op->rsp.clen;

	if (op->rsp.data == NULL) {
		int ret;
		/* requester wants us to allocate a recv iov */
		/* TODO check clen isn't too huge */
		ret = azure_op_data_iov_new(NULL, clen, 0, true, &op->rsp.data);
		return ret;
	}

	switch (op->rsp.data->type) {
	case AOP_DATA_IOV:
		if (clen + op->rsp.data->base_off > op->rsp.data->len) {
			dbg(0, "preallocated rsp buf not large enough - "
			       "alloced=%lu, clen=%lu\n",
			       op->rsp.data->len, clen);
			return -E2BIG;
		}
		break;
	case AOP_DATA_FILE:
		op->rsp.data->len = clen + op->rsp.data->base_off;
		/* TODO, could fallocate entire file */
		break;
	default:
		assert(true);
		break;
	}

	return 0;
}

static int
curl_write_err(struct azure_op *op,
	       uint8_t *data,
	       uint64_t num_bytes)
{
	if (op->rsp.err.off + num_bytes > op->rsp.err.len) {
		dbg(0, "fatal: error rsp buffer exceeded, "
		       "len %lu off %lu io_sz %lu\n",
		       op->rsp.err.len, op->rsp.err.off, num_bytes);
		return -E2BIG;
	}
	memcpy((void *)(op->rsp.err.buf + op->rsp.err.off), data,
	       num_bytes);
	op->rsp.err.off += num_bytes;

	return 0;
}

static int
curl_write_std(struct azure_op *op,
	       uint8_t *data,
	       uint64_t num_bytes)
{
	int ret;
	uint64_t write_off = op->rsp.data->base_off + op->rsp.data->off;

	/* rsp buffer must have been allocated */
	assert(op->rsp.data != NULL);

	switch (op->rsp.data->type) {
	case AOP_DATA_IOV:
		if (write_off + num_bytes > op->rsp.data->len) {
			dbg(0, "fatal: curl_write_cb buffer exceeded, "
			       "len %lu off %lu io_sz %lu\n",
			       op->rsp.data->len, write_off, num_bytes);
			return -E2BIG;
		}
		memcpy((void *)(op->rsp.data->buf + write_off), data, num_bytes);
		break;
	case AOP_DATA_FILE:
		if (write_off + num_bytes > op->rsp.data->len) {
			dbg(0, "fatal: curl_write_cb file exceeded, "
			       "len %lu off %lu io_sz %lu\n",
			       op->rsp.data->len, write_off, num_bytes);
			return -E2BIG;
		}
		ret = pwrite(op->rsp.data->file.fd, data, num_bytes, write_off);
		if (ret != num_bytes) {
			dbg(0, "file write io failed: %s\n", strerror(errno));
			return -EBADF;
		}
		break;
	default:
		assert(true);
		break;
	}
	op->rsp.data->off += num_bytes;
	return 0;
}

static size_t
curl_write_cb(char *ptr,
	      size_t size,
	      size_t nmemb,
	      void *userdata)
{
	struct azure_op *op = (struct azure_op *)userdata;
	uint64_t num_bytes = (size * nmemb);
	int ret;

	if (op->rsp.write_cbs++ == 0) {
		CURLcode cc;
		int ret_code;
		/* should already have the http response code by the time we get here */
		cc = curl_easy_getinfo(op->econn->curl, CURLINFO_RESPONSE_CODE,
				       &ret_code);
		if (cc != CURLE_OK) {
			dbg(0, "could not get response code in write cb\n");
			return -1;
		}

		op->rsp.err_code = ret_code;
		op->rsp.is_error = azure_rsp_is_error(op->opcode, ret_code);

		if (op->rsp.is_error) {
			ret = curl_write_alloc_err(op);
		} else {
			ret = curl_write_alloc_std(op);
		}
		if (ret < 0) {
			dbg(0, "failed to allocate response buffer\n");
			return -1;
		}

	}

	if (op->rsp.is_error) {
		ret = curl_write_err(op, (uint8_t *)ptr, num_bytes);
	} else {
		ret = curl_write_std(op, (uint8_t *)ptr, num_bytes);
	}
	if (ret < 0) {
		return -1;
	}
	return num_bytes;
}

static size_t
curl_fail_cb(char *ptr,
	     size_t size,
	     size_t nmemb,
	     void *userdata)
{
	dbg(0, "Failure: server body data when not expected!\n");
	return 0;
}

static int
elasto_conn_send_sign(struct elasto_conn *econn,
		      struct azure_op *op)
{
	int ret;
	char *sig_str;
	char *hdr_str = NULL;

	if (econn->sign.key == NULL) {
		dbg(0, "op requires signing, but conn key not set\n");
		return -EINVAL;
	}

	if (econn->type == CONN_TYPE_AZURE) {
		ret = sign_gen_lite_azure(econn->sign.account,
					  econn->sign.key, econn->sign.key_len,
					  op, &op->sig_src, &sig_str);
		if (ret < 0) {
			dbg(0, "Azure signing failed: %s\n",
			    strerror(-ret));
			return ret;
		}
		ret = asprintf(&hdr_str, "Authorization: SharedKeyLite %s:%s",
			       econn->sign.account, sig_str);
		free(sig_str);
		if (ret < 0) {
			return -ENOMEM;
		}
	} else if (econn->type == CONN_TYPE_S3) {
		ret = sign_gen_s3(econn->sign.key, econn->sign.key_len,
				  op, &op->sig_src, &sig_str);
		if (ret < 0) {
			dbg(0, "S3 signing failed: %s\n",
			    strerror(-ret));
			return ret;
		}
		ret = asprintf(&hdr_str, "Authorization: AWS %s:%s",
			       econn->sign.account, sig_str);
		free(sig_str);
		if (ret < 0) {
			return -ENOMEM;
		}
	} else {
		return -ENOTSUP;
	}

	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}

	return 0;
}

/* a bit ugly, the signature src string is stored in @op for debugging */
static int
elasto_conn_send_prepare(struct elasto_conn *econn, struct azure_op *op)
{
	int ret;

	curl_easy_setopt(econn->curl, CURLOPT_CUSTOMREQUEST, op->method);
	curl_easy_setopt(econn->curl, CURLOPT_URL, op->url);
	curl_easy_setopt(econn->curl, CURLOPT_HEADERFUNCTION, curl_hdr_cb);
	curl_easy_setopt(econn->curl, CURLOPT_HEADERDATA, op);
	curl_easy_setopt(econn->curl, CURLOPT_WRITEDATA, op);
	curl_easy_setopt(econn->curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	if (strcmp(op->method, REQ_METHOD_GET) == 0) {
		curl_easy_setopt(econn->curl, CURLOPT_HTTPGET, 1);
		curl_easy_setopt(econn->curl, CURLOPT_UPLOAD, 0);
		curl_easy_setopt(econn->curl, CURLOPT_INFILESIZE_LARGE, 0);
		curl_easy_setopt(econn->curl, CURLOPT_READFUNCTION,
				 curl_fail_cb);
	} else if ((strcmp(op->method, REQ_METHOD_PUT) == 0)
				|| (strcmp(op->method, REQ_METHOD_POST) == 0)) {
		uint64_t len = (op->req.data ? op->req.data->len : 0);
		/* INFILESIZE_LARGE sets Content-Length hdr */
		curl_easy_setopt(econn->curl, CURLOPT_INFILESIZE_LARGE, len);
		curl_easy_setopt(econn->curl, CURLOPT_UPLOAD, 1);
		curl_easy_setopt(econn->curl, CURLOPT_READDATA, op);
		curl_easy_setopt(econn->curl, CURLOPT_READFUNCTION,
				 curl_read_cb);
	}

	if (op->sign) {
		ret = elasto_conn_send_sign(econn, op);
		if (ret < 0) {
			return ret;
		}
	}

	curl_easy_setopt(econn->curl, CURLOPT_HTTPHEADER, op->http_hdr);

	return 0;	/* FIXME detect curl_easy_setopt errors */
}

int
elasto_conn_send_op(struct elasto_conn *econn,
		   struct azure_op *op)
{
	int ret;
	CURLcode res;

	op->econn = econn;
	ret = elasto_conn_send_prepare(econn, op);
	if (ret < 0) {
		op->econn = NULL;
		return ret;
	}

	/* dispatch */
	res = curl_easy_perform(econn->curl);
	if (res != CURLE_OK) {
		dbg(0, "curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		curl_easy_setopt(econn->curl, CURLOPT_HTTPHEADER, NULL);
		op->econn = NULL;
		return -EBADF;
	}

	if (op->rsp.write_cbs == 0) {
		/* write callback already sets this, otherwise still needed */
		curl_easy_getinfo(econn->curl, CURLINFO_RESPONSE_CODE,
				  &op->rsp.err_code);
		op->rsp.is_error = azure_rsp_is_error(op->opcode,
						      op->rsp.err_code);
	}

	/* reset headers, so that op->http_hdr can be freed */
	curl_easy_setopt(econn->curl, CURLOPT_HTTPHEADER, NULL);
	op->econn = NULL;

	return 0;
}

static int
elasto_conn_init_common(struct elasto_conn **econn_out)
{
	uint32_t debug_level;
	struct elasto_conn *econn = malloc(sizeof(*econn));
	if (econn == NULL) {
		return -ENOMEM;
	}

	econn->curl = curl_easy_init();
	if (econn->curl == NULL) {
		free(econn);
		return -ENOMEM;
	}

	debug_level = dbg_level_get();
	if (debug_level > 2) {
		curl_easy_setopt(econn->curl, CURLOPT_VERBOSE, 1);
	}
	memset(&econn->sign, 0, sizeof(econn->sign));
	*econn_out = econn;

	return 0;
}

int
elasto_conn_init_az(const char *pem_file,
		    const char *pem_pw,
		    struct elasto_conn **econn_out)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_common(&econn);
	if (ret < 0) {
		return ret;
	}
	econn->type = CONN_TYPE_AZURE;
	curl_easy_setopt(econn->curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(econn->curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(econn->curl, CURLOPT_SSLCERT, pem_file);
	curl_easy_setopt(econn->curl, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(econn->curl, CURLOPT_SSLKEY, pem_file);
	if (pem_pw) {
		curl_easy_setopt(econn->curl, CURLOPT_KEYPASSWD, pem_pw);
	}
	*econn_out = econn;

	return 0;
}

/* signing keys are set immediately for S3 */
int
elasto_conn_init_s3(const char *id,
		    const char *secret,
		    struct elasto_conn **econn_out)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_common(&econn);
	if (ret < 0) {
		goto err_out;
	}
	econn->type = CONN_TYPE_S3;
	econn->sign.key = (uint8_t *)strdup(secret);
	if (econn->sign.key == NULL) {
		ret = -ENOMEM;
		goto err_conn_free;
	}
	econn->sign.key_len = strlen(secret);

	econn->sign.account = strdup(id);
	if (econn->sign.account == NULL) {
		ret = -ENOMEM;
		goto err_secret_free;
	}

	*econn_out = econn;

	return 0;

err_secret_free:
	free(econn->sign.key);
err_conn_free:
	free(econn);
err_out:
	return ret;
}

void
elasto_conn_free(struct elasto_conn *econn)
{
	curl_easy_cleanup(econn->curl);
	if (econn->sign.key_len > 0) {
		free(econn->sign.key);
		free(econn->sign.account);
	}
	free(econn);
}

int
elasto_conn_subsys_init(void)
{
	CURLcode res;

	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK)
		return -ENOMEM;

	sign_init();

	return 0;
}

void
elasto_conn_subsys_deinit(void)
{
	curl_global_cleanup();
	sign_deinit();
}
