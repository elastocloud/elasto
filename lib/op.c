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

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "data_api.h"
#include "op.h"

static int
op_hdr_add(struct list_head *hdrs,
	   const char *key,
	   const char *val)
{
	int ret;
	struct op_hdr *hdr = malloc(sizeof(*hdr));
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
op_req_hdr_add(struct op *op,
	       const char *key,
	       const char *val)
{
	int ret = op_hdr_add(&op->req.hdrs, key, val);
	if (ret < 0) {
		return ret;
	}
	op->req.num_hdrs++;
	dbg(4, "added req hdr(%u): \"%s: %s\"\n", op->req.num_hdrs, key, val);

	return 0;
}

int
op_rsp_hdr_add(struct op *op,
	       const char *key,
	       const char *val)
{
	int ret = op_hdr_add(&op->rsp.hdrs, key, val);
	if (ret < 0) {
		return ret;
	}
	op->rsp.num_hdrs++;
	dbg(4, "added rsp hdr(%u): \"%s: %s\"\n", op->rsp.num_hdrs, key, val);

	return 0;
}

int
op_hdr_val_lookup(struct list_head *hdrs,
		  const char *key,
		  char **_val)
{
	struct op_hdr *hdr;

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

int
op_hdr_u64_val_lookup(struct list_head *hdrs,
		      const char *key,
		      uint64_t *_val)
{
	int ret;
	char *sval;
	char *sval_end;
	uint64_t val;

	ret = op_hdr_val_lookup(hdrs, key, &sval);
	if (ret < 0) {
		return ret;
	}

	val = strtoull(sval, &sval_end, 10);
	if (sval_end == sval) {
		dbg(0, "non-numeric at %s: %s\n",
		    key, sval);
		return -EINVAL;
	}
	*_val = val;

	return 0;
}

static int
op_hdr_del(struct list_head *hdrs,
	   const char *key)
{
	struct op_hdr *hdr;

	list_for_each(hdrs, hdr, list) {
		if (strcmp(hdr->key, key) == 0) {
			list_del_from(hdrs, &hdr->list);
			free(hdr->key);
			free(hdr->val);
			free(hdr);
			return 0;
		}
	}

	return -ENOENT;
}

static int
op_req_hdr_del(struct op *op,
	       const char *key)
{
	int ret = op_hdr_del(&op->req.hdrs, key);
	if (ret < 0) {
		return ret;
	}
	op->req.num_hdrs--;
	dbg(4, "deleted req hdr(%u): \"%s\"\n", op->req.num_hdrs, key);

	return 0;
}

void
op_hdrs_free(struct list_head *hdrs)
{
	struct op_hdr *hdr;
	struct op_hdr *hdr_n;

	list_for_each_safe(hdrs, hdr, hdr_n, list) {
		free(hdr->key);
		free(hdr->val);
		free(hdr);
	}
}

/* initialize a pre-zeroed op structure */
void
op_init(int opcode,
	struct op *op)
{
	list_head_init(&op->req.hdrs);
	list_head_init(&op->rsp.hdrs);
	op->opcode = opcode;
}

static void
op_rsp_error_free(struct op_rsp_error *err)
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
op_rsp_is_error(int opcode, int err_code)
{
	if (err_code == 0) {
		return false;
	} else if ((err_code >= 200) && (err_code < 300)) {
		return false;
	}
	return true;
}

static void
op_req_free(struct op *op)
{
	op_hdrs_free(&op->req.hdrs);
	elasto_data_free(op->req.data);
	op->req_free(op);
}

static void
op_rsp_free(struct op *op)
{
	op_hdrs_free(&op->rsp.hdrs);
	elasto_data_free(op->rsp.data);

	if (op->rsp.is_error) {
		/* error response only, no aop data */
		op_rsp_error_free(&op->rsp.err);
		return;
	}

	free(op->rsp.req_id);
	op->rsp_free(op);
}

void
op_free(struct op *op)
{
	free(op->sig_src);
	free(op->url_host);
	free(op->url_path);
	op_req_free(op);
	op_rsp_free(op);
	op->ebo_free(op);
}

/*
 * Process error response and return 0, or -EAGAIN in the case of a redirect.
 * Error information is stored under op->rsp.err.
 */
static int
op_rsp_error_process(struct op *op)
{
	int ret;
	struct xml_doc *xdoc;
	bool got_err_msg = false;

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

	ret = exml_slurp((const char *)op->rsp.err.buf, op->rsp.err.off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "/Error/Message", false,
			    &op->rsp.err.msg, &got_err_msg);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	if (op->rsp.err_code == 307) {
		/* temporary redirect, fill location */
		ret = exml_str_want(xdoc, "/Error/Endpoint", true,
				    &op->rsp.err.redir_endpoint, NULL);
	}

	ret = exml_parse(xdoc);
	if (ret == -ENOENT) {
		dbg(1, "got redirect response without endpoint\n");
		goto err_msg_free;
	} else if (ret < 0) {
		goto err_msg_free;
	}

	ret = 0;
	if (!got_err_msg) {
		/* data attached, but no error description XML */
		op->rsp.err.msg = strdup("no error description");
		if (op->rsp.err.msg == NULL) {
			ret = -ENOMEM;
			goto err_xdoc_free;
		}
	}
	if (op->rsp.err_code == 307) {
		dbg(3, "redirect response endpoint: %s\n",
		    op->rsp.err.redir_endpoint);
		/* EAGAIN implies resend with redirect */
		ret = -EAGAIN;
	} else if (got_err_msg) {
		dbg(0, "got error msg: %s\n", op->rsp.err.msg);
	}

	exml_free(xdoc);
	return ret;

err_msg_free:
	free(op->rsp.err.msg);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

int
op_req_redirect(struct op *op)
{
	struct elasto_data *data;

	if (!op->rsp.is_error || (op->rsp.err_code != 307)) {
		dbg(0, "no redirect response for op\n");
		return -EINVAL;
	}
	if (op->rsp.err.redir_endpoint == NULL) {
		dbg(0, "no endpoint for redirect\n");
		return -EFAULT;
	}

	dbg(1, "redirecting %d request from %s to %s\n",
	    op->opcode, op->url_host, op->rsp.err.redir_endpoint);
	free(op->url_host);
	op->url_host = op->rsp.err.redir_endpoint;
	op->rsp.err.redir_endpoint = NULL;

	if (op->req_sign != NULL) {
		int ret;
		/*
		 * Remove existing auth hdr added by conn layer
		 */
		ret = op_req_hdr_del(op, "Authorization");
		if (ret < 0) {
			dbg(0, "no auth header for redirected req\n");
		}
	}

	/* save rsp data buffer */
	data = op->rsp.data;
	op->rsp.data = NULL;
	op_rsp_free(op);
	memset(&op->rsp, 0, sizeof(op->rsp));
	list_head_init(&op->rsp.hdrs);
	op->rsp.data = data;
	op->redirs++;

	return 0;
}

/*
 * unmarshall response data
 */
int
op_rsp_process(struct op *op)
{
	int ret;

	if (op->rsp.is_error) {
		/* set by conn layer, error response only */
		return op_rsp_error_process(op);
	}

	ret = op->rsp_process(op);
	return ret;
}
