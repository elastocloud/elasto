/*
 * Copyright (C) SUSE LINUX GmbH 2012-2016, all rights reserved.
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
#ifndef _OP_H_
#define _OP_H_

struct op_hdr {
	struct list_node list;
	char *key;
	char *val;
};

/* error response buffer is separate to request/response data */
struct op_rsp_error {
	char *msg;
	uint8_t *buf;
	uint64_t len;
	uint64_t off;
	char *redir_endpoint;
};

enum op_req_method {
	REQ_METHOD_GET = 1,
	REQ_METHOD_PUT,
	REQ_METHOD_DELETE,
	REQ_METHOD_POST,
	REQ_METHOD_HEAD,
};

struct op;
typedef int (*req_sign_cb_t)(const char *acc,
			     const uint8_t *key,
			     int key_len,
			     struct op *op);
typedef void (*req_free_cb_t)(struct op *op);
typedef void (*rsp_free_cb_t)(struct op *op);
typedef int (*rsp_process_cb_t)(struct op *op);
typedef void (*ebo_free_cb_t)(struct op *op);

struct op {
	struct elasto_conn *econn;
	int opcode;
	char *sig_src;	/* debug, compare with signing error response */
	enum op_req_method method;
	bool url_https_only;	/* overrides conn insecure_http setting */
	char *url_host;
	char *url_path;
	int redirs;
	int retries;

	struct {
		uint64_t read_cbs;
		struct elasto_data *data;
		uint32_t num_hdrs;
		struct list_head hdrs;
		struct evhttp_request *ev_http;
	} req;

	struct {
		bool is_error;
		int32_t err_code;
		struct op_rsp_error err;
		char *req_id;
		bool clen_recvd;
		uint64_t clen;
		uint64_t write_cbs;
		struct elasto_data *data;
		bool recv_cb_alloced;	/* data buffer alloced by conn cb */
		uint32_t num_hdrs;
		struct list_head hdrs;
	} rsp;

	req_sign_cb_t req_sign;
	req_free_cb_t req_free;
	rsp_free_cb_t rsp_free;
	rsp_process_cb_t rsp_process;
	ebo_free_cb_t ebo_free;
};

void
op_init(int opcode,
	struct op *op);

int
op_req_hdr_add(struct op *op,
	       const char *key,
	       const char *val);

int
op_rsp_hdr_add(struct op *op,
	       const char *key,
	       const char *val);

int
op_hdr_val_lookup(struct list_head *hdrs,
		  const char *key,
		  char **_val);

int
op_hdr_u64_val_lookup(struct list_head *hdrs,
		      const char *key,
		      uint64_t *_val);

/* lookup and convert RFC 1123 format to time_t */
int
op_hdr_date_time_val_lookup(struct list_head *hdrs,
			    const char *key,
			    time_t *_val);

void
op_hdrs_free(struct list_head *hdrs);

bool
op_rsp_is_error(int opcode,
		int err_code);


bool
op_rsp_error_match(struct op *op,
		   int err_code);

int
op_req_redirect(struct op *op);

int
op_req_retry(struct op *op);

void
op_free(struct op *op);

int
op_rsp_process(struct op *op);

const char *op_method_str(enum op_req_method method);

#endif /* ifdef _OP_H_ */
