/*
 * Copyright (C) SUSE LINUX GmbH 2012-2017, all rights reserved.
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
#ifndef _AZURE_CONN_H_
#define _AZURE_CONN_H_

#include <event2/util.h>

enum elasto_conn_type {
	CONN_TYPE_AZURE = 1,
	CONN_TYPE_S3,
};

struct ssl_ctx_st;
struct ssl_st;

struct elasto_conn {
	enum elasto_conn_type type;
	bool insecure_http;
	char *pem_file;
	struct event_base *ev_base;
	struct bufferevent *ev_bev;
	struct evhttp_connection *ev_conn;
	struct ssl_ctx_st *ssl_ctx;
	struct ssl_st *ssl;
	char *hostname;
	struct {
		char *account;
		uint8_t *key;
		uint64_t key_len;
	} sign;
};

int
elasto_conn_sign_setkey(struct elasto_conn *econn,
		       const char *account,
		       const char *key_b64);

/* asyncronously dispatch @op */
struct event *
elasto_conn_op_tx(struct elasto_conn *econn,
		  struct op *op,
		  void (*cb)(evutil_socket_t, short, void *),
		  void *cb_arg);
/* retrieve result of @op dispatch (after completion cb) */
int
elasto_conn_op_rx(struct event *ev_xmit);
/* free async request state */
void
elasto_conn_op_free(struct event *ev_xmit);

int
elasto_conn_op_txrx(struct elasto_conn *econn,
		    struct op *op);

int
elasto_conn_init_az(const char *pem_file,
		    bool insecure_http,
		    const char *host,
		    struct elasto_conn **econn);

int
elasto_conn_init_s3(const char *id,
		    const char *secret,
		    bool insecure_http,
		    const char *host,
		    struct elasto_conn **econn);

void
elasto_conn_free(struct elasto_conn *econn);

struct event_base *
elasto_conn_ev_base_get(struct elasto_conn *econn);

int
elasto_conn_subsys_init(void);

void
elasto_conn_subsys_deinit(void);

#endif /* ifdef _AZURE_CONN_H_ */
