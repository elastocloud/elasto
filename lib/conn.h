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
#ifndef _AZURE_CONN_H_
#define _AZURE_CONN_H_

enum elasto_conn_type {
	CONN_TYPE_AZURE = 1,
	CONN_TYPE_S3,
};

struct elasto_conn {
	enum elasto_conn_type type;
	CURL *curl;
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

int
elasto_conn_send_op(struct elasto_conn *econn,
		    struct azure_op *op);

int
elasto_conn_init_az(const char *pem_file,
		    const char *pem_pw,
		    struct elasto_conn **econn);

int
elasto_conn_init_s3(const char *id,
		    const char *secret,
		    struct elasto_conn **econn);

void
elasto_conn_free(struct elasto_conn *econn);

int
elasto_conn_subsys_init(void);

void
elasto_conn_subsys_deinit(void);

#endif /* ifdef _AZURE_CONN_H_ */
