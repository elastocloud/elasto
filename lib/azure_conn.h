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

struct azure_conn {
	CURL *curl;
	struct {
		char *account;
		uint8_t *key;
		uint64_t key_len;
	} sign;
};

int
azure_conn_sign_setkey(struct azure_conn *aconn,
		       const char *account,
		       const char *key_b64);

int
azure_conn_send_op(struct azure_conn *aconn,
		    struct azure_op *op);

int
azure_conn_init(const char *pem_file,
		const char *pem_pw,
		struct azure_conn **aconn);

void
azure_conn_free(struct azure_conn *aconn);

int
azure_conn_subsys_init(void);

void
azure_conn_subsys_deinit(void);

#endif /* ifdef _AZURE_CONN_H_ */
