/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
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
azure_conn_send_req(struct azure_conn *aconn,
		    struct azure_req *req);

int
azure_conn_init(const char *pem_file,
		const char *pem_pw,
		struct azure_conn *aconn);

void
azure_conn_free(struct azure_conn *aconn);

int
azure_conn_subsys_init(void);

void
azure_conn_subsys_deinit(void);

#endif /* ifdef _AZURE_CONN_H_ */
