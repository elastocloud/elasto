/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
#ifndef _AZURE_REQ_H_
#define _AZURE_REQ_H_

enum azure_op {
	AOP_MGMT_GET_SA_KEYS = 1,
};

struct azure_mgmt_get_sa_keys {
	struct {
		char *sub_id;
		char *service_name;
	} in;
	struct {
		xmlChar *primary;
		xmlChar *secondary;
	} out;
};

#define REQ_METHOD_GET		"GET"
#define REQ_METHOD_PUT		"PUT"
#define REQ_METHOD_DELETE	"DELETE"
struct azure_req {
	CURL *curl;
	struct {
		uint8_t *buf;
		uint64_t buf_len;
		uint64_t off;
	} iov;
	char *signature;
	const char *method;
	char *url;

	enum azure_op op;
	union {
		struct azure_mgmt_get_sa_keys mgmt_get_sa_keys;
	};
};

int
azure_req_mgmt_get_sa_keys_init(const char *sub_id,
				const char *service_name,
			        struct azure_req *req);

int
azure_req_mgmt_get_sa_keys_rsp(struct azure_req *req);

void
azure_req_free(struct azure_req *req);

#endif /* ifdef _AZURE_REQ_H_ */
