/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
#ifndef _AZURE_REQ_H_
#define _AZURE_REQ_H_

enum azure_op {
	AOP_MGMT_GET_SA_KEYS = 1,
	AOP_BLOB_PUT,
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

/*
 * The Content-Length header and body data are derived from req.iov.
 * @content_len_bytes corresponds to the x-ms-blob-content-length header, and
 * is needed for page blobs only.
 */
#define BLOB_TYPE_BLOCK	"BlockBlob"
#define BLOB_TYPE_PAGE	"PageBlob"
#define PBLOB_SECTOR_SZ 512
struct azure_blob_put {
	struct {
		char *account;
		char *container;
		char *bname;
		char *type;
		uint64_t content_len_bytes;
	} in;
	struct {
		time_t last_mod;
		char *content_md5;
	} out;
};

#define REQ_METHOD_GET		"GET"
#define REQ_METHOD_PUT		"PUT"
#define REQ_METHOD_DELETE	"DELETE"
struct azure_req {
	struct curl_slist *http_hdr;
	struct {
		uint8_t *buf;
		uint64_t buf_len;
		uint64_t off;
	} iov;
	bool sign;
	char *signature;
	const char *method;
	char *url;

	enum azure_op op;
	union {
		struct azure_mgmt_get_sa_keys mgmt_get_sa_keys;
		struct azure_blob_put blob_put;
	};
};

int
azure_req_mgmt_get_sa_keys_init(const char *sub_id,
				const char *service_name,
			        struct azure_req *req);

int
azure_req_mgmt_get_sa_keys_rsp(struct azure_req *req);

int
azure_req_blob_put_init(const char *account,
			const char *container,
			const char *bname,
			bool is_page,
			uint64_t content_len_bytes,
			uint8_t *buf,
			uint64_t len,
			struct azure_req *req);

int
azure_req_blob_put_rsp(struct azure_req *req);

void
azure_req_free(struct azure_req *req);

#endif /* ifdef _AZURE_REQ_H_ */
