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
#ifndef _AZURE_REQ_H_
#define _AZURE_REQ_H_

enum azure_op {
	AOP_MGMT_GET_SA_KEYS = 1,
	AOP_CONTAINER_LIST,
	AOP_CONTAINER_CREATE,
	AOP_BLOB_PUT,
	AOP_BLOB_GET,
};

struct azure_mgmt_get_sa_keys {
	struct {
		char *sub_id;
		char *service_name;
	} in;
	struct {
		char *primary;
		char *secondary;
	} out;
};

struct azure_ctnr {
	struct list_node list;
	char *name;
};

/* @ctnrs: struct azure_blob_ctnr list */
struct azure_ctnr_list {
	struct {
		char *account;
	} in;
	struct {
		int num_ctnrs;
		struct list_head ctnrs;
	} out;
};

struct azure_ctnr_create {
	struct {
		char *account;
		char *ctnr;
	} in;
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

struct azure_blob_get {
	struct {
		char *account;
		char *container;
		char *bname;
		char *type;
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
	} iov_out;	/* alloced by req */
	bool sign;
	char *sig_src;	/* debug, compare with signing error response */
	const char *method;
	char *url;

	enum azure_op op;
	union {
		struct azure_mgmt_get_sa_keys mgmt_get_sa_keys;
		struct azure_ctnr_list ctnr_list;
		struct azure_ctnr_create ctnr_create;
		struct azure_blob_put blob_put;
		struct azure_blob_get blob_get;
	};

	struct {
		uint8_t *buf;
		uint64_t buf_len;
		uint64_t off;
	} iov_in;	/* alloced by conn hdr callback */
	int32_t rsp_code;
};

int
azure_req_mgmt_get_sa_keys(const char *sub_id,
			   const char *service_name,
			   struct azure_req *req);

int
azure_req_mgmt_get_sa_keys_rsp(struct azure_req *req);

int
azure_req_ctnr_list(const char *account,
		    struct azure_req *req);

int
azure_req_ctnr_list_rsp(struct azure_req *req);

int
azure_req_ctnr_create(const char *account,
		      const char *ctnr,
		      struct azure_req *req);

int
azure_req_blob_put(const char *account,
		   const char *container,
		   const char *bname,
		   bool is_page,
		   uint64_t content_len_bytes,
		   uint8_t *buf,
		   uint64_t len,
		   struct azure_req *req);

int
azure_req_blob_put_rsp(struct azure_req *req);

int
azure_req_blob_get(const char *account,
		   const char *container,
		   const char *bname,
		   struct azure_req *req);

void
azure_req_free(struct azure_req *req);

#endif /* ifdef _AZURE_REQ_H_ */
