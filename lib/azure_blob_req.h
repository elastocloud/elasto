/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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
#ifndef _AZURE_BLOB_REQ_H_
#define _AZURE_BLOB_REQ_H_

enum az_blob_opcode {
	AOP_CONTAINER_LIST,
	AOP_CONTAINER_CREATE,
	AOP_CONTAINER_DEL,
	AOP_CONTAINER_PROP_GET,
	AOP_BLOB_LIST,
	AOP_BLOB_PUT,
	AOP_BLOB_GET,
	AOP_PAGE_PUT,
	AOP_BLOCK_PUT,
	AOP_BLOCK_LIST_PUT,
	AOP_BLOCK_LIST_GET,
	AOP_BLOB_DEL,
	AOP_BLOB_CP,
	AOP_BLOB_PROP_GET,
	AOP_BLOB_PROP_SET,
	AOP_BLOB_LEASE,
};

struct azure_ctnr {
	struct list_node list;
	char *name;
};

struct az_req_ctnr_list {
	char *account;
};
/* @ctnrs: struct azure_ctnr list */
struct az_rsp_ctnr_list {
	int num_ctnrs;
	struct list_head ctnrs;
};

struct az_req_ctnr_create {
	char *account;
	char *ctnr;
};

struct az_req_ctnr_del {
	char *account;
	char *container;
};

struct az_req_ctnr_prop_get {
	char *acc;
	char *ctnr;
};

enum az_lease_state {
	AOP_LEASE_STATE_AVAILABLE,
	AOP_LEASE_STATE_LEASED,
	AOP_LEASE_STATE_EXPIRED,
	AOP_LEASE_STATE_BREAKING,
	AOP_LEASE_STATE_BROKEN,
};

enum az_lease_status {
	AOP_LEASE_STATUS_LOCKED,
	AOP_LEASE_STATUS_UNLOCKED,
};

struct az_rsp_ctnr_prop_get {
	enum az_lease_state lease_state;
	enum az_lease_status lease_status;
};

struct azure_blob {
	struct list_node list;
	char *name;
	bool is_page;
	uint64_t len;
	enum az_lease_status lease_status;
};

struct az_req_blob_list {
	char *account;
	char *ctnr;
};
/* @blobs: struct azure_blob list */
struct az_rsp_blob_list {
	int num_blobs;
	struct list_head blobs;
};

/*
 * The Content-Length header and body data are derived from op.iov.
 * @content_len_bytes corresponds to the x-ms-blob-content-length header, and
 * is needed for page blobs only.
 */
#define BLOB_TYPE_BLOCK	"BlockBlob"
#define BLOB_TYPE_PAGE	"PageBlob"
#define PBLOB_SECTOR_SZ 512
struct az_req_blob_put {
	char *account;
	char *container;
	char *bname;
	char *type;
	uint64_t pg_len;
};
struct az_rsp_blob_put {
	time_t last_mod;
	char *content_md5;
};

struct az_req_blob_get {
	char *account;
	char *container;
	char *bname;
	char *type;
	uint64_t off;
	uint64_t len;
};
struct az_rsp_blob_get {
	time_t last_mod;
	char *content_md5;
};

struct az_req_page_put {
	char *account;
	char *container;
	char *bname;
	uint64_t off;
	uint64_t len;
	bool clear_data;
};
struct az_rsp_page_put {
	time_t last_mod;
	char *content_md5;
	uint64_t seq_num;
};

/* The block must be less than or equal to 4 MB in size. */
#define BLOB_BLOCK_MAX (4 * 1024 * 1024)
struct az_req_block_put {
	char *account;
	char *container;
	char *bname;
	char *blk_id;
};
struct az_rsp_block_put {
	char *content_md5;
};

enum azure_block_state {
	BLOCK_STATE_UNSENT = 0,
	BLOCK_STATE_COMMITED,
	BLOCK_STATE_UNCOMMITED,
	BLOCK_STATE_LATEST,
};

struct azure_block {
	struct list_node list;
	enum azure_block_state state;
	char *id;
	uint64_t len;
};
struct az_req_block_list_put {
	char *account;
	char *container;
	char *bname;
	struct list_head *blks;
};

struct az_req_block_list_get {
	char *account;
	char *container;
	char *bname;
};
struct az_rsp_block_list_get {
	int num_blks;
	struct list_head blks;
};

struct az_req_blob_del {
	char *account;
	char *container;
	char *bname;
};

struct az_req_blob_cp {
	struct {
		char *account;
		char *container;
		char *bname;
	} src;
	struct {
		char *account;
		char *container;
		char *bname;
	} dst;
};

enum az_cp_status {
	AOP_CP_STATUS_PENDING,
	AOP_CP_STATUS_SUCCESS,
	AOP_CP_STATUS_ABORTED,
	AOP_CP_STATUS_FAILED,
};
struct az_req_blob_prop_get {
	char *account;
	char *container;
	char *bname;
};
struct az_rsp_blob_prop_get {
	bool is_page;
	uint64_t len;
	char *content_type;
	enum az_lease_state lease_state;
	enum az_lease_status lease_status;
	char *cp_id;
	enum az_cp_status cp_status;
};

struct az_req_blob_prop_set {
	char *account;
	char *container;
	char *bname;
	bool is_page;
	uint64_t len;
};

enum az_lease_action {
	AOP_LEASE_ACTION_ACQUIRE,
	AOP_LEASE_ACTION_RENEW,
	AOP_LEASE_ACTION_CHANGE,
	AOP_LEASE_ACTION_RELEASE,
	AOP_LEASE_ACTION_BREAK,
};

struct az_req_blob_lease {
	char *acc;
	char *ctnr;
	char *blob;
	char *lid;
	char *lid_proposed;
	enum az_lease_action action;
	union {
		int32_t break_period;
		int32_t duration;
	};
};

struct az_rsp_blob_lease {
	char *lid;
	uint64_t time_remaining;
};

struct az_blob_req {
	union {
		struct az_req_ctnr_list ctnr_list;
		struct az_req_ctnr_create ctnr_create;
		struct az_req_ctnr_del ctnr_del;
		struct az_req_ctnr_prop_get ctnr_prop_get;
		struct az_req_blob_list blob_list;
		struct az_req_blob_put blob_put;
		struct az_req_blob_get blob_get;
		struct az_req_page_put page_put;
		struct az_req_block_put block_put;
		struct az_req_block_list_put block_list_put;
		struct az_req_block_list_get block_list_get;
		struct az_req_blob_del blob_del;
		struct az_req_blob_cp blob_cp;
		struct az_req_blob_prop_get blob_prop_get;
		struct az_req_blob_prop_set blob_prop_set;
		struct az_req_blob_lease blob_lease;
	};
};

struct az_blob_rsp {
	union {
		struct az_rsp_ctnr_list ctnr_list;
		struct az_rsp_ctnr_prop_get ctnr_prop_get;
		struct az_rsp_blob_list blob_list;
		struct az_rsp_block_list_get block_list_get;
		struct az_rsp_blob_prop_get blob_prop_get;
		struct az_rsp_blob_lease blob_lease;
		/*
		 * No response specific data handled yet:
		 * struct az_rsp_ctnr_create ctnr_create;
		 * struct az_rsp_ctnr_del ctnr_del;
		 * struct az_rsp_blob_put blob_put;
		 * struct az_rsp_blob_get blob_get;
		 * struct az_rsp_page_put page_put;
		 * struct az_rsp_block_put block_put;
		 * struct az_rsp_blob_del blob_del;
		 * struct az_rsp_blob_cp blob_cp;
		 */
	};
};

int
az_req_ctnr_list(const char *account,
		 struct op **_op);

int
az_req_ctnr_create(const char *account,
		   const char *ctnr,
		   struct op **_op);

int
az_req_ctnr_del(const char *account,
		const char *container,
		struct op **_op);

int
az_req_ctnr_prop_get(const char *acc,
		     const char *ctnr,
		     struct op **_op);

int
az_req_blob_list(const char *account,
		 const char *ctnr,
		 struct op **_op);

int
az_req_blob_put(const char *account,
		const char *container,
		const char *bname,
		struct elasto_data *data,
		uint64_t page_len,
		struct op **_op);

int
az_req_blob_get(const char *account,
		const char *container,
		const char *bname,
		bool is_page,
		struct elasto_data *data,
		uint64_t req_off,
		uint64_t req_len,
		struct op **_op);

int
az_req_page_put(const char *account,
		const char *container,
		const char *bname,
		struct elasto_data *src_data,
		uint64_t dest_off,
		uint64_t dest_len,
		struct op **_op);

int
az_req_block_put(const char *account,
		 const char *container,
		 const char *bname,
		 const char *blk_id,
		 struct elasto_data *data,
		 struct op **_op);

int
az_req_block_list_put(const char *account,
		      const char *container,
		      const char *bname,
		      struct list_head *blks,
		      struct op **_op);

int
az_req_block_list_get(const char *account,
		      const char *container,
		      const char *bname,
		      struct op **_op);

int
az_req_blob_del(const char *account,
		const char *ctnr,
		const char *bname,
		struct op **_op);

int
az_req_blob_cp(const char *src_account,
	       const char *src_ctnr,
	       const char *src_bname,
	       const char *dst_account,
	       const char *dst_ctnr,
	       const char *dst_bname,
	       struct op **_op);

int
az_req_blob_prop_get(const char *account,
		     const char *container,
		     const char *bname,
		     struct op **_op);

int
az_req_blob_prop_set(const char *account,
		     const char *container,
		     const char *bname,
		     bool is_page,
		     uint64_t len,
		     struct op **_op);

int
az_req_blob_lease(const char *account,
		  const char *ctnr,
		  const char *bname,
		  const char *lid,
		  const char *lid_proposed,
		  enum az_lease_action action,
		  int32_t duration,
		  struct op **_op);

struct az_rsp_ctnr_list *
az_rsp_ctnr_list(struct op *op);

struct az_rsp_ctnr_prop_get *
az_rsp_ctnr_prop_get(struct op *op);

struct az_rsp_blob_list *
az_rsp_blob_list(struct op *op);

struct az_rsp_block_list_get *
az_rsp_block_list_get(struct op *op);

struct az_rsp_blob_prop_get *
az_rsp_blob_prop_get(struct op *op);

struct az_rsp_blob_lease *
az_rsp_blob_lease_get(struct op *op);
#endif /* ifdef _AZURE_BLOB_REQ_H_ */
