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
#ifndef _AZURE_FS_REQ_H_
#define _AZURE_FS_REQ_H_

enum az_fs_opcode {
	AOP_FS_SHARES_LIST = 100,
	AOP_FS_SHARE_CREATE,
	AOP_FS_SHARE_DEL,
	AOP_FS_SHARE_PROP_GET,
	AOP_FS_DIRS_FILES_LIST,
	AOP_FS_DIR_CREATE,
	AOP_FS_DIR_DEL,
	AOP_FS_DIR_PROP_GET,
	AOP_FS_FILE_CREATE,
	AOP_FS_FILE_DEL,
	AOP_FS_FILE_GET,
	AOP_FS_FILE_PUT,
	AOP_FS_FILE_CP,
	AOP_FS_FILE_PROP_GET,
	AOP_FS_FILE_PROP_SET,
};

struct az_fs_req_shares_list {
	char *acc;
};

struct az_fs_share {
	struct list_node list;
	char *name;
	time_t last_mod;
};

struct az_fs_rsp_shares_list {
	int num_shares;
	struct list_head shares;
};

struct az_fs_req_share_create {
	char *acc;
	char *share;
};

struct az_fs_req_share_del {
	char *acc;
	char *share;
};

struct az_fs_req_share_prop_get {
	char *acc;
	char *share;
};

struct az_fs_rsp_share_prop_get {
	time_t last_mod;
};

struct az_fs_req_dirs_files_list {
	char *acc;
	char *share;
	char *dir_path;	/* NULL for share child listings */
};

/* @file.size may be incorrect due to SMB oplocks etc. */
struct az_fs_ent {
	struct list_node list;
	enum {
		AZ_FS_ENT_TYPE_FILE,
		AZ_FS_ENT_TYPE_DIR,
	} type;
	union {
		struct {
			char *name;
			uint64_t size;
		} file;
		struct {
			char *name;
		} dir;
	};
};

struct az_fs_rsp_dirs_files_list {
	int num_ents;
	struct list_head ents;
};

/* @parent_dir_path optional */
struct az_fs_req_dir_create {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *dir;
};

/* @parent_dir_path optional */
struct az_fs_req_dir_del {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *dir;
};

struct az_fs_req_dir_prop_get {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *dir;
};

struct az_fs_rsp_dir_prop_get {
	time_t last_mod;
};

/* @parent_dir_path optional */
struct az_fs_req_file_create {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
	uint64_t max_size_bytes;
};

/* @parent_dir_path optional */
struct az_fs_req_file_del {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
};

struct az_fs_req_file_get {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
	uint64_t off;
	uint64_t len;
};

struct az_fs_req_file_put {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
	uint64_t off;
	uint64_t len;
	bool clear_data;
};

struct az_fs_req_file_cp {
	struct {
		char *acc;
		char *share;
		char *parent_dir_path;
		char *file;
	} src;
	struct {
		char *acc;
		char *share;
		char *parent_dir_path;
		char *file;
	} dst;
};

struct az_fs_rsp_file_cp {
	char *cp_id;
	enum az_cp_status cp_status;
};

enum az_fs_file_prop {
	AZ_FS_FILE_PROP_LEN		= 0x01,
	AZ_FS_FILE_PROP_CTYPE		= 0x02,
	AZ_FS_FILE_PROP_CP_ID		= 0x04,
	AZ_FS_FILE_PROP_CP_STATUS	= 0x08,
};

struct az_fs_req_file_prop_get {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
};

/* @relevant reflects which values were actually supplied in the response */
struct az_fs_rsp_file_prop_get {
	uint64_t relevant;
	uint64_t len;
	char *content_type;
	char *cp_id;
	enum az_cp_status cp_status;
};

/* @relevant reflects which values should be supplied in the request */
struct az_fs_req_file_prop_set {
	char *acc;
	char *share;
	char *parent_dir_path;
	char *file;
	uint64_t relevant;
	uint64_t len;
	char *content_type;
};

struct az_fs_req {
	union {
		struct az_fs_req_shares_list shares_list;
		struct az_fs_req_share_create share_create;
		struct az_fs_req_share_del share_del;
		struct az_fs_req_share_prop_get share_prop_get;
		struct az_fs_req_dirs_files_list dirs_files_list;
		struct az_fs_req_dir_create dir_create;
		struct az_fs_req_dir_del dir_del;
		struct az_fs_req_dir_prop_get dir_prop_get;
		struct az_fs_req_file_create file_create;
		struct az_fs_req_file_del file_del;
		struct az_fs_req_file_get file_get;
		struct az_fs_req_file_put file_put;
		struct az_fs_req_file_cp file_cp;
		struct az_fs_req_file_prop_get file_prop_get;
		struct az_fs_req_file_prop_set file_prop_set;
	};
};

struct az_fs_rsp {
	union {
		struct az_fs_rsp_shares_list shares_list;
		struct az_fs_rsp_share_prop_get share_prop_get;
		struct az_fs_rsp_dirs_files_list dirs_files_list;
		struct az_fs_rsp_dir_prop_get dir_prop_get;
		struct az_fs_rsp_file_cp file_cp;
		struct az_fs_rsp_file_prop_get file_prop_get;
		/*
		 * No response specific data handled yet:
		 * struct az_fs_rsp_share_create share_create;
		 * struct az_fs_rsp_share_del share_del;
		 * struct az_fs_rsp_dirs_files_list dirs_files_list;
		 * struct az_fs_rsp_dir_create dir_create;
		 * struct az_fs_rsp_dir_del dir_del;
		 * struct az_fs_rsp_file_create file_create;
		 * struct az_fs_rsp_file_del file_del;
		 * struct az_fs_rsp_file_get file_get;
		 * struct az_fs_rsp_file_put file_put;
		 * struct az_fs_rsp_file_prop_set file_prop_set;
		 */
	};
};

int
az_fs_req_shares_list(const char *acc,
		      struct op **_op);

struct az_fs_rsp_shares_list *
az_fs_rsp_shares_list(struct op *op);

int
az_fs_req_share_create(const char *acc,
		       const char *share,
		       struct op **_op);

int
az_fs_req_share_del(const char *acc,
		    const char *share,
		    struct op **_op);

int
az_fs_req_share_prop_get(const char *acc,
			 const char *share,
			 struct op **_op);

struct az_fs_rsp_share_prop_get *
az_fs_rsp_share_prop_get(struct op *op);

int
az_fs_req_dirs_files_list(const char *acc,
			  const char *share,
			  const char *dir_path,	/* optional */
			  struct op **_op);

struct az_fs_rsp_dirs_files_list *
az_fs_rsp_dirs_files_list(struct op *op);

int
az_fs_req_dir_create(const char *acc,
		     const char *share,
		     const char *parent_dir_path,	/* optional */
		     const char *dir,
		     struct op **_op);

int
az_fs_req_dir_del(const char *acc,
		  const char *share,
		  const char *parent_dir_path,	/* optional */
		  const char *dir,
		  struct op **_op);

int
az_fs_req_dir_prop_get(const char *acc,
		       const char *share,
		       const char *parent_dir_path,	/* optional */
		       const char *dir,
		       struct op **_op);

struct az_fs_rsp_dir_prop_get *
az_fs_rsp_dir_prop_get(struct op *op);

int
az_fs_req_file_create(const char *acc,
		     const char *share,
		     const char *parent_dir_path,	/* optional */
		     const char *file,
		     uint64_t max_size_bytes,
		     struct op **_op);

int
az_fs_req_file_del(const char *acc,
		  const char *share,
		  const char *parent_dir_path,	/* optional */
		  const char *file,
		  struct op **_op);

int
az_fs_req_file_get(const char *acc,
		   const char *share,
		   const char *parent_dir_path,
		   const char *file,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *dest_data,
		   struct op **_op);

int
az_fs_req_file_put(const char *acc,
		   const char *share,
		   const char *parent_dir_path,
		   const char *file,
		   uint64_t off,
		   uint64_t len,
		   struct elasto_data *src_data,
		   struct op **_op);

int
az_fs_req_file_cp(const char *src_acc,
		  const char *src_share,
		  const char *src_parent_dir_path,
		  const char *src_file,
		  const char *dst_acc,
		  const char *dst_share,
		  const char *dst_parent_dir_path,
		  const char *dst_file,
		  struct op **_op);

struct az_fs_rsp_file_cp *
az_fs_rsp_file_cp(struct op *op);

int
az_fs_req_file_prop_get(const char *acc,
			const char *share,
			const char *parent_dir_path,
			const char *file,
			struct op **_op);

struct az_fs_rsp_file_prop_get *
az_fs_rsp_file_prop_get(struct op *op);

/* @relevant reflects which values should be supplied in the request */
int
az_fs_req_file_prop_set(const char *acc,
			const char *share,
			const char *parent_dir_path,
			const char *file,
			uint64_t relevant,
			uint64_t len,
			const char *content_type,
			struct op **_op);
#endif /* ifdef _AZURE_FS_REQ_H_ */
