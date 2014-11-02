/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2014, all rights reserved.
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
	AOP_FS_SHARE_CREATE = 101,
	AOP_FS_SHARE_DEL,
	AOP_FS_DIRS_FILES_LIST,
};

struct az_fs_req_share_create {
	char *acc;
	char *share;
};

struct az_fs_req_share_del {
	char *acc;
	char *share;
};

struct az_fs_req_dirs_files_list {
	char *acc;
	char *share;
	char *dir_path;
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

struct az_fs_req {
	union {
		struct az_fs_req_share_create share_create;
		struct az_fs_req_share_del share_del;
		struct az_fs_req_dirs_files_list dirs_files_list;
	};
};

struct az_fs_rsp {
	union {
		struct az_fs_rsp_dirs_files_list dirs_files_list;
		/*
		 * No response specific data handled yet:
		 * struct az_fs_rsp_share_create share_create;
		 * struct az_fs_rsp_share_del share_del;
		 * struct az_fs_rsp_dirs_files_list dirs_files_list;
		 */
	};
};

int
az_fs_req_share_create(const char *acc,
		       const char *share,
		       struct op **_op);

int
az_fs_req_share_del(const char *acc,
		    const char *share,
		    struct op **_op);

int
az_fs_req_dirs_files_list(const char *acc,
			  const char *share,
			  const char *dir_path,
			  struct op **_op);

struct az_fs_rsp_dirs_files_list *
az_fs_rsp_dirs_files_list(struct op *op);
#endif /* ifdef _AZURE_FS_REQ_H_ */
