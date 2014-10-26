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
};

struct az_fs_req_share_create {
	char *acc;
	char *share;
};

struct az_fs_req_share_del {
	char *acc;
	char *share;
};

struct az_fs_req {
	union {
		struct az_fs_req_share_create share_create;
		struct az_fs_req_share_del share_del;
	};
};

struct az_fs_rsp {
	union {
		/*
		 * No response specific data handled yet:
		 * struct az_fs_rsp_share_create share_create;
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
#endif /* ifdef _AZURE_FS_REQ_H_ */
