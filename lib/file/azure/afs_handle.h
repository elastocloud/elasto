/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#ifndef _AFS_HANDLE_H_
#define _AFS_HANDLE_H_

/**
 * Azure File Service path representation
 *
 * The Azure File Service allows for files and folders at any depth under a
 * share.
 *
 * @acc: Azure account name
 * @share: Azure File Server share name
 * @parent_dir: Parent directory for @file or @dir. NULL if item is nested
 *		directly below @share.
 * @fs_ent: Last component of path (type obtained from open flags).
 * @file: Same as @fs_ent.
 * @dir: Same as @fs_ent.
 */
struct elasto_fh_afs_path {
	char *acc;
	char *share;
	char *parent_dir;
	union {
		char *fs_ent;		/* generic dir/file */
		char *file;
		char *dir;
	};
};

/**
 * Azure File Service private handle
 *
 * @open_flags: FIXME open_flags are also stored with vfs fh.
 * @path: AFS path, split into components.
 * @pem_path: local path to PEM Publish Settings credentials file. May be NULL
 *	      if access key was provided instead of publish settings file.
 * @sub_id: Subscription ID. NULL if access key auth.
 * @sub_name: Subscription name. NULL if access key auth.
 * @acc_access_key: Account access key.
 * @insecure_http: Use HTTP instead of HTTPS where applicable.
 * @mgmt_conn: Connection to Management service. NULL if access key auth.
 * @io_conn: Connection to Azure File Service.
 */
struct afs_fh {
	uint64_t open_flags;
	struct elasto_fh_afs_path path;
	char *pem_path;
	char *sub_id;
	char *sub_name;
	char *acc_access_key;
	bool insecure_http;
	struct elasto_conn *mgmt_conn;
	struct elasto_conn *io_conn;
};

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_fh_mod_ops *mod_ops);

void
afs_fh_free(void *mod_priv);

#endif /* _AFS_HANDLE_H_ */
