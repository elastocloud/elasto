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

/* FIXME open_flags are also stored with vfs fh */
struct afs_fh {
	uint64_t open_flags;
	struct elasto_fh_afs_path path;
	char *pem_path;
	char *sub_id;
	char *sub_name;
};

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_conn **_conn,
			struct elasto_fh_mod_ops *mod_ops);

void
afs_fh_free(void *mod_priv);

#endif /* _AFS_HANDLE_H_ */
