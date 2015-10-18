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
#ifndef _AZURE_FS_PATH_H_
#define _AZURE_FS_PATH_H_

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
struct az_fs_path {
	char *acc;
	char *share;
	char *parent_dir;
	union {
		char *fs_ent;		/* generic dir/file */
		char *file;
		char *dir;
	};
};

#define AZ_FS_PATH_IS_ACC(path) \
	((path != NULL) \
	 && (path->acc != NULL) \
	 && (path->share == NULL) \
	 && (path->parent_dir == NULL) \
	 && (path->fs_ent == NULL))

#define AZ_FS_PATH_IS_SHARE(path) \
	((path != NULL) \
	 && (path->acc != NULL) \
	 && (path->share != NULL) \
	 && (path->parent_dir == NULL) \
	 && (path->fs_ent == NULL))

/* for files and directories, @parent_dir can be NULL */
#define AZ_FS_PATH_IS_ENT(path) \
	((path != NULL) \
	 && (path->acc != NULL) \
	 && (path->share != NULL) \
	 && (path->fs_ent != NULL))

int
az_fs_path_parse(const char *path_str,
		 struct az_fs_path *az_fs_path);

void
az_fs_path_free(struct az_fs_path *az_fs_path);

int
az_fs_path_dup(const struct az_fs_path *path_orig,
	       struct az_fs_path *path_dup);

#endif /* ifdef _AZURE_FS_PATH_H_ */
