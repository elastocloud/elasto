/*
 * Copyright (C) SUSE LINUX GmbH 2015-2016, all rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/azure_fs_path.h"
#include "lib/azure_fs_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"

int
az_fs_path_parse(const char *path_str,
		 struct az_fs_path *az_fs_path)
{
	int ret;
	char *s;
	char *comp1 = NULL;
	char *comp2 = NULL;
	char *midpart = NULL;
	char *trailer = NULL;

	if ((path_str == NULL) || (az_fs_path == NULL)) {
		return -EINVAL;
	}

	s = (char *)path_str;
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		az_fs_path->type = AZ_FS_PATH_ROOT;
		goto done;
	}

	comp1 = strdup(s);
	if (comp1 == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(comp1, '/');
	if (s == NULL) {
		/* acc only */
		az_fs_path->type = AZ_FS_PATH_ACC;
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* acc + slashes only */
		az_fs_path->type = AZ_FS_PATH_ACC;
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s == NULL) {
		/* share only */
		az_fs_path->type = AZ_FS_PATH_SHARE;
		goto done;
	}

	*(s++) = '\0';	/* null term for share */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* share + slashes only */
		az_fs_path->type = AZ_FS_PATH_SHARE;
		goto done;
	}

	midpart = strdup(s);
	if (midpart == NULL) {
		ret = -ENOMEM;
		goto err_2_free;
	}

	/* need last component as dir or share */
	s = strrchr(midpart, '/');
	if (s == NULL) {
		/* midpart is the last path component */
		trailer = midpart;
		midpart = NULL;
		az_fs_path->type = AZ_FS_PATH_ENT;
		goto done;
	}

	if (strlen(s) <= 1) {
		/* trailing slash - FIXME: should allow this for dir opens? */
		dbg(0, "invalid AFS path, trailing garbage: %s\n", midpart);
		goto err_midpart_free;
	}

	s++;	/* move past last slash */
	trailer = strdup(s);
	if (trailer == NULL) {
		ret = -ENOMEM;
		goto err_midpart_free;
	}

	s--;	/* move back to last slash */
	while (*s == '/') {
		*s = '\0';	/* null term for midpart */
		s--;
	}

	assert(s >= midpart);
	az_fs_path->type = AZ_FS_PATH_ENT;

done:
	assert(az_fs_path->type != 0);
	az_fs_path->acc = comp1;
	az_fs_path->share = comp2;
	az_fs_path->parent_dir = midpart;
	/* fs_ent, file or dir. all are members of the same union */
	az_fs_path->fs_ent = trailer;
	dbg(2, "parsed %s as AFS path: acc=%s, share=%s, parent_dir=%s, "
	       "file or dir=%s\n",
	    path_str, (az_fs_path->acc ? az_fs_path->acc : ""),
	    (az_fs_path->share ? az_fs_path->share : ""),
	    (az_fs_path->parent_dir ? az_fs_path->parent_dir : ""),
	    (az_fs_path->fs_ent ? az_fs_path->fs_ent : ""));

	return 0;

err_midpart_free:
	free(midpart);
err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_out:
	return ret;
}

void
az_fs_path_free(struct az_fs_path *az_fs_path)
{
	free(az_fs_path->acc);
	az_fs_path->acc = NULL;
	free(az_fs_path->share);
	az_fs_path->share = NULL;
	free(az_fs_path->parent_dir);
	az_fs_path->parent_dir = NULL;
	/* file and dir are members of the same union */
	free(az_fs_path->fs_ent);
	az_fs_path->fs_ent = NULL;
}

int
az_fs_path_dup(const struct az_fs_path *path_orig,
	       struct az_fs_path *path_dup)
{
	int ret;
	struct az_fs_path dup = { 0 };

	dup.type = path_orig->type;
	if (path_orig->acc != NULL) {
		dup.acc = strdup(path_orig->acc);
		if (dup.acc == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		/* all nested items must also be NULL */
		goto done;
	}

	if (path_orig->share != NULL) {
		dup.share = strdup(path_orig->share);
		if (dup.share == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	} else {
		/* all nested items must also be NULL */
		goto done;
	}

	if (path_orig->parent_dir != NULL) {
		dup.parent_dir = strdup(path_orig->parent_dir);
		if (dup.parent_dir == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

	if (path_orig->fs_ent != NULL) {
		dup.fs_ent = strdup(path_orig->fs_ent);
		if (dup.fs_ent == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

done:
	*path_dup = dup;
	return 0;

err_path_free:
	az_fs_path_free(&dup);
err_out:
	return ret;
}
