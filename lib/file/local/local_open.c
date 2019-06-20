/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#include "ccan/list/list.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "elasto/file.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "local_path.h"
#include "local_handle.h"
#include "local_open.h"

static int
local_fopen_file(struct local_fh *local_fh,
		 uint64_t flags)
{
	int ret;
	struct stat sbuf;
	int oflags = 0;
	bool created = false;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open file with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = stat(local_fh->path.path, &sbuf);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_out;
	} else if ((ret == 0) && (!S_ISREG(sbuf.st_mode))) {
		dbg(0, "open path is not a regular file\n");
		ret = -EINVAL;
		goto err_out;
	} else if ((ret < 0) && (errno == ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		oflags = O_CREAT;
		if (flags & ELASTO_FOPEN_EXCL) {
			oflags |= O_EXCL;
		}
		created = true;
	} else if (ret < 0) {
		ret = -errno;
		goto err_out;
	}
	/* always write synchronously */
	oflags |= O_DSYNC;
	oflags |= O_RDWR;

	ret = open(local_fh->path.path, oflags, S_IRWXU);
	if (ret < 0) {
		ret = -errno;
		goto err_out;
	}
	local_fh->fd = ret;

	ret = (created ? ELASTO_FOPEN_RET_CREATED : ELASTO_FOPEN_RET_EXISTED);
err_out:
	return ret;
}

static int
local_fopen_dir(struct local_fh *local_fh,
		uint64_t flags)
{
	int ret;
	struct stat sbuf;
	bool created = false;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open dir without flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = stat(local_fh->path.path, &sbuf);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_out;
	} else if ((ret == 0) && (!S_ISDIR(sbuf.st_mode))) {
		dbg(0, "open path is not a directory\n");
		ret = -EINVAL;
		goto err_out;
	} else if ((ret < 0) && (errno == ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		ret = mkdir(local_fh->path.path, 0700);
		if (ret < 0) {
			ret = -errno;
			goto err_out;
		}
		created = true;
	} else if (ret < 0) {
		ret = -errno;
		goto err_out;
	}

	local_fh->dir = opendir(local_fh->path.path);
	if (local_fh->dir == NULL) {
		ret = -errno;
		goto err_out;
	}

	local_fh->fd = dirfd(local_fh->dir);
	if (local_fh->fd < 0) {
		ret = -errno;
		dbg(0, "dirfd failed: %s\n", strerror(-ret));
		goto err_closedir;
	}

	ret = (created ? ELASTO_FOPEN_RET_CREATED : ELASTO_FOPEN_RET_EXISTED);
	return ret;

err_closedir:
	closedir(local_fh->dir);
err_out:
	return ret;
}

int
local_fopen(struct event_base *ev_base,
	    void *mod_priv,
	    const char *host,
	    uint16_t port,
	    const char *path,
	    uint64_t flags,
	    struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct local_fh *local_fh = mod_priv;

	if (host != NULL) {
		dbg(0, "local back-end doesn't support open host\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = local_path_parse(path, &local_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		local_fh->path.type = LOCAL_PATH_DIR;
		ret = local_fopen_dir(local_fh, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	} else {
		local_fh->path.type = LOCAL_PATH_FILE;
		ret = local_fopen_file(local_fh, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	}

	return ret;

err_path_free:
	local_path_free(&local_fh->path);
err_out:
	return ret;
}

int
local_fclose(void *mod_priv)
{
	struct local_fh *local_fh = mod_priv;

	if (local_fh->path.type == LOCAL_PATH_DIR) {
		closedir(local_fh->dir);
	} else if (local_fh->path.type == LOCAL_PATH_FILE) {
		close(local_fh->fd);
	}
	local_path_free(&local_fh->path);

	return 0;
}
