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
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <dirent.h>

#include "ccan/list/list.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "lib/file/file_api.h"
#include "lib/file/handle.h"
#include "local_path.h"
#include "local_handle.h"
#include "local_unlink.h"

int
local_funlink(void *mod_priv)
{
	int ret;
	struct local_fh *local_fh = mod_priv;

	if (local_fh->path.type == LOCAL_PATH_DIR) {
		/* currently differs from cloud backends: non-recursive */
		ret = rmdir(local_fh->path.path);
		if (ret < 0) {
			ret = -errno;
			dbg(0, "rmdir failed: %s\n", strerror(-ret));
			goto err_out;
		}
	} else if (local_fh->path.type == LOCAL_PATH_FILE) {
		unlink(local_fh->path.path);
	} else {
		dbg(0, "non-dir/file deletion not supported\n");
		ret = -ENOTSUP;
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}
