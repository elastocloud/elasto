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
#include <sys/types.h>
#include <dirent.h>

#include "ccan/list/list.h"
#include "lib/data.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/handle.h"
#include "local_path.h"
#include "local_handle.h"
#include "local_open.h"
#include "local_dir.h"

int
local_freaddir(void *mod_priv,
	    void *cli_priv,
	    int (*dent_cb)(struct elasto_dent *,
			    void *))
{
	int ret;
	struct local_fh *local_fh = mod_priv;
	struct dirent *dirent;

	if (local_fh->path.type != LOCAL_PATH_DIR) {
		ret = -EINVAL;
		goto err_out;
	}

	rewinddir(local_fh->dir);
	for (dirent = readdir(local_fh->dir); dirent != NULL;
					dirent = readdir(local_fh->dir)) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = dirent->d_name;

		if (dirent->d_type == DT_DIR) {
			dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
			dent.fstat.field_mask = ELASTO_FSTAT_FIELD_TYPE;
		} else if (dirent->d_type == DT_REG) {
			struct stat sbuf;

			ret = fstatat(local_fh->fd, dirent->d_name, &sbuf, 0);
			if (ret < 0) {
				ret = -errno;
				dbg(0, "fstatat failed: %s\n", strerror(-ret));
				goto err_out;
			}

			dent.fstat.ent_type = ELASTO_FSTAT_ENT_FILE;
			dent.fstat.size = sbuf.st_size;
			dent.fstat.blksize = sbuf.st_blksize;
			dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_SIZE
						| ELASTO_FSTAT_FIELD_BSIZE);
		} else {
			dbg(1, "skipping non-dir/file entry: %s\n",
			    dirent->d_name);
			continue;
		}

		ret = dent_cb(&dent, cli_priv);
		if (ret < 0) {
			/* cb requests immediate error return */
			goto err_out;
		}
	}

	ret = 0;
err_out:
	return ret;
}
