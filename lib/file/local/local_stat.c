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
#include "lib/data.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "elasto/file.h"
#include "lib/file/handle.h"
#include "local_path.h"
#include "local_handle.h"
#include "local_stat.h"

int
local_fstat(void *mod_priv,
	    struct elasto_fstat *fstat)
{
	int ret;
	struct local_fh *local_fh = mod_priv;
	struct stat sbuf;

	ret = stat(local_fh->path.path, &sbuf);
	if (ret < 0) {
		goto err_out;
	}

	memset(fstat, 0, sizeof(*fstat));
	if (S_ISREG(sbuf.st_mode)) {
		fstat->ent_type = ELASTO_FSTAT_ENT_FILE;
		fstat->size = sbuf.st_size;
		fstat->blksize = sbuf.st_blksize;
		fstat->field_mask = (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_SIZE
					| ELASTO_FSTAT_FIELD_BSIZE);
	} else if (S_ISDIR(sbuf.st_mode)) {
		fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
		fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	} else {
		dbg(0, "open let thorugh non-dir/file\n");
		assert(false);
	}

	ret = 0;
err_out:
	return ret;
}

int
local_fstatvfs(void *mod_priv,
	       struct elasto_fstatfs *fstatfs)
{
	fstatfs->iosize_min = 1;
	/* TODO use fstatfs here */
	fstatfs->iosize_optimal = 512;

	/*
	 * local back-end supports sparse files that can be written at any
	 * offset. Leases are not supported.
	 */
	fstatfs->cap_flags = (ELASTO_FSTATFS_CAP_SPARSE
			    | ELASTO_FSTATFS_CAP_WRITE_RANGE);
	fstatfs->prop_flags = 0;

	fstatfs->num_regions = 0;
	fstatfs->regions = NULL;

	return 0;
}
