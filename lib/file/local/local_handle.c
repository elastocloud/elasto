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
#include "local_io.h"
#include "local_open.h"
#include "local_dir.h"
#include "local_stat.h"
#include "local_unlink.h"

static int
local_fh_init(const struct elasto_fauth *auth,
	      void **_fh_priv,
	      struct elasto_fh_mod_ops *_ops)
{
	int ret;
	struct local_fh *local_fh;

	assert(auth->type == ELASTO_FILE_LOCAL);

	local_fh = malloc(sizeof(*local_fh));
	if (local_fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(local_fh, 0, sizeof(*local_fh));

	*_fh_priv = local_fh;
	*_ops = (struct elasto_fh_mod_ops){
		.fh_free = local_fh_free,
		.open = local_fopen,
		.close = local_fclose,
		.write = local_fwrite,
		.read = local_fread,
		.allocate = local_fallocate,
		.truncate = local_ftruncate,
		.splice = NULL,
		.stat = local_fstat,
		.statfs = local_fstatvfs,
		.lease_acquire = NULL,
		.lease_break = NULL,
		.lease_release = NULL,
		.lease_free = NULL,
		.readdir = local_freaddir,
		.unlink = local_funlink,
	};

	ret = 0;
err_out:
	return ret;
}

/* module version number */
uint64_t elasto_file_mod_version = ELASTO_FILE_MOD_VERS_VAL;

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_fh_mod_ops *_ops)
{
	return local_fh_init(auth, _fh_priv, _ops);
}

void
local_fh_free(void *mod_priv)
{
	struct local_fh *local_fh = mod_priv;

	free(local_fh);
}
