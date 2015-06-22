/*
 * Copyright (C) SUSE LINUX GmbH 2013, all rights reserved.
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
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"
#include "xmit.h"

int
elasto_fmkdir(const struct elasto_fauth *auth,
	      const char *path)
{
	int ret;
	struct elasto_fh *fh;

	/* default location */
	ret = elasto_fopen(auth, path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fclose(fh);
err_out:
	return ret;
}

int
elasto_frmdir(const struct elasto_fauth *auth,
	      const char *path)
{
	int ret;
	struct elasto_fh *fh;

	ret = elasto_fopen(auth, path, ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_funlink_close(fh);
err_out:
	return ret;
}

int
elasto_freaddir(struct elasto_fh *fh,
		void *priv,
		int (*dent_cb)(struct elasto_dent *,
			       void *))
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.readdir == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if ((fh->open_flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "invalid readdir request for non-directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = fh->ops.readdir(fh->mod_priv, fh->conn, priv, dent_cb);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}
