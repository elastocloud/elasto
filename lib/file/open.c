/*
 * Copyright (C) SUSE LINUX GmbH 2013-2015, all rights reserved.
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
elasto_fopen(const struct elasto_fauth *auth,
	     const char *path,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks,
	     struct elasto_fh **_fh)
{
	int ret;
	struct elasto_fh *fh;

	if (auth->type != ELASTO_FILE_AZURE) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if ((flags & ELASTO_FOPEN_FLAGS_MASK) != flags) {
		dbg(0, "invalid open flags: %lx\n", (long)flags);
		ret = -EINVAL;
		goto err_out;
	}

	ret = elasto_conn_subsys_init();
	if (ret < 0) {
		dbg(0, "failed to initialize connection subsystem\n");
		goto err_out;
	}

	ret = elasto_fh_init(auth, &fh);
	if (ret < 0) {
		dbg(0, "failed to initialize elasto fh\n");
		/* don't deinit subsystem on error */
		goto err_out;
	}

	ret = fh->ops.open(fh->mod_priv, fh->conn, path, flags, open_toks);
	if (ret < 0) {
		goto err_fh_free;
	}
	fh->open_flags = flags;

	*_fh = fh;
	return 0;

err_fh_free:
	elasto_fh_free(fh);
err_out:
	return ret;

}

int
elasto_fclose(struct elasto_fh *fh)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		return ret;
	}

	if (fh->lease_state == ELASTO_FH_LEASE_ACQUIRED) {
		dbg(4, "cleaning up lease %p on close\n", fh->flease_h);
		int ret = elasto_flease_release(fh);
		if (ret < 0) {
			dbg(0, "failed to release lease %p on close: %s\n",
			    fh->flease_h, strerror(-ret));
			/* the lid still needs to be freed on failure */
			fh->ops.lease_free(fh->mod_priv, &fh->flease_h);
		}
	}

	fh->ops.close(fh->mod_priv, fh->conn);

	elasto_fh_free(fh);

	return 0;
}

int
elasto_fdebug(int level)
{
	int ret = dbg_level_get();
	dbg_level_set(level);

	return ret;
}
