/*
 * Copyright (C) SUSE LINUX GmbH 2014-2015, all rights reserved.
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

/*
 * @duration: Lease duration in seconds. -1 is indefinite, otherwise it must be
 *	      between 15 and 60 seconds.
 * @_lid: lease ID assigned by provider, allocated and returned on success.
 */
int
elasto_flease_acquire(struct elasto_fh *fh,
		     int32_t duration)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	/* ensure back-end supports request */
	if (fh->ops.lease_acquire == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->lease_state != ELASTO_FH_LEASE_NONE) {
		dbg(2, "bad attempt to acquire lease while in %d state\n",
		    fh->lease_state);
		ret = -EINVAL;
		goto err_out;
	}

	ret = fh->ops.lease_acquire(fh->mod_priv, fh->conn,
				    duration, &fh->lid);
	if (ret < 0) {
		goto err_out;
	}

	fh->lease_state = ELASTO_FH_LEASE_ACQUIRED;

	ret = 0;
err_out:
	return ret;
}

int
elasto_flease_break(struct elasto_fh *fh)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	/* ensure back-end supports request */
	if (fh->ops.lease_break == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	/* fh->lid may be NULL, will be freed if non-null */
	ret = fh->ops.lease_break(fh->mod_priv, fh->conn,
				  &fh->lid);
	if (ret < 0) {
		goto err_out;
	}

	fh->lease_state = ELASTO_FH_LEASE_NONE;

	ret = 0;
err_out:
	return ret;
}

int
elasto_flease_release(struct elasto_fh *fh)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	/* ensure back-end supports request */
	if (fh->ops.lease_release == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->lease_state != ELASTO_FH_LEASE_ACQUIRED) {
		ret = -EINVAL;
		goto err_out;
	}

	if (fh->lid == NULL) {
		dbg(0, "invalid release with NULL lease id\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* fh->lid will be freed and zeroed */
	ret = fh->ops.lease_release(fh->mod_priv, fh->conn, &fh->lid);
	if (ret < 0) {
		goto err_out;
	}

	fh->lease_state = ELASTO_FH_LEASE_NONE;

	ret = 0;
err_out:
	return ret;
}
