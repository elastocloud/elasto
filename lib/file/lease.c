/*
 * Copyright (C) SUSE LINUX Products GmbH 2014, all rights reserved.
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

#include <curl/curl.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
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
	struct op *op;
	struct az_rsp_blob_lease *blob_lease_rsp;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (fh_priv->lease_state != ELASTO_FH_LEASE_NONE) {
		dbg(2, "bad attempt to acquire lease while in %d state\n",
		    fh_priv->lease_state);
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_lease(fh_priv->az.path.acc,
				fh_priv->az.path.ctnr,
				fh_priv->az.path.blob,
				NULL,
				NULL,
				AOP_LEASE_ACTION_ACQUIRE,
				duration,
				&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_lease_rsp = az_rsp_blob_lease_get(op);
	if ((blob_lease_rsp->lid == NULL)
				|| (strlen(blob_lease_rsp->lid) == 0 )) {
		ret = -ENOENT;
		dbg(0, "failed to fetch lease ID on success\n");
		goto err_op_free;
	}

	/* save this with @fh */
	fh_priv->az.lid = strdup(blob_lease_rsp->lid);
	if (fh_priv->az.lid == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fh_priv->lease_state = ELASTO_FH_LEASE_ACQUIRED;

	dbg(3, "acquired lease %s for %" PRIu64 " seconds\n",
	    blob_lease_rsp->lid, blob_lease_rsp->time_remaining);

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
elasto_flease_release(struct elasto_fh *fh)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_lease *blob_lease_rsp;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (fh_priv->lease_state != ELASTO_FH_LEASE_ACQUIRED) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_lease(fh_priv->az.path.acc,
				fh_priv->az.path.ctnr,
				fh_priv->az.path.blob,
				fh_priv->az.lid,
				NULL,
				AOP_LEASE_ACTION_RELEASE,
				0,
				&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_lease_rsp = az_rsp_blob_lease_get(op);
	dbg(3, "released lease %s\n", blob_lease_rsp->lid);
	free(fh_priv->az.lid);
	fh_priv->az.lid = NULL;
	fh_priv->lease_state = ELASTO_FH_LEASE_NONE;

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}
