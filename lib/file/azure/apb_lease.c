/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#include "lib/azure_blob_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "apb_handle.h"
#include "apb_lease.h"

struct apb_flease {
	char *lid;
};

void
apb_flease_free(void *mod_priv,
		void **_flease_h)
{
	struct apb_flease *lease;

	if (_flease_h == NULL) {
		dbg(0, "NULL lease handle for free!\n");
		return;
	}

	lease = *_flease_h;

	if (lease == NULL) {
		return;
	}
	free(lease->lid);
	free(lease);
	*_flease_h = NULL;
}

/*
 * @duration: Lease duration in seconds. -1 is indefinite, otherwise it must be
 *	      between 15 and 60 seconds.
 * @_flease_h: lease handle assigned by provider, allocated and returned on
 *	       success.
 */
int
apb_flease_acquire(void *mod_priv,
		   struct elasto_conn *conn,
		   int32_t duration,
		   void **_flease_h)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_lease *blob_lease_rsp;
	struct apb_flease *lease;
	struct apb_fh *apb_fh = mod_priv;

	if (_flease_h == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_lease(apb_fh->path.acc,
				apb_fh->path.ctnr,
				apb_fh->path.blob,
				NULL,
				NULL,
				AOP_LEASE_ACTION_ACQUIRE,
				duration,
				&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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

	lease = malloc(sizeof(*lease));
	if (lease == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	lease->lid = strdup(blob_lease_rsp->lid);
	if (lease->lid == NULL) {
		ret = -ENOMEM;
		goto err_lease_free;
	}

	dbg(3, "got lease %s\n", lease->lid);

	*_flease_h = lease;
	op_free(op);
	return 0;

err_lease_free:
	free(lease);
err_op_free:
	op_free(op);
err_out:
	return ret;
}

/* @_flease_h is optional */
int
apb_flease_break(void *mod_priv,
		 struct elasto_conn *conn,
		 void **_flease_h)
{
	int ret;
	char *lid = NULL;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	if (_flease_h == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (*_flease_h != NULL) {
		struct apb_flease *lease = *_flease_h;
		lid = lease->lid;
	}

	ret = az_req_blob_lease(apb_fh->path.acc,
				apb_fh->path.ctnr,
				apb_fh->path.blob,
				lid,
				NULL,
				AOP_LEASE_ACTION_BREAK,
				0,
				&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	dbg(3, "broke lease %s\n", (lid ? lid: "unknown"));

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
apb_flease_release(void *mod_priv,
		   struct elasto_conn *conn,
		   void **_flease_h)
{
	int ret;
	struct op *op;
	struct apb_flease *lease;
	struct az_rsp_blob_lease *blob_lease_rsp;
	struct apb_fh *apb_fh = mod_priv;

	if (_flease_h == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	lease = *_flease_h;
	if (lease == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_lease(apb_fh->path.acc,
				apb_fh->path.ctnr,
				apb_fh->path.blob,
				lease->lid,
				NULL,
				AOP_LEASE_ACTION_RELEASE,
				0,
				&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_lease_rsp = az_rsp_blob_lease_get(op);

	dbg(3, "released lease %s\n", blob_lease_rsp->lid);

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}
