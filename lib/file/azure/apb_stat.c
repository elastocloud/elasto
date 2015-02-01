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
#include "apb_stat.h"

int
apb_fstat(void *mod_priv,
	  struct elasto_conn *conn,
	  struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	/* fstat checked by caller */
	fstat->size = blob_prop_get_rsp->len;
	fstat->blksize = 512;
	if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
		fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	} else if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_LOCKED) {
		fstat->lease_status = ELASTO_FLEASE_LOCKED;
	}
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}
