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

int
elasto_fstat(struct elasto_fh *fh,
	     struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (fstat == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_prop_get(fh_priv->az.path.acc,
				   fh_priv->az.path.ctnr,
				   fh_priv->az.path.blob,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		goto err_op_free;
	}

	fh_priv->len = blob_prop_get_rsp->len;
	fstat->size = blob_prop_get_rsp->len;
	fstat->blksize = 512;
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}
