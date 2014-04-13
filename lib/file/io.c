/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
elasto_fwrite(struct elasto_fh *fh,
	      uint64_t dest_off,
	      uint64_t dest_len,
	      struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "%s range at %" PRIu64 ", len %" PRIu64 "\n",
	    (src_data == NULL ? "clearing" : "writing"),
	    dest_off, dest_len);

	ret = az_req_page_put(fh_priv->az.path.acc,
			      fh_priv->az.path.ctnr,
			      fh_priv->az.path.blob,
			      src_data,
			      dest_off,
			      dest_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
elasto_fread(struct elasto_fh *fh,
	     uint64_t src_off,
	     uint64_t src_len,
	     struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "reading range at %" PRIu64 ", len %" PRIu64 "\n",
	    src_off, src_len);

	ret = az_req_blob_get(fh_priv->az.path.acc,
			      fh_priv->az.path.ctnr,
			      fh_priv->az.path.blob,
			      true,
			      dest_data,
			      src_off,
			      src_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op->rsp.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
elasto_ftruncate(struct elasto_fh *fh,
		 uint64_t len)
{
	int ret;
	struct op *op;
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "truncating to len %" PRIu64 "\n", len);

	ret = az_req_blob_prop_set(fh_priv->az.path.acc,
				   fh_priv->az.path.ctnr,
				   fh_priv->az.path.blob,
				   true,	/* is_page */
				   len,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;
	fh_priv->len = len;

err_op_free:
	op_free(op);
err_out:
	return ret;
}
