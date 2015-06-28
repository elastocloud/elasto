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
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "apb_handle.h"
#include "apb_unlink.h"

static int
apb_funlink_blob(struct apb_fh *apb_fh)
{
	int ret;
	struct op *op;

	ret = az_req_blob_del(apb_fh->path.acc, apb_fh->path.ctnr,
			      apb_fh->path.blob, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_funlink_ctnr(struct apb_fh *apb_fh)
{
	int ret;
	struct op *op;

	ret = az_req_ctnr_del(apb_fh->path.acc, apb_fh->path.ctnr, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_funlink_acc(struct apb_fh *apb_fh)
{
	int ret;
	struct op *op;

	ret = az_mgmt_req_acc_del(apb_fh->sub_id, apb_fh->path.acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
apb_funlink(void *mod_priv)
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	if (apb_fh->path.blob != NULL) {
		ret = apb_funlink_blob(apb_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_funlink_ctnr(apb_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.acc != NULL) {
		ret = apb_funlink_acc(apb_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		dbg(0, "root deletion not supported\n");
		ret = -ENOTSUP;
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}
