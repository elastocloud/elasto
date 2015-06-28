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
#include "lib/s3_path.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "s3_handle.h"
#include "s3_unlink.h"

static int
s3_funlink_obj(struct s3_fh *s3_fh)
{
	int ret;
	struct op *op;

	ret = s3_req_obj_del(s3_fh->path.bkt,
			     s3_fh->path.obj,
			     &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
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
s3_funlink_bkt(struct s3_fh *s3_fh)
{
	int ret;
	struct op *op;

	ret = s3_req_bkt_del(s3_fh->path.bkt, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
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
s3_funlink(void *mod_priv,
	   struct elasto_conn *conn)
{
	int ret;
	struct s3_fh *s3_fh = mod_priv;

	if (s3_fh->path.obj != NULL) {
		ret = s3_funlink_obj(s3_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else if (s3_fh->path.bkt != NULL) {
		ret = s3_funlink_bkt(s3_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		dbg(0, "root deletion not supported\n");
		ret = -ENOTSUP;
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}
