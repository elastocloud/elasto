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
#include "s3_stat.h"
#include "s3_io.h"

int
s3_fwrite(void *mod_priv,
	  struct elasto_conn *conn,
	  uint64_t dest_off,
	  uint64_t dest_len,
	  struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct elasto_fstat fstat;
	struct s3_fh *s3_fh = mod_priv;

	if (dest_len == 0) {
		ret = 0;
		goto err_out;
	}

	if (dest_off != 0) {
		/* https://forums.aws.amazon.com/thread.jspa?threadID=10752 */
		dbg(0, "S3 doesn't allow writes at arbitrary offsets\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* check current length <= dest_len, otherwise overwrite truncates */
	ret = s3_fstat(mod_priv, conn, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size > dest_len) {
		dbg(0, "S3 backend doesn't allow overwrites when IO len (%"
		    PRIu64 ") < current len (%" PRIu64 ")\n",
		    dest_len, fstat.size);
		ret = -EINVAL;
		goto err_out;
	}

	/* TODO split large IOs into multi-part uploads */
	ret = s3_req_obj_put(s3_fh->path.bkt,
			     s3_fh->path.obj,
			     src_data, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
s3_fread(void *mod_priv,
	 struct elasto_conn *conn,
	 uint64_t src_off,
	 uint64_t src_len,
	 struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct s3_fh *s3_fh = mod_priv;

	ret = s3_req_obj_get(s3_fh->path.bkt,
			      s3_fh->path.obj,
			      src_off,
			      src_len,
			      dest_data,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
