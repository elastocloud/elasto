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
#include "lib/azure_fs_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "afs_handle.h"
#include "afs_stat.h"
#include "afs_io.h"

int
afs_fwrite(void *mod_priv,
	   struct elasto_conn *conn,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_req_file_put(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
				 dest_off,
				 dest_len,
				 src_data,
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
	op->req.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
afs_fread(void *mod_priv,
	  struct elasto_conn *conn,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_req_file_get(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
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

int
afs_ftruncate(void *mod_priv,
	      struct elasto_conn *conn,
	      uint64_t len)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_req_file_prop_set(afs_fh->path.acc,
				      afs_fh->path.share,
				      afs_fh->path.parent_dir,
				      afs_fh->path.file,
				      AZ_FS_FILE_PROP_LEN,
				      len,
				      NULL,
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
	op_free(op);
err_out:
	return ret;
}

int
afs_fallocate(void *mod_priv,
	      struct elasto_conn *conn,
	      uint32_t mode,
	      uint64_t dest_off,
	      uint64_t dest_len)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	if (mode != ELASTO_FALLOC_PUNCH_HOLE) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_file_put(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
				 dest_off,
				 dest_len,
				 NULL, /* clear range */
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
	op->req.data = NULL;
	op_free(op);
err_out:
	return ret;
}
