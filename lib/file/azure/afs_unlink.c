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
#include "afs_handle.h"
#include "afs_unlink.h"

static int
afs_funlink_file(struct afs_fh *afs_fh)
{
	int ret;
	struct op *op;

	ret = az_fs_req_file_del(afs_fh->path.acc, afs_fh->path.share,
				 afs_fh->path.parent_dir, afs_fh->path.file,
				 &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
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
afs_funlink_dir(struct afs_fh *afs_fh)
{
	int ret;
	struct op *op;

	ret = az_fs_req_dir_del(afs_fh->path.acc, afs_fh->path.share,
				afs_fh->path.parent_dir, afs_fh->path.dir, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
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
afs_funlink_share(struct afs_fh *afs_fh)
{
	int ret;
	struct op *op;

	ret = az_fs_req_share_del(afs_fh->path.acc, afs_fh->path.share, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
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
afs_funlink_acc(struct afs_fh *afs_fh)
{
	int ret;
	struct op *op;

	ret = az_mgmt_req_acc_del(afs_fh->sub_id, afs_fh->path.acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
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
afs_funlink(void *mod_priv,
	    struct elasto_conn *conn)
{
	int ret;
	struct afs_fh *afs_fh = mod_priv;

	if (afs_fh->path.fs_ent != NULL) {
		if (afs_fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
			ret = afs_funlink_dir(afs_fh);
		} else {
			ret = afs_funlink_file(afs_fh);
		}
	} else if (afs_fh->path.share != NULL) {
		ret = afs_funlink_share(afs_fh);
		if (ret < 0) {
			goto err_out;
		}
	} else if (afs_fh->path.acc != NULL) {
		ret = afs_funlink_acc(afs_fh);
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
