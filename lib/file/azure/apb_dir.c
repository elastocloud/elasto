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
#include "apb_open.h"
#include "apb_dir.h"

int
apb_fmkdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = apb_fpath_parse(path, &apb_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if ((apb_fh->path.acc == NULL)
	 || (apb_fh->path.ctnr == NULL)) {
		dbg(0, "invalid mkdir path: must include account and container "
		       "components\n");
		goto err_path_free;
	}
	if (apb_fh->path.blob != NULL) {
		dbg(0, "invalid mkdir path: blob component must not be "
		       "present\n");
		goto err_path_free;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_ctnr_create(apb_fh->path.acc, apb_fh->path.ctnr,
				 &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(conn, op);
	op_free(op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = 0;
err_path_free:
	apb_fpath_free(&apb_fh->path);
err_out:
	return ret;
}

int
apb_frmdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = apb_fpath_parse(path, &apb_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if ((apb_fh->path.acc == NULL)
	 || (apb_fh->path.ctnr == NULL)) {
		dbg(0, "invalid mkdir path: must include account and container "
		       "components\n");
		goto err_path_free;
	}
	if (apb_fh->path.blob != NULL) {
		dbg(0, "invalid mkdir path: blob component must not be "
		       "present\n");
		goto err_path_free;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_ctnr_del(apb_fh->path.acc, apb_fh->path.ctnr,
			      &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(conn, op);
	op_free(op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = 0;
err_path_free:
	apb_fpath_free(&apb_fh->path);
err_out:
	return ret;
}
