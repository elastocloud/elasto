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
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "s3_handle.h"
#include "s3_open.h"
#include "s3_dir.h"

int
s3_fmkdir(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path)
{
	int ret;
	struct op *op;
	struct s3_fh *s3_fh = mod_priv;

	ret = s3_fpath_parse(path, &s3_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (s3_fh->path.bkt == NULL) {
		dbg(0, "invalid mkdir path: must include S3 bucket "
		       "components\n");
		goto err_path_free;
	}
	if (s3_fh->path.obj != NULL) {
		dbg(0, "invalid mkdir path: S3 object component must not be "
		       "present\n");
		goto err_path_free;
	}

	/* NULL location, use S3 default */
	ret = s3_req_bkt_create(s3_fh->path.bkt, NULL, &op);
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
	s3_fpath_free(&s3_fh->path);
err_out:
	return ret;
}

int
s3_frmdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path)
{
	int ret;
	struct op *op;
	struct s3_fh *s3_fh = mod_priv;

	ret = s3_fpath_parse(path, &s3_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (s3_fh->path.bkt == NULL) {
		dbg(0, "invalid rmdir path: must include S3 bucket "
		       "components\n");
		goto err_path_free;
	}
	if (s3_fh->path.obj != NULL) {
		dbg(0, "invalid rmdir path: S3 object component must not be "
		       "present\n");
		goto err_path_free;
	}

	ret = s3_req_bkt_del(s3_fh->path.bkt, &op);
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
	s3_fpath_free(&s3_fh->path);
err_out:
	return ret;
}

static int
s3_freaddir_bkt(struct s3_fh *s3_fh,
		struct elasto_conn *conn,
		void *cli_priv,
		int (*dent_cb)(struct elasto_dent *,
			       void *))
{
	int ret;
	struct op *op;
	struct s3_rsp_bkt_list *bkt_list_rsp;
	struct s3_object *obj;

	ret = s3_req_bkt_list(s3_fh->path.bkt, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	bkt_list_rsp = s3_rsp_bkt_list(op);
	if (bkt_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&bkt_list_rsp->objs, obj, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = obj->key;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_FILE;
		dent.fstat.size = obj->size;
		dent.fstat.blksize = 0;	/* flag as vacant */
		dent.fstat.lease_status = ELASTO_FLEASE_UNLOCKED;
		dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_SIZE);
		ret = dent_cb(&dent, cli_priv);
		if (ret < 0) {
			/* cb requests immediate error return */
			goto err_op_free;
		}
	}

	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_freaddir_root(struct s3_fh *s3_fh,
		  struct elasto_conn *conn,
		  void *cli_priv,
		  int (*dent_cb)(struct elasto_dent *,
				 void *))
{
	int ret;
	struct op *op;
	struct s3_rsp_svc_list *svc_list_rsp;
	struct s3_bucket *bkt;

	ret = s3_req_svc_list(&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	svc_list_rsp = s3_rsp_svc_list(op);
	if (svc_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&svc_list_rsp->bkts, bkt, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = bkt->name;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
		dent.fstat.size = 0;
		dent.fstat.blksize = 0;
		dent.fstat.lease_status = ELASTO_FLEASE_UNLOCKED;
		dent.fstat.field_mask = ELASTO_FSTAT_FIELD_TYPE;
		ret = dent_cb(&dent, cli_priv);
		if (ret < 0) {
			/* cb requests immediate error return */
			goto err_op_free;
		}
	}

	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
s3_freaddir(void *mod_priv,
	    struct elasto_conn *conn,
	    void *cli_priv,
	    int (*dent_cb)(struct elasto_dent *,
			    void *))
{
	int ret;
	struct s3_fh *s3_fh = mod_priv;

	if (s3_fh->path.obj != NULL) {
		/* only applicable for directory objects */
		ret = -EINVAL;
		goto err_out;
	} else if (s3_fh->path.bkt != NULL) {
		ret = s3_freaddir_bkt(s3_fh, conn, cli_priv, dent_cb);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = s3_freaddir_root(s3_fh, conn, cli_priv, dent_cb);
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	return ret;
}
