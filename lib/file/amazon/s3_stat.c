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
#include "s3_stat.h"

static int
s3_fstat_obj(struct s3_fh *s3_fh,
	     struct elasto_conn *conn,
	     struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct s3_rsp_obj_head *obj_head_rsp;

	ret = s3_req_obj_head(s3_fh->path.bkt,
			      s3_fh->path.obj,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	obj_head_rsp = s3_rsp_obj_head(op);
	if (obj_head_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_FILE;
	fstat->size = obj_head_rsp->len;
	fstat->blksize = 0;	/* leave vacant for now */
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	/* flag which values are valid in the stat response */
	fstat->field_mask = (ELASTO_FSTAT_FIELD_TYPE
				| ELASTO_FSTAT_FIELD_SIZE);
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fstat_bkt(struct s3_fh *s3_fh,
	     struct elasto_conn *conn,
	     struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct s3_rsp_bkt_loc_get *bkt_loc_get_rsp;

	ret = s3_req_bkt_loc_get(s3_fh->path.bkt, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	bkt_loc_get_rsp = s3_rsp_bkt_loc_get(op);
	if (bkt_loc_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}
	/* TODO location not packed in fstat yet */

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
	fstat->size = 0;
	fstat->blksize = 0;	/* leave vacant for now */
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fstat_root(struct s3_fh *s3_fh,
	       struct elasto_conn *conn,
	       struct elasto_fstat *fstat)
{
	/*
	 * Could issue a GET Service request here, to check subscription
	 * validity, but it's already done on open.
	 */
	fstat->ent_type = ELASTO_FSTAT_ENT_DIR | ELASTO_FSTAT_ENT_ROOT;
	fstat->size = 0;
	fstat->blksize = 0;	/* leave vacant for now */
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;

	return 0;
}

int
s3_fstat(void *mod_priv,
	 struct elasto_conn *conn,
	 struct elasto_fstat *fstat)
{
	int ret;
	struct s3_fh *s3_fh = mod_priv;

	if (s3_fh->path.obj != NULL) {
		ret = s3_fstat_obj(s3_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else if (s3_fh->path.bkt != NULL) {
		ret = s3_fstat_bkt(s3_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = s3_fstat_root(s3_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	return ret;
}

const struct elasto_fstatfs_region s3_regions[] = {
	{"US Standard", "us-east-1"},
	{"US West (Oregon)", "us-west-2"},
	{"US West (N. California)", "us-west-1"},
	{"EU (Ireland)", "eu-west-1"},
	{"EU (Frankfurt)", "eu-central-1"},
	{"Asia Pacific (Singapore)", "ap-southeast-1"},
	{"Asia Pacific (Sydney)", "ap-southeast-2"},
	{"Asia Pacific (Tokyo)", "ap-northeast-1"},
	{"South America (Sao Paulo)", "sa-east-1"},
};

int
s3_fstatvfs(void *mod_priv,
	    struct elasto_conn *conn,
	    struct elasto_fstatfs *fstatfs)
{
	fstatfs->iosize_min = 1;
	fstatfs->iosize_optimal = 512;

	/*
	 * S3 objects aren't sparse, nor can they be written to at arbitrary
	 * offsets - no capabilities!
	 */
	fstatfs->cap_flags = 0;
	fstatfs->prop_flags = 0;

	fstatfs->num_regions = ARRAY_SIZE(s3_regions);
	fstatfs->regions = s3_regions;

	return 0;
}
