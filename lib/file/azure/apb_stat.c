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
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "apb_handle.h"
#include "apb_stat.h"

static int
apb_fstat_blob(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (!blob_prop_get_rsp->is_page) {
		/* should have been checked on open */
		dbg(0, "blob flagged as block in stat for page blob!\n");
		ret = -EINVAL;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_FILE;
	fstat->size = blob_prop_get_rsp->len;
	fstat->blksize = 512;
	if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
		fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	} else if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_LOCKED) {
		fstat->lease_status = ELASTO_FLEASE_LOCKED;
	}
	/* flag which values are valid in the stat response */
	fstat->field_mask = (ELASTO_FSTAT_FIELD_TYPE
				| ELASTO_FSTAT_FIELD_SIZE
				| ELASTO_FSTAT_FIELD_BSIZE
				| ELASTO_FSTAT_FIELD_LEASE);
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fstat_ctnr(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_rsp_ctnr_prop_get *ctnr_prop_get_rsp;

	ret = az_req_ctnr_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ctnr_prop_get_rsp = az_rsp_ctnr_prop_get(op);
	if (ctnr_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
	fstat->size = 0;
	fstat->blksize = 0;
	if (ctnr_prop_get_rsp->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
		fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	} else if (ctnr_prop_get_rsp->lease_status == AOP_LEASE_STATUS_LOCKED) {
		fstat->lease_status = ELASTO_FLEASE_LOCKED;
	}
	fstat->field_mask = (ELASTO_FSTAT_FIELD_TYPE
				| ELASTO_FSTAT_FIELD_LEASE);
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fstat_acc(struct apb_fh *apb_fh,
	      struct elasto_conn *conn,
	      struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_prop_get *acc_prop_get_rsp;

	ret = az_mgmt_req_acc_prop_get(apb_fh->sub_id,
				       apb_fh->path.acc,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	acc_prop_get_rsp = az_mgmt_rsp_acc_prop_get(op);
	if (acc_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
	fstat->size = 0;
	fstat->blksize = 0;
	/* Azure only supports leases at a container or blob level */
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fstat_root(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       struct elasto_fstat *fstat)
{
	/*
	 * Could issue a List Storage Accounts request here, to check
	 * subscription validity.
	 */

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR | ELASTO_FSTAT_ENT_ROOT;
	fstat->size = 0;
	fstat->blksize = 0;
	/* Azure only supports leases at a container or blob level */
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;

	return 0;
}

int
apb_fstat(void *mod_priv,
	  struct elasto_conn *conn,
	  struct elasto_fstat *fstat)
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	if (apb_fh->path.blob != NULL) {
		ret = apb_fstat_blob(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_fstat_ctnr(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.acc != NULL) {
		ret = apb_fstat_acc(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = apb_fstat_root(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	return ret;
}

const struct elasto_fstatfs_region apb_regions[] = {
	{"Central US", "Iowa"},
	{"East US", "Virginia"},
	{"East US 2", "Virginia"},
	{"US Gov Iowa", "Iowa"},
	{"US Gov Virginia", "Virginia"},
	{"North Central US", "Illinois"},
	{"South Central US", "Texas"},
	{"West US", "California"},
	{"North Europe", "Ireland"},
	{"West Europe", "Netherlands"},
	{"East Asia", "Hong Kong"},
	{"Southeast Asia", "Singapore"},
	{"Japan East", "Saitama Prefecture"},
	{"Japan West", "Osaka Prefecture"},
	{"Brazil South", "Sao Paulo State"},
	{"Australia East", "New South Wales"},
	{"Australia Southeast", "Victoria"},
};

int
apb_fstatvfs(void *mod_priv,
	     struct elasto_conn *conn,
	     struct elasto_fstatfs *fstatfs)
{
	/* fstatfs checked by caller */
	fstatfs->iosize_min = 512;
	fstatfs->iosize_optimal = 512;

	/* Azure Page Blobs are sparse and can be written at any offset */
	fstatfs->cap_flags = (ELASTO_FSTATFS_CAP_SPARSE
			    | ELASTO_FSTATFS_CAP_WRITE_RANGE
			    | ELASTO_FSTATFS_CAP_LEASES);
	fstatfs->prop_flags = 0;

	fstatfs->num_regions = ARRAY_SIZE(apb_regions);
	fstatfs->regions = apb_regions;

	return 0;
}

static int
abb_fstat_blob(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (blob_prop_get_rsp->is_page) {
		/* should have been checked on open */
		dbg(0, "blob flagged as page in stat for block blob!\n");
		ret = -EINVAL;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_FILE;
	fstat->size = blob_prop_get_rsp->len;
	fstat->blksize = 0;	/* leave vacant for now */
	if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
		fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	} else if (blob_prop_get_rsp->lease_status == AOP_LEASE_STATUS_LOCKED) {
		fstat->lease_status = ELASTO_FLEASE_LOCKED;
	}
	/* flag which values are valid in the stat response */
	fstat->field_mask = (ELASTO_FSTAT_FIELD_TYPE
				| ELASTO_FSTAT_FIELD_SIZE
				| ELASTO_FSTAT_FIELD_LEASE);
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
abb_fstat(void *mod_priv,
	  struct elasto_conn *conn,
	  struct elasto_fstat *fstat)
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	if (apb_fh->path.blob != NULL) {
		ret = abb_fstat_blob(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_fstat_ctnr(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.acc != NULL) {
		ret = apb_fstat_acc(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = apb_fstat_root(apb_fh, conn, fstat);
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	return ret;
}

int
abb_fstatvfs(void *mod_priv,
	     struct elasto_conn *conn,
	     struct elasto_fstatfs *fstatfs)
{
	fstatfs->iosize_min = 1;
	fstatfs->iosize_optimal = 512;

	/*
	 * Azure Block Blobs aren't sparse, nor can they be written to at
	 * arbitrary offsets.
	 */
	fstatfs->cap_flags = ELASTO_FSTATFS_CAP_LEASES;
	fstatfs->prop_flags = 0;

	fstatfs->num_regions = ARRAY_SIZE(apb_regions);
	fstatfs->regions = apb_regions;

	return 0;
}
