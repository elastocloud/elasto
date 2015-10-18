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
#include "lib/azure_fs_path.h"
#include "lib/azure_fs_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "afs_handle.h"
#include "afs_stat.h"

static int
afs_fstat_file(struct afs_fh *afs_fh,
	       struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_fs_rsp_file_prop_get *file_prop_get_rsp;

	ret = az_fs_req_file_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	file_prop_get_rsp = az_fs_rsp_file_prop_get(op);
	if (file_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_FILE;
	fstat->size = file_prop_get_rsp->len;
	fstat->blksize = 0;
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
afs_fstat_dir(struct afs_fh *afs_fh,
	      struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_fs_rsp_dir_prop_get *dir_prop_get_rsp;

	ret = az_fs_req_dir_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	dir_prop_get_rsp = az_fs_rsp_dir_prop_get(op);
	if (dir_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
	fstat->size = 0;
	fstat->blksize = 0;
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	/* TODO add last_mod field to fstat */
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fstat_share(struct afs_fh *afs_fh,
		struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_fs_rsp_share_prop_get *share_prop_get_rsp;

	ret = az_fs_req_share_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	share_prop_get_rsp = az_fs_rsp_share_prop_get(op);
	if (share_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR;
	fstat->size = 0;
	fstat->blksize = 0;
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	/* TODO add last_mod field to fstat */
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fstat_acc(struct afs_fh *afs_fh,
	      struct elasto_fstat *fstat)
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_prop_get *acc_prop_get_rsp;

	if (afs_fh->mgmt_conn == NULL) {
		dbg(0, "Account stat requires Publish Settings "
		       "credentials\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_req_acc_prop_get(afs_fh->sub_id,
				       afs_fh->path.acc,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
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
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fstat_root(struct afs_fh *afs_fh,
	       struct elasto_fstat *fstat)
{
	/*
	 * Could issue a List Storage Accounts request here, to check
	 * subscription validity.
	 */

	fstat->ent_type = ELASTO_FSTAT_ENT_DIR | ELASTO_FSTAT_ENT_ROOT;
	fstat->size = 0;
	fstat->blksize = 0;
	fstat->lease_status = ELASTO_FLEASE_UNLOCKED;
	fstat->field_mask = ELASTO_FSTAT_FIELD_TYPE;

	return 0;
}

int
afs_fstat(void *mod_priv,
	  struct elasto_fstat *fstat)
{
	int ret;
	struct afs_fh *afs_fh = mod_priv;

	if (afs_fh->path.fs_ent != NULL) {
		if (afs_fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
			ret = afs_fstat_dir(afs_fh, fstat);
		} else {
			ret = afs_fstat_file(afs_fh, fstat);
		}
	} else if (afs_fh->path.share != NULL) {
		ret = afs_fstat_share(afs_fh, fstat);
	} else if (afs_fh->path.acc != NULL) {
		ret = afs_fstat_acc(afs_fh, fstat);
	} else {
		ret = afs_fstat_root(afs_fh, fstat);
	}
	if (ret < 0) {
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

/* same as apb - TODO move to lib/az_mgmt_req */
const struct elasto_fstatfs_region afs_regions[] = {
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
afs_fstatvfs(void *mod_priv,
	     struct elasto_fstatfs *fstatfs)
{
	/* fstatfs checked by caller */
	fstatfs->iosize_min = 1;
	fstatfs->iosize_optimal = 512;

	/*
	 * Azure File Service files are sparse and can be written at any
	 * offset. Leases are not supported via the REST interface.
	 */
	fstatfs->cap_flags = (ELASTO_FSTATFS_CAP_SPARSE
			    | ELASTO_FSTATFS_CAP_WRITE_RANGE);
	fstatfs->prop_flags = 0;

	fstatfs->num_regions = ARRAY_SIZE(afs_regions);
	fstatfs->regions = afs_regions;

	return 0;
}
