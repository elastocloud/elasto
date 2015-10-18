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
#include "lib/azure_blob_path.h"
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
#include "apb_open.h"
#include "apb_dir.h"

static int
apb_freaddir_ctnr(struct apb_fh *apb_fh,
		  void *cli_priv,
		  int (*dent_cb)(struct elasto_dent *,
				 void *))
{
	int ret;
	struct op *op;
	struct az_rsp_blob_list *blob_list_rsp;
	struct azure_blob *blob;

	ret = az_req_blob_list(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	blob_list_rsp = az_rsp_blob_list(op);
	if (blob_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&blob_list_rsp->blobs, blob, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = blob->name;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_FILE;
		dent.fstat.size = blob->len;
		dent.fstat.blksize = 512;
		if (blob->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
			dent.fstat.lease_status = ELASTO_FLEASE_UNLOCKED;
		} else if (blob->lease_status == AOP_LEASE_STATUS_LOCKED) {
			dent.fstat.lease_status = ELASTO_FLEASE_LOCKED;
		}
		/* flag which values are valid in the stat response */
		dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_SIZE
					| ELASTO_FSTAT_FIELD_BSIZE
					| ELASTO_FSTAT_FIELD_LEASE);

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
apb_freaddir_acc(struct apb_fh *apb_fh,
		 void *cli_priv,
		 int (*dent_cb)(struct elasto_dent *,
				void *))
{
	int ret;
	struct op *op;
	struct az_rsp_ctnr_list *ctnr_list_rsp;
	struct azure_ctnr *ctnr;

	ret = az_req_ctnr_list(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ctnr_list_rsp = az_rsp_ctnr_list(op);
	if (ctnr_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&ctnr_list_rsp->ctnrs, ctnr, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = ctnr->name;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
		dent.fstat.size = 0;
		dent.fstat.blksize = 512;
		if (ctnr->lease_status == AOP_LEASE_STATUS_UNLOCKED) {
			dent.fstat.lease_status = ELASTO_FLEASE_UNLOCKED;
		} else if (ctnr->lease_status == AOP_LEASE_STATUS_LOCKED) {
			dent.fstat.lease_status = ELASTO_FLEASE_LOCKED;
		}
		dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_BSIZE
					| ELASTO_FSTAT_FIELD_LEASE);
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
apb_freaddir_root(struct apb_fh *apb_fh,
		  void *cli_priv,
		  int (*dent_cb)(struct elasto_dent *,
				 void *))
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_list *acc_list_rsp;
	struct azure_account *acc;

	/* root open guarantees that mgmt conn is established */

	ret = az_mgmt_req_acc_list(apb_fh->sub_id, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	acc_list_rsp = az_mgmt_rsp_acc_list(op);
	if (acc_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&acc_list_rsp->accs, acc, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = acc->svc_name;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
		dent.fstat.size = 0;
		dent.fstat.blksize = 512;
		/* Azure only supports leases at a container or blob level */
		dent.fstat.lease_status = ELASTO_FLEASE_UNLOCKED;
		dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_BSIZE);
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
apb_freaddir(void *mod_priv,
	     void *cli_priv,
	     int (*dent_cb)(struct elasto_dent *,
			      void *))
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	if (apb_fh->path.blob != NULL) {
		/* only applicable for directory objects */
		ret = -EINVAL;
		goto err_out;
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_freaddir_ctnr(apb_fh, cli_priv, dent_cb);
		if (ret < 0) {
			goto err_out;
		}
	} else if (apb_fh->path.acc != NULL) {
		ret = apb_freaddir_acc(apb_fh, cli_priv, dent_cb);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		ret = apb_freaddir_root(apb_fh, cli_priv, dent_cb);
		if (ret < 0) {
			goto err_out;
		}
	}

	return 0;

err_out:
	return ret;
}
