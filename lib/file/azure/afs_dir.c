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
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "afs_handle.h"
#include "afs_open.h"
#include "afs_dir.h"

static int
afs_freaddir_share(struct afs_fh *afs_fh,
		   void *cli_priv,
		   int (*dent_cb)(struct elasto_dent *,
				  void *))
{
	int ret;
	struct op *op;
	struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp;
	char *dir_path = NULL;
	struct az_fs_ent *fs_ent;

	if (afs_fh->path.dir != NULL) {
		/* listing under a subdir, rather than the share itself */
		const char *pd = afs_fh->path.parent_dir;
		ret = asprintf(&dir_path, "%s%s%s",
			       (pd ? pd : ""), (pd ? "/" : ""),
			       afs_fh->path.dir);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	ret = az_fs_req_dirs_files_list(afs_fh->path.acc,
					afs_fh->path.share,
					dir_path, &op);
	free(dir_path);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	if (dirs_files_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&dirs_files_list_rsp->ents, fs_ent, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		if (fs_ent->type == AZ_FS_ENT_TYPE_FILE) {
			dent.fstat.ent_type = ELASTO_FSTAT_ENT_FILE;
			dent.name = fs_ent->file.name;
			dent.fstat.size = fs_ent->file.size;
			dent.fstat.field_mask = (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_SIZE);
		} else if (fs_ent->type == AZ_FS_ENT_TYPE_DIR) {
			dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
			dent.name = fs_ent->dir.name;
			dent.fstat.field_mask = ELASTO_FSTAT_FIELD_TYPE;
		} else {
			dbg(0, "invalid fs_ent type: %d\n", (int)fs_ent->type);
			ret = -EINVAL;
			goto err_op_free;
		}

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
afs_freaddir_acc(struct afs_fh *afs_fh,
		 void *cli_priv,
		 int (*dent_cb)(struct elasto_dent *,
				void *))
{
	int ret;
	struct op *op;
	struct az_fs_rsp_shares_list *shares_list_rsp;
	struct az_fs_share *share;

	ret = az_fs_req_shares_list(afs_fh->path.acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	shares_list_rsp = az_fs_rsp_shares_list(op);
	if (shares_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	list_for_each(&shares_list_rsp->shares, share, list) {
		struct elasto_dent dent;

		memset(&dent, 0, sizeof(dent));
		dent.name = share->name;
		dent.fstat.ent_type = ELASTO_FSTAT_ENT_DIR;
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

static int
afs_freaddir_root(struct afs_fh *afs_fh,
		  void *cli_priv,
		  int (*dent_cb)(struct elasto_dent *,
				 void *))
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_list *acc_list_rsp;
	struct azure_account *acc;

	ret = az_mgmt_req_acc_list(afs_fh->sub_id,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
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
afs_freaddir(void *mod_priv,
	     void *cli_priv,
	     int (*dent_cb)(struct elasto_dent *,
			      void *))
{
	int ret;
	struct afs_fh *afs_fh = mod_priv;

	/* vfs already confirms non-file directory */
	if ((afs_fh->path.dir != NULL)
	 || (afs_fh->path.share != NULL)) {
		/* fn capable of listing dirs, or directly beneath shares */
		ret = afs_freaddir_share(afs_fh, cli_priv, dent_cb);
	} else if (afs_fh->path.acc != NULL) {
		ret = afs_freaddir_acc(afs_fh, cli_priv, dent_cb);
	} else {
		ret = afs_freaddir_root(afs_fh, cli_priv, dent_cb);
	}
	if (ret < 0) {
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}
