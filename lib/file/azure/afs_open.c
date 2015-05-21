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
#include "afs_open.h"

#define AFS_FOPEN_LOCATION_DEFAULT "West Europe"

int
afs_fpath_parse(const char *path,
		struct elasto_fh_afs_path *afs_path)
{
	int ret;
	char *s;
	char *comp1 = NULL;
	char *comp2 = NULL;
	char *midpart = NULL;
	char *trailer = NULL;

	if ((path == NULL) || (afs_path == NULL)) {
		return -EINVAL;
	}

	s = (char *)path;
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		goto done;
	}

	comp1 = strdup(s);
	if (comp1 == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(comp1, '/');
	if (s == NULL) {
		/* acc only */
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* acc + slashes only */
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s == NULL) {
		/* share only */
		goto done;
	}

	*(s++) = '\0';	/* null term for share */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* share + slashes only */
		goto done;
	}

	midpart = strdup(s);
	if (midpart == NULL) {
		ret = -ENOMEM;
		goto err_2_free;
	}

	/* need last component as dir or share */
	s = strrchr(midpart, '/');
	if (s == NULL) {
		/* midpart is the last path component */
		trailer = midpart;
		midpart = NULL;
		goto done;
	}

	if (strlen(s) <= 1) {
		/* trailing slash - FIXME: should allow this for dir opens? */
		dbg(0, "invalid path, trailing garbage: %s\n", midpart);
		goto err_midpart_free;
	}

	s++;	/* move past last slash */
	trailer = strdup(s);
	if (trailer == NULL) {
		ret = -ENOMEM;
		goto err_midpart_free;
	}

	s--;	/* move back to last slash */
	while (*s == '/') {
		*s = '\0';	/* null term for midpart */
		s--;
	}

	assert(s >= midpart);

done:
	afs_path->acc = comp1;
	afs_path->share = comp2;
	afs_path->parent_dir = midpart;
	/* fs_ent, file or dir. all are members of the same union */
	afs_path->fs_ent = trailer;
	dbg(2, "parsed %s as AFS path: acc=%s, share=%s, parent_dir=%s, "
	       "file or dir=%s\n",
	    path, (afs_path->acc ? afs_path->acc : ""),
	    (afs_path->share ? afs_path->share : ""),
	    (afs_path->parent_dir ? afs_path->parent_dir : ""),
	    (afs_path->fs_ent ? afs_path->fs_ent : ""));

	return 0;

err_midpart_free:
	free(midpart);
err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_out:
	return ret;
}

void
afs_fpath_free(struct elasto_fh_afs_path *afs_path)
{
	free(afs_path->acc);
	afs_path->acc = NULL;
	free(afs_path->share);
	afs_path->share = NULL;
	free(afs_path->parent_dir);
	afs_path->parent_dir = NULL;
	/* file and dir are members of the same union */
	free(afs_path->fs_ent);
	afs_path->fs_ent = NULL;
}

/* XXX dup of cli_sign_conn_setup */
int
afs_fsign_conn_setup(struct elasto_conn *conn,
		     const char *sub_id,
		     const char *acc)
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp;

	ret = az_mgmt_req_acc_keys_get(sub_id, acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	acc_keys_get_rsp = az_mgmt_rsp_acc_keys_get(op);
	if (acc_keys_get_rsp == NULL) {
		goto err_op_free;
	}

	ret = elasto_conn_sign_setkey(conn, acc, acc_keys_get_rsp->primary);
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
afs_fopen_file(struct afs_fh *afs_fh,
	       struct elasto_conn *conn,
	       uint64_t flags)
{
	int ret;
	struct op *op;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open file with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = afs_fsign_conn_setup(conn, afs_fh->sub_id, afs_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_req_file_prop_get(afs_fh->path.acc,
				   afs_fh->path.share,
				   afs_fh->path.parent_dir,
				   afs_fh->path.file,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "file already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "file not found, creating\n");
		op_free(op);
		ret = az_fs_req_file_create(afs_fh->path.acc,
					    afs_fh->path.share,
					    afs_fh->path.parent_dir,
					    afs_fh->path.file,
					    0,	/* initial size */
					    &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		goto done;
	} else if (ret < 0) {
		goto err_op_free;
	}

done:
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fopen_dir(struct afs_fh *afs_fh,
	      struct elasto_conn *conn,
	      uint64_t flags)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open dir without directory flag\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = afs_fsign_conn_setup(conn, afs_fh->sub_id, afs_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_req_dir_prop_get(afs_fh->path.acc,
				     afs_fh->path.share,
				     afs_fh->path.parent_dir,
				     afs_fh->path.dir,
				     &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_fs_req_dir_create(afs_fh->path.acc,
					   afs_fh->path.share,
					   afs_fh->path.parent_dir,
					   afs_fh->path.dir,
					   &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		goto done;
	} else if (ret < 0) {
		goto err_op_free;
	}

done:
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}


static int
afs_fopen_share(struct afs_fh *afs_fh,
		struct elasto_conn *conn,
		uint64_t flags)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open share without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = afs_fsign_conn_setup(conn, afs_fh->sub_id, afs_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_fs_req_share_prop_get(afs_fh->path.acc,
				       afs_fh->path.share,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_fs_req_share_create(afs_fh->path.acc,
					     afs_fh->path.share,
					     &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
	} else if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

#define APB_OP_POLL_PERIOD 2
#define APB_OP_POLL_TIMEOUT 10	/* multiplied by APB_OP_POLL_PERIOD */

static int
afs_fopen_acc_create_wait(struct afs_fh *afs_fh,
			  struct elasto_conn *conn,
			  const char *req_id)
{
	struct op *op;
	int i;
	enum az_req_status status;
	int err_code;
	int ret;

	for (i = 0; i < APB_OP_POLL_TIMEOUT; i++) {
		struct az_mgmt_rsp_status_get *sts_get_rsp;

		ret = az_mgmt_req_status_get(afs_fh->sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		sts_get_rsp = az_mgmt_rsp_status_get(op);
		if (sts_get_rsp == NULL) {
			ret = -ENOMEM;
			goto err_op_free;
		}

		if (sts_get_rsp->status != AOP_STATUS_IN_PROGRESS) {
			status = sts_get_rsp->status;
			if (sts_get_rsp->status == AOP_STATUS_FAILED) {
				err_code = sts_get_rsp->err.code;
			}
			op_free(op);
			break;
		}

		op_free(op);

		sleep(APB_OP_POLL_PERIOD);
	}

	if (i >= APB_OP_POLL_TIMEOUT) {
		dbg(0, "timeout waiting for req %s to complete\n", req_id);
		ret = -ETIMEDOUT;
		goto err_out;
	}
	if (status == AOP_STATUS_FAILED) {
		ret = -EIO;
		dbg(0, "failed async response: %d\n", err_code);
		goto err_out;
	} else {
		dbg(3, "create completed successfully\n");
	}

	return 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

/* FIXME duplicate of apb_fopen_acc */
static int
afs_fopen_acc(struct afs_fh *afs_fh,
	      struct elasto_conn *conn,
	      uint64_t flags,
	      struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open account without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_req_acc_prop_get(afs_fh->sub_id, afs_fh->path.acc,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		const char *location;

		dbg(4, "path not found, creating\n");
		op_free(op);

		ret = elasto_ftoken_find(open_toks,
					 ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					 &location);
		if (ret == -ENOENT) {
			location = AFS_FOPEN_LOCATION_DEFAULT;
			dbg(1, "location token not specified for new account "
			    "%s, using default: %s\n",
			    afs_fh->path.acc, location);
		}

		ret = az_mgmt_req_acc_create(afs_fh->sub_id,
					     afs_fh->path.acc,
					     afs_fh->path.acc, /* label */
					     NULL,	       /* description */
					     NULL,	       /* affin group */
					     location,
					     &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.err_code == 202) {
			ret = afs_fopen_acc_create_wait(afs_fh, conn,
							op->rsp.req_id);
			if (ret < 0) {
				goto err_op_free;
			}
		}
	} else if (ret < 0) {
		dbg(4, "failed to retrieve account properties: %s\n",
		    strerror(-ret));
		goto err_op_free;
	}

	/*
	 * signing setup not needed for mgmt reqs, but in case of readdir
	 * (List Containers)
	 */
	ret = afs_fsign_conn_setup(conn, afs_fh->sub_id, afs_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}


	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fopen_root(struct afs_fh *afs_fh,
	       struct elasto_conn *conn,
	       uint64_t flags)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open account without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (flags & (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL)) {
		dbg(1, "invalid flag for root open\n");
		ret = -EINVAL;
		goto err_out;
	}

	/*
	 * XXX use the heavy-weight List Storage Accounts request to check that
	 * the subscription information is correct at open time.
	 */
	ret = az_mgmt_req_acc_list(afs_fh->sub_id, &op);
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
afs_fopen(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct afs_fh *afs_fh = mod_priv;

	ret = afs_fpath_parse(path, &afs_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (afs_fh->path.fs_ent != NULL) {
		if (flags & ELASTO_FOPEN_DIRECTORY) {
			ret = afs_fopen_dir(afs_fh, conn, flags);
		} else {
			ret = afs_fopen_file(afs_fh, conn, flags);
		}
	} else if (afs_fh->path.share != NULL) {
		ret = afs_fopen_share(afs_fh, conn, flags);
	} else if (afs_fh->path.acc != NULL) {
		ret = afs_fopen_acc(afs_fh, conn, flags, open_toks);
	} else {
		ret = afs_fopen_root(afs_fh, conn, flags);
	}
	if (ret < 0) {
		goto err_path_free;
	}
	afs_fh->open_flags = flags;

	return 0;

err_path_free:
	afs_fpath_free(&afs_fh->path);
err_out:
	return ret;
}

int
afs_fclose(void *mod_priv,
	   struct elasto_conn *conn)
{
	struct afs_fh *afs_fh = mod_priv;

	afs_fpath_free(&afs_fh->path);

	return 0;
}
