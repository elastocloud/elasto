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
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "apb_handle.h"
#include "apb_open.h"

#define APB_FOPEN_LOCATION_DEFAULT "West Europe"

int
apb_fpath_parse(const char *path,
		struct elasto_fh_az_path *az_path)
{
	int ret;
	char *s;
	char *comp1 = NULL;
	char *comp2 = NULL;
	char *comp3 = NULL;

	if ((path == NULL) || (az_path == NULL)) {
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
		/* account only */
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* account + slashes only */
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s == NULL) {
		/* ctnr only */
		goto done;
	}

	*(s++) = '\0';	/* null term for ctnr */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* container + slashes only */
		goto done;
	}

	comp3 = strdup(s);
	if (comp3 == NULL) {
		ret = -ENOMEM;
		goto err_2_free;
	}

	s = strchr(comp3, '/');
	if (s != NULL) {
		/* blob has a trailing slash */
		dbg(0, "Invalid remote path: blob has trailing garbage");
		ret = -EINVAL;
		goto err_3_free;
	}
done:
	az_path->acc = comp1;
	az_path->ctnr = comp2;
	az_path->blob = comp3;
	dbg(2, "parsed %s as APB path: acc=%s, ctnr=%s, blob=%s\n",
	    path, (az_path->acc ? az_path->acc : ""),
	    (az_path->ctnr ? az_path->ctnr : ""),
	    (az_path->blob ? az_path->blob : ""));

	return 0;

err_3_free:
	free(comp3);
err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_out:
	return ret;
}

void
apb_fpath_free(struct elasto_fh_az_path *az_path)
{
	free(az_path->acc);
	az_path->acc = NULL;
	free(az_path->ctnr);
	az_path->ctnr = NULL;
	free(az_path->blob);
	az_path->blob = NULL;
}

int
apb_fsign_conn_setup(struct elasto_conn *conn,
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
apb_fopen_blob(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       uint64_t flags)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open blob with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
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
		ret = az_req_blob_put(apb_fh->path.acc, apb_fh->path.ctnr,
				      apb_fh->path.blob, NULL, 0,
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

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		goto err_op_free;
	}

	if (!blob_prop_get_rsp->is_page) {
		dbg(0, "invalid request to open non-page blob via page blob "
		    "backend\n");
		ret = -EINVAL;
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
abb_fopen_blob(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       uint64_t flags)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open blob with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
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
		struct elasto_data *data;
		/* put a zero length block blob */
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = elasto_data_iov_new(NULL, 0, false, &data);
		if (ret < 0) {
			goto err_out;
		}
		ret = az_req_blob_put(apb_fh->path.acc, apb_fh->path.ctnr,
				      apb_fh->path.blob, data, 0,
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

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		goto err_op_free;
	}

	if (blob_prop_get_rsp->is_page) {
		dbg(0, "invalid request to open page blob via block blob "
		    "backend\n");
		ret = -EINVAL;
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
apb_fopen_ctnr(struct apb_fh *apb_fh,
	       struct elasto_conn *conn,
	       uint64_t flags)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open container without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_req_ctnr_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
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
		ret = az_req_ctnr_create(apb_fh->path.acc, apb_fh->path.ctnr,
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

/* FIXME duplicate of cli_op_wait() */
static int
apb_fopen_acc_create_wait(struct apb_fh *apb_fh,
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

		ret = az_mgmt_req_status_get(apb_fh->sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_conn_op_txrx(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.is_error) {
			ret = -EIO;
			dbg(0, "failed get status response: %d\n",
			       op->rsp.err_code);
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

static int
apb_fopen_acc(struct apb_fh *apb_fh,
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

	ret = az_mgmt_req_acc_prop_get(apb_fh->sub_id, apb_fh->path.acc,
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
			location = APB_FOPEN_LOCATION_DEFAULT;
			dbg(1, "location token not specified for new account "
			    "%s, using default: %s\n",
			    apb_fh->path.acc, location);
		}

		ret = az_mgmt_req_acc_create(apb_fh->sub_id,
					     apb_fh->path.acc,
					     apb_fh->path.acc, /* label */
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
			ret = apb_fopen_acc_create_wait(apb_fh, conn,
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
	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
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
apb_fopen_root(struct apb_fh *apb_fh,
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
	ret = az_mgmt_req_acc_list(apb_fh->sub_id, &op);
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

static int
apb_abb_fopen(void *mod_priv,
	      struct elasto_conn *conn,
	      const char *path,
	      uint64_t flags,
	      struct elasto_ftoken_list *open_toks,
	      bool page_blob)
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	ret = apb_fpath_parse(path, &apb_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (apb_fh->path.blob != NULL) {
		if (page_blob) {
			ret = apb_fopen_blob(apb_fh, conn, flags);
		} else {
			ret = abb_fopen_blob(apb_fh, conn, flags);
		}
		if (ret < 0) {
			goto err_path_free;
		}
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_fopen_ctnr(apb_fh, conn, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	} else if (apb_fh->path.acc != NULL) {
		ret = apb_fopen_acc(apb_fh, conn, flags, open_toks);
		if (ret < 0) {
			goto err_path_free;
		}
	} else {
		ret = apb_fopen_root(apb_fh, conn, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	}

	return 0;

err_path_free:
	apb_fpath_free(&apb_fh->path);
err_out:
	return ret;
}

int
apb_fopen(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	return apb_abb_fopen(mod_priv, conn, path, flags, open_toks, true);
}

int
apb_fclose(void *mod_priv,
	   struct elasto_conn *conn)
{
	struct apb_fh *apb_fh = mod_priv;

	apb_fpath_free(&apb_fh->path);

	return 0;
}

int
abb_fopen(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	return apb_abb_fopen(mod_priv, conn, path, flags, open_toks, false);
}
