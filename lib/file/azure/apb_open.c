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
#include "apb_open.h"

/* XXX dup of path parsing code in elasto_cli.c */
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

/* XXX dup of cli_sign_conn_setup */
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

int
apb_fopen(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path,
	  uint64_t flags)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;
	struct apb_fh *apb_fh = mod_priv;

	ret = apb_fpath_parse(path, &apb_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	ret = apb_fsign_conn_setup(conn, apb_fh->sub_id, apb_fh->path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_prop_get(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
				   &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret < 0) && op_rsp_error_match(op, 404)
					&& (flags & ELASTO_FOPEN_CREATE)) {
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
		dbg(0, "request to open unsupported non-page blob\n");
		ret = -EINVAL;
		goto err_op_free;
	}

done:
	op_free(op);
	return 0;

err_op_free:
	op_free(op);
err_path_free:
	apb_fpath_free(&apb_fh->path);
err_out:
	return ret;
}

int
apb_fclose(void *mod_priv,
	   struct elasto_conn *conn)
{
	struct apb_fh *apb_fh = mod_priv;

	apb_fpath_free(&apb_fh->path);

	return 0;
}
