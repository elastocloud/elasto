/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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

#include <curl/curl.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"
#include "xmit.h"

/* XXX dup of path parsing code in elasto_cli.c */
int
elasto_fpath_az_parse(const char *path,
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
elasto_fpath_az_free(struct elasto_fh_az_path *az_path)
{
	free(az_path->acc);
	free(az_path->ctnr);
	free(az_path->blob);
}

/* XXX dup of cli_sign_conn_setup */
int
elasto_fsign_conn_setup(struct elasto_conn *econn,
			const char *sub_id,
			const char *acc)
{
	int ret;
	struct op *op;
	struct az_rsp_acc_keys_get *acc_keys_get_rsp;

	ret = az_req_acc_keys_get(sub_id, acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	acc_keys_get_rsp = az_rsp_acc_keys_get(op);
	if (acc_keys_get_rsp == NULL) {
		goto err_op_free;
	}

	ret = elasto_conn_sign_setkey(econn, acc, acc_keys_get_rsp->primary);
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
elasto_fcreate(const struct elasto_fauth *auth,
	       const char *path,
	       uint64_t len,
	       struct elasto_fh **_fh)
{
	int ret;
	struct elasto_fh *fh;
	struct elasto_fh_priv *fh_priv;
	struct op *op;

	if (auth->type != ELASTO_FILE_AZURE) {
		ret = -ENOTSUP;
		goto err_out;
	}

	ret = elasto_conn_subsys_init();
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fh_init(auth->az.ps_path, auth->insecure_http, &fh);
	if (ret < 0) {
		goto err_connss_deinit;
	}
	fh_priv = fh->priv;

	ret = elasto_fpath_az_parse(path, &fh_priv->az.path);
	if (ret < 0) {
		goto err_fhconn_free;
	}

	ret = elasto_fsign_conn_setup(fh_priv->conn, fh_priv->az.sub_id,
				      fh_priv->az.path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_put(fh_priv->az.path.acc, fh_priv->az.path.ctnr,
			      fh_priv->az.path.blob, NULL, len,
			      &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	op_free(op);
	if (ret < 0) {
		goto err_path_free;
	}
	fh_priv->len = len;

	*_fh = fh;
	return 0;

err_path_free:
	elasto_fpath_az_free(&fh_priv->az.path);
err_fhconn_free:
	elasto_fh_free(fh);
err_connss_deinit:
	elasto_conn_subsys_deinit();
err_out:
	return ret;
}

int
elasto_fopen(const struct elasto_fauth *auth,
	     const char *path,
	     uint64_t flags,
	     struct elasto_fh **_fh)
{
	int ret;
	struct elasto_fh *fh;
	struct elasto_fh_priv *fh_priv;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;

	if (auth->type != ELASTO_FILE_AZURE) {
		ret = -ENOTSUP;
		goto err_out;
	}

	ret = elasto_fh_init(auth->az.ps_path, auth->insecure_http, &fh);
	if (ret < 0) {
		goto err_out;
	}
	fh_priv = fh->priv;

	ret = elasto_fpath_az_parse(path, &fh_priv->az.path);
	if (ret < 0) {
		goto err_fhconn_free;
	}

	ret = elasto_fsign_conn_setup(fh_priv->conn, fh_priv->az.sub_id,
				      fh_priv->az.path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_prop_get(fh_priv->az.path.acc,
				   fh_priv->az.path.ctnr,
				   fh_priv->az.path.blob,
				   &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret < 0) && op_rsp_error_match(op, 404)
					&& (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_req_blob_put(fh_priv->az.path.acc, fh_priv->az.path.ctnr,
				      fh_priv->az.path.blob, NULL, 0,
				      &op);
		if (ret < 0) {
			goto err_path_free;
		}

		ret = elasto_fop_send_recv(fh_priv->conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		fh_priv->len = 0;
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
	fh_priv->len = blob_prop_get_rsp->len;

done:
	op_free(op);
	*_fh = fh;
	return 0;

err_op_free:
	op_free(op);
err_path_free:
	elasto_fpath_az_free(&fh_priv->az.path);
err_fhconn_free:
	elasto_fh_free(fh);
err_out:
	return ret;

}

int
elasto_fclose(struct elasto_fh *fh)
{
	struct elasto_fh_priv *fh_priv = elasto_fh_validate(fh);
	if (fh_priv == NULL) {
		return -EINVAL;
	}

	if (fh_priv->lease_state == ELASTO_FH_LEASE_ACQUIRED) {
		dbg(4, "cleaning up lease %s on close\n", fh_priv->az.lid);
		int ret = elasto_flease_release(fh);
		if (ret < 0) {
			dbg(0, "failed to release lease %s on close: %s\n",
			    fh_priv->az.lid, strerror(ret));
		}
	}

	elasto_fpath_az_free(&fh_priv->az.path);
	elasto_fh_free(fh);

	return 0;
}

int
elasto_fdebug(int level)
{
	int ret = dbg_level_get();
	dbg_level_set(level);

	return ret;
}
