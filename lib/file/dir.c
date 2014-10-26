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
#include "lib/azure_mgmt_req.h"
#include "lib/azure_blob_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"
#include "xmit.h"
#include "open.h"

int
elasto_fmkdir(const struct elasto_fauth *auth,
	      const char *path)
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

	if ((fh_priv->az.path.acc == NULL)
	 || (fh_priv->az.path.ctnr == NULL)) {
		dbg(0, "invalid mkdir path: must include account and container "
		       "components\n");
		goto err_path_free;
	}
	if (fh_priv->az.path.blob != NULL) {
		dbg(0, "invalid mkdir path: blob component must not be "
		       "present\n");
		goto err_path_free;
	}

	ret = elasto_fsign_conn_setup(fh_priv->conn, fh_priv->az.sub_id,
				      fh_priv->az.path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_ctnr_create(fh_priv->az.path.acc, fh_priv->az.path.ctnr,
				 &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	op_free(op);
	if (ret < 0) {
		goto err_path_free;
	}

	elasto_fpath_az_free(&fh_priv->az.path);
	elasto_fh_free(fh);

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
elasto_frmdir(const struct elasto_fauth *auth,
	      const char *path)
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

	if ((fh_priv->az.path.acc == NULL)
	 || (fh_priv->az.path.ctnr == NULL)) {
		dbg(0, "invalid rmdir path: must include account and container "
		       "components\n");
		goto err_path_free;
	}
	if (fh_priv->az.path.blob != NULL) {
		dbg(0, "invalid rmdir path: blob component must not be "
		       "present\n");
		goto err_path_free;
	}

	ret = elasto_fsign_conn_setup(fh_priv->conn, fh_priv->az.sub_id,
				      fh_priv->az.path.acc);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_ctnr_del(fh_priv->az.path.acc, fh_priv->az.path.ctnr,
			      &op);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = elasto_fop_send_recv(fh_priv->conn, op);
	op_free(op);
	if (ret < 0) {
		goto err_path_free;
	}

	elasto_fpath_az_free(&fh_priv->az.path);
	elasto_fh_free(fh);

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
