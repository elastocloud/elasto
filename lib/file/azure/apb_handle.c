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
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "apb_handle.h"
#include "apb_io.h"
#include "apb_lease.h"
#include "apb_open.h"
#include "apb_dir.h"
#include "apb_stat.h"

static int
apb_fh_init(const struct elasto_fauth *auth,
	    void **_fh_priv,
	    struct elasto_conn **_conn,
	    struct elasto_fh_mod_ops *_ops)
{
	int ret;
	struct apb_fh *apb_fh;
	struct elasto_conn *conn;
	struct elasto_fh_mod_ops ops = {
		.fh_free = apb_fh_free,
		.open = apb_fopen,
		.close = apb_fclose,
		.write = apb_fwrite,
		.read = apb_fread,
		.allocate = apb_fallocate,
		.truncate = apb_ftruncate,
		.stat = apb_fstat,
		.lease_acquire = apb_flease_acquire,
		.lease_break = apb_flease_break,
		.lease_release = apb_flease_release,
		.lease_free = apb_flease_free,
		.mkdir = apb_fmkdir,
		.rmdir = apb_frmdir,
	};

	assert(auth->type == ELASTO_FILE_AZURE);

	apb_fh = malloc(sizeof(*apb_fh));
	if (apb_fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(apb_fh, 0, sizeof(*apb_fh));

	ret = azure_ssl_pubset_process(auth->az.ps_path,
				       &apb_fh->pem_path,
				       &apb_fh->sub_id,
				       &apb_fh->sub_name);
	if (ret < 0) {
		goto err_priv_free;
	}

	ret = elasto_conn_init_az(apb_fh->pem_path, NULL, auth->insecure_http,
				  &conn);
	if (ret < 0) {
		goto err_ssl_free;
	}

	*_fh_priv = apb_fh;
	*_conn = conn;
	/* FIXME shouldn't be needed */
	*_ops = ops;

	return 0;

err_ssl_free:
	free(apb_fh->pem_path);
	free(apb_fh->sub_id);
	free(apb_fh->sub_name);
err_priv_free:
	free(apb_fh);
err_out:
	return ret;
}

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_conn **_conn,
			struct elasto_fh_mod_ops *_ops)
{
	return apb_fh_init(auth, _fh_priv, _conn, _ops);
}

void
apb_fh_free(void *mod_priv)
{
	struct apb_fh *apb_fh = mod_priv;

	azure_ssl_pubset_cleanup(apb_fh->pem_path);
	free(apb_fh->pem_path);
	free(apb_fh->sub_id);
	free(apb_fh->sub_name);
	free(apb_fh);
}
