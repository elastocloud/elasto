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
#include "lib/s3_path.h"
#include "lib/s3_req.h"
#include "lib/s3_creds.h"
#include "lib/conn.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "s3_handle.h"
#include "s3_io.h"
#include "s3_open.h"
#include "s3_dir.h"
#include "s3_stat.h"
#include "s3_unlink.h"

static int
s3_fh_init(const struct elasto_fauth *auth,
	   void **_fh_priv,
	   struct elasto_conn **_conn,
	   struct elasto_fh_mod_ops *_ops)
{
	int ret;
	struct s3_fh *s3_fh;

	assert(auth->type == ELASTO_FILE_S3);

	s3_fh = malloc(sizeof(*s3_fh));
	if (s3_fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(s3_fh, 0, sizeof(*s3_fh));

	ret = s3_creds_csv_process(auth->s3.creds_path,
				   &s3_fh->iam_user,
				   &s3_fh->key_id,
				   &s3_fh->secret);
	if (ret < 0) {
		goto err_priv_free;
	}

	s3_fh->insecure_http = auth->insecure_http;
	/* connect on open */

	*_fh_priv = s3_fh;
	*_conn = NULL;
	*_ops = (struct elasto_fh_mod_ops){
		.fh_free = s3_fh_free,
		.open = s3_fopen,
		.close = s3_fclose,
		.write = s3_fwrite,
		.read = s3_fread,
		.allocate = NULL,
		.truncate = NULL,
		.splice = s3_fsplice,
		.stat = s3_fstat,
		.statfs = s3_fstatvfs,
		.lease_acquire = NULL,
		.lease_break = NULL,
		.lease_release = NULL,
		.lease_free = NULL,
		.readdir = s3_freaddir,
		.unlink = s3_funlink,
	};

	return 0;

err_priv_free:
	free(s3_fh);
err_out:
	return ret;
}

/* module version number */
uint64_t elasto_file_mod_version = ELASTO_FILE_MOD_VERS_VAL;

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_conn **_conn,
			struct elasto_fh_mod_ops *_ops)
{
	return s3_fh_init(auth, _fh_priv, _conn, _ops);
}

void
s3_fh_free(void *mod_priv)
{
	struct s3_fh *s3_fh = mod_priv;

	free(s3_fh->iam_user);
	free(s3_fh->key_id);
	free(s3_fh->secret);
	free(s3_fh);
}
