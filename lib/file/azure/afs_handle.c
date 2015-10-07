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
#include "afs_handle.h"
#include "afs_io.h"
#include "afs_open.h"
#include "afs_dir.h"
#include "afs_stat.h"
#include "afs_unlink.h"

static int
afs_fh_init(const struct elasto_fauth *auth,
	    void **_fh_priv)
{
	int ret;
	struct afs_fh *afs_fh;

	afs_fh = malloc(sizeof(*afs_fh));
	if (afs_fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(afs_fh, 0, sizeof(*afs_fh));

	if (auth->az.ps_path != NULL) {
		ret = azure_ssl_pubset_process(auth->az.ps_path,
					       &afs_fh->pem_path,
					       &afs_fh->sub_id,
					       &afs_fh->sub_name);
		if (ret < 0) {
			goto err_priv_free;
		}
	} else if (auth->az.access_key != NULL) {
		afs_fh->acc_access_key = strdup(auth->az.access_key);
		if (afs_fh->acc_access_key == NULL) {
			ret = -ENOMEM;
			goto err_priv_free;
		}
	} else {
		dbg(0, "init called without auth credentials\n");
		ret = -EINVAL;
		goto err_priv_free;
	}

	afs_fh->insecure_http = auth->insecure_http;
	/* connect on open */

	*_fh_priv = afs_fh;

	return 0;

err_priv_free:
	free(afs_fh);
err_out:
	return ret;
}

/* module version number */
uint64_t elasto_file_mod_version = ELASTO_FILE_MOD_VERS_VAL;

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_fh_mod_ops *_ops)
{
	int ret;

	if (auth->type != ELASTO_FILE_AFS) {
		return -EINVAL;
	}

	*_ops = (struct elasto_fh_mod_ops){
		.fh_free = afs_fh_free,
		.open = afs_fopen,
		.close = afs_fclose,
		.write = afs_fwrite,
		.read = afs_fread,
		.allocate = afs_fallocate,
		.truncate = afs_ftruncate,
		.splice = afs_fsplice,
		.stat = afs_fstat,
		.statfs = afs_fstatvfs,
		.lease_acquire = NULL,
		.lease_break = NULL,
		.lease_release = NULL,
		.lease_free = NULL,
		.readdir = afs_freaddir,
		.unlink = afs_funlink,
	};
	ret = afs_fh_init(auth, _fh_priv);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

void
afs_fh_free(void *mod_priv)
{
	struct afs_fh *afs_fh = mod_priv;

	if (afs_fh->pem_path != NULL) {
		azure_ssl_pubset_cleanup(afs_fh->pem_path);
		free(afs_fh->pem_path);
		free(afs_fh->sub_id);
		free(afs_fh->sub_name);
	}
	free(afs_fh->acc_access_key);
	free(afs_fh);
}
