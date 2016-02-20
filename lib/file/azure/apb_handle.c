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
#include "apb_unlink.h"

static int
apb_fh_init(const struct elasto_fauth *auth,
	    void **_fh_priv)
{
	int ret;
	struct apb_fh *apb_fh;

	apb_fh = malloc(sizeof(*apb_fh));
	if (apb_fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(apb_fh, 0, sizeof(*apb_fh));

	if (auth->az.ps_path != NULL) {
		ret = azure_ssl_pubset_process(auth->az.ps_path,
					       &apb_fh->pem_path,
					       &apb_fh->sub_id,
					       &apb_fh->sub_name);
		if (ret < 0) {
			goto err_priv_free;
		}
	} else if (auth->az.access_key != NULL) {
		apb_fh->acc_access_key = strdup(auth->az.access_key);
		if (apb_fh->acc_access_key == NULL) {
			ret = -ENOMEM;
			goto err_priv_free;
		}
	} else {
		dbg(0, "init called without auth credentials\n");
		ret = -EINVAL;
		goto err_priv_free;
	}

	apb_fh->insecure_http = auth->insecure_http;
	/* connect on open */

	*_fh_priv = apb_fh;

	return 0;

err_priv_free:
	free(apb_fh);
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

	if (auth->type == ELASTO_FILE_APB) {
		*_ops = (struct elasto_fh_mod_ops){
			.fh_free = apb_fh_free,
			.open = apb_fopen,
			.close = apb_fclose,
			.write = apb_fwrite,
			.read = apb_fread,
			.allocate = apb_fallocate,
			.truncate = apb_ftruncate,
			.splice = apb_fsplice,
			.stat = apb_fstat,
			.statfs = apb_fstatvfs,
			.lease_acquire = apb_flease_acquire,
			.lease_break = apb_flease_break,
			.lease_release = apb_flease_release,
			.lease_free = apb_flease_free,
			.readdir = apb_freaddir,
			.unlink = apb_funlink,
			.list_ranges = apb_flist_ranges,
		};
	} else if (auth->type == ELASTO_FILE_ABB) {
		/*
		 * block blob operations match those of page blobs, except for
		 * open, IO & stat.
		 */
		*_ops = (struct elasto_fh_mod_ops){
			.fh_free = apb_fh_free,
			.open = abb_fopen,
			.close = apb_fclose,
			.write = abb_fwrite,
			.read = abb_fread,
			.allocate = NULL,
			.truncate = NULL,
			.splice = abb_fsplice,
			.stat = abb_fstat,
			.statfs = abb_fstatvfs,
			.lease_acquire = apb_flease_acquire,
			.lease_break = apb_flease_break,
			.lease_release = apb_flease_release,
			.lease_free = apb_flease_free,
			.readdir = apb_freaddir,
			.unlink = apb_funlink,
			.list_ranges = NULL,
		};
	} else {
		return -EINVAL;
	}
	ret = apb_fh_init(auth, _fh_priv);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

void
apb_fh_free(void *mod_priv)
{
	struct apb_fh *apb_fh = mod_priv;

	if (apb_fh->pem_path != NULL) {
		azure_ssl_pubset_cleanup(apb_fh->pem_path);
		free(apb_fh->pem_path);
		free(apb_fh->sub_id);
		free(apb_fh->sub_name);
	}
	free(apb_fh->acc_access_key);
	free(apb_fh);
}
