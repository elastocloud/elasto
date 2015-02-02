/*
 * Copyright (C) SUSE LINUX GmbH 2013-2015, all rights reserved.
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
#include <dlfcn.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"

int
elasto_fh_init(const struct elasto_fauth *auth,
	       struct elasto_fh **_fh)
{
	struct elasto_fh *fh;
	int ret;
	const char *mod_path;
	int (*mod_fh_init)(const struct elasto_fauth *auth,
			   void **_fh_priv,
			   struct elasto_conn **_conn,
			   struct elasto_fh_mod_ops *_ops);

	if (auth == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (auth->type != ELASTO_FILE_AZURE) {
		dbg(0, "unsupported auth type: %d\n", auth->type);
		ret = -EINVAL;
		goto err_out;
	}

	fh = malloc(sizeof(*fh));
	if (fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(fh, 0, sizeof(*fh));

	if (auth->type == ELASTO_FILE_AZURE) {
		fh->type = ELASTO_FILE_AZURE;
		mod_path = "libelasto_file_mod_apb.so";
	} else {
		assert(false);
	}

	fh->mod_dl_h = dlopen(mod_path, RTLD_NOW);
	if (fh->mod_dl_h == NULL) {
		dbg(0, "failed to load module (%d) at path \"%s\": %s\n",
		    auth->type, mod_path, dlerror());
		ret = -EFAULT;
		goto err_fh_free;
	}

	mod_fh_init = dlsym(fh->mod_dl_h, ELASTO_FILE_MOD_INIT_FN);
	if (mod_fh_init == NULL) {
		dbg(0, "failed to find init fn \"%s\" for module at %s: %s\n",
		    ELASTO_FILE_MOD_INIT_FN, mod_path, dlerror());
		ret = -EFAULT;
		goto err_dl_close;
	}

	/* initialise back-end module */
	ret = mod_fh_init(auth, &fh->mod_priv, &fh->conn, &fh->ops);
	if (ret < 0) {
		goto err_fh_free;
	}

	assert(ARRAY_SIZE(fh->magic) == sizeof(ELASTO_FH_MAGIC));
	memcpy(fh->magic, ELASTO_FH_MAGIC, sizeof(ELASTO_FH_MAGIC));

	*_fh = fh;

	return 0;

err_dl_close:
	dlclose(fh->mod_dl_h);
err_fh_free:
	free(fh);
err_out:
	return ret;
}

void
elasto_fh_free(struct elasto_fh *fh)
{
	int ret;

	fh->ops.fh_free(fh->mod_priv);
	if (fh->conn != NULL) {
		elasto_conn_free(fh->conn);
	}
	ret = dlclose(fh->mod_dl_h);
	if (ret != 0) {
		dbg(0, "failed to unload module (%d): %s\n",
		    fh->type, dlerror());
	}
	free(fh);
}

int
elasto_fh_validate(struct elasto_fh *fh)
{
	if (fh == NULL) {
		dbg(0, "invalid NULL handle\n");
		return -EINVAL;
	}

	if (fh->type != ELASTO_FILE_AZURE) {
		dbg(0, "handle has invalid type %x\n", fh->type);
		return -EINVAL;
	}

	if (memcmp(fh->magic, ELASTO_FH_MAGIC, sizeof(ELASTO_FH_MAGIC))) {
		dbg(0, "handle has invalid magic\n");
		return -EINVAL;
	}

	return 0;
}
