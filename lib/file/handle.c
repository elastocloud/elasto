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
#include <apr-1/apr_general.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/xml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"

int
elasto_fh_init(const char *ps_path,
	       bool insecure_http,
	       struct elasto_fh **_fh)
{
	struct elasto_fh *fh;
	struct elasto_fh_priv *fh_priv;
	int ret;

	fh = malloc(sizeof(*fh));
	if (fh == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(fh, 0, sizeof(*fh));

	fh_priv = malloc(sizeof(*fh_priv));
	if (fh_priv == NULL) {
		ret = -ENOMEM;
		goto err_fh_free;
	}
	memset(fh_priv, 0, sizeof(*fh_priv));

	fh_priv->type = ELASTO_FILE_AZURE;
	assert(ARRAY_SIZE(fh_priv->magic) == sizeof(ELASTO_FH_MAGIC));
	memcpy(fh_priv->magic, ELASTO_FH_MAGIC, sizeof(ELASTO_FH_MAGIC));
	fh->priv = fh_priv;

	ret = azure_ssl_pubset_process(ps_path,
				       &fh_priv->az.pem_path,
				       &fh_priv->az.sub_id,
				       &fh_priv->az.sub_name);
	if (ret < 0) {
		goto err_priv_free;
	}

	ret = elasto_conn_init_az(fh_priv->az.pem_path, NULL, insecure_http,
				  &fh_priv->conn);
	if (ret < 0) {
		goto err_ssl_free;
	}
	*_fh = fh;

	return 0;

err_ssl_free:
	free(fh_priv->az.pem_path);
	free(fh_priv->az.sub_id);
	free(fh_priv->az.sub_name);
err_priv_free:
	free(fh_priv);
err_fh_free:
	free(fh);
err_out:
	return ret;
}

void
elasto_fh_free(struct elasto_fh *fh)
{
	struct elasto_fh_priv *fh_priv = fh->priv;

	if (fh_priv->conn != NULL) {
		elasto_conn_free(fh_priv->conn);
	}
	free(fh_priv->az.pem_path);
	free(fh_priv->az.sub_id);
	free(fh_priv->az.sub_name);
	free(fh_priv);
	free(fh);
}

struct elasto_fh_priv *
elasto_fh_validate(struct elasto_fh *fh)
{
	struct elasto_fh_priv *fh_priv = fh->priv;

	if (fh_priv->type != ELASTO_FILE_AZURE) {
		dbg(0, "handle has invalid type %x\n", fh_priv->type);
		return NULL;
	}

	if (memcmp(fh_priv->magic, ELASTO_FH_MAGIC, sizeof(ELASTO_FH_MAGIC))) {
		dbg(0, "handle has invalid magic\n");
		return NULL;
	}

	return fh_priv;
}
