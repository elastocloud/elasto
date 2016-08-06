/*
 * Copyright (C) SUSE LINUX GmbH 2015-2016, all rights reserved.
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
#include <ctype.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/azure_blob_path.h"
#include "lib/azure_blob_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"

static int
az_blob_path_validate(struct az_blob_path *az_path)
{
	int i;
	char c;

	assert(az_path != NULL);

	switch (az_path->type) {
	case AZ_BLOB_PATH_BLOB:
		if (strlen(az_path->blob) > 1024) {
			dbg(0, "oversize blob name\n");
			goto fail;
		}
	case AZ_BLOB_PATH_CTNR:	/* FALL THROUGH */
		/*
		 * Must be lower case, digit, or hyphen. Can't start with a
		 * hyphen or contain two in a row.
		 */
		for (i = 0; i < strlen(az_path->ctnr); i++) {
			c = az_path->ctnr[i];
			if (islower(c) || isdigit(c)
				    || ((c == '-') && (i > 0)
					    && (az_path->ctnr[i - 1] != '-'))) {
				continue;
			}
			dbg(0, "invalid container string: %s\n", az_path->ctnr);
			goto fail;
		}
		if ((i < 3) || (i > 63)) {
			dbg(0, "invalid container string length: %d\n", i);
			goto fail;
		}
	case AZ_BLOB_PATH_ACC:	/* FALL THROUGH */
		/*
		 * Must be lower case or digit.
		 */
		for (i = 0; i < strlen(az_path->acc); i++) {
			c = az_path->acc[i];
			if (islower(c) || isdigit(c)) {
				continue;
			}
			dbg(0, "invalid account string: %s\n", az_path->acc);
			goto fail;
		}
		if ((i < 3) || (i > 24)) {
			dbg(0, "invalid account string length: %d\n", i);
			goto fail;
		}
	case AZ_BLOB_PATH_ROOT:	/* FALL THROUGH */
		/* nothing to validate for root */
	default:
		break;
	}

	return 0;
fail:
	return -EINVAL;
}

int
az_blob_path_parse(const char *path,
		struct az_blob_path *az_path)
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

	if (*s != '/') {
		/* no leading slash */
		ret = -EINVAL;
		goto err_out;
	}

	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		az_path->type = AZ_BLOB_PATH_ROOT;
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
		az_path->type = AZ_BLOB_PATH_ACC;
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* account + slashes only */
		az_path->type = AZ_BLOB_PATH_ACC;
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
		az_path->type = AZ_BLOB_PATH_CTNR;
		goto done;
	}

	*(s++) = '\0';	/* null term for ctnr */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* container + slashes only */
		az_path->type = AZ_BLOB_PATH_CTNR;
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
		dbg(0, "Invalid remote path: blob has trailing garbage\n");
		ret = -EINVAL;
		goto err_3_free;
	}

	az_path->type = AZ_BLOB_PATH_BLOB;
done:
	assert(az_path->type != 0);
	az_path->acc = comp1;
	az_path->ctnr = comp2;
	az_path->blob = comp3;
	ret = az_blob_path_validate(az_path);
	if (ret < 0) {
		goto err_3_free;
	}
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
az_blob_path_free(struct az_blob_path *az_path)
{
	free(az_path->acc);
	az_path->acc = NULL;
	free(az_path->ctnr);
	az_path->ctnr = NULL;
	free(az_path->blob);
	az_path->blob = NULL;
}

int
az_blob_path_dup(const struct az_blob_path *path_orig,
		 struct az_blob_path *path_dup)
{
	int ret;
	struct az_blob_path dup = { 0 };

	dup.type = path_orig->type;
	if (path_orig->acc != NULL) {
		dup.acc = strdup(path_orig->acc);
		if (dup.acc == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		/* all nested items must also be NULL */
		goto done;
	}

	if (path_orig->ctnr != NULL) {
		dup.ctnr = strdup(path_orig->ctnr);
		if (dup.ctnr == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	} else {
		/* all nested items must also be NULL */
		goto done;
	}

	if (path_orig->blob != NULL) {
		dup.blob = strdup(path_orig->blob);
		if (dup.blob == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

done:
	*path_dup = dup;
	return 0;

err_path_free:
	az_blob_path_free(&dup);
err_out:
	return ret;
}
