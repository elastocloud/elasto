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
#include <sys/stat.h>

#include "lib/dbg.h"
#include "lib/s3_path.h"

/* default host. bkt is normally added as prefix for bkt and obj operations */
#define S3_FOPEN_HOST_DEFAULT "s3.amazonaws.com"
#define S3_URI_PREFIX "s3://"

/* _very_ basic URI host component parser. Doesn't come close to RFC 3986 */
static int
s3_path_uri_pull(const char *path,
		 char **_host,
		 char **_after_host)
{
	int ret;
	char *host;
	char *s = (char *)path;

	if (strncmp(s, S3_URI_PREFIX, sizeof(S3_URI_PREFIX) - 1) != 0) {
		ret = -EINVAL;
		goto err_out;
	}

	s += (sizeof(S3_URI_PREFIX) - 1);

	while (*s == '/')
		s++;

	if (*s == '\0') {
		ret = -EINVAL;
		goto err_out;
	}

	host = strdup(s);
	if (host == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(host, '/');
	if (s == NULL) {
		/* host only */
		ret = -EINVAL;
		goto err_host_free;
	}

	*(s++) = '\0';	/* null term for host */
	*_host = host;
	*_after_host = s;

	return 0;

err_host_free:
	free(host);
err_out:
	return ret;
}

int
s3_path_parse(const char *path,
		     struct s3_path *s3_path)
{
	int ret;
	char *s;
	char *host = NULL;
	char *comp1 = NULL;
	char *comp2 = NULL;

	if ((path == NULL) || (s3_path == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (strstr(path, "://")) {
		char *after_host;
		ret = s3_path_uri_pull(path, &host, &after_host);
		if (ret < 0) {
			goto err_out;
		}
		s = after_host;
	} else {
		s = (char *)path;

		host = strdup(S3_FOPEN_HOST_DEFAULT);
		if (host == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		s3_path->type = S3_PATH_ROOT;
		goto done;
	}

	comp1 = strdup(s);
	if (comp1 == NULL) {
		ret = -ENOMEM;
		goto err_host_free;
	}

	s = strchr(comp1, '/');
	if (s == NULL) {
		/* bucket only */
		s3_path->type = S3_PATH_BKT;
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* bucket + slashes only */
		s3_path->type = S3_PATH_BKT;
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s != NULL) {
		dbg(0, "Invalid remote path: S3 object has trailing garbage");
		ret = -EINVAL;
		goto err_2_free;
	}
	s3_path->type = S3_PATH_OBJ;
done:
	assert(s3_path->type != 0);
	s3_path->host = host;
	s3_path->bkt = comp1;
	s3_path->obj = comp2;
	dbg(2, "parsed %s as S3 path: host=%s, bkt=%s, obj=%s\n",
	    path, s3_path->host, (s3_path->bkt ? s3_path->bkt : ""),
	    (s3_path->obj ? s3_path->obj : ""));

	return 0;

err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_host_free:
	free(comp1);
err_out:
	return ret;
}

void
s3_path_free(struct s3_path *s3_path)
{
	free(s3_path->host);
	s3_path->host = NULL;
	free(s3_path->bkt);
	s3_path->bkt = NULL;
	free(s3_path->obj);
	s3_path->obj = NULL;
}

int
s3_path_dup(const struct s3_path *path_orig,
	    struct s3_path *path_dup)
{
	int ret;
	struct s3_path dup = { 0 };

	if (path_orig->host != NULL) {
		dup.host = strdup(path_orig->host);
		if (dup.host == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	dup.type = path_orig->type;
	if (path_orig->bkt != NULL) {
		dup.bkt = strdup(path_orig->bkt);
		if (dup.bkt == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	} else {
		/* obj must also be NULL */
		goto done;
	}

	if (path_orig->obj != NULL) {
		dup.obj = strdup(path_orig->obj);
		if (dup.obj == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

done:
	*path_dup = dup;
	return 0;

err_path_free:
	s3_path_free(&dup);
err_out:
	return ret;
}
