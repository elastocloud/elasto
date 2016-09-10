/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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
#include "local_path.h"

int
local_path_parse(const char *path,
		 struct local_path *local_path)
{
	int ret;

	if ((path == NULL) || (local_path == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (strstr(path, "://")) {
		ret = -EINVAL;
		goto err_out;
	}

	if (*path != '/') {
		/* no leading slash */
		ret = -EINVAL;
		goto err_out;
	}

	local_path->path = strdup(path);
	if (local_path->path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* dir or file set following open */
	local_path->type = LOCAL_PATH_ENT;
	dbg(2, "parsed %s as local path: %s\n",
	    path, local_path->path);

	return 0;

err_out:
	return ret;
}

void
local_path_free(struct local_path *local_path)
{
	free(local_path->path);
	local_path->path = NULL;
}

int
local_path_dup(const struct local_path *path_orig,
	       struct local_path *path_dup)
{
	int ret;
	struct local_path dup = { 0 };

	dup.type = path_orig->type;
	dup.path = strdup(path_orig->path);
	if (dup.path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	*path_dup = dup;
	ret = 0;
err_out:
	return ret;
}
