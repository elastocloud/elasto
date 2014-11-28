/*
 * Copyright (C) SUSE LINUX Products GmbH 2014, all rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"

int
slurp_file(const char *path,
	   char **_buf,
	   uint64_t *_len)
{
	int ret;
	uint64_t off;
	char *buf;
	int fd;
	struct stat st;

	ret = stat(path, &st);
	if (ret < 0) {
		dbg(0, "failed to stat %s\n", path);
		ret = -errno;
		goto err_out;
	}

	if (st.st_size > 4096) {
		dbg(0, "file too large to slurp\n");
		ret = -E2BIG;
		goto err_out;
	}

	/* +1 for null terminator */
	buf = malloc(st.st_size + 1);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		dbg(0, "failed to open %s\n", path);
		ret = -errno;
		goto err_free;
	}

	off = 0;
	while (off < st.st_size) {
		ssize_t got;
		size_t to_read = MIN(st.st_size - off, 1024);

		got = read(fd, buf + off, to_read);
		if (got < 0) {
		} else if (got == 0) {
			break;
		}
		off += got;
	}

	ret = close(fd);
	if (ret < 0) {
		ret = -errno;
		goto err_free;
	}

	/* null terminate, not included in length */
	buf[off] = '\0';

	*_buf = buf;
	*_len = off;
	return 0;
err_free:
	free(buf);
err_out:
	return ret;
}
