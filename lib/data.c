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
#define _GNU_SOURCE
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

#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "data.h"

void
elasto_data_destroy(struct elasto_data **data)
{
	struct elasto_data *adata = *data;
	if (adata == NULL)
		return;
	free(adata->buf);
	if (adata->type == ELASTO_DATA_FILE)
		close(adata->file.fd);
	free(adata);
	*data = NULL;
}

/*
 * allocate a file based data structure, opening the underlying file
 */
int
elasto_data_file_new(char *path,
		       uint64_t file_len,
		       uint64_t base_off,
		       int open_flags,
		       mode_t create_mode,
		       struct elasto_data **data)
{
	struct elasto_data *adata;

	adata = malloc(sizeof(*adata));
	if (adata == NULL)
		return -ENOMEM;

	adata->type = ELASTO_DATA_FILE;
	if (open_flags | O_CREAT)
		adata->file.fd = open(path, open_flags, create_mode);
	else
		adata->file.fd = open(path, open_flags);

	if (adata->file.fd == -1) {
		free(adata);
		return -errno;
	}
	adata->buf = (uint8_t *)path;
	adata->len = file_len;
	adata->off = 0;
	adata->base_off = base_off;
	*data = adata;

	return 0;
}

/*
 * allocate an iov based data structure
 * if @buf_alloc is set then allocate @buf_len, ignoring @buf and @base_off
 */
int
elasto_data_iov_new(uint8_t *buf,
		      uint64_t buf_len,
		      uint64_t base_off,
		      bool buf_alloc,
		      struct elasto_data **data)
{
	struct elasto_data *adata;

	adata = malloc(sizeof(*adata));
	if (adata == NULL)
		return -ENOMEM;

	adata->type = ELASTO_DATA_IOV;
	if (buf_alloc) {
		assert(buf_len > 0);
		adata->buf = malloc(buf_len);
		if (adata->buf == NULL) {
			free(adata);
			return -ENOMEM;
		}
		adata->base_off = 0;
	} else {
		adata->buf = buf;
		adata->base_off = base_off;
	}
	adata->len = buf_len;
	adata->off = 0;
	*data = adata;

	return 0;
}

int
elasto_data_iov_grow(struct elasto_data *data,
		       uint64_t grow_by)
{
	uint8_t *buf_old;
	if (data->type != ELASTO_DATA_IOV) {
		dbg(0, "invalid data type %d\n", data->type);
		return -EINVAL;
	}

	if (grow_by == 0) {
		return 0;
	}

	buf_old = data->buf;
	data->buf = realloc(data->buf, data->len + grow_by);
	if (data->buf == NULL) {
		data->buf = buf_old;
		return -ENOMEM;
	}

	data->len += grow_by;
	return 0;
}

