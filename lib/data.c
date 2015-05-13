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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "data_api.h"

void
elasto_data_free(struct elasto_data *data)
{
	if (data == NULL)
		return;
	if (data->type == ELASTO_DATA_IOV) {
		free(data->iov.buf);
	} else if (data->type == ELASTO_DATA_FILE) {
		free(data->file.path);
		close(data->file.fd);
	}
	free(data);
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
		     struct elasto_data **_data)
{
	int ret;
	struct elasto_data *data;

	data = malloc(sizeof(*data));
	if (data == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	data->type = ELASTO_DATA_FILE;
	if (open_flags | O_CREAT)
		data->file.fd = open(path, open_flags, create_mode);
	else
		data->file.fd = open(path, open_flags);

	if (data->file.fd == -1) {
		ret = -errno;
		goto err_data_free;
	}
	data->file.path = strdup(path);
	if (data->file.path == NULL) {
		ret = -ENOMEM;
		goto err_fd_close;
	}
	data->len = file_len;
	data->off = 0;
	data->base_off = base_off;
	*_data = data;

	return 0;

err_fd_close:
	close(data->file.fd);
err_data_free:
	free(data);
err_out:
	return ret;
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
		    struct elasto_data **_data)
{
	struct elasto_data *data;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->type = ELASTO_DATA_IOV;
	if (buf_alloc) {
		assert(buf_len > 0);
		data->iov.buf = malloc(buf_len);
		if (data->iov.buf == NULL) {
			free(data);
			return -ENOMEM;
		}
		data->base_off = 0;
	} else {
		data->iov.buf = buf;
		data->base_off = base_off;
	}
	data->len = buf_len;
	data->off = 0;
	*_data = data;

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

	buf_old = data->iov.buf;
	data->iov.buf = realloc(data->iov.buf, data->len + grow_by);
	if (data->iov.buf == NULL) {
		data->iov.buf = buf_old;
		return -ENOMEM;
	}

	data->len += grow_by;
	return 0;
}

int
elasto_data_cb_new(uint64_t out_len,
		   int (*out_cb)(uint64_t stream_off,
				 uint64_t need,
				 uint8_t **_out_buf,
				 uint64_t *buf_len,
				 void *priv),
		   uint64_t in_len,
		   int (*in_cb)(uint64_t stream_off,
				uint64_t got,
				uint8_t *in_buf,
				uint64_t buf_len,
				void *priv),
		   void *cb_priv,
		   struct elasto_data **_data)
{
	struct elasto_data *data;

	if (((in_len != 0) && (in_cb == NULL))
	 || ((out_len != 0) && (out_cb == NULL))) {
		dbg(0, "data_cb type requires cb for non-zero len\n");
		return -EINVAL;
	}

	if (((in_len == 0) && (in_cb != NULL))
	 || ((out_len == 0) && (out_cb != NULL))) {
		dbg(0, "data_cb type requires NULL cb for zero len\n");
		return -EINVAL;
	}

	if ((in_len * out_len) != 0) {
		dbg(0, "data_cb type only supports a sigle direction\n");
		return -EINVAL;
	}

	data = malloc(sizeof(*data));
	if (data == NULL) {
		return -ENOMEM;
	}
	memset(data, 0, sizeof(*data));

	if (in_len != 0) {
		data->len = in_len;
	} else {
		data->len = out_len;
	}
	data->type = ELASTO_DATA_CB;
	data->cb.out_cb = out_cb;
	data->cb.in_cb = in_cb;
	data->cb.priv = cb_priv;
	*_data = data;

	return 0;
}
