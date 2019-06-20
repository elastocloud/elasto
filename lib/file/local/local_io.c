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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>

#include "ccan/list/list.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "elasto/file.h"
#include "lib/file/handle.h"
#include "local_path.h"
#include "local_handle.h"
#include "local_stat.h"
#include "local_io.h"

static int
local_fwrite_buf_get(struct elasto_data *src_data,
		     uint64_t need_len,
		     struct iovec *iov)
{
	uint8_t *out_buf = NULL;
	uint64_t buf_len = 0;
	uint64_t remain;
	int ret;

	assert(iov != NULL);

	switch (src_data->type) {
	case ELASTO_DATA_IOV:
		if (src_data->off > src_data->len) {
			return -EINVAL;
		}
		remain = src_data->len - src_data->off;
		if (remain < need_len) {
			return -EINVAL;
		}
		iov->iov_base = src_data->iov.buf + src_data->off;
		iov->iov_len = need_len;
		break;
	case ELASTO_DATA_CB:
		assert(src_data->cb.out_cb != NULL);
		/* cb must provide a buffer with enough data to satisfy req */
		ret = src_data->cb.out_cb(src_data->off, need_len, &out_buf,
					  &buf_len, src_data->cb.priv);
		if (ret < 0) {
			dbg(0, "data out_cb returned an error (%d), ending "
			       "xfer\n", ret);
			return -EIO;
		} else if (out_buf == NULL) {
			return -EINVAL;
		} else if (buf_len < need_len) {
			dbg(0, "out_cb didn't provide enough data: needed %"
			       PRIu64 " got %" PRIu64 "\n", need_len, buf_len);
			/* now buf owner, so must cleanup */
			free(out_buf);
			return -EINVAL;
		}
		iov->iov_base = out_buf;
		iov->iov_len = need_len;
		break;
	default:
		dbg(0, "write data needed but not available\n");
		return -EINVAL;
		break;
	}

	return 0;
}

static void
local_fwrite_buf_commit(struct elasto_data *src_data,
			struct iovec *iov)
{
	if (src_data->type == ELASTO_DATA_CB) {
		/* no longer need to keep write buffer around */
		free(iov->iov_base);
	}
	src_data->off += iov->iov_len;
}

int
local_fwrite(void *mod_priv,
	     uint64_t dest_off,
	     uint64_t dest_len,
	     struct elasto_data *src_data)
{
	struct local_fh *local_fh = mod_priv;
	int ret;
	struct iovec iov;
	struct iovec iov_remain;

	assert(src_data != NULL);

	ret = local_fwrite_buf_get(src_data, dest_len, &iov);
	if (ret < 0) {
		dbg(0, "failed to obtain write buf of len %" PRIu64 "\n",
		    dest_len);
		goto err_out;
	}

	iov_remain = iov;

	while (iov_remain.iov_len > 0) {
		ret = pwritev(local_fh->fd, &iov_remain, 1, dest_off);
		if (ret < 0) {
			ret = -errno;
			dbg(0, "pwritev failed: %s\n", strerror(-ret));
			goto err_buf_put;
		}
		if ((ret == 0) || (ret > iov_remain.iov_len)) {
			dbg(0, "invalid pwritev return %d\n", ret);
			ret = -EIO;
			goto err_buf_put;
		}
		dest_off += ret;
		iov_remain.iov_base += ret;
		iov_remain.iov_len -= ret;
	}

	local_fwrite_buf_commit(src_data, &iov);

	return 0;

err_buf_put:
	if (src_data->type == ELASTO_DATA_CB) {
		/* no longer need to keep write buffer around */
		free(iov.iov_base);
	}
err_out:
	return ret;
}

static int
local_fread_buf_get(struct elasto_data *dest_data,
		    uint64_t need_len,
		    struct iovec *iov)
{
	uint8_t *buf;
	uint64_t remain;

	assert(iov != NULL);

	switch (dest_data->type) {
	case ELASTO_DATA_IOV:
		if (dest_data->off > dest_data->len) {
			return -EINVAL;
		}
		remain = dest_data->len - dest_data->off;
		if (remain < need_len) {
			return -EINVAL;
		}
		iov->iov_base = dest_data->iov.buf + dest_data->off;
		iov->iov_len = need_len;
		break;
	case ELASTO_DATA_CB:
		/* allocate a buffer to be given to the callback */
		buf = malloc(need_len);
		if (buf == NULL) {
			return -ENOMEM;
		}
		iov->iov_base = buf;
		iov->iov_len = need_len;
		break;
	default:
		dbg(0, "read data needed but not available\n");
		return -EINVAL;
		break;
	}

	return 0;
}

static int
local_fread_buf_commit(struct elasto_data *dest_data,
		       struct iovec *iov)
{
	if (dest_data->type == ELASTO_DATA_CB) {
		int ret;

		assert(dest_data->cb.in_cb != NULL);
		/* in_cb is responsible for freeing iov_base on success */
		ret = dest_data->cb.in_cb(dest_data->off, iov->iov_len,
					  iov->iov_base, iov->iov_len,
					  dest_data->cb.priv);
		if (ret < 0) {
			dbg(0, "data in_cb returned an error (%d), ending "
			       "xfer\n", ret);
			return -EIO;
		}
	}
	dest_data->off += iov->iov_len;

	return 0;
}

int
local_fread(void *mod_priv,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct local_fh *local_fh = mod_priv;
	struct iovec iov;
	struct iovec iov_remain;

	assert(dest_data != NULL);

	ret = local_fread_buf_get(dest_data, src_len, &iov);
	if (ret < 0) {
		dbg(0, "failed to obtain read buf of len %" PRIu64 "\n",
		    src_len);
		goto err_out;
	}

	iov_remain = iov;

	while (iov_remain.iov_len > 0) {
		ret = preadv(local_fh->fd, &iov_remain, 1, src_off);
		if (ret < 0) {
			ret = -errno;
			dbg(0, "preadv failed: %s\n", strerror(-ret));
			goto err_buf_put;
		}
		if ((ret == 0) || (ret > iov_remain.iov_len)) {
			dbg(0, "invalid preadv return %d\n", ret);
			ret = -EIO;
			goto err_buf_put;
		}
		src_off += ret;
		iov_remain.iov_base += ret;
		iov_remain.iov_len -= ret;
	}

	ret = local_fread_buf_commit(dest_data, &iov);
	if (ret < 0) {
		goto err_buf_put;
	}

	return 0;

err_buf_put:
	if (dest_data->type == ELASTO_DATA_CB) {
		free(iov.iov_base);
	}
err_out:
	return ret;
}

int
local_ftruncate(void *mod_priv,
		uint64_t len)
{
	int ret;
	struct local_fh *local_fh = mod_priv;

	ret = ftruncate(local_fh->fd, len);
	if (ret < 0) {
		ret = -errno;
		goto err_out;
	}
	ret = 0;
err_out:
	return ret;
}

int
local_fallocate(void *mod_priv,
		uint32_t mode,
		uint64_t dest_off,
		uint64_t dest_len)
{
	int ret;
	struct local_fh *local_fh = mod_priv;

	if (mode != ELASTO_FALLOC_PUNCH_HOLE) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = fallocate(local_fh->fd, FALLOC_FL_PUNCH_HOLE, dest_off, dest_len);
	if (ret < 0) {
		ret = -errno;
		goto err_out;
	}
	ret = 0;
err_out:
	return ret;
}
