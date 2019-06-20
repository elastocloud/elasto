/*
 * Copyright (C) SUSE LINUX GmbH 2013-2016, all rights reserved.
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
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "elasto/file.h"
#include "handle.h"
#include "xmit.h"

int
elasto_fwrite(struct elasto_fh *fh,
	      uint64_t dest_off,
	      uint64_t dest_len,
	      uint8_t *out_buf)
{
	int ret;
	struct elasto_data *src_data;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.write == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (out_buf == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (dest_len == 0) {
		dbg(3, "zero length write\n");
		return 0;
	}

	ret = elasto_data_iov_new(out_buf, dest_len, false, &src_data);
	if (ret < 0) {
		goto err_out;
	}

	dbg(3, "writing range at %" PRIu64 ", len %" PRIu64 "\n",
	    dest_off, dest_len);

	ret = fh->ops.write(fh->mod_priv, dest_off, dest_len,
			    src_data);
	if (ret < 0) {
		goto err_data_free;
	}
	ret = 0;

err_data_free:
	elasto_data_free(src_data);
err_out:
	return ret;
}

int
elasto_fwrite_cb(struct elasto_fh *fh,
		 uint64_t dest_off,
		 uint64_t dest_len,
		 void *cb_priv,
		 int (*out_cb)(uint64_t stream_off,
			       uint64_t need,
			       uint8_t **_out_buf,
			       uint64_t *buf_len,
			       void *priv))
{
	int ret;
	struct elasto_data *src_data;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.write == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (out_cb == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (dest_len == 0) {
		dbg(3, "zero length write\n");
		return 0;
	}

	ret = elasto_data_cb_new(dest_len, out_cb, 0, NULL, cb_priv, &src_data);
	if (ret < 0) {
		goto err_out;
	}

	dbg(3, "writing range at %" PRIu64 ", len %" PRIu64 "\n",
	    dest_off, dest_len);

	ret = fh->ops.write(fh->mod_priv, dest_off, dest_len, src_data);
	if (ret < 0) {
		goto err_data_free;
	}
	ret = 0;

err_data_free:
	elasto_data_free(src_data);
err_out:
	return ret;
}

int
elasto_fread(struct elasto_fh *fh,
	     uint64_t src_off,
	     uint64_t src_len,
	     uint8_t *in_buf)
{
	int ret;
	struct elasto_data *dest_data;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.read == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (in_buf == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (src_len == 0) {
		dbg(3, "zero length read\n");
		return 0;
	}

	ret = elasto_data_iov_new(in_buf, src_len, false, &dest_data);
	if (ret < 0) {
		goto err_out;
	}

	dbg(3, "reading range at %" PRIu64 ", len %" PRIu64 "\n",
	    src_off, src_len);

	ret = fh->ops.read(fh->mod_priv, src_off, src_len, dest_data);
	if (ret < 0) {
		goto err_data_free;
	}
	ret = 0;

err_data_free:
	elasto_data_free(dest_data);
err_out:
	return ret;
}

int
elasto_fread_cb(struct elasto_fh *fh,
		uint64_t src_off,
		uint64_t src_len,
		void *cb_priv,
		int (*in_cb)(uint64_t stream_off,
			     uint64_t got,
			     uint8_t *in_buf,
			     uint64_t buf_len,
			     void *priv))
{
	int ret;
	struct elasto_data *dest_data;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.read == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (in_cb == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (src_len == 0) {
		dbg(3, "zero length read\n");
		return 0;
	}

	ret = elasto_data_cb_new(0, NULL, src_len, in_cb, cb_priv, &dest_data);
	if (ret < 0) {
		goto err_out;
	}

	dbg(3, "reading range at %" PRIu64 ", len %" PRIu64 "\n",
	    src_off, src_len);

	ret = fh->ops.read(fh->mod_priv, src_off, src_len, dest_data);
	if (ret < 0) {
		goto err_data_free;
	}
	ret = 0;

err_data_free:
	elasto_data_free(dest_data);
err_out:
	return ret;
}

int
elasto_fallocate(struct elasto_fh *fh,
		 uint32_t mode,
		 uint64_t dest_off,
		 uint64_t dest_len)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.allocate == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if ((mode & ELASTO_FALLOC_ALL_MASK) == mode) {
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "hole-punching range at %" PRIu64 ", len %" PRIu64 "\n",
	    dest_off, dest_len);

	ret = fh->ops.allocate(fh->mod_priv, mode, dest_off, dest_len);
	if (ret < 0) {
		goto err_out;
	}
	ret = 0;

err_out:
	return ret;
}

int
elasto_ftruncate(struct elasto_fh *fh,
		 uint64_t len)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.truncate == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "truncating to len %" PRIu64 "\n", len);

	ret = fh->ops.truncate(fh->mod_priv, len);
	if (ret < 0) {
		goto err_out;
	}
	ret = 0;

err_out:
	return ret;
}

int
elasto_fsplice(struct elasto_fh *src_fh,
	       uint64_t src_off,
	       struct elasto_fh *dest_fh,
	       uint64_t dest_off,
	       uint64_t len)
{
	int ret;

	ret = elasto_fh_validate(src_fh);
	if (ret < 0) {
		goto err_out;
	}
	ret = elasto_fh_validate(dest_fh);
	if (ret < 0) {
		goto err_out;
	}

	/* source and dest handles must use the same backend */
	if (src_fh->type != dest_fh->type) {
		ret = -EINVAL;
		dbg(0, "splice src and dest must be of the same type\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (src_fh->ops.splice == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if ((src_fh->open_flags & ELASTO_FOPEN_DIRECTORY)
			|| (dest_fh->open_flags & ELASTO_FOPEN_DIRECTORY)) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "splicing %" PRIu64 " bytes from %s to %s\n",
	    len, src_fh->open_path, dest_fh->open_path);

	ret = src_fh->ops.splice(src_fh->mod_priv, src_off,
				 dest_fh->mod_priv, dest_off, len);
	if (ret < 0) {
		goto err_out;
	}
	ret = 0;

err_out:
	return ret;
}

int
elasto_flist_ranges(struct elasto_fh *fh,
		    uint64_t off,
		    uint64_t len,
		    uint64_t flags,	/* reserved */
		    void *cb_priv,
		    int (*range_cb)(struct elasto_frange *range,
				    void *priv))
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fh->ops.list_ranges == NULL) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (fh->open_flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (flags != 0) {
		 dbg(0, "invalid IO request for directory handle\n");
		ret = -EINVAL;
		goto err_out;
	}

	dbg(3, "listing ranges %" PRIu64 " bytes at %" PRIu64 " from %s\n",
	    len, off, fh->open_path);

	ret = fh->ops.list_ranges(fh->mod_priv, off, len, flags,
				  cb_priv, range_cb);
	if (ret < 0) {
		goto err_out;
	}
	ret = 0;

err_out:
	return ret;
}
