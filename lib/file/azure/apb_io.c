/*
 * Copyright (C) SUSE LINUX GmbH 2015-2017, all rights reserved.
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
#include "lib/azure_req.h"
#include "lib/azure_blob_path.h"
#include "lib/azure_blob_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "elasto/file.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "apb_handle.h"
#include "apb_stat.h"
#include "apb_io.h"

int
apb_fwrite(void *mod_priv,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_page_put(&apb_fh->path,
			      src_data,
			      dest_off,
			      dest_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
apb_fread(void *mod_priv,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_get(&apb_fh->path,
			      true,
			      dest_data,
			      src_off,
			      src_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op->rsp.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
apb_ftruncate(void *mod_priv,
	      uint64_t len)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_prop_set(&apb_fh->path,
				   true,	/* is_page */
				   len,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
apb_fallocate(void *mod_priv,
	      uint32_t mode,
	      uint64_t dest_off,
	      uint64_t dest_len)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	if (mode != ELASTO_FALLOC_PUNCH_HOLE) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_page_put(&apb_fh->path,
			      NULL, /* clear range */
			      dest_off,
			      dest_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}
	ret = 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_out:
	return ret;
}

int
apb_fsplice(void *src_mod_priv,
	    uint64_t src_off,
	    void *dest_mod_priv,
	    uint64_t dest_off,
	    uint64_t len)
{
	struct apb_fh *src_apb_fh = src_mod_priv;
	struct apb_fh *dest_apb_fh = dest_mod_priv;
	struct op *op;
	struct elasto_fstat fstat;
	int ret;

	if (len == 0) {
		ret = 0;
		goto err_out;
	}

	if ((src_off != 0) || (dest_off != 0)) {
		dbg(0, "Azure blob backend doesn't support copies at arbitrary "
		       "offsets\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* check source length matches the copy length */
	ret = apb_fstat(src_mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size != len) {
		dbg(0, "Azure blob backend doesn't allow partial copies: "
		       "src_len=%" PRIu64 ", copy_len=%" PRIu64 "\n",
		       fstat.size, len);
		ret = -EINVAL;
		goto err_out;
	}

	/*
	 * check dest file's current length <= copy len, otherwise overwrite
	 * truncates.
	 */
	ret = apb_fstat(dest_mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size > len) {
		dbg(0, "Azure backend doesn't allow splice overwrites when IO "
		       "len (%" PRIu64 ") < current len (%" PRIu64 ")\n",
		       len, fstat.size);
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_cp(&src_apb_fh->path, &dest_apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(dest_apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_flist_ranges_iter(struct apb_fh *apb_fh,
		      uint64_t this_off,
		      uint64_t this_len,
		      void *priv,
		      int (*range_cb)(struct elasto_frange *,
				      void *))
{
	int ret;
	struct op *op;
	struct az_rsp_page_ranges_get *page_ranges_get_rsp;
	struct az_page_range *range;
	struct elasto_frange frange;

	ret = az_req_page_ranges_get(&apb_fh->path, this_off, this_len, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	page_ranges_get_rsp = az_rsp_page_ranges_get(op);
	frange.file_size = page_ranges_get_rsp->blob_len;
	list_for_each(&page_ranges_get_rsp->ranges, range, list) {
		if (range->start_byte > range->end_byte) {
			ret = -EIO;
			goto err_op_free;
		}
		frange.off = range->start_byte;
		frange.len = range->end_byte - range->start_byte + 1;
		ret = range_cb(&frange, priv);
		if (ret < 0) {
			goto err_op_free;
		}
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
apb_flist_ranges(void *mod_priv,
		 uint64_t off,
		 uint64_t len,
		 uint64_t flags,	/* reserved */
		 void *cb_priv,
		 int (*range_cb)(struct elasto_frange *range,
				 void *priv))
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;
	uint64_t remain;
	uint64_t this_off;

	remain = len;
	this_off = off;

	/* split into 1GB chunks - fragmented blobs may timeout otherwise */
	while (remain > 0) {
		uint64_t this_len;

		this_len = MIN(remain, BYTES_IN_GB);
		ret = apb_flist_ranges_iter(apb_fh, this_off, this_len,
					    cb_priv, range_cb);
		if (ret < 0) {
			goto err_out;
		}

		this_off += this_len;
		remain -= this_len;
	}
	ret = 0;
err_out:
	return ret;
}
