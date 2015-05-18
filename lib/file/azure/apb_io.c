/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#include "lib/azure_blob_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "apb_handle.h"
#include "apb_stat.h"
#include "apb_io.h"

int
apb_fwrite(void *mod_priv,
	   struct elasto_conn *conn,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_page_put(apb_fh->path.acc,
			      apb_fh->path.ctnr,
			      apb_fh->path.blob,
			      src_data,
			      dest_off,
			      dest_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
	  struct elasto_conn *conn,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_get(apb_fh->path.acc,
			      apb_fh->path.ctnr,
			      apb_fh->path.blob,
			      true,
			      dest_data,
			      src_off,
			      src_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
	      struct elasto_conn *conn,
	      uint64_t len)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_prop_set(apb_fh->path.acc,
				   apb_fh->path.ctnr,
				   apb_fh->path.blob,
				   true,	/* is_page */
				   len,
				   &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
	      struct elasto_conn *conn,
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

	ret = az_req_page_put(apb_fh->path.acc,
			      apb_fh->path.ctnr,
			      apb_fh->path.blob,
			      NULL, /* clear range */
			      dest_off,
			      dest_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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

#define ABB_MAX_PART (4 * BYTES_IN_MB)
#define ABB_IO_SIZE_HTTP ABB_MAX_PART
/* FIXME: https writes over 16KB timeout. */
#define ABB_IO_SIZE_HTTPS (16 * BYTES_IN_KB)

/* FIXME data_ctx is a dup of afx_io. combine in vfs */
struct abb_fwrite_multi_data_ctx {
	uint64_t this_off;
	uint64_t this_len;
	struct elasto_data *src_data;
};

static int
abb_fwrite_multi_iov_data_out_cb(uint64_t stream_off,
				uint64_t need,
				uint8_t **_out_buf,
				uint64_t *buf_len,
				void *priv)
{
	struct abb_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_src_buf;
	uint8_t *out_buf;

	/* sanity checks */
	if ((need > ABB_MAX_PART)
	 || (data_ctx->this_off + stream_off + need
					> data_ctx->src_data->len)) {
		dbg(0, "failed write len sanity check!\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* TODO add free_cb to ELASTO_DATA_CB and avoid copy */
	out_buf = malloc(need);
	if (out_buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	this_src_buf = data_ctx->src_data->iov.buf
					+ data_ctx->this_off + stream_off;
	memcpy(out_buf, this_src_buf, need);
	/* out_buf freed by connection layer after send */
	*_out_buf = out_buf;
	*buf_len = need;

	ret = 0;
err_out:
	return ret;
}

static int
abb_fwrite_multi_cb_data_out_cb(uint64_t stream_off,
			       uint64_t need,
			       uint8_t **_out_buf,
			       uint64_t *buf_len,
			       void *priv)
{
	struct abb_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_out_buf = NULL;
	uint64_t this_buf_len = 0;

	/* sanity checks */
	if ((need > ABB_MAX_PART)
	 || (data_ctx->this_off + stream_off + need > data_ctx->src_data->len)) {
		dbg(0, "failed write len sanity check!\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = data_ctx->src_data->cb.out_cb(data_ctx->this_off + stream_off,
					    need, &this_out_buf, &this_buf_len,
					    data_ctx->src_data->cb.priv);
	if (ret < 0) {
		goto err_out;
	}

	/* out_buf freed by connection layer after send */
	*_out_buf = this_out_buf;
	*buf_len = this_buf_len;

	ret = 0;
err_out:
	return ret;
}

static int
abb_fwrite_multi_data_setup(uint64_t this_off,
			    uint64_t this_len,
			    struct elasto_data *src_data,
			    struct elasto_data **_this_data)
{
	struct elasto_data *this_data;
	struct abb_fwrite_multi_data_ctx *data_ctx;
	int ret;

	data_ctx = malloc(sizeof(*data_ctx));
	if (data_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	data_ctx->this_off = this_off;
	data_ctx->this_len = this_len;
	data_ctx->src_data = src_data;

	if (src_data->type == ELASTO_DATA_IOV) {
		ret = elasto_data_cb_new(this_len,
					 abb_fwrite_multi_iov_data_out_cb,
					 0, NULL, data_ctx, &this_data);
	} else if (src_data->type == ELASTO_DATA_CB) {
		ret = elasto_data_cb_new(this_len,
					 abb_fwrite_multi_cb_data_out_cb,
					 0, NULL, data_ctx, &this_data);
	} else {
		assert(false);	/* already checked */
	}
	if (ret < 0) {
		goto err_ctx_free;
	}

	*_this_data = this_data;

	return 0;

err_ctx_free:
	free(data_ctx);
err_out:
	return ret;
}

static void
abb_fwrite_multi_data_free(struct elasto_data *this_data)
{
	struct abb_fwrite_multi_data_ctx *data_ctx = this_data->cb.priv;

	free(data_ctx);
	elasto_data_free(this_data);
}

static int
abb_fwrite_multi_handle(struct apb_fh *apb_fh,
			struct elasto_conn *conn,
			int blk_num,
			struct elasto_data *this_data,
			struct azure_block **_blk)
{
	int ret;
	struct op *op;
	struct azure_block *blk;

	blk = malloc(sizeof(*blk));
	if (blk == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(blk, 0, sizeof(*blk));

	/*
	 * For a given blob, the length of the value specified for the
	 * blockid parameter must be the same size for each block.
	 */
	ret = asprintf(&blk->id, "%s_block%06d",
		       apb_fh->path.blob, blk_num);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_blk_free;
	}

	ret = az_req_block_put(apb_fh->path.acc,
			       apb_fh->path.ctnr,
			       apb_fh->path.blob,
			       blk->id,
			       this_data,
			       &op);
	if (ret < 0) {
		goto err_id_free;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		dbg(0, "part put failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	blk->state = BLOCK_STATE_UNCOMMITED;
	*_blk = blk;
	op->req.data = NULL;
	op_free(op);

	return 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_id_free:
	free(blk->id);
err_blk_free:
	free(blk);
err_out:
	return ret;
}

static int
abb_fwrite_multi_finish(struct apb_fh *apb_fh,
			struct elasto_conn *conn,
			uint64_t num_blks,
			struct list_head *blks)
{
	int ret;
	struct op *op;

	ret = az_req_block_list_put(apb_fh->path.acc,
				    apb_fh->path.ctnr,
				    apb_fh->path.blob,
				    num_blks, blks, &op);
	if (ret < 0) {
		dbg(0, "multi-part done req init failed: %s\n", strerror(-ret));
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		dbg(0, "multi-part done req failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	dbg(0, "multipart upload finished\n");
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static void
abb_fwrite_blks_free(struct list_head *blks)
{
	struct azure_block *blk;
	struct azure_block *blk_n;

	list_for_each_safe(blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
}

static int
abb_fwrite_multi(struct apb_fh *apb_fh,
		 struct elasto_conn *conn,
		 uint64_t dest_off,
		 uint64_t dest_len,
		 struct elasto_data *src_data,
		 uint64_t max_io)
{
	int ret;
	struct elasto_data *this_data;
	uint64_t data_remain = dest_len;
	uint64_t data_off = 0;
	struct list_head blks;
	uint64_t blk_num = 0;	/* can start at 0, unlike S3 multi-part */

	if ((dest_len / max_io > 100000) || dest_len > INT64_MAX) {
		/*
		 * A blob can have a maximum of 100,000 uncommitted blocks at
		 * any given time, and the set of uncommitted blocks cannot
		 * exceed 400 GB in total size.
		 */
		ret = -EINVAL;
		goto err_out;
	}

	list_head_init(&blks);
	while (data_remain > 0) {
		struct azure_block *blk;
		uint64_t this_off = dest_off + data_off;
		uint64_t this_len = MIN(max_io, data_remain);

		dbg(0, "multi fwrite: off=%" PRIu64 ", len=%" PRIu64 "\n",
		    this_off, this_len);

		ret = abb_fwrite_multi_data_setup(this_off, this_len, src_data,
						  &this_data);
		if (ret < 0) {
			dbg(0, "data setup failed\n");
			goto err_mp_abort;
		}

		ret = abb_fwrite_multi_handle(apb_fh, conn, blk_num,
					      this_data, &blk);
		if (ret < 0) {
			goto err_data_free;
		}

		abb_fwrite_multi_data_free(this_data);
		data_off += this_len;
		data_remain -= this_len;
		list_add_tail(&blks, &blk->list);
		blk_num++;
	}

	ret = abb_fwrite_multi_finish(apb_fh, conn, blk_num, &blks);
	if (ret < 0) {
		goto err_mp_abort;
	}
	abb_fwrite_blks_free(&blks);

	return 0;

err_data_free:
	abb_fwrite_multi_data_free(this_data);
err_mp_abort:
	/* FIXME cleanup uploaded blob blocks */
	abb_fwrite_blks_free(&blks);
err_out:
	return ret;
}

int
abb_fwrite(void *mod_priv,
	   struct elasto_conn *conn,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct elasto_fstat fstat;
	struct apb_fh *apb_fh = mod_priv;
	uint32_t max_io;

	if (dest_len == 0) {
		ret = 0;
		goto err_out;
	}

	if (dest_off != 0) {
		dbg(0, "Azure block blobs don't allow writes at arbitrary "
		    "offsets\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* check current length <= dest_len, otherwise overwrite truncates */
	ret = abb_fstat(mod_priv, conn, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size > dest_len) {
		dbg(0, "Azure block blobs don't allow overwrites when IO len (%"
		    PRIu64 ") < current len (%" PRIu64 ")\n",
		    dest_len, fstat.size);
		ret = -EINVAL;
		goto err_out;
	}

	max_io = (conn->insecure_http ? ABB_IO_SIZE_HTTP : ABB_IO_SIZE_HTTPS);
	if (dest_len > max_io) {
		/* split large IOs into multi-part uploads */
		ret = abb_fwrite_multi(apb_fh, conn, dest_off, dest_len,
				       src_data, max_io);
		return ret;
	}

	ret = az_req_blob_put(apb_fh->path.acc,
			      apb_fh->path.ctnr,
			      apb_fh->path.blob,
			      src_data, 0,	/* non-page block blob */
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
abb_fread(void *mod_priv,
	  struct elasto_conn *conn,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_get(apb_fh->path.acc,
			      apb_fh->path.ctnr,
			      apb_fh->path.blob,
			      false,
			      dest_data,
			      src_off,
			      src_len,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
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
