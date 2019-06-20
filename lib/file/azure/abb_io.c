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
#include <event2/event.h>

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
#include "abb_io.h"

#define ABB_MAX_IN_FLIGHT 8
#define ABB_MAX_PART (4 * BYTES_IN_MB)
#define ABB_IO_SIZE_HTTP (2 * BYTES_IN_MB)
#define ABB_IO_SIZE_HTTPS (2 * BYTES_IN_MB)

struct abb_io_multi_state {
	int error_ret;
	struct apb_fh *apb_fh;
	struct event_base *ev_base;
	uint64_t off;
	struct elasto_data *data;
	uint64_t max_io;
	uint64_t data_remain;
	uint64_t data_off;
	uint32_t max_in_flight;
	uint32_t in_flight;
	/*
	 * blks list is needed as a parameter for block list put req, so use
	 * same list to access child data_ctxs with container_of().
	 */
	uint32_t blk_num;
	struct list_head blks;
	char *content_type;
};

struct abb_fwrite_multi_data_ctx {
	struct abb_io_multi_state *parent_state;
	uint64_t this_off;
	uint64_t this_len;
	struct op *op;
	struct event *ev_tx;
	struct elasto_data *this_data;
	struct azure_block blk;
};

static int
abb_fwrite_multi_iov_data_out_cb(uint64_t stream_off,
				uint64_t need,
				uint8_t **_out_buf,
				uint64_t *buf_len,
				void *priv)
{
	struct abb_fwrite_multi_data_ctx *data_ctx = priv;
	struct elasto_data *src_data;
	int ret;
	uint8_t *this_src_buf;
	uint8_t *out_buf;

	/* sanity checks */
	if ((need > ABB_MAX_PART)
			 || (data_ctx->parent_state == NULL)
			 || (data_ctx->parent_state->data == NULL)
			 || ((data_ctx->this_off + stream_off + need)
				> data_ctx->parent_state->data->len)) {
		dbg(0, "failed write len sanity check!\n");
		ret = -EINVAL;
		goto err_out;
	}

	src_data = data_ctx->parent_state->data;

	/* TODO add free_cb to ELASTO_DATA_CB and avoid copy */
	out_buf = malloc(need);
	if (out_buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	this_src_buf = src_data->iov.buf + data_ctx->this_off + stream_off;
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
	struct elasto_data *src_data;
	int ret;
	uint8_t *this_out_buf = NULL;
	uint64_t this_buf_len = 0;

	/* sanity checks */
	if ((need > ABB_MAX_PART)
			 || (data_ctx->parent_state == NULL)
			 || (data_ctx->parent_state->data == NULL)
			 || ((data_ctx->this_off + stream_off + need)
				> data_ctx->parent_state->data->len)) {
		dbg(0, "failed write len sanity check!\n");
		ret = -EINVAL;
		goto err_out;
	}

	src_data = data_ctx->parent_state->data;

	ret = src_data->cb.out_cb(data_ctx->this_off + stream_off, need,
				  &this_out_buf, &this_buf_len,
				  src_data->cb.priv);
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
abb_fwrite_multi_data_setup(struct abb_io_multi_state *multi_state,
			    uint64_t this_off,
			    uint64_t this_len,
			    struct abb_fwrite_multi_data_ctx **_data_ctx)
{
	struct abb_fwrite_multi_data_ctx *data_ctx;
	int ret;

	data_ctx = malloc(sizeof(*data_ctx));
	if (data_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(data_ctx, 0, sizeof(*data_ctx));

	data_ctx->parent_state = multi_state;
	data_ctx->this_off = this_off;
	data_ctx->this_len = this_len;

	if (multi_state->data->type == ELASTO_DATA_IOV) {
		ret = elasto_data_cb_new(this_len,
					 abb_fwrite_multi_iov_data_out_cb,
					 0, NULL, data_ctx,
					 &data_ctx->this_data);
	} else if (multi_state->data->type == ELASTO_DATA_CB) {
		ret = elasto_data_cb_new(this_len,
					 abb_fwrite_multi_cb_data_out_cb,
					 0, NULL, data_ctx,
					 &data_ctx->this_data);
	} else {
		assert(false);	/* already checked */
	}
	if (ret < 0) {
		goto err_ctx_free;
	}

	*_data_ctx = data_ctx;

	return 0;

err_ctx_free:
	free(data_ctx);
err_out:
	return ret;
}

static void
abb_fwrite_multi_data_free(struct abb_fwrite_multi_data_ctx *data_ctx)
{
	elasto_conn_op_free(data_ctx->ev_tx);
	if (data_ctx->op != NULL) {
		data_ctx->op->req.data = NULL;
		op_free(data_ctx->op);
	}
	elasto_data_free(data_ctx->this_data);
	free(data_ctx->blk.id);
	free(data_ctx);
}

static void
abb_fwrite_multi_data_list_free(struct list_head *blks)
{
	struct azure_block *blk;
	struct azure_block *blk_n;

	list_for_each_safe(blks, blk, blk_n, list) {
		struct abb_fwrite_multi_data_ctx *data_ctx;

		data_ctx = container_of(blk, struct abb_fwrite_multi_data_ctx,
					blk);
		abb_fwrite_multi_data_free(data_ctx);
	}
}

static void
abb_io_multi_error_set(struct abb_io_multi_state *multi_state,
		       int ret)
{
	/* first error code takes precedence */
	if ((multi_state->error_ret != 0) || (ret == 0)) {
		return;
	}

	dbg(0, "setting multi-state put error: %d\n", ret);
	multi_state->error_ret = ret;
}

struct abb_fwrite_multi_finish_state {
	struct abb_io_multi_state *multi_state;
	struct op *op;
	struct event *ev_tx;
};

static void
abb_fwrite_multi_finish_cmpl(evutil_socket_t sock,
			     short flags,
			     void *priv)
{
	int ret;
	struct abb_fwrite_multi_finish_state *finish_state = priv;
	struct abb_io_multi_state *multi_state = finish_state->multi_state;

	ret = elasto_conn_op_rx(finish_state->ev_tx);
	if (ret < 0) {
		dbg(2, "block list put failed: %s\n", strerror(-ret));
		abb_io_multi_error_set(multi_state, ret);
	} else if (finish_state->op->rsp.is_error) {
		ret = elasto_fop_err_code_map(finish_state->op->rsp.err_code);
		dbg(2, "block list put error response: %d\n", ret);
		abb_io_multi_error_set(multi_state, ret);
	}
	elasto_conn_op_free(finish_state->ev_tx);
	op_free(finish_state->op);

	dbg(0, "multipart upload finished\n");

	ret = event_base_loopbreak(multi_state->ev_base);
	if (ret < 0) {
		dbg(0, "failed to break dispatch loop\n");
	}
	/* data_ctx cleanup after event loop exit */
}

static int
abb_fwrite_multi_finish(struct abb_io_multi_state *multi_state)
{
	int ret;
	struct abb_fwrite_multi_finish_state *finish_state;

	finish_state = malloc(sizeof(*finish_state));
	if (finish_state == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(finish_state, 0, sizeof(*finish_state));

	finish_state->multi_state = multi_state;

	ret = az_req_block_list_put(&multi_state->apb_fh->path,
				    multi_state->blk_num, &multi_state->blks,
				    multi_state->content_type,
				    &finish_state->op);
	if (ret < 0) {
		dbg(0, "multi-part done req init failed: %s\n", strerror(-ret));
		goto err_state_free;
	}

	finish_state->ev_tx = elasto_conn_op_tx(multi_state->apb_fh->io_conn,
						finish_state->op,
						abb_fwrite_multi_finish_cmpl,
						finish_state);
	if (finish_state->ev_tx == NULL) {
		dbg(0, "multi-part done tx failed: %s\n", strerror(-ret));
		ret = -ENOMEM;
		goto err_op_free;
	}

	return 0;
err_op_free:
	op_free(finish_state->op);
err_state_free:
	free(finish_state);
err_out:
	return ret;
}

static void
abb_io_multi_tx_pipe_fill(struct abb_io_multi_state *multi_state);

static void
abb_fwrite_multi_tx_cmpl(evutil_socket_t sock,
			 short flags,
			 void *priv)
{
	int ret;
	struct abb_fwrite_multi_data_ctx *data_ctx = priv;
	struct abb_io_multi_state *multi_state = data_ctx->parent_state;

	ret = elasto_conn_op_rx(data_ctx->ev_tx);
	if (ret < 0) {
		dbg(2, "part put failed: %s\n", strerror(-ret));
		abb_io_multi_error_set(multi_state, ret);
		goto err_loopbreak;
	}
	if (data_ctx->op->rsp.is_error) {
		ret = elasto_fop_err_code_map(data_ctx->op->rsp.err_code);
		dbg(2, "part put error response: %d\n", ret);
		abb_io_multi_error_set(multi_state, ret);
		goto err_loopbreak;
	}

	data_ctx->blk.state = BLOCK_STATE_UNCOMMITED;
	data_ctx->parent_state->in_flight--;
	abb_io_multi_tx_pipe_fill(data_ctx->parent_state);

	if ((data_ctx->parent_state->in_flight != 0)
			|| (data_ctx->parent_state->data_remain != 0)) {
		dbg(3, "fwrite multi tx: still in flight: %u, data remaining: %"
		    PRIu64 "\n", data_ctx->parent_state->in_flight,
		    data_ctx->parent_state->data_remain);
		return;
	}

	/* all done, just need to commit all blocks */
	ret = abb_fwrite_multi_finish(multi_state);
	if (ret < 0) {
		abb_io_multi_error_set(multi_state, ret);
		goto err_loopbreak;
	}

	return;

err_loopbreak:
	ret = event_base_loopbreak(multi_state->ev_base);
	if (ret < 0) {
		dbg(0, "failed to break dispatch loop\n");
	}
	/* data_ctx cleanup after event loop exit */
}

static int
abb_fwrite_multi_tx(struct abb_io_multi_state *multi_state,
		    uint64_t this_off,
		    uint64_t this_len)
{
	int ret;
	struct azure_block *blk;
	struct abb_fwrite_multi_data_ctx *data_ctx;
	struct event *ev_tx;

	ret = abb_fwrite_multi_data_setup(multi_state,
					  this_off, this_len,
					  &data_ctx);
	if (ret < 0) {
		dbg(0, "data setup failed\n");
		goto err_out;
	}

	blk = &data_ctx->blk;

	/*
	 * For a given blob, the length of the value specified for the
	 * blockid parameter must be the same size for each block, and
	 * mustn't exceed 64 bytes.
	 */
	ret = asprintf(&blk->id, "block%06d", multi_state->blk_num);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_ctx_free;
	}

	ret = az_req_block_put(&multi_state->apb_fh->path,
			       blk->id,
			       data_ctx->this_data,
			       &data_ctx->op);
	if (ret < 0) {
		goto err_data_ctx_free;
	}

	ev_tx = elasto_conn_op_tx(multi_state->apb_fh->io_conn, data_ctx->op,
				  abb_fwrite_multi_tx_cmpl, data_ctx);
	if (ev_tx == NULL) {
		ret = -ENOMEM;
		goto err_data_ctx_free;
	}
	data_ctx->ev_tx = ev_tx;
	list_add_tail(&multi_state->blks, &blk->list);
	multi_state->blk_num++;

	return 0;

err_data_ctx_free:
	abb_fwrite_multi_data_free(data_ctx);
err_out:
	return ret;
}

static void
abb_io_multi_tx_pipe_fill(struct abb_io_multi_state *multi_state)
{
	int ret;

	while ((multi_state->in_flight < multi_state->max_in_flight)
					&& (multi_state->data_remain > 0)) {
		uint64_t this_off = multi_state->off
					+ multi_state->data_off;
		uint64_t this_len = MIN(multi_state->max_io,
					multi_state->data_remain);

		dbg(0, "multi fwrite: off=%" PRIu64 ", len=%" PRIu64 "\n",
		    this_off, this_len);

		ret = abb_fwrite_multi_tx(multi_state, this_off, this_len);
		if (ret < 0) {
			goto err_break;
		}

		multi_state->data_off += this_len;
		multi_state->data_remain -= this_len;
		multi_state->in_flight++;
	}

	return;

err_break:
	abb_io_multi_error_set(multi_state, ret);
	ret = event_base_loopbreak(multi_state->ev_base);
	if (ret < 0) {
		dbg(0, "failed to break dispatch loop\n");
	}
	/* data_ctx cleanup after event loop exit */
}

static int
abb_fwrite_multi(struct apb_fh *apb_fh,
		 uint64_t dest_off,
		 uint64_t dest_len,
		 struct elasto_data *src_data,
		 uint64_t max_io,
		 const char *content_type)
{
	int ret;
	struct abb_io_multi_state *multi_state;

	if ((dest_len / max_io > 100000) || dest_len > INT64_MAX) {
		/*
		 * A blob can have a maximum of 100,000 uncommitted blocks at
		 * any given time, and the set of uncommitted blocks cannot
		 * exceed 400 GB in total size.
		 */
		ret = -EINVAL;
		goto err_out;
	}

	multi_state = malloc(sizeof(*multi_state));
	if (multi_state == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(multi_state, 0, sizeof(*multi_state));
	multi_state->ev_base = elasto_conn_ev_base_get(apb_fh->io_conn);
	multi_state->apb_fh = apb_fh;
	multi_state->off = dest_off;
	multi_state->data = src_data;
	multi_state->max_io = max_io;
	multi_state->data_remain = dest_len;
	multi_state->max_in_flight = ABB_MAX_IN_FLIGHT;
	/* blk_num can start at 0, unlike S3 multi-part */
	list_head_init(&multi_state->blks);
	if (content_type != NULL) {
		multi_state->content_type = strdup(content_type);
		if (multi_state->content_type == NULL) {
			ret = -ENOMEM;
			goto err_mstate_free;
		}
	}

	abb_io_multi_tx_pipe_fill(multi_state);

	ret = event_base_dispatch(multi_state->ev_base);
	if (ret < 0) {
		dbg(0, "event_base_dispatch() failed\n");
		goto err_mp_abort;
	}

	if (multi_state->error_ret != 0) {
		ret = multi_state->error_ret;
		goto err_mp_abort;
	}

	abb_fwrite_multi_data_list_free(&multi_state->blks);
	free(multi_state->content_type);
	free(multi_state);

	return 0;

err_mp_abort:
	/* FIXME cleanup uploaded blob blocks */
	abb_fwrite_multi_data_list_free(&multi_state->blks);
	free(multi_state->content_type);
err_mstate_free:
	free(multi_state);
err_out:
	return ret;
}

int
abb_fwrite(void *mod_priv,
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
	ret = abb_fstat(mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	}

       if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
               ret = -EBADF;
               goto err_out;
       }

	/*
	 * XXX we're overwriting an existing object, so need to retain the
	 * content-type provided at open+create time.
	 */
	if ((fstat.field_mask & ELASTO_FSTAT_FIELD_CONTENT_TYPE) == 0) {
		dbg(0, "Block blob stat content-type missing\n");
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

	if (apb_fh->io_conn->insecure_http) {
		max_io = ABB_IO_SIZE_HTTP;
	} else {
		max_io = ABB_IO_SIZE_HTTPS;
	}
	if (dest_len > max_io) {
		/* split large IOs into multi-part uploads */
		ret = abb_fwrite_multi(apb_fh, dest_off, dest_len, src_data,
				       max_io, fstat.content_type);
		return ret;
	}

	ret = az_req_blob_put(&apb_fh->path,
			      src_data, 0,	/* non-page block blob */
			      fstat.content_type,
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
abb_fread(void *mod_priv,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct apb_fh *apb_fh = mod_priv;

	ret = az_req_blob_get(&apb_fh->path,
			      false,
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
abb_fsplice(void *src_mod_priv,
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
	ret = abb_fstat(src_mod_priv, &fstat);
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
	ret = abb_fstat(dest_mod_priv, &fstat);
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
