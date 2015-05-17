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
#include "lib/azure_fs_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "afs_handle.h"
#include "afs_stat.h"
#include "afs_io.h"

/*
 * Each range submitted with Put Range for an update operation may be up to 4 MB
 * in size. If you attempt to upload a range that is larger than 4 MB, the
 * service returns status code 413 (Request Entity Too Large).
 */
#define AFS_MAX_WRITE (4 * BYTES_IN_MB)

struct afs_fwrite_multi_data_ctx {
	uint64_t this_off;
	uint64_t this_len;
	struct elasto_data *src_data;
};

static int
afs_fwrite_multi_iov_data_out_cb(uint64_t stream_off,
				 uint64_t need,
				 uint8_t **_out_buf,
				 uint64_t *buf_len,
				 void *priv)
{
	struct afs_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_src_buf;
	uint8_t *out_buf;

	/* sanity checks */
	if ((need > AFS_MAX_WRITE)
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
afs_fwrite_multi_cb_data_out_cb(uint64_t stream_off,
				uint64_t need,
				uint8_t **_out_buf,
				uint64_t *buf_len,
				void *priv)
{
	struct afs_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_out_buf = NULL;
	uint64_t this_buf_len = 0;

	/* sanity checks */
	if ((need > AFS_MAX_WRITE)
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
afs_fwrite_multi_data_setup(uint64_t this_off,
			    uint64_t this_len,
			    struct elasto_data *src_data,
			    struct elasto_data **_this_data)
{
	struct elasto_data *this_data;
	struct afs_fwrite_multi_data_ctx *data_ctx;
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
					 afs_fwrite_multi_iov_data_out_cb,
					 0, NULL, data_ctx, &this_data);
	} else if (src_data->type == ELASTO_DATA_CB) {
		ret = elasto_data_cb_new(this_len,
					 afs_fwrite_multi_cb_data_out_cb,
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
afs_fwrite_multi_data_free(struct elasto_data *this_data)
{
	/* TODO implement and use elasto_data_cbpriv_get */
	struct afs_fwrite_multi_data_ctx *data_ctx = this_data->cb.priv;

	free(data_ctx);
	elasto_data_free(this_data);
}

static int
afs_fwrite_multi(struct afs_fh *afs_fh,
		 struct elasto_conn *conn,
		 uint64_t dest_off,
		 uint64_t dest_len,
		 struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct elasto_data *this_data;
	uint64_t data_remain = dest_len;
	uint64_t data_off = 0;

	while (data_remain > 0) {
		uint64_t this_off = dest_off + data_off;
		uint64_t this_len = MIN(AFS_MAX_WRITE, data_remain);

		dbg(0, "multi fwrite: off=%" PRIu64 ", len=%" PRIu64 "\n",
		    this_off, this_len);

		ret = afs_fwrite_multi_data_setup(this_off, this_len, src_data,
						  &this_data);
		if (ret < 0) {
			dbg(0, "data setup failed\n");
			goto err_out;
		}

		ret = az_fs_req_file_put(afs_fh->path.acc,
					 afs_fh->path.share,
					 afs_fh->path.parent_dir,
					 afs_fh->path.file,
					 this_off,
					 this_len,
					 this_data,
					 &op);
		if (ret < 0) {
			goto err_data_free;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			dbg(0, "multi-write failed at data_off %" PRIu64 "\n",
			    data_off);
			goto err_op_free;
		}

		op->req.data = NULL;
		op_free(op);
		afs_fwrite_multi_data_free(this_data);
		data_off += this_len;
		data_remain -= this_len;
	}

	return 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_data_free:
	afs_fwrite_multi_data_free(this_data);
err_out:
	return ret;
}

int
afs_fwrite(void *mod_priv,
	   struct elasto_conn *conn,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;
	struct elasto_fstat fstat;

	if ((src_data->type != ELASTO_DATA_CB)
				&& (src_data->type != ELASTO_DATA_IOV)) {
		dbg(0, "afs write only supports CB and IOV data types\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = afs_fstat(mod_priv, conn, &fstat);
	if (ret < 0) {
		dbg(0, "failed to stat dest file: %s\n", strerror(-ret));
		goto err_out;
	}

	if (fstat.size < dest_off + dest_len) {
		/*
		 * Need to truncate file out to new (larger) length, as AFS Put
		 * Range doesn't allow writes past the current length.
		 */
		dbg(0, "truncating file to %" PRIu64 " prior to write\n",
		    dest_off + dest_len);
		ret = afs_ftruncate(mod_priv, conn, dest_off + dest_len);
		if (ret < 0) {
			dbg(0, "failed to truncate dest file: %s\n",
			    strerror(-ret));
			goto err_out;
		}
	}

	if (dest_len > AFS_MAX_WRITE) {
		ret = afs_fwrite_multi(afs_fh, conn, dest_off, dest_len,
				       src_data);
		return ret;
	}

	ret = az_fs_req_file_put(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
				 dest_off,
				 dest_len,
				 src_data,
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
afs_fread(void *mod_priv,
	  struct elasto_conn *conn,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_req_file_get(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
				 src_off,
				 src_len,
				 dest_data,
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
afs_ftruncate(void *mod_priv,
	      struct elasto_conn *conn,
	      uint64_t len)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_req_file_prop_set(afs_fh->path.acc,
				      afs_fh->path.share,
				      afs_fh->path.parent_dir,
				      afs_fh->path.file,
				      AZ_FS_FILE_PROP_LEN,
				      len,
				      NULL,
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
afs_fallocate(void *mod_priv,
	      struct elasto_conn *conn,
	      uint32_t mode,
	      uint64_t dest_off,
	      uint64_t dest_len)
{
	int ret;
	struct op *op;
	struct afs_fh *afs_fh = mod_priv;

	if (mode != ELASTO_FALLOC_PUNCH_HOLE) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_file_put(afs_fh->path.acc,
				 afs_fh->path.share,
				 afs_fh->path.parent_dir,
				 afs_fh->path.file,
				 dest_off,
				 dest_len,
				 NULL, /* clear range */
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
