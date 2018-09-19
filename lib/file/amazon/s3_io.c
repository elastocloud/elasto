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
#include "lib/s3_path.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "s3_handle.h"
#include "s3_stat.h"
#include "s3_io.h"

/*  S3 requires 5MB part uploads, except for the last part */
#define S3_MAX_PART (5 * BYTES_IN_MB)
#define S3_IO_SIZE_HTTP S3_MAX_PART
#define S3_IO_SIZE_HTTPS S3_MAX_PART

/* FIXME data_ctx is a dup of afx_io. combine in vfs */
struct s3_fwrite_multi_data_ctx {
	uint64_t this_off;
	uint64_t this_len;
	struct elasto_data *src_data;
};

static int
s3_fwrite_multi_iov_data_out_cb(uint64_t stream_off,
				uint64_t need,
				uint8_t **_out_buf,
				uint64_t *buf_len,
				void *priv)
{
	struct s3_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_src_buf;
	uint8_t *out_buf;

	/* sanity checks */
	if ((need > S3_MAX_PART)
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
s3_fwrite_multi_cb_data_out_cb(uint64_t stream_off,
			       uint64_t need,
			       uint8_t **_out_buf,
			       uint64_t *buf_len,
			       void *priv)
{
	struct s3_fwrite_multi_data_ctx *data_ctx = priv;
	int ret;
	uint8_t *this_out_buf = NULL;
	uint64_t this_buf_len = 0;

	/* sanity checks */
	if ((need > S3_MAX_PART)
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
s3_fwrite_multi_data_setup(uint64_t this_off,
			    uint64_t this_len,
			    struct elasto_data *src_data,
			    struct elasto_data **_this_data)
{
	struct elasto_data *this_data;
	struct s3_fwrite_multi_data_ctx *data_ctx;
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
					 s3_fwrite_multi_iov_data_out_cb,
					 0, NULL, data_ctx, &this_data);
	} else if (src_data->type == ELASTO_DATA_CB) {
		ret = elasto_data_cb_new(this_len,
					 s3_fwrite_multi_cb_data_out_cb,
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
s3_fwrite_multi_data_free(struct elasto_data *this_data)
{
	/* TODO implement and use elasto_data_cbpriv_get */
	struct s3_fwrite_multi_data_ctx *data_ctx = this_data->cb.priv;

	free(data_ctx);
	elasto_data_free(this_data);
}

static int
s3_fwrite_multi_start(struct s3_fh *s3_fh,
		      char **_upload_id)
{
	int ret;
	struct op *op;
	struct s3_rsp_mp_start *mp_start_rsp;
	char *upload_id;

	ret = s3_req_mp_start(&s3_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
	if (ret < 0) {
		dbg(0, "multi-part start req failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	mp_start_rsp = s3_rsp_mp_start(op);

	upload_id = strdup(mp_start_rsp->upload_id);
	if (upload_id == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	printf("multipart upload %s started\n", upload_id);
	*_upload_id = upload_id;
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fwrite_multi_handle(struct s3_fh *s3_fh,
		       const char *upload_id,
		       int part_num,
		       struct elasto_data *this_data,
		       struct s3_part **_part)
{
	int ret;
	struct op *op;
	struct s3_rsp_part_put *part_put_rsp;
	struct s3_part *part;

	part = malloc(sizeof(*part));
	if (part == NULL) {
		goto err_out;
	}
	memset(part, 0, sizeof(*part));

	ret = s3_req_part_put(&s3_fh->path, upload_id, part_num, this_data,
			      &op);
	if (ret < 0) {
		goto err_part_free;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
	if (ret < 0) {
		dbg(0, "part put failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	part_put_rsp = s3_rsp_part_put(op);
	if (part_put_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	part->pnum = part_num;
	part->etag = strdup(part_put_rsp->etag);
	if (part->etag == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}
	*_part = part;
	op->req.data = NULL;
	op_free(op);

	return 0;

err_op_free:
	op->req.data = NULL;
	op_free(op);
err_part_free:
	free(part);
err_out:
	return ret;
}

static int
s3_fwrite_multi_finish(struct s3_fh *s3_fh,
		       char *upload_id,
		       uint64_t num_parts,
		       struct list_head *parts)
{
	int ret;
	struct op *op;

	ret = s3_req_mp_done(&s3_fh->path, upload_id, num_parts, parts, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
	if (ret < 0) {
		dbg(0, "multi-part done req failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	dbg(0, "multipart upload %s finished\n", upload_id);
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fwrite_multi_abort(struct s3_fh *s3_fh,
		      char *upload_id)
{
	int ret;
	struct op *op;

	ret = s3_req_mp_abort(&s3_fh->path, upload_id, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
	if (ret < 0) {
		dbg(0, "multi-part abort req failed: %s\n", strerror(-ret));
		goto err_op_free;
	}

	dbg(0, "multipart upload %s aborted\n", upload_id);
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static void
s3_fwrite_parts_free(struct list_head *parts)
{
	struct s3_part *part;
	struct s3_part *part_n;

	list_for_each_safe(parts, part, part_n, list) {
		free(part->etag);
		free(part);
	}
}

static int
s3_fwrite_multi(struct s3_fh *s3_fh,
		uint64_t dest_off,
		uint64_t dest_len,
		struct elasto_data *src_data,
		uint64_t max_io)
{
	int ret;
	char *upload_id;
	struct elasto_data *this_data;
	uint64_t data_remain = dest_len;
	uint64_t data_off = 0;
	struct list_head parts;
	uint64_t part_num = 1;	/* must be > 0 */

	ret = s3_fwrite_multi_start(s3_fh, &upload_id);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&parts);
	while (data_remain > 0) {
		struct s3_part *part;
		uint64_t this_off = dest_off + data_off;
		uint64_t this_len = MIN(max_io, data_remain);

		dbg(0, "%" PRIu64 " multi fwrite: off=%" PRIu64 ", len=%"
		       PRIu64 "\n", part_num, this_off, this_len);

		ret = s3_fwrite_multi_data_setup(this_off, this_len, src_data,
						  &this_data);
		if (ret < 0) {
			dbg(0, "data setup failed\n");
			goto err_mp_abort;
		}

		ret = s3_fwrite_multi_handle(s3_fh, upload_id, part_num,
					     this_data, &part);
		if (ret < 0) {
			goto err_data_free;
		}

		s3_fwrite_multi_data_free(this_data);
		data_off += this_len;
		data_remain -= this_len;
		list_add_tail(&parts, &part->list);
		part_num++;
	}

	/* -1, as @part_num starts at 1 */
	ret = s3_fwrite_multi_finish(s3_fh, upload_id, part_num - 1,
				     &parts);
	if (ret < 0) {
		goto err_mp_abort;
	}
	free(upload_id);
	s3_fwrite_parts_free(&parts);

	return 0;

err_data_free:
	s3_fwrite_multi_data_free(this_data);
err_mp_abort:
	s3_fwrite_multi_abort(s3_fh, upload_id);
	free(upload_id);
	s3_fwrite_parts_free(&parts);
err_out:
	return ret;
}

int
s3_fwrite(void *mod_priv,
	  uint64_t dest_off,
	  uint64_t dest_len,
	  struct elasto_data *src_data)
{
	int ret;
	struct op *op;
	struct elasto_fstat fstat;
	struct s3_fh *s3_fh = mod_priv;
	uint32_t max_io;

	if (dest_len == 0) {
		ret = 0;
		goto err_out;
	}

	if (dest_off != 0) {
		/* https://forums.aws.amazon.com/thread.jspa?threadID=10752 */
		dbg(0, "S3 doesn't allow writes at arbitrary offsets\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* check current length <= dest_len, otherwise overwrite truncates */
	ret = s3_fstat(mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size > dest_len) {
		dbg(0, "S3 backend doesn't allow overwrites when IO len (%"
		    PRIu64 ") < current len (%" PRIu64 ")\n",
		    dest_len, fstat.size);
		ret = -EINVAL;
		goto err_out;
	}

	if (s3_fh->conn->insecure_http) {
		max_io = S3_IO_SIZE_HTTP;
	} else {
		max_io = S3_IO_SIZE_HTTPS;
	}
	if (dest_len > max_io) {
		/* split large IOs into multi-part uploads */
		ret = s3_fwrite_multi(s3_fh, dest_off, dest_len,
				      src_data, max_io);
		return ret;
	}

	ret = s3_req_obj_put(&s3_fh->path, src_data, NULL, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
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
s3_fread(void *mod_priv,
	 uint64_t src_off,
	 uint64_t src_len,
	 struct elasto_data *dest_data)
{
	int ret;
	struct op *op;
	struct s3_fh *s3_fh = mod_priv;

	ret = s3_req_obj_get(&s3_fh->path, src_off, src_len, dest_data, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(s3_fh->conn, op);
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
s3_fsplice(void *src_mod_priv,
	   uint64_t src_off,
	   void *dest_mod_priv,
	   uint64_t dest_off,
	   uint64_t len)
{
	struct s3_fh *src_s3_fh = src_mod_priv;
	struct s3_fh *dest_s3_fh = dest_mod_priv;
	struct op *op;
	struct elasto_fstat fstat;
	int ret;

	if (len == 0) {
		ret = 0;
		goto err_out;
	}

	if ((src_off != 0) || (dest_off != 0)) {
		dbg(0, "S3 backend doesn't support copies at arbitrary "
		       "offsets\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* check source length matches the copy length */
	ret = s3_fstat(src_mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size != len) {
		/* TODO could play with multi-part copies here */
		dbg(0, "S3 backend doesn't allow partial copies: src_len=%"
		    PRIu64 ", copy_len=%" PRIu64 "\n", fstat.size, len);
		ret = -EINVAL;
		goto err_out;
	}

	/*
	 * check dest file's current length <= copy len, otherwise overwrite
	 * truncates.
	 */
	ret = s3_fstat(dest_mod_priv, &fstat);
	if (ret < 0) {
		goto err_out;
	} else if ((fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) == 0) {
		ret = -EBADF;
		goto err_out;
	}

	if (fstat.size > len) {
		dbg(0, "S3 backend doesn't allow splice overwrites when IO len "
		       "(%" PRIu64 ") < current len (%" PRIu64 ")\n",
		       len, fstat.size);
		ret = -EINVAL;
		goto err_out;
	}

	ret = s3_req_obj_cp(&src_s3_fh->path, &dest_s3_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(dest_s3_fh->conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}
