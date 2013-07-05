/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2013, all rights reserved.
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
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <curl/curl.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_put.h"

/* split any blob over 10MB into separate blocks */
#define BLOCK_THRESHOLD (10 * 1024 * 1024)

void
cli_put_args_free(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		free(cli_args->az.blob_acc);
		free(cli_args->az.ctnr_name);
		free(cli_args->az.blob_name);
	} else if (cli_args->type == CLI_TYPE_S3) {
		free(cli_args->s3.bkt_name);
		free(cli_args->s3.obj_name);
	}
	free(cli_args->put.local_path);
}

static int
cli_put_args_parse_az(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[2],
				  &cli_args->az.blob_acc,
				  &cli_args->az.ctnr_name,
				  &cli_args->az.blob_name);
	if (ret < 0)
		goto err_out;

	if (cli_args->az.blob_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
	    "Invalid remote Azure path, must be <account>/<container>/<blob>");
		ret = -EINVAL;
		goto err_path_free;
	}

	return 0;

err_path_free:
	free(cli_args->az.ctnr_name);
	free(cli_args->az.blob_acc);
err_out:
	return ret;
}

static int
cli_put_args_parse_s3(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[2],
				  &cli_args->s3.bkt_name,
				  &cli_args->s3.obj_name, NULL);
	if (ret < 0)
		goto err_out;

	if (cli_args->s3.obj_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
		   "Invalid remote S3 path, must be <bucket>/<object>");
		ret = -EINVAL;
		goto err_bkt_free;
	}

	return 0;

err_bkt_free:
	free(cli_args->s3.bkt_name);
err_out:
	return ret;
}

int
cli_put_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	cli_args->put.local_path = strdup(argv[1]);
	if (cli_args->put.local_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = cli_put_args_parse_az(argc, argv, cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_put_args_parse_s3(argc, argv, cli_args);
	} else {
		ret = -ENOTSUP;
	}
	if (ret < 0) {
		goto err_local_free;
	}
	cli_args->cmd = CLI_CMD_PUT;

	return 0;

err_local_free:
	free(cli_args->put.local_path);
err_out:
	return ret;
}

#define min(a, b) (((a) < (b)) ? (a) : (b))

static int
cli_put_blocks(struct elasto_conn *econn,
	       struct cli_args *cli_args,
	       uint64_t size,
	       struct list_head **blks_ret)
{
	int num_blks = (size / BLOB_BLOCK_MAX) + ((size % BLOB_BLOCK_MAX) != 0);
	int ret;
	struct azure_op_data *op_data;
	struct list_head *blks;
	struct azure_block *blk;
	struct azure_block *blk_n;
	uint64_t bytes_put = 0;
	int blks_put = 0;
	struct azure_op op;

	if ((num_blks > 100000) || size > INT64_MAX) {
		/*
		 * A blob can have a maximum of 100,000 uncommitted blocks at
		 * any given time, and the set of uncommitted blocks cannot
		 * exceed 400 GB in total size.
		 */
		return -EINVAL;
	}

	ret = azure_op_data_file_new(cli_args->put.local_path,
				     min(BLOB_BLOCK_MAX, size), 0, O_RDONLY, 0,
				     &op_data);
	if (ret < 0) {
		return ret;
	}

	blks = malloc(sizeof(*blks));
	if (blks == NULL) {
		/* don't free the args filename */
		op_data->buf = NULL;
		azure_op_data_destroy(&op_data);
		return -ENOMEM;
	}

	list_head_init(blks);
	memset(&op, 0, sizeof(op));
	while (bytes_put < size) {
		blk = malloc(sizeof(*blk));
		if (blk == NULL) {
			ret = -ENOMEM;
			goto err_blks_free;
		}

		blk->state = BLOCK_STATE_UNSENT;

		/*
		 * For a given blob, the length of the value specified for the
		 * blockid parameter must be the same size for each block.
		 */
		ret = asprintf(&blk->id, "%s_block%06d",
			       cli_args->az.blob_name, blks_put);
		if (ret < 0) {
			ret = -ENOMEM;
			free(blk);
			goto err_blks_free;
		}

		list_add_tail(blks, &blk->list);

		ret = azure_op_block_put(cli_args->az.blob_acc,
					 cli_args->az.ctnr_name,
					 cli_args->az.blob_name,
					 blk->id,
					 op_data,
					 cli_args->insecure_http,
					 &op);
		if (ret < 0) {
			goto err_blks_free;
		}

		ret = elasto_conn_send_op(econn, &op);
		if (ret < 0) {
			goto err_op_free;
		}

		ret = azure_rsp_process(&op);
		if (ret < 0) {
			goto err_op_free;
		}
		/* ensure data is not freed */
		op.req.data = NULL;
		azure_op_free(&op);

		blk->state = BLOCK_STATE_UNCOMMITED;
		bytes_put += op_data->off;
		op_data->base_off = bytes_put;
		op_data->off = 0;
		op_data->len = min(BLOB_BLOCK_MAX, (size - bytes_put));
		blks_put++;
	}
	assert(blks_put == num_blks);
	/* don't free the args filename */
	op_data->buf = NULL;
	azure_op_data_destroy(&op_data);
	*blks_ret = blks;

	return 0;

err_op_free:
	/* don't free the args filename */
	op_data->buf = NULL;
	azure_op_free(&op);
err_blks_free:
	list_for_each_safe(blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}

	return ret;
}

static int
cli_put_blob_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct stat st;
	struct azure_op op;
	int ret;

	assert(cli_args->type == CLI_TYPE_AZURE);

	ret = elasto_conn_init_az(cli_args->az.pem_file, NULL, &econn);
	if (ret < 0) {
		goto err_out;
	}

	ret = cli_sign_conn_setup(econn,
				  cli_args->az.blob_acc,
				  cli_args->az.sub_id);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = stat(cli_args->put.local_path, &st);
	if (ret < 0) {
		printf("failed to stat %s\n", cli_args->put.local_path);
		goto err_conn_free;
	}

	printf("putting %ld from %s to container %s blob %s\n",
	       (long int)st.st_size,
	       cli_args->put.local_path,
	       cli_args->az.ctnr_name,
	       cli_args->az.blob_name);

	if (st.st_size < BLOCK_THRESHOLD) {
		ret = azure_op_blob_put(cli_args->az.blob_acc,
					cli_args->az.ctnr_name,
					cli_args->az.blob_name,
					AOP_DATA_FILE,
					(uint8_t *)cli_args->put.local_path,
					st.st_size,
					cli_args->insecure_http,
					&op);
		if (ret < 0) {
			goto err_conn_free;
		}
	} else {
		struct list_head *blks;
		ret = cli_put_blocks(econn, cli_args, st.st_size, &blks);
		if (ret < 0) {
			goto err_conn_free;
		}
		ret = azure_op_block_list_put(cli_args->az.blob_acc,
					      cli_args->az.ctnr_name,
					      cli_args->az.blob_name,
					      blks,
					      cli_args->insecure_http,
					      &op);
		if (ret < 0) {
			goto err_conn_free;
		}
	}

	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	/* data buffer contains cli_args->put.local_path */
	if (op.req.data)
		op.req.data->buf = NULL;
	azure_op_free(&op);
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

static int
cli_put_single_obj_handle(struct elasto_conn *econn,
			  struct cli_args *cli_args,
			  struct stat *src_st)
{
	int ret;
	struct azure_op_data *op_data;
	struct azure_op op;

	ret = azure_op_data_file_new(cli_args->put.local_path,
				     src_st->st_size, 0, O_RDONLY, 0,
				     &op_data);
	if (ret < 0) {
		goto err_out;
	}

	ret = s3_op_obj_put(cli_args->s3.bkt_name,
			    cli_args->s3.obj_name,
			    op_data,
			    cli_args->insecure_http,
			    &op);
	if (ret < 0) {
		op_data->buf = NULL;
		azure_op_data_destroy(&op_data);
		goto err_out;
	}

	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	/* data buffer contains cli_args->put.local_path */
	if (op.req.data)
		op.req.data->buf = NULL;
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_put_multi_part_abort(struct elasto_conn *econn,
			 const char *bkt,
			 const char *obj,
			 const char *upload_id,
			 bool insecure_http)
{
	int ret;
	struct azure_op op;

	printf("aborting upload %s\n", upload_id);

	ret = s3_op_mp_abort(bkt,
			     obj,
			     upload_id,
			     insecure_http,
			     &op);
	if (ret < 0) {
		goto err_out;
	}
	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}
	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed to abort upload %s: %d\n",
		       upload_id, op.rsp.err_code);
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_put_part_handle(struct elasto_conn *econn,
		    const char *bkt,
		    const char *obj,
		    const char *upload_id,
		    int pnum,
		    struct azure_op_data *op_data,
		    bool insecure_http,
		    struct s3_part **_part)
{
	int ret;
	struct azure_op op;
	struct s3_part *part;

	part = malloc(sizeof(*part));
	if (part == NULL) {
		goto err_out;
	}
	memset(part, 0, sizeof(*part));

	ret = s3_op_part_put(bkt,
			     obj,
			     upload_id,
			     pnum,
			     op_data,
			     insecure_http,
			     &op);
	if (ret < 0) {
		goto err_part_free;
	}
	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	part->pnum = pnum;
	part->etag = strdup(op.rsp.part_put.etag);
	if (part->etag == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}
	*_part = part;
	op.req.data = NULL;
	azure_op_free(&op);

	return 0;

err_op_free:
	op.req.data = NULL;
	azure_op_free(&op);
err_part_free:
	free(part);
err_out:
	return ret;
}

#define PART_LEN (5 * 1024 * 1024)
static int
cli_put_multi_part_handle(struct elasto_conn *econn,
			  struct cli_args *cli_args,
			  struct stat *src_st)
{
	int ret;
	uint64_t bytes_put;
	int parts_put;
	char *upload_id = NULL;
	struct azure_op_data *op_data;
	struct azure_op op;
	struct list_head parts;

	ret = s3_op_mp_start(cli_args->s3.bkt_name,
			     cli_args->s3.obj_name,
			     cli_args->insecure_http,
			     &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		azure_op_free(&op);
		goto err_out;
	}
	ret = azure_rsp_process(&op);
	if (ret < 0) {
		azure_op_free(&op);
		goto err_out;
	}
	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed mp_start response: %d\n", op.rsp.err_code);
		azure_op_free(&op);
		goto err_out;
	}

	upload_id = strdup(op.rsp.part_put.etag);
	if (upload_id == NULL) {
		ret = -ENOMEM;
		azure_op_free(&op);
		goto err_out;
	}

	printf("multipart upload %s started\n", upload_id);
	azure_op_free(&op);

	ret = azure_op_data_file_new(cli_args->put.local_path,
				     min(PART_LEN, src_st->st_size),
				     0, O_RDONLY, 0,
				     &op_data);
	if (ret < 0) {
		goto err_out;
	}

	bytes_put = 0;
	parts_put = 0;
	list_head_init(&parts);
	while (bytes_put < src_st->st_size) {
		struct s3_part *part;
		ret = cli_put_part_handle(econn,
					  cli_args->s3.bkt_name,
					  cli_args->s3.obj_name,
					  upload_id,
					  parts_put + 1, /* pnum must be > 0 */
					  op_data,
					  cli_args->insecure_http,
					  &part);
		if (ret < 0) {
			goto err_upload_abort;
		}
		list_add_tail(&parts, &part->list);

		bytes_put += op_data->off;
		op_data->base_off = bytes_put;
		op_data->off = 0;
		op_data->len = min(PART_LEN,
				   (src_st->st_size - bytes_put));
		parts_put++;
	}

	op_data->buf = NULL;
	azure_op_data_destroy(&op_data);

	ret = s3_op_mp_done(cli_args->s3.bkt_name,
			    cli_args->s3.obj_name,
			    upload_id,
			    &parts,
			    cli_args->insecure_http,
			    &op);
	if (ret < 0) {
		goto err_upload_abort;
	}

	ret = elasto_conn_send_op(econn, &op);
	if (ret < 0) {
		azure_op_free(&op);
		goto err_upload_abort;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		azure_op_free(&op);
		goto err_upload_abort;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed mp_done response: %d\n", op.rsp.err_code);
		azure_op_free(&op);
		goto err_upload_abort;
	}
	printf("multipart upload %s done\n", upload_id);

	ret = 0;
err_out:
	free(upload_id);
	return ret;

err_upload_abort:
	cli_put_multi_part_abort(econn,
				 cli_args->s3.bkt_name,
				 cli_args->s3.obj_name,
				 upload_id,
				 cli_args->insecure_http);
	free(upload_id);
	return ret;
}

static int
cli_put_obj_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct stat st;
	int ret;

	assert(cli_args->type == CLI_TYPE_S3);

	ret = elasto_conn_init_s3(cli_args->s3.key_id,
				  cli_args->s3.secret, &econn);
	if (ret < 0) {
		goto err_out;
	}

	ret = stat(cli_args->put.local_path, &st);
	if (ret < 0) {
		printf("failed to stat %s\n", cli_args->put.local_path);
		goto err_conn_free;
	}

	printf("putting %ld from %s to bucket %s object %s\n",
	       (long int)st.st_size,
	       cli_args->put.local_path,
	       cli_args->s3.bkt_name,
	       cli_args->s3.obj_name);

	if (st.st_size < BLOCK_THRESHOLD) {
		ret = cli_put_single_obj_handle(econn, cli_args, &st);
		if (ret < 0) {
			goto err_conn_free;
		}
	} else {
		ret = cli_put_multi_part_handle(econn, cli_args, &st);
		if (ret < 0) {
			goto err_conn_free;
		}
	}

	ret = 0;
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

int
cli_put_handle(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		return cli_put_blob_handle(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		return cli_put_obj_handle(cli_args);
	}

	return -ENOTSUP;
}
