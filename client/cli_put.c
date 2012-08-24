/*
 * Copyright (C) SUSE LINUX Products GmbH 2012, all rights reserved.
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
 *
 * Author: David Disseldorp <ddiss@suse.de>
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
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/azure_conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_put.h"

/* split any blob over 10MB into separate blocks */
#define BLOCK_THRESHOLD (10 * 1024 * 1024)

void
cli_put_args_free(struct cli_args *cli_args)
{
	free(cli_args->put.local_path);
	free(cli_args->put.ctnr_name);
	free(cli_args->put.blob_name);
}

/* put <src> <container>/<blob> */
int
cli_put_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;
	char *s;

	cli_args->put.local_path = strdup(argv[1]);
	if (cli_args->put.local_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	cli_args->put.ctnr_name = strdup(argv[2]);
	if (cli_args->put.ctnr_name == NULL) {
		ret = -ENOMEM;
		goto err_local_free;
	}

	s = strchr(cli_args->put.ctnr_name, '/');
	if ((s == NULL) || (s == cli_args->put.ctnr_name)) {
		cli_args_usage(progname,
		    "Invalid remote path, must be <container>/<blob>");
		ret = -EINVAL;
		goto err_ctnr_free;
	}
	*(s++) = '\0';	/* null term for cntnr */
	if (*s == '\0') {
		/* zero len blob name */
		cli_args_usage(progname, NULL);
		ret = -EINVAL;
		goto err_ctnr_free;
	}
	cli_args->put.blob_name = strdup(s);
	if (cli_args->put.blob_name == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	cli_args->cmd = CLI_CMD_PUT;
	return 0;

err_ctnr_free:
	free(cli_args->put.ctnr_name);
err_local_free:
	free(cli_args->put.local_path);
err_out:
	return ret;
}

#define min(a, b) (((a) < (b)) ? (a) : (b))

static int
cli_put_blocks(struct azure_conn *aconn,
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
			       cli_args->put.blob_name, blks_put);
		if (ret < 0) {
			ret = -ENOMEM;
			free(blk);
			goto err_blks_free;
		}

		list_add_tail(blks, &blk->list);

		ret = azure_op_block_put(cli_args->blob_acc,
					 cli_args->put.ctnr_name,
					 cli_args->put.blob_name,
					 blk->id,
					 op_data, &op);
		if (ret < 0) {
			goto err_blks_free;
		}

		ret = azure_conn_send_op(aconn, &op);
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

int
cli_put_handle(struct azure_conn *aconn,
	       struct cli_args *cli_args)
{
	struct stat st;
	struct azure_op op;
	int ret;

	ret = stat(cli_args->put.local_path, &st);
	if (ret < 0) {
		printf("failed to stat %s\n", cli_args->put.local_path);
		goto err_out;
	}
	memset(&op, 0, sizeof(op));
	ret = azure_op_ctnr_create(cli_args->blob_acc,
				   cli_args->put.ctnr_name, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error && (op.rsp.err_code == 409)) {
		printf("container already exists, proceeding with put\n");
	} else if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	azure_op_free(&op);

	printf("putting %zd from %s to container %s blob %s\n",
	       st.st_size,
	       cli_args->put.local_path,
	       cli_args->put.ctnr_name,
	       cli_args->put.blob_name);

	if (st.st_size < BLOCK_THRESHOLD) {
		ret = azure_op_blob_put(cli_args->blob_acc,
					cli_args->put.ctnr_name,
					cli_args->put.blob_name,
					AOP_DATA_FILE,
					(uint8_t *)cli_args->put.local_path,
					st.st_size, &op);
		if (ret < 0) {
			goto err_out;
		}
	} else {
		struct list_head *blks;
		ret = cli_put_blocks(aconn, cli_args, st.st_size, &blks);
		if (ret < 0) {
			goto err_out;
		}
		ret = azure_op_block_list_put(cli_args->blob_acc,
					      cli_args->put.ctnr_name,
					      cli_args->put.blob_name,
					      blks, &op);
		if (ret < 0) {
			goto err_out;
		}
	}

	ret = azure_conn_send_op(aconn, &op);
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
err_out:
	return ret;
}
