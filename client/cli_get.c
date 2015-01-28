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
#include <sys/stat.h>
#include <fcntl.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/data_api.h"
#include "lib/op.h"
#include "lib/azure_blob_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_get.h"

void
cli_get_args_free(struct cli_args *cli_args)
{
	free(cli_args->get.local_path);
	if (cli_args->type == CLI_TYPE_AZURE) {
		free(cli_args->az.blob_acc);
		free(cli_args->az.ctnr_name);
		free(cli_args->az.blob_name);
	} else if (cli_args->type == CLI_TYPE_S3) {
		free(cli_args->s3.bkt_name);
		free(cli_args->s3.obj_name);
	}
}

static int
cli_get_az_args_parse(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[1],
				  &cli_args->az.blob_acc,
				  &cli_args->az.ctnr_name,
				  &cli_args->az.blob_name);
	if (ret < 0)
		goto err_out;

	if (cli_args->az.blob_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
		   "Invalid remote path, must be <account>/<container>/<blob>");
		ret = -EINVAL;
		goto err_args_free;
	}

	return 0;

err_args_free:
	free(cli_args->az.ctnr_name);
	free(cli_args->az.blob_acc);
err_out:
	return ret;
}

static int
cli_get_s3_args_parse(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[1],
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
cli_get_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	cli_args->get.local_path = strdup(argv[2]);
	if (cli_args->get.local_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = cli_get_az_args_parse(argc, argv, cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_get_s3_args_parse(argc, argv, cli_args);
	} else {
		ret = -ENOTSUP;
	}
	if (ret < 0) {
		goto err_local_free;
	}
	cli_args->cmd = CLI_CMD_GET;

	return 0;

err_local_free:
	free(cli_args->get.local_path);
err_out:
	return ret;
}

static int
cli_get_blob_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct stat st;
	struct op *op;
	struct elasto_data *op_data;
	int ret;

	assert(cli_args->type == CLI_TYPE_AZURE);

	ret = elasto_conn_init_az(cli_args->az.pem_file, NULL,
				  cli_args->insecure_http, &econn);
	if (ret < 0) {
		goto err_out;
	}

	ret = cli_sign_conn_setup(econn,
				  cli_args->az.blob_acc,
				  cli_args->az.sub_id);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = stat(cli_args->get.local_path, &st);
	if (ret == 0) {
		printf("destination already exists at %s\n",
		       cli_args->get.local_path);
		goto err_conn_free;
	}
	printf("getting container %s blob %s for %s\n",
	       cli_args->az.ctnr_name,
	       cli_args->az.blob_name,
	       cli_args->get.local_path);

	ret = elasto_data_file_new(cli_args->get.local_path, 0, 0,
				     O_CREAT | O_WRONLY,
				     (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH),
				     &op_data);
	if (ret < 0) {
		goto err_conn_free;
	}


	ret = az_req_blob_get(cli_args->az.blob_acc,
				cli_args->az.ctnr_name,
				cli_args->az.blob_name,
				false,
				op_data,
				0, 0,
				&op);
	if (ret < 0) {
		op_data->iov.buf = NULL;
		elasto_data_free(op_data);
		goto err_conn_free;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	/* TODO handle error */

	ret = 0;
err_op_free:
	/* data buffer contains cli_args->get.local_path */
	if (op->rsp.data)
		op->rsp.data->iov.buf = NULL;
	op_free(op);
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

static int
cli_get_obj_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct stat st;
	struct op *op;
	struct elasto_data *op_data;
	int ret;

	assert(cli_args->type == CLI_TYPE_S3);

	ret = elasto_conn_init_s3(cli_args->s3.key_id,
				  cli_args->s3.secret,
				  cli_args->insecure_http, &econn);
	if (ret < 0) {
		goto err_out;
	}

	ret = stat(cli_args->get.local_path, &st);
	if (ret == 0) {
		printf("destination already exists at %s\n",
		       cli_args->get.local_path);
		goto err_conn_free;
	}
	printf("getting bucket %s container %s for %s\n",
	       cli_args->s3.bkt_name,
	       cli_args->s3.obj_name,
	       cli_args->get.local_path);

	ret = elasto_data_file_new(cli_args->get.local_path, 0, 0,
				     O_CREAT | O_WRONLY,
				     (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH),
				     &op_data);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = s3_req_obj_get(cli_args->s3.bkt_name,
			    cli_args->s3.obj_name,
			    op_data,
			    &op);
	if (ret < 0) {
		op_data->iov.buf = NULL;
		elasto_data_free(op_data);
		goto err_conn_free;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	/* TODO handle error */

	ret = 0;
err_op_free:
	/* data buffer contains cli_args->get.local_path */
	if (op->rsp.data)
		op->rsp.data->iov.buf = NULL;
	op_free(op);
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

int
cli_get_handle(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		return cli_get_blob_handle(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		return cli_get_obj_handle(cli_args);
	}

	return -ENOTSUP;
}
