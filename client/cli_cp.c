/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
#include "lib/data_api.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_cp.h"

void
cli_cp_args_free(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		free(cli_args->az.blob_name);
		free(cli_args->az.ctnr_name);
		free(cli_args->az.blob_acc);
		free(cli_args->cp.az.src_blob);
		free(cli_args->cp.az.src_ctnr);
		free(cli_args->cp.az.src_acc);
	} else if (cli_args->type == CLI_TYPE_S3) {
		free(cli_args->s3.bkt_name);
		free(cli_args->s3.obj_name);
		free(cli_args->cp.s3.src_bkt);
		free(cli_args->cp.s3.src_obj);
	}
}

static int
cli_cp_args_az_parse(int argc,
		     char * const *argv,
		     struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[1],
				  &cli_args->cp.az.src_acc,
				  &cli_args->cp.az.src_ctnr,
				  &cli_args->cp.az.src_blob);
	if (ret < 0)
		goto err_out;

	if (cli_args->cp.az.src_blob == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
	   "Invalid cp source path, must be <account>/<container>/<blob>");
		ret = -EINVAL;
		goto err_src_free;
	}

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[2],
				  &cli_args->az.blob_acc,
				  &cli_args->az.ctnr_name,
				  &cli_args->az.blob_name);
	if (ret < 0)
		goto err_src_free;

	if (cli_args->az.blob_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
	   "Invalid cp destination path, must be <account>/<container>/<blob>");
		ret = -EINVAL;
		goto err_dst_free;
	}

	return 0;

err_dst_free:
	free(cli_args->az.blob_name);
	free(cli_args->az.ctnr_name);
	free(cli_args->az.blob_acc);
err_src_free:
	free(cli_args->cp.az.src_blob);
	free(cli_args->cp.az.src_ctnr);
	free(cli_args->cp.az.src_acc);
err_out:
	return ret;
}

static int
cli_cp_args_s3_parse(int argc,
		     char * const *argv,
		     struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[1],
				  &cli_args->cp.s3.src_bkt,
				  &cli_args->cp.s3.src_obj, NULL);
	if (ret < 0)
		goto err_out;

	if (cli_args->cp.s3.src_obj== NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
		   "Invalid S3 cp source path, must be <bucket>/<object>");
		ret = -EINVAL;
		goto err_src_free;
	}

	ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
				  argv[2],
				  &cli_args->s3.bkt_name,
				  &cli_args->s3.obj_name, NULL);
	if (ret < 0)
		goto err_src_free;

	if (cli_args->s3.obj_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
		   "Invalid S3 cp destination path, must be <bucket>/<object>");
		ret = -EINVAL;
		goto err_dst_free;
	}

	return 0;

err_dst_free:
	free(cli_args->s3.obj_name);
	free(cli_args->s3.bkt_name);
err_src_free:
	free(cli_args->cp.s3.src_obj);
	free(cli_args->cp.s3.src_bkt);
err_out:
	return ret;
}

int
cli_cp_args_parse(int argc,
		  char * const *argv,
		  struct cli_args *cli_args)
{
	int ret;

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = cli_cp_args_az_parse(argc, argv, cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_cp_args_s3_parse(argc, argv, cli_args);
	} else {
		ret = -ENOTSUP;
	}
	if (ret < 0) {
		goto err_out;
	}
	cli_args->cmd = CLI_CMD_CP;

	return 0;

err_out:
	return ret;
}

static int
cli_cp_blob_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct op *op;
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

	printf("copying blob %s to %s\n",
	       cli_args->cp.az.src_blob,
	       cli_args->az.blob_name);

	ret = az_req_blob_cp(cli_args->cp.az.src_acc,
			     cli_args->cp.az.src_ctnr,
			     cli_args->cp.az.src_blob,
			     cli_args->az.blob_acc,
			     cli_args->az.ctnr_name,
			     cli_args->az.blob_name,
			     &op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op->rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op->rsp.err_code);
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

int
cli_cp_obj_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct op *op;
	int ret;

	assert(cli_args->type == CLI_TYPE_S3);

	ret = elasto_conn_init_s3(cli_args->s3.key_id,
				  cli_args->s3.secret,
				  cli_args->insecure_http, &econn);
	if (ret < 0) {
		goto err_out;
	}

	printf("copying object %s to %s\n",
	       cli_args->cp.s3.src_obj,
	       cli_args->s3.obj_name);

	ret = s3_req_obj_cp(cli_args->cp.s3.src_bkt,
			    cli_args->cp.s3.src_obj,
			    cli_args->s3.bkt_name,
			    cli_args->s3.obj_name,
			    &op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op->rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op->rsp.err_code);
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

int
cli_cp_handle(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		return cli_cp_blob_handle(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		return cli_cp_obj_handle(cli_args);
	}

	return -ENOTSUP;
}
