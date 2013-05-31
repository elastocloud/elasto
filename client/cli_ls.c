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

#include <curl/curl.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_ls.h"

void
cli_ls_az_args_free(struct cli_args *cli_args)
{
	free(cli_args->az.blob_acc);
	free(cli_args->az.ctnr_name);
	free(cli_args->az.blob_name);
}

void
cli_ls_s3_args_free(struct cli_args *cli_args)
{
	free(cli_args->s3.bkt_name);
}

void
cli_ls_args_free(struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		return cli_ls_az_args_free(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		return cli_ls_s3_args_free(cli_args);
	}
}

int
cli_ls_args_parse_az(int argc,
		     char * const *argv,
		     struct cli_args *cli_args)
{
	int ret;

	if (argc == 2) {
		ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
					  argv[1],
					  &cli_args->az.blob_acc,
					  &cli_args->az.ctnr_name,
					  &cli_args->az.blob_name);
		if (ret < 0)
			goto err_out;

		if (cli_args->az.blob_acc == NULL) {
			cli_args_usage(cli_args->progname, cli_args->flags,
	"Invalid remote path, must be [<account>[/<container>[/<blob>]]]");
			ret = -EINVAL;
			goto err_out;
		}
	} else {
		cli_args->az.blob_acc = NULL;
		cli_args->az.ctnr_name = NULL;
		cli_args->az.blob_name = NULL;
	}

	cli_args->cmd = CLI_CMD_LS;
	ret = 0;

err_out:
	return ret;
}

int
cli_ls_args_parse_s3(int argc,
		     char * const *argv,
		     struct cli_args *cli_args)
{
	int ret;

	if (argc == 2) {
		ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
					  argv[1],
					  &cli_args->s3.bkt_name,
					  NULL,
					  NULL);
		if (ret < 0)
			goto err_out;
	}
	cli_args->s3.obj_name = NULL;

	cli_args->cmd = CLI_CMD_LS;
	ret = 0;

err_out:
	return ret;
}

int
cli_ls_args_parse(int argc,
		  char * const *argv,
		  struct cli_args *cli_args)
{
	if (cli_args->type == CLI_TYPE_AZURE) {
		return cli_ls_args_parse_az(argc, argv, cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		return cli_ls_args_parse_s3(argc, argv, cli_args);
	}
	return -ENOTSUP;
}

static int
cli_ls_blob_handle(struct elasto_conn *econn,
		   const char *acc_name,
		   const char *ctnr_name,
		   const char *blob_name)
{
	struct azure_op op;
	struct azure_block *blk;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = azure_op_block_list_get(acc_name, ctnr_name, blob_name, &op);
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

	if (op.rsp.is_error && (op.rsp.err_code == 404)) {
		printf("Blob %s Not Found\n", blob_name);
		ret = -ENOENT;
		goto err_op_free;
	} else if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.block_list_get.num_blks == 0) {
		printf("Blob %s does not have any associated blocks\n",
		       blob_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Blob %s has %d associated blocks (^ = uncommitted)\n",
	       blob_name, op.rsp.block_list_get.num_blks);
	list_for_each(&op.rsp.block_list_get.blks, blk, list) {
		printf("%lu\t%s%s\n",
		       blk->len, blk->id,
		       (blk->state == BLOCK_STATE_UNCOMMITED ? "^" : ""));
	}
	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_ctnr_handle(struct elasto_conn *econn,
		   const char *acc_name,
		   const char *ctnr_name)
{
	struct azure_op op;
	struct azure_blob *blob;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = azure_op_blob_list(acc_name, ctnr_name, &op);
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

	if (op.rsp.is_error && (op.rsp.err_code == 404)) {
		printf("Container %s Not Found\n", ctnr_name);
		ret = -ENOENT;
		goto err_op_free;
	} else if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.blob_list.num_blobs == 0) {
		printf("Container %s is empty\n", ctnr_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Contents of container %s (*= page blob)\n", ctnr_name);
	list_for_each(&op.rsp.blob_list.blobs, blob, list) {
		printf("%lu\t%s%s\n",
		       blob->len, blob->name,
		       (blob->is_page ? "*" : ""));
	}
	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_acc_handle(struct elasto_conn *econn,
		  const char *acc_name)
{
	struct azure_op op;
	struct azure_ctnr *ctnr;
	bool ctnr_exists;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = azure_op_ctnr_list(acc_name, &op);
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
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	ctnr_exists = false;
	printf("Containers under account %s\n", acc_name);
	list_for_each(&op.rsp.ctnr_list.ctnrs, ctnr, list) {
			/* list all containers */
			printf("\t%s/\n", ctnr->name);
			ctnr_exists = true;
	}
	if (!ctnr_exists) {
		printf("No Containers Found\n");
	}

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_sub_handle(struct elasto_conn *econn,
		  const char *sub_id)
{
	struct azure_op op;
	struct azure_account *acc;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = azure_op_acc_list(sub_id, &op);
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
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.acc_list.num_accs == 0) {
		printf("No storage accounts for subscription %s\n", sub_id);
		ret = 0;
		goto err_op_free;
	}

	printf("Accounts for subscription %s:\n", sub_id);
	list_for_each(&op.rsp.acc_list.accs, acc, list) {
			printf("\t%s\n", acc->svc_name);
			if (acc->desc != NULL)
				printf("\t\tdescription = %s\n", acc->desc);
			if (acc->affin_grp != NULL)
				printf("\t\taffinity group = %s\n", acc->affin_grp);
			if (acc->location != NULL)
				printf("\t\tlocation = %s\n", acc->location);
	}

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_svc_handle(struct elasto_conn *econn,
		  bool insecure_http)
{
	struct azure_op op;
	struct s3_bucket *bkt;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = s3_op_svc_list(insecure_http, &op);
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
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.svc_list.num_bkts == 0) {
		printf("No buckets assigned to owner %s\n",
		       op.rsp.svc_list.disp_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Buckets for owner %s:\n", op.rsp.svc_list.disp_name);
	list_for_each(&op.rsp.svc_list.bkts, bkt, list) {
		printf("%s\t%s\n",
		       bkt->create_date, bkt->name);
	}
	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_bkt_handle(struct elasto_conn *econn,
		  bool insecure_http,
		  const char *bkt_name)
{
	struct azure_op op;
	struct s3_object *obj;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = s3_op_bkt_list(bkt_name, insecure_http, &op);
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
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.bkt_list.num_objs == 0) {
		printf("Bucket %s is empty\n", bkt_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Contents of bucket %s\n", bkt_name);
	list_for_each(&op.rsp.bkt_list.objs, obj, list) {
		printf("%s\t%s\n",
		       obj->last_mod, obj->key);
	}
	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}

static int
cli_ls_az_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_az(cli_args->az.pem_file, NULL, &econn);
	if (ret < 0) {
		goto err_out;
	}

	if ((cli_args->az.blob_name == NULL)
	 && (cli_args->az.ctnr_name == NULL)
	 && (cli_args->az.blob_acc == NULL)) {
		/* list accounts for subscription, signing setup not needed */
		ret = cli_ls_sub_handle(econn, cli_args->az.sub_id);
		goto err_conn_free;
	}

	ret = cli_sign_conn_setup(econn,
				  cli_args->az.blob_acc,
				  cli_args->az.sub_id);
	if (ret < 0) {
		goto err_conn_free;
	}

	if (cli_args->az.blob_name != NULL) {
		/* list blocks for a specific blob */
		ret = cli_ls_blob_handle(econn, cli_args->az.blob_acc,
					 cli_args->az.ctnr_name,
					 cli_args->az.blob_name);
	} else if (cli_args->az.ctnr_name != NULL) {
		/* list specific container */
		ret = cli_ls_ctnr_handle(econn, cli_args->az.blob_acc,
					 cli_args->az.ctnr_name);
	} else if (cli_args->az.blob_acc != NULL) {
		/* list all containers for account */
		ret = cli_ls_acc_handle(econn, cli_args->az.blob_acc);
	}
	if (ret < 0) {
		goto err_conn_free;
	}
	ret = 0;

err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

static int
cli_ls_s3_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_s3(cli_args->s3.key_id,
				  cli_args->s3.secret, &econn);
	if (ret < 0) {
		goto err_out;
	}

	if ((cli_args->s3.bkt_name == NULL)
	 && (cli_args->s3.obj_name == NULL)) {
		ret = cli_ls_svc_handle(econn, cli_args->insecure_http);
	} else if (cli_args->s3.obj_name != NULL) {
		ret = -ENOTSUP;
	} else if (cli_args->s3.bkt_name != NULL) {
		ret = cli_ls_bkt_handle(econn, cli_args->insecure_http,
					cli_args->s3.bkt_name);
	}
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = 0;

err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

int
cli_ls_handle(struct cli_args *cli_args)
{
	int ret = -ENOTSUP;

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = cli_ls_az_handle(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_ls_s3_handle(cli_args);
	}
	return ret;
}
