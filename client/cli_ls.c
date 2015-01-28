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
#include <inttypes.h>

#include "ccan/list/list.h"
#include "lib/util.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_mgmt_req.h"
#include "lib/azure_blob_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_ls.h"

static void
human_size(double bytes,
	   char *buf,
	   size_t buflen)
{
	int i = 0;
	const char* units[] = {"B", "K", "M", "G", "T", "P", "E", "Z"};

	while ((bytes > 1024) && (i < ARRAY_SIZE(units) - 1)) {
		bytes /= 1024;
		i++;
	}
	snprintf(buf, buflen, "%.*f %s", i, bytes, units[i]);
}

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
	} else {
		cli_args->s3.bkt_name = NULL;
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
	struct op *op;
	struct az_rsp_block_list_get *block_list_get_rsp;
	struct azure_block *blk;
	int ret;

	ret = az_req_block_list_get(acc_name, ctnr_name, blob_name, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op->rsp.is_error && (op->rsp.err_code == 404)) {
		printf("Blob %s Not Found\n", blob_name);
		ret = -ENOENT;
		goto err_op_free;
	} else if (op->rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op->rsp.err_code);
		goto err_op_free;
	}

	block_list_get_rsp = az_rsp_block_list_get(op);
	if (block_list_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (block_list_get_rsp->num_blks == 0) {
		printf("Blob %s does not have any associated blocks\n",
		       blob_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Blob %s has %d associated blocks (^ = uncommitted)\n",
	       blob_name, block_list_get_rsp->num_blks);
	list_for_each(&block_list_get_rsp->blks, blk, list) {
		printf("%" PRIu64 "\t%s%s\n",
		       blk->len, blk->id,
		       (blk->state == BLOCK_STATE_UNCOMMITED ? "^" : ""));
	}
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_ctnr_handle(struct elasto_conn *econn,
		   const char *acc_name,
		   const char *ctnr_name)
{
	struct op *op;
	struct azure_blob *blob;
	struct az_rsp_blob_list *blob_list_rsp;
	int ret;

	ret = az_req_blob_list(acc_name, ctnr_name, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op->rsp.is_error && (op->rsp.err_code == 404)) {
		printf("Container %s Not Found\n", ctnr_name);
		ret = -ENOENT;
		goto err_op_free;
	} else if (op->rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op->rsp.err_code);
		goto err_op_free;
	}

	blob_list_rsp = az_rsp_blob_list(op);
	if (blob_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (blob_list_rsp->num_blobs == 0) {
		printf("Container %s is empty\n", ctnr_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Contents of container %s (*= page blob):\n", ctnr_name);
	list_for_each(&blob_list_rsp->blobs, blob, list) {
		char buf[20];
		human_size(blob->len, buf, ARRAY_SIZE(buf));
		printf("%*s\t%s%s\n",
		       10, buf, blob->name,
		       (blob->is_page ? "*" : ""));
	}
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_acc_handle(struct elasto_conn *econn,
		  const char *acc_name)
{
	struct op *op;
	struct az_rsp_ctnr_list *ctnr_list_rsp;
	struct azure_ctnr *ctnr;
	bool ctnr_exists;
	int ret;

	ret = az_req_ctnr_list(acc_name, &op);
	if (ret < 0) {
		goto err_out;
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

	ctnr_list_rsp = az_rsp_ctnr_list(op);
	if (ctnr_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	ctnr_exists = false;
	printf("Containers under account %s\n", acc_name);
	list_for_each(&ctnr_list_rsp->ctnrs, ctnr, list) {
			/* list all containers */
			printf("\t%s/\n", ctnr->name);
			ctnr_exists = true;
	}
	if (!ctnr_exists) {
		printf("No Containers Found\n");
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_sub_handle(struct elasto_conn *econn,
		  const char *sub_id,
		  const char *sub_name)
{
	struct op *op;
	struct az_mgmt_rsp_acc_list *acc_list_rsp;
	struct azure_account *acc;
	int ret;

	ret = az_mgmt_req_acc_list(sub_id, &op);
	if (ret < 0) {
		goto err_out;
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

	acc_list_rsp = az_mgmt_rsp_acc_list(op);
	if (acc_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (acc_list_rsp->num_accs == 0) {
		printf("No storage accounts for subscription %s (%s)\n",
		       sub_name, sub_id);
		ret = 0;
		goto err_op_free;
	}

	printf("Accounts for subscription %s (%s):\n", sub_name, sub_id);
	list_for_each(&acc_list_rsp->accs, acc, list) {
			printf("\t%s\n", acc->svc_name);
			if (acc->label != NULL)
				printf("\t\tlabel = %s\n", acc->label);
			if (acc->desc != NULL)
				printf("\t\tdescription = %s\n", acc->desc);
			if (acc->affin_grp != NULL)
				printf("\t\taffinity group = %s\n", acc->affin_grp);
			if (acc->location != NULL)
				printf("\t\tlocation = %s\n", acc->location);
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_svc_handle(struct elasto_conn *econn)
{
	struct op *op;
	struct s3_rsp_svc_list *svc_list_rsp;
	struct s3_bucket *bkt;
	int ret;

	ret = s3_req_svc_list(&op);
	if (ret < 0) {
		goto err_out;
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

	svc_list_rsp = s3_rsp_svc_list(op);
	if (svc_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (svc_list_rsp->num_bkts == 0) {
		printf("No buckets assigned to owner %s\n",
		       svc_list_rsp->disp_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Buckets for owner %s:\n", svc_list_rsp->disp_name);
	list_for_each(&svc_list_rsp->bkts, bkt, list) {
		printf("%s\t%s\n",
		       bkt->create_date, bkt->name);
	}
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_bkt_handle(struct elasto_conn *econn,
		  const char *bkt_name)
{
	struct op *op;
	struct s3_rsp_bkt_list *bkt_list_rsp;
	struct s3_object *obj;
	int ret;

	ret = s3_req_bkt_list(bkt_name, &op);
	if (ret < 0) {
		goto err_out;
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

	bkt_list_rsp = s3_rsp_bkt_list(op);
	if (bkt_list_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (bkt_list_rsp->num_objs == 0) {
		printf("Bucket %s is empty\n", bkt_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Contents of bucket %s:\n", bkt_name);
	list_for_each(&bkt_list_rsp->objs, obj, list) {
		char buf[20];
		human_size(obj->size, buf, ARRAY_SIZE(buf));
		printf("%*s\t%s\t%s\n",
		       10, buf, obj->last_mod, obj->key);
	}
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
cli_ls_az_handle(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_az(cli_args->az.pem_file, NULL,
				  cli_args->insecure_http,
				  &econn);
	if (ret < 0) {
		goto err_out;
	}

	if ((cli_args->az.blob_name == NULL)
	 && (cli_args->az.ctnr_name == NULL)
	 && (cli_args->az.blob_acc == NULL)) {
		/* list accounts for subscription, signing setup not needed */
		ret = cli_ls_sub_handle(econn, cli_args->az.sub_id,
					cli_args->az.sub_name);
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
				  cli_args->s3.secret,
				  cli_args->insecure_http,
				  &econn);
	if (ret < 0) {
		goto err_out;
	}

	if ((cli_args->s3.bkt_name == NULL)
	 && (cli_args->s3.obj_name == NULL)) {
		ret = cli_ls_svc_handle(econn);
	} else if (cli_args->s3.obj_name != NULL) {
		ret = -ENOTSUP;
	} else if (cli_args->s3.bkt_name != NULL) {
		ret = cli_ls_bkt_handle(econn,
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
