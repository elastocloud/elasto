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
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/azure_conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_ls.h"

void
cli_ls_args_free(struct cli_args *cli_args)
{
	free(cli_args->blob_acc);
	free(cli_args->ctnr_name);
	free(cli_args->blob_name);
}

int
cli_ls_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	if (argc == 2) {
		ret = cli_args_azure_path_parse(progname, argv[1],
						&cli_args->blob_acc,
						&cli_args->ctnr_name,
						&cli_args->blob_name);
		if (ret < 0)
			goto err_out;

		if (cli_args->blob_acc == NULL) {
			cli_args_usage(progname,
	"Invalid remote path, must be [<account>[/<container>[/<blob>]]]");
			ret = -EINVAL;
			goto err_out;
		}
	} else {
		cli_args->blob_acc = NULL;
		cli_args->ctnr_name = NULL;
		cli_args->blob_name = NULL;
	}

	cli_args->cmd = CLI_CMD_LS;
	ret = 0;

err_out:
	return ret;
}

static int
cli_ls_blob_handle(struct azure_conn *aconn,
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

	ret = azure_conn_send_op(aconn, &op);
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
cli_ls_ctnr_handle(struct azure_conn *aconn,
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

	ret = azure_conn_send_op(aconn, &op);
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
cli_ls_acc_handle(struct azure_conn *aconn,
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

	ret = azure_conn_send_op(aconn, &op);
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
cli_ls_sub_handle(struct azure_conn *aconn,
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

	ret = azure_conn_send_op(aconn, &op);
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

int
cli_ls_handle(struct azure_conn *aconn,
	       struct cli_args *cli_args)
{
	int ret;

	if ((cli_args->blob_name == NULL)
	 && (cli_args->ctnr_name == NULL)
	 && (cli_args->blob_acc == NULL)) {
		/* list accounts for subscription, signing setup not needed */
		ret = cli_ls_sub_handle(aconn, cli_args->sub_id);
		return ret;
	}

	ret = cli_sign_conn_setup(aconn,
				  cli_args->blob_acc,
				  cli_args->sub_id);
	if (ret < 0) {
		goto err_out;
	}

	if (cli_args->blob_name != NULL) {
		/* list blocks for a specific blob */
		ret = cli_ls_blob_handle(aconn, cli_args->blob_acc,
					 cli_args->ctnr_name,
					 cli_args->blob_name);
		return ret;
	} else if (cli_args->ctnr_name != NULL) {
		/* list specific container */
		ret = cli_ls_ctnr_handle(aconn, cli_args->blob_acc,
					 cli_args->ctnr_name);
		return ret;
	} else if (cli_args->blob_acc != NULL) {
		/* list all containers for account */
		ret = cli_ls_acc_handle(aconn, cli_args->blob_acc);
		return ret;
	}

	return ret;

	ret = 0;
err_out:
	return ret;
}
