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
#include "cli_ls.h"

void
cli_ls_args_free(struct cli_args *cli_args)
{
	free(cli_args->ls.ctnr_name);
}

/* ls [container] */
int
cli_ls_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	if ((argc < 1) || (argc > 2)) {
		cli_args_usage(progname, NULL);
		ret = -EINVAL;
		goto err_out;
	}

	if (argc == 2) {
		char *s;
		int len;
		cli_args->ls.ctnr_name = strdup(argv[1]);
		if (cli_args->ls.ctnr_name == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		s = strchr(cli_args->ls.ctnr_name, '/');
		if (s != NULL) {
			len = strlen(cli_args->ls.ctnr_name);
			if ((s == cli_args->ls.ctnr_name)
			 || (s != cli_args->ls.ctnr_name + len - 1)) {
				ret = -EINVAL;
				goto err_ctnr_free;
			}
			/* remove a trailing slash */
			*s = '\0';
		}
	} else {
		cli_args->ls.ctnr_name = NULL;
	}


	cli_args->cmd = CLI_CMD_LS;
	return 0;

err_ctnr_free:
	free(cli_args->ls.ctnr_name);
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

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	if (op.rsp.blob_list.num_blobs == 0) {
		printf("Container %s is empty\n", ctnr_name);
		ret = 0;
		goto err_op_free;
	}

	printf("Contents of %s (*= page blob)\n", ctnr_name);
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

int
cli_ls_handle(struct azure_conn *aconn,
	       struct cli_args *cli_args)
{
	struct azure_ctnr *ctnr;
	bool ctnr_exists;
	struct azure_op op;
	int ret;

	memset(&op, 0, sizeof(op));
	ret = azure_op_ctnr_list(cli_args->blob_acc, &op);
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
	list_for_each(&op.rsp.ctnr_list.ctnrs, ctnr, list) {
		if (cli_args->ls.ctnr_name == NULL) {
			/* list all containers */
			printf("\t%s/\n", ctnr->name);
			ctnr_exists = true;
		} else if (strcmp(ctnr->name, cli_args->ls.ctnr_name) == 0) {
			ret = cli_ls_ctnr_handle(aconn, cli_args->blob_acc,
						 ctnr->name);
			if (ret < 0) {
				goto err_op_free;
			}
			ctnr_exists = true;
			break;
		}
	}
	if (!ctnr_exists) {
		if (cli_args->ls.ctnr_name == NULL) {
			printf("No Containers Found\n");
		} else {
			printf("Container %s Not Found\n",
			       cli_args->ls.ctnr_name);
			ret = -ENOENT;
			goto err_op_free;
		}
	}

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}
