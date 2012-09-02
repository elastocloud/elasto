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
#include "cli_del.h"

void
cli_del_args_free(struct cli_args *cli_args)
{
	free(cli_args->del.blob_acc);
	free(cli_args->del.ctnr_name);
	free(cli_args->del.blob_name);
}

int
cli_del_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	ret = cli_args_azure_path_parse(progname, argv[1],
					&cli_args->del.blob_acc,
					&cli_args->del.ctnr_name,
					&cli_args->del.blob_name);
	if (ret < 0)
		goto err_out;

	if (cli_args->del.ctnr_name == NULL) {
		cli_args_usage(progname,
			       "Invalid remote path, must be "
			       "<account>/<container>[/<blob>]");
		ret = -EINVAL;
		goto err_ctnr_free;
	}
	/* ctnr_name implies we also have a ctnr */

	cli_args->cmd = CLI_CMD_DEL;
	return 0;

err_ctnr_free:
	free(cli_args->del.ctnr_name);
err_out:
	return ret;
}

int
cli_del_handle(struct azure_conn *aconn,
	       struct cli_args *cli_args)
{
	struct azure_op op;
	int ret;

	ret = cli_sign_conn_setup(aconn,
				  cli_args->del.blob_acc,
				  cli_args->sub_id);
	if (ret < 0) {
		goto err_out;
	}

	memset(&op, 0, sizeof(op));
	if (cli_args->del.blob_name == NULL) {
		/* remove container */
		ret = azure_op_ctnr_del(cli_args->del.blob_acc,
					cli_args->del.ctnr_name, &op);
	} else {
		ret = azure_op_blob_del(cli_args->del.blob_acc,
					cli_args->del.ctnr_name,
					cli_args->del.blob_name, &op);
	}
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

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}
