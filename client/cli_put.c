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
#include "cli_put.h"

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

	ret = azure_op_blob_put(cli_args->blob_acc,
				cli_args->put.ctnr_name,
				cli_args->put.blob_name,
				AOP_DATA_FILE,
				(uint8_t *)cli_args->put.local_path,
				st.st_size, &op);
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

	ret = 0;
err_op_free:
	/* data buffer contains cli_args->put.local_path */
	op.req.data.buf = NULL;
	azure_op_free(&op);
err_out:
	return ret;
}
