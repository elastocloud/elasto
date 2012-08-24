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
#include "cli_get.h"

void
cli_get_args_free(struct cli_args *cli_args)
{
	free(cli_args->get.ctnr_name);
	free(cli_args->get.blob_name);
	free(cli_args->get.local_path);
}

/* get <container>/<blob> <src> */
int
cli_get_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;
	char *s;

	cli_args->get.ctnr_name = strdup(argv[1]);
	if (cli_args->get.ctnr_name == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(cli_args->get.ctnr_name, '/');
	if ((s == NULL) || (s == cli_args->get.ctnr_name)) {
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
	cli_args->get.blob_name = strdup(s);
	if (cli_args->get.blob_name == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	cli_args->get.local_path = strdup(argv[2]);
	if (cli_args->get.local_path == NULL) {
		ret = -ENOMEM;
		goto err_blob_free;
	}

	cli_args->cmd = CLI_CMD_GET;
	return 0;

err_blob_free:
	free(cli_args->get.blob_name);
err_ctnr_free:
	free(cli_args->get.ctnr_name);
err_out:
	return ret;
}

int
cli_get_handle(struct azure_conn *aconn,
	       struct cli_args *cli_args)
{
	struct stat st;
	struct azure_op op;
	int ret;

	ret = stat(cli_args->get.local_path, &st);
	if (ret == 0) {
		printf("destination already exists at %s\n",
		       cli_args->get.local_path);
		goto err_out;
	}
	memset(&op, 0, sizeof(op));
	printf("getting container %s blob %s for %s\n",
	       cli_args->get.ctnr_name,
	       cli_args->get.blob_name,
	       cli_args->get.local_path);

	ret = azure_op_blob_get(cli_args->blob_acc,
				cli_args->get.ctnr_name,
				cli_args->get.blob_name,
				false,
				AOP_DATA_FILE,
				(uint8_t *)cli_args->get.local_path,
				0, 0, &op);
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
	/* data buffer contains cli_args->get.local_path */
	if (op.rsp.data)
		op.rsp.data->buf = NULL;
	azure_op_free(&op);
err_out:
	return ret;
}
