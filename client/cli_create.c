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
#include "lib/azure_conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_create.h"

void
cli_create_args_free(struct cli_args *cli_args)
{
	free(cli_args->blob_acc);
	free(cli_args->create.label);
	free(cli_args->create.desc);
	free(cli_args->create.affin_grp);
	free(cli_args->create.location);
}

static int
cli_create_args_validate(const char *progname,
			 struct cli_args *cli_args)
{
	if (cli_args->blob_acc == NULL) {
		cli_args_usage(progname,
			       "Create must include an <account> argument");
		return -EINVAL;
	}

	if (cli_args->ctnr_name != NULL) {
		/* container creation */
		if ((cli_args->create.label != NULL)
		 || (cli_args->create.desc != NULL)
		 || (cli_args->create.location != NULL)
		 || (cli_args->create.affin_grp != NULL)) {
			cli_args_usage(progname,
				       "container creation does take "
				       "-l, -d, -A or -L arguments");
			return -EINVAL;
		}
		return 0;
	}

	if (cli_args->create.label == NULL) {
		cli_args_usage(progname,
			       "Account creation requires a <label> argument");
		return -EINVAL;
	}
	if ((cli_args->create.location == NULL)
	 && (cli_args->create.affin_grp == NULL)) {
		cli_args_usage(progname,
			       "Create must specify either a <location> or "
			       "<affinity group>");
		return -EINVAL;
	}

	return 0;
}

int
cli_create_args_parse(const char *progname,
		   int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int opt;
	int ret;
	extern char *optarg;
	extern int optind;
	/* reset index to start scanning again */
	optind = 1;

	while ((opt = getopt(argc, argv, "l:d:A:L:")) != -1) {
		switch (opt) {
		case 'l':
			cli_args->create.label = strdup(optarg);
			if (cli_args->create.label == NULL) {
				ret = -ENOMEM;
				goto err_args_free;
			}
			break;
		case 'd':
			cli_args->create.desc = strdup(optarg);
			if (cli_args->create.desc == NULL) {
				ret = -ENOMEM;
				goto err_args_free;
			}
			break;
		case 'A':
			cli_args->create.affin_grp = strdup(optarg);
			if (cli_args->create.affin_grp == NULL) {
				ret = -ENOMEM;
				goto err_args_free;
			}
			break;
		case 'L':
			cli_args->create.location = strdup(optarg);
			if (cli_args->create.location == NULL) {
				ret = -ENOMEM;
				goto err_args_free;
			}
			break;
		default: /* '?' */
			cli_args_usage(progname, "invalid create argument");
			ret = -EINVAL;
			goto err_args_free;
			break;
		}
	}

	ret = cli_args_azure_path_parse(progname, argv[optind],
					&cli_args->blob_acc,
					&cli_args->ctnr_name, NULL);
	if (ret < 0)
		goto err_args_free;

	ret = cli_create_args_validate(progname, cli_args);
	if (ret < 0)
		goto err_args_free;

	cli_args->cmd = CLI_CMD_CREATE;
	return 0;

err_args_free:
	cli_create_args_free(cli_args);
	return ret;
}

static int
cli_create_handle_acc(struct cli_args *cli_args)
{
	struct azure_conn *aconn;
	struct azure_op op;
	int ret;

	ret = azure_conn_init(cli_args->az.pem_file, NULL, &aconn);
	if (ret < 0) {
		goto err_out;
	}

	memset(&op, 0, sizeof(op));
	ret = azure_op_acc_create(cli_args->az.sub_id,
				  cli_args->blob_acc,
				  cli_args->create.label,
				  cli_args->create.desc,
				  cli_args->create.affin_grp,
				  cli_args->create.location,
				  &op);
	if (ret < 0) {
		goto err_conn_free;
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
err_conn_free:
	azure_conn_free(aconn);
err_out:
	return ret;
}

static int
cli_create_handle_ctnr(struct cli_args *cli_args)
{
	struct azure_conn *aconn;
	struct azure_op op;
	int ret;

	ret = azure_conn_init(cli_args->az.pem_file, NULL, &aconn);
	if (ret < 0) {
		goto err_out;
	}

	ret = cli_sign_conn_setup(aconn,
				  cli_args->blob_acc,
				  cli_args->az.sub_id);
	if (ret < 0) {
		goto err_conn_free;
	}

	memset(&op, 0, sizeof(op));
	ret = azure_op_ctnr_create(cli_args->blob_acc,
				   cli_args->ctnr_name,
				   &op);
	if (ret < 0) {
		goto err_conn_free;
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
err_conn_free:
	azure_conn_free(aconn);
err_out:
	return ret;
}

int
cli_create_handle(struct cli_args *cli_args)
{
	int ret;

	if (cli_args->ctnr_name != NULL) {
		/* container creation */
		ret = cli_create_handle_ctnr(cli_args);
	} else {
		/* account creation */
		ret = cli_create_handle_acc(cli_args);
	}

	return ret;
}
