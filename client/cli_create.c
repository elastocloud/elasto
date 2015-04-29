/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_mgmt_req.h"
#include "lib/azure_blob_req.h"
#include "lib/azure_fs_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/file/file_api.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_util.h"
#include "cli_create.h"

void
cli_create_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
	if (cli_args->type == CLI_TYPE_AZURE) {
		free(cli_args->az.blob_acc);
		free(cli_args->az.ctnr_name);
	} else if (cli_args->type == CLI_TYPE_S3) {
		free(cli_args->s3.bkt_name);
	}
	free(cli_args->create.label);
	free(cli_args->create.desc);
	free(cli_args->create.affin_grp);
	free(cli_args->create.location);
}

static int
cli_create_args_validate_az(struct cli_args *cli_args)
{
	if (cli_args->az.blob_acc == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "Create must include an <account> argument");
		return -EINVAL;
	}

	if (cli_args->az.ctnr_name != NULL) {
		/* container creation */
		if ((cli_args->create.label != NULL)
		 || (cli_args->create.desc != NULL)
		 || (cli_args->create.location != NULL)
		 || (cli_args->create.affin_grp != NULL)) {
			cli_args_usage(cli_args->progname, cli_args->flags,
				       "container creation does take "
				       "-l, -d, -A or -L arguments");
			return -EINVAL;
		}
		if (cli_args->create.type != CLI_CMD_CREATE_SHARE) {
			cli_args->create.type = CLI_CMD_CREATE_CTNR;
		}
		return 0;
	}

	cli_args->create.type = CLI_CMD_CREATE_ACC;
	if (cli_args->create.label == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "Account creation requires a <label> argument");
		return -EINVAL;
	}
	if ((cli_args->create.location == NULL)
	 && (cli_args->create.affin_grp == NULL)) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "Create must specify either a <location> or "
			       "<affinity group>");
		return -EINVAL;
	}

	return 0;
}

static int
cli_create_args_validate_s3(struct cli_args *cli_args)
{
	if (cli_args->s3.bkt_name == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "Create must include a <bucket> argument");
		return -EINVAL;
	}

	return 0;
}

int
cli_create_args_parse(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int opt;
	int ret;
	extern char *optarg;
	extern int optind;
	/* reset index to start scanning again */
	optind = 1;

	memset(&cli_args->create, 0, sizeof(cli_args->create));
	while ((opt = getopt(argc, argv, "l:d:A:L:s")) != -1) {
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
		case 's':
			cli_args->create.type = CLI_CMD_CREATE_SHARE;
			break;
		default: /* '?' */
			cli_args_usage(cli_args->progname, cli_args->flags,
				       "invalid create argument");
			ret = -EINVAL;
			goto err_args_free;
			break;
		}
	}

	/* path is parsed by libfile on open. FIXME use for share too */
	cli_args->path = strdup(argv[optind]);
	if (cli_args->path == NULL) {
		ret = -ENOMEM;
		goto err_args_free;
	}

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
					  argv[optind],
					  &cli_args->az.blob_acc,
					  &cli_args->az.ctnr_name, NULL);
		if (ret < 0)
			goto err_args_free;
		ret = cli_create_args_validate_az(cli_args);
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_args_path_parse(cli_args->progname, cli_args->flags,
					  argv[optind],
					  &cli_args->s3.bkt_name,
					  NULL, NULL);
		if (ret < 0)
			goto err_args_free;
		ret = cli_create_args_validate_s3(cli_args);
	} else {
		ret = -ENOTSUP;
	}
	if (ret < 0)
		goto err_args_free;

	cli_args->cmd = CLI_CMD_CREATE;
	return 0;

err_args_free:
	cli_create_args_free(cli_args);
	return ret;
}

static int
cli_create_handle_apb(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_ftoken_list *toks = NULL;
	struct elasto_fauth auth;
	int ret;

	if (cli_args->type != CLI_TYPE_AZURE) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (cli_args->create.location != NULL) {
		ret = elasto_ftoken_add(ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					cli_args->create.location, &toks);
		if (ret < 0) {
			goto err_out;
		}
		/* FIXME label, desc and affin_grp are ignored */
	}

	auth.type = ELASTO_FILE_ABB;	/* FIXME support cli page blobs */
	auth.az.ps_path = cli_args->az.ps_file;
	auth.insecure_http = cli_args->insecure_http;
	ret = elasto_fopen(&auth, cli_args->path, ELASTO_FOPEN_CREATE
						| ELASTO_FOPEN_EXCL
						| ELASTO_FOPEN_DIRECTORY,
			   toks, &fh);
	if (ret < 0) {
		printf("%s path creation failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}
	printf("successfully created path at %s\n", cli_args->path);
	elasto_fclose(fh);

	ret = 0;
err_out:
	return ret;
}

static int
cli_create_handle_share(struct cli_args *cli_args)
{
	struct elasto_conn *econn;
	struct op *op;
	int ret;

	if (cli_args->type == CLI_TYPE_AZURE) {
		ret = elasto_conn_init_az(cli_args->az.pem_file, NULL,
					  cli_args->insecure_http, &econn);
	} else {
		ret = -ENOTSUP;
	}
	if (ret < 0) {
		goto err_out;
	}

	ret = cli_sign_conn_setup(econn,
				  cli_args->az.blob_acc,
				  cli_args->az.sub_id);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = az_fs_req_share_create(cli_args->az.blob_acc,
				     cli_args->az.ctnr_name,
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

static int
cli_create_handle_bkt(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_ftoken_list *toks = NULL;
	struct elasto_fauth auth;
	int ret;

	if (cli_args->type != CLI_TYPE_S3) {
		ret = -ENOTSUP;
		goto err_out;
	}

	if (cli_args->create.location != NULL) {
		ret = elasto_ftoken_add(ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					cli_args->create.location, &toks);
		if (ret < 0) {
			goto err_out;
		}
	}

	auth.type = ELASTO_FILE_S3;
	auth.s3.creds_path = cli_args->s3.creds_file;
	auth.insecure_http = cli_args->insecure_http;
	ret = elasto_fopen(&auth, cli_args->path, ELASTO_FOPEN_CREATE
						| ELASTO_FOPEN_EXCL
						| ELASTO_FOPEN_DIRECTORY,
			   toks, &fh);
	if (ret < 0) {
		printf("%s path creation failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}
	printf("successfully created path at %s\n", cli_args->path);
	elasto_fclose(fh);

	ret = 0;
err_out:
	return ret;
}

int
cli_create_handle(struct cli_args *cli_args)
{
	int ret = -ENOTSUP;

	if (cli_args->type == CLI_TYPE_AZURE) {
		if ((cli_args->create.type == CLI_CMD_CREATE_ACC)
		 || (cli_args->create.type == CLI_CMD_CREATE_CTNR)) {
			ret = cli_create_handle_apb(cli_args);
		} else if (cli_args->create.type == CLI_CMD_CREATE_SHARE) {
			ret = cli_create_handle_share(cli_args);
		}
	} else if (cli_args->type == CLI_TYPE_S3) {
		ret = cli_create_handle_bkt(cli_args);
	}

	return ret;
}
