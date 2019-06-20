/*
 * Copyright (C) SUSE LINUX GmbH 2012-2016, all rights reserved.
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

#include "elasto/file.h"
#include "ccan/list/list.h"
#include "cli_common.h"
#include "cli_open.h"

struct cli_create_args {
    char *remote_path;
    char *location;
};

static void
_cli_create_args_free(struct cli_create_args *create_args) {
	if (create_args == NULL) {
		return;
	}

	free(create_args->remote_path);
	free(create_args->location);
	free(create_args);
}

static void
cli_create_args_free(struct cli_args *cli_args)
{
	_cli_create_args_free(cli_args->cmd_priv);
	cli_args->cmd_priv = NULL;
}

static int
cli_create_args_parse(int argc,
		      char * const *argv,
		      struct cli_args *cli_args)
{
	int opt;
	int ret;
	extern char *optarg;
	extern int optind;
	struct cli_create_args *create_args = NULL;

	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		ret = -ENOTSUP;
		goto err_out;
	}

	create_args = calloc(1, sizeof(*create_args));
	if (create_args == NULL) {
		goto err_out;
	}

	/* reset index to start scanning again */
	optind = 1;
	while ((opt = getopt(argc, argv, "L:")) != -1) {
		switch (opt) {
		case 'L':
			create_args->location = strdup(optarg);
			if (create_args->location == NULL) {
				ret = -ENOMEM;
				goto err_free;
			}
			break;
		default: /* '?' */
			cli_args_usage(cli_args->progname, cli_args->flags,
				       "invalid create argument");
			ret = -EINVAL;
			goto err_free;
			break;
		}
	}

	/* path is parsed by libfile on open */
	ret = cli_path_realize(cli_args->cwd, argv[optind],
			       &create_args->remote_path);
	if (ret < 0) {
		goto err_free;
	}
	cli_args->cmd_priv = create_args;

	return 0;

err_free:
	_cli_create_args_free(create_args);
err_out:
	return ret;
}

static int
cli_create_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_ftoken_list *toks = NULL;
	struct cli_create_args *create_args = cli_args->cmd_priv;
	int ret;

	if (create_args->location != NULL) {
		ret = elasto_ftoken_add(ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					create_args->location, &toks);
		if (ret < 0) {
			goto err_out;
		}
		/* FIXME ABB label, desc and affin_grp are not supported */
	}

	ret = cli_open_efh(cli_args, create_args->remote_path,
			   ELASTO_FOPEN_CREATE
			   | ELASTO_FOPEN_EXCL
			   | ELASTO_FOPEN_DIRECTORY,
			   toks, &fh);
	if (ret < 0) {
		printf("%s path creation failed with: %s\n",
		       create_args->remote_path, strerror(-ret));
		goto err_out;
	}
	printf("successfully created path at %s\n", create_args->remote_path);
	elasto_fclose(fh);

	ret = 0;
err_out:
	return ret;
}

static struct cli_cmd_spec spec = {
	.name = "create",
	.generic_help = "<cloud path>",
	.az_help = "[-L <location>] <account>[/<container>]",
	.afs_help = "[-L <location>] <account>[/<share>[/<dir path>]]",
	.s3_help = "[-L <location>] <bucket>",
	.arg_min = 1,
	.arg_max = 7,
	.args_parse = &cli_create_args_parse,
	.handle = &cli_create_handle,
	.args_free = &cli_create_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
			| CLI_FL_CLOUD_MASK_ALL,
};

static cli_cmd_init cli_create_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_create_deinit(void)
{
	cli_cmd_unregister(&spec);
}
