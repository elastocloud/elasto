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

#include "lib/file/file_api.h"
#include "ccan/list/list.h"
#include "cli_common.h"

void
cli_create_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
	free(cli_args->create.location);
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

	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		ret = -ENOTSUP;
		goto err_out;
	}

	/* reset index to start scanning again */
	optind = 1;
	cli_args->path = NULL;

	memset(&cli_args->create, 0, sizeof(cli_args->create));
	while ((opt = getopt(argc, argv, "L:")) != -1) {
		switch (opt) {
		case 'L':
			cli_args->create.location = strdup(optarg);
			if (cli_args->create.location == NULL) {
				ret = -ENOMEM;
				goto err_args_free;
			}
			break;
		default: /* '?' */
			cli_args_usage(cli_args->progname, cli_args->flags,
				       "invalid create argument");
			ret = -EINVAL;
			goto err_args_free;
			break;
		}
	}

	/* path is parsed by libfile on open */
	ret = cli_path_realize(cli_args->cwd, argv[optind], &cli_args->path);
	if (ret < 0) {
		goto err_args_free;
	}

	return 0;

err_args_free:
	cli_create_args_free(cli_args);
err_out:
	return ret;
}

int
cli_create_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_ftoken_list *toks = NULL;
	int ret;

	if (cli_args->create.location != NULL) {
		ret = elasto_ftoken_add(ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					cli_args->create.location, &toks);
		if (ret < 0) {
			goto err_out;
		}
		/* FIXME ABB label, desc and affin_grp are not supported */
	}

	ret = elasto_fopen(&cli_args->auth, cli_args->path,
			   ELASTO_FOPEN_CREATE
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

static struct cli_cmd_spec spec = {
	.name = "create",
	.az_help = "[-L <location>] <account>[/<container>]",
	.afs_help = "[-L <location>] <account>[/<share>[/<dir path>]]",
	.s3_help = "[-L <location>] <bucket>",
	.arg_min = 1,
	.arg_max = 7,
	.args_parse = &cli_create_args_parse,
	.handle = &cli_create_handle,
	.args_free = &cli_create_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
			| CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
};

static cli_cmd_init cli_create_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_create_deinit(void)
{
	cli_cmd_unregister(&spec);
}
