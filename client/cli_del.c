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
#include "cli_open.h"

void
cli_del_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
}

int
cli_del_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		return -ENOTSUP;
	}

	/* path is parsed by libfile on open */
	return cli_path_realize(cli_args->cwd, argv[1], &cli_args->path);
}

int
cli_del_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	int ret;

	/* XXX not sure whether we've been given a dir or file path, try both */
	ret = cli_open_efh(cli_args, cli_args->path,
			   ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	if (ret < 0) {
		ret = cli_open_efh(cli_args, cli_args->path, 0, NULL,
				   &fh);
		if (ret < 0) {
			printf("%s path open failed as dir and file\n",
			       cli_args->path);
			goto err_out;
		}
	}

	ret = elasto_funlink_close(fh);
	if (ret < 0) {
		printf("%s path unlink failed with: %s\n",
		       cli_args->path, strerror(-ret));
		if (elasto_fclose(fh) < 0) {
			printf("close failed\n");
		}
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static struct cli_cmd_spec spec = {
	.name = "del",
	.az_help = "<account>[/<container>[/<blob>]]",
	.afs_help = "<account>[/<share>[/<file path>]]",
	.s3_help = "<bucket>[/<object>]",
	.arg_min = 1,
	.arg_max = 1,
	.args_parse = &cli_del_args_parse,
	.handle = &cli_del_handle,
	.args_free = &cli_del_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
				| CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
};

static cli_cmd_init cli_del_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_del_deinit(void)
{
	cli_cmd_unregister(&spec);
}
