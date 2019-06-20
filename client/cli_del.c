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

struct cli_del_args {
    char *remote_path;
};

static void
_cli_del_args_free(struct cli_del_args *del_args) {
	if (del_args == NULL) {
		return;
	}

	free(del_args->remote_path);
	free(del_args);
}

static void
cli_del_args_free(struct cli_args *cli_args)
{
	_cli_del_args_free(cli_args->cmd_priv);
	cli_args->cmd_priv = NULL;
}

static int
cli_del_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	struct cli_del_args *del_args = NULL;
	int ret;

	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		return -ENOTSUP;
	}

	del_args = calloc(1, sizeof(*del_args));
	if (del_args == NULL) {
		goto err_out;
	}

	/* path is parsed by libfile on open */
	ret = cli_path_realize(cli_args->cwd, argv[1], &del_args->remote_path);
	if (ret < 0) {
		goto err_free;
	}
	cli_args->cmd_priv = del_args;

	return 0;

err_free:
	_cli_del_args_free(del_args);
err_out:
	return ret;
}

static int
cli_del_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct cli_del_args *del_args = cli_args->cmd_priv;
	int ret;

	/* XXX not sure whether we've been given a dir or file path, try both */
	ret = cli_open_efh(cli_args, del_args->remote_path,
			   ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	if (ret < 0) {
		ret = cli_open_efh(cli_args, del_args->remote_path, 0, NULL,
				   &fh);
		if (ret < 0) {
			printf("%s path open failed as dir and file\n",
			       del_args->remote_path);
			goto err_out;
		}
	}

	ret = elasto_funlink_close(fh);
	if (ret < 0) {
		printf("%s path unlink failed with: %s\n",
		       del_args->remote_path, strerror(-ret));
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
	.generic_help = "<cloud path>",
	.az_help = "<account>[/<container>[/<blob>]]",
	.afs_help = "<account>[/<share>[/<file path>]]",
	.s3_help = "<bucket>[/<object>]",
	.arg_min = 1,
	.arg_max = 1,
	.args_parse = &cli_del_args_parse,
	.handle = &cli_del_handle,
	.args_free = &cli_del_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
				| CLI_FL_CLOUD_MASK_ALL,
};

static cli_cmd_init cli_del_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_del_deinit(void)
{
	cli_cmd_unregister(&spec);
}
