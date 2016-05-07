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
#include <inttypes.h>

#include "lib/file/file_api.h"
#include "lib/util.h"
#include "ccan/list/list.h"
#include "cli_common.h"

static void
human_size(double bytes,
	   char *buf,
	   size_t buflen)
{
	int i = 0;
	const char* units[] = {"B", "K", "M", "G", "T", "P", "E", "Z"};

	while ((bytes > 1024) && (i < ARRAY_SIZE(units) - 1)) {
		bytes /= 1024;
		i++;
	}
	snprintf(buf, buflen, "%.*f %s", i, bytes, units[i]);
}

void
cli_ls_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
}

int
cli_ls_args_parse(int argc,
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
	if (argc == 2) {
		cli_args->path = strdup(argv[1]);
	} else {
		/* no explicit path - assume root */
		cli_args->path = strdup("/");
	}
	if (cli_args->path == NULL) {
		return -ENOMEM;
	}

	return 0;
}

static int
cli_ls_readdir_cb(struct elasto_dent *dent,
		  void *priv)
{
	char size_buf[20];
	char *type;

	size_buf[0] = '\0';
	if (dent->fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) {
		human_size(dent->fstat.size, size_buf, ARRAY_SIZE(size_buf));
	}

	if ((dent->fstat.field_mask & ELASTO_FSTAT_FIELD_TYPE)
	 && (dent->fstat.ent_type & ELASTO_FSTAT_ENT_DIR)) {
		type = "d\t";
	} else {
		type = "\t";
	}

	printf("%s%s\t%s\n", type, dent->name, size_buf);

	return 0;
}

int
cli_ls_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	int ret;

	ret = elasto_fopen(&cli_args->auth, cli_args->path,
			   ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	if (ret < 0) {
		printf("%s path open failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}

	ret = elasto_freaddir(fh, NULL, cli_ls_readdir_cb);
	if (ret < 0) {
		printf("readdir failed with: %s\n", strerror(-ret));
		goto err_fclose;
	}

	ret = 0;
err_fclose:
	if (elasto_fclose(fh) < 0) {
		printf("close failed\n");
	}
err_out:
	return ret;
}

static struct cli_cmd_spec spec = {
	.name = "ls",
	.az_help = "[<account>[/container[/blob]]]",
	.afs_help = "[<account>[/share[/dir path]]]",
	.s3_help = "[<bucket>]",
	.arg_min = 0,
	.arg_max = 1,
	.args_parse = &cli_ls_args_parse,
	.handle = &cli_ls_handle,
	.args_free = &cli_ls_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
				| CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
};

static cli_cmd_init cli_ls_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_ls_deinit(void)
{
	cli_cmd_unregister(&spec);
}
