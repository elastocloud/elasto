/*
 * Copyright (C) SUSE LINUX GmbH 2017, all rights reserved.
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
#include "cli_open.h"
#include "cli_util.h"

void
cli_stat_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
}

int
cli_stat_args_parse(int argc,
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

static char *
cli_stat_ent_str(uint64_t ent_type)
{

	if (ent_type & ELASTO_FSTAT_ENT_FILE)
		return "file";
	/* root carries DIR and ROOT type flags */
	if (ent_type & ELASTO_FSTAT_ENT_ROOT)
		return "root";
	if (ent_type & ELASTO_FSTAT_ENT_DIR)
		return "dir";

	return "UNKNOWN";
}

static char *
cli_stat_lease_str(enum elasto_flease_status lease_status)
{
	switch (lease_status) {
	case ELASTO_FLEASE_LOCKED:
		return "locked";
	case ELASTO_FLEASE_UNLOCKED:
		return "unlocked";
	default:	/* ELASTO_FLEASE_UNKNOWN */
		return "unknown";
	}
}

int
cli_stat_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	char size_buf[20];
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

	ret = elasto_fstat(fh, &fstat);
	if (ret < 0) {
		printf("fstat failed with: %s\n", strerror(-ret));
		goto err_fclose;
	}

	printf("path: %s\n", cli_args->path);
	if (fstat.field_mask & ELASTO_FSTAT_FIELD_TYPE) {
		printf("type: %s\n", cli_stat_ent_str(fstat.ent_type));
	} else {
		printf("type: -\n");
	}

	if (fstat.field_mask & ELASTO_FSTAT_FIELD_SIZE) {
		size_buf[0] = '\0';
		cli_human_size(fstat.size, size_buf, ARRAY_SIZE(size_buf));
		printf("size: %s\n", size_buf);
	} else {
		printf("size: -\n");
	}

	if (fstat.field_mask & ELASTO_FSTAT_FIELD_BSIZE) {
		size_buf[0] = '\0';
		cli_human_size(fstat.blksize, size_buf, ARRAY_SIZE(size_buf));
		printf("blksize: %s\n", size_buf);
	} else {
		printf("blksize: -\n");
	}

	if (fstat.field_mask & ELASTO_FSTAT_FIELD_LEASE) {
		printf("lease: %s\n", cli_stat_lease_str(fstat.lease_status));
	} else {
		printf("lease: -\n");
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
	.name = "stat",
	.az_help = "<account>[/container[/blob]]",
	.afs_help = "<account>[/<share>[/<file path>]]",
	.s3_help = "<bucket>[/<object>]",
	.arg_min = 1,
	.arg_max = 1,
	.args_parse = &cli_stat_args_parse,
	.handle = &cli_stat_handle,
	.args_free = &cli_stat_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
				| CLI_FL_CLOUD_MASK_ALL,
};

static cli_cmd_init
cli_stat_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit
cli_stat_deinit(void)
{
	cli_cmd_unregister(&spec);
}
