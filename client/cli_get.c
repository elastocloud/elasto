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
#include <fcntl.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/op.h"
#include "lib/azure_blob_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_get.h"

void
cli_get_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
	free(cli_args->get.local_path);
}

int
cli_get_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	/* path is parsed by libfile on open */
	cli_args->path = strdup(argv[1]);
	if (cli_args->path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	cli_args->get.local_path = strdup(argv[2]);
	if (cli_args->get.local_path == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	cli_args->cmd = CLI_CMD_GET;

	return 0;

err_path_free:
	free(cli_args->path);
err_out:
	return ret;
}

int
cli_get_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_fauth auth;
	struct stat st;
	struct elasto_fstat fstat;
	struct elasto_data *dest_data;
	int ret;

	if (cli_args->type == CLI_TYPE_AZURE) {
		auth.type = ELASTO_FILE_ABB;
		auth.az.ps_path = cli_args->az.ps_file;
	} else if (cli_args->type == CLI_TYPE_S3) {
		auth.type = ELASTO_FILE_S3;
		auth.s3.creds_path = cli_args->s3.creds_file;
	} else if (cli_args->type == CLI_TYPE_AFS) {
		auth.type = ELASTO_FILE_AFS;
		auth.az.ps_path = cli_args->az.ps_file;
	} else {
		ret = -ENOTSUP;
		goto err_out;
	}
	auth.insecure_http = cli_args->insecure_http;

	ret = stat(cli_args->get.local_path, &st);
	if (ret == 0) {
		printf("destination already exists at %s\n",
		       cli_args->get.local_path);
		ret = -EEXIST;
		goto err_out;
	}

	/* open without create or dir flags */
	ret = elasto_fopen(&auth, cli_args->path, 0, NULL, &fh);
	if (ret < 0) {
		printf("%s path open failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}

	/* stat to determine size to retrieve */
	ret = elasto_fstat(fh, &fstat);
	if (ret < 0) {
		printf("stat failed with: %s\n", strerror(-ret));
		goto err_fclose;
	}

	printf("getting %" PRIu64 " bytes from %s for %s\n",
	       fstat.size, cli_args->path, cli_args->get.local_path);

	ret = elasto_data_file_new(cli_args->get.local_path, 0, 0,
				   O_CREAT | O_WRONLY,
				   (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH),
				   &dest_data);
	if (ret < 0) {
		goto err_fclose;
	}

	/* TODO implement and use seek(HOLE/DATA) here for efficiency */

	ret = elasto_fread(fh, 0, fstat.size, dest_data);
	if (ret < 0) {
		printf("read failed with: %s\n", strerror(-ret));
		goto err_fclose;
	}

	elasto_data_free(dest_data);

	ret = 0;
err_fclose:
	if (elasto_fclose(fh) < 0) {
		printf("close failed\n");
	}
err_out:
	return ret;
}
