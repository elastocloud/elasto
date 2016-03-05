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
#include <fcntl.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "lib/file/file_api.h"
#include "cli_common.h"
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

	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		ret = -ENOTSUP;
		goto err_out;
	}

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

struct cli_get_data_ctx {
	struct elasto_fh *elasto_fh;
	int fd;
	char *path;
	uint64_t total_len;
	uint64_t num_ranges;
	struct list_head ranges;
};

struct cli_get_range_ctx {
	struct list_node list;
	struct cli_get_data_ctx *data_ctx;
	uint64_t off;
	uint64_t len;
};

static int
cli_get_range_data_in_cb(uint64_t stream_off,
			 uint64_t got,
			 uint8_t *in_buf,
			 uint64_t buf_len,
			 void *priv)
{
	struct cli_get_range_ctx *range_ctx = priv;
	size_t wrote;
	int ret;

	wrote = pwrite(range_ctx->data_ctx->fd, in_buf, got,
		       range_ctx->off + stream_off);
	if ((wrote == -1) || (wrote != got)) {
		printf("write callback failed: %s\n", strerror(errno));
		ret = -EBADF;
		goto err_out;
	}

	free(in_buf);

	ret = 0;
err_out:
	return ret;
}

static int
cli_get_range_ctx_setup(struct cli_get_data_ctx *data_ctx,
			uint64_t range_off,
			uint64_t range_len,
			struct cli_get_range_ctx **_range_ctx)
{
	struct cli_get_range_ctx *range_ctx;

	range_ctx = malloc(sizeof(*range_ctx));
	if (range_ctx == NULL) {
		return -ENOMEM;
	}
	memset(range_ctx, 0, sizeof(*range_ctx));
	range_ctx->data_ctx = data_ctx;
	range_ctx->off = range_off;
	range_ctx->len = range_len;
	list_add_tail(&data_ctx->ranges, &range_ctx->list);
	data_ctx->num_ranges++;
	*_range_ctx = range_ctx;

	return 0;
}

static int
cli_get_range_cb(struct elasto_frange *range,
		 void *priv)
{
	struct cli_get_data_ctx *data_ctx = priv;
	struct cli_get_range_ctx *range_ctx;
	int ret;

	ret = cli_get_range_ctx_setup(data_ctx, range->off, range->len,
				      &range_ctx);
	if (ret < 0) {
		goto err_out;
	}

	printf("getting allocated range of %" PRIu64 "@%" PRIu64 " bytes "
	       "from %s\n",
	       range_ctx->len, range_ctx->off, range_ctx->data_ctx->path);

	ret = elasto_fread_cb(data_ctx->elasto_fh, range->off, range->len,
			      range_ctx, cli_get_range_data_in_cb);
	if (ret < 0) {
		goto err_range_ctx_free;
	}

	return 0;
err_range_ctx_free:
	free(range_ctx);
err_out:
	return ret;
}

static int
cli_get_data_ctx_setup(struct elasto_fh *fh,
		       const char *path,
		       uint64_t len,
		       struct cli_get_data_ctx **_data_ctx)
{
	struct cli_get_data_ctx *data_ctx;
	int ret;

	data_ctx = malloc(sizeof(*data_ctx));
	if (data_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(data_ctx, 0, sizeof(*data_ctx));

	data_ctx->elasto_fh = fh;
	data_ctx->fd = open(path, (O_CREAT | O_WRONLY),
			    (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
	if (data_ctx->fd == -1) {
		ret = -errno;
		goto err_ctx_free;
	}

	if (len != 0) {
		ret = ftruncate(data_ctx->fd, len);
		if (ret < 0) {
			printf("ftruncate failed: %s\n", strerror(errno));
			ret = -EBADF;
			goto err_fd_close;
		}
	}

	data_ctx->path = strdup(path);
	if (data_ctx->path == NULL) {
		ret = -ENOMEM;
		goto err_fd_close;
	}
	data_ctx->total_len = len;
	list_head_init(&data_ctx->ranges);

	*_data_ctx = data_ctx;

	return 0;

err_fd_close:
	close(data_ctx->fd);
err_ctx_free:
	free(data_ctx);
err_out:
	return ret;
}

static void
cli_get_data_ctx_free(struct cli_get_data_ctx *data_ctx)
{
	struct cli_get_range_ctx *range_ctx;
	struct cli_get_range_ctx *range_ctx_n;

	free(data_ctx->path);
	if (close(data_ctx->fd) == -1) {
		printf("close failed: %s\n", strerror(errno));
	}
	list_for_each_safe(&data_ctx->ranges, range_ctx, range_ctx_n, list) {
		free(range_ctx);
	}
	free(data_ctx);
}

int
cli_get_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_fstatfs fstatfs;
	struct stat st;
	struct elasto_fstat fstat;
	struct cli_get_data_ctx *data_ctx;
	int ret;

	ret = stat(cli_args->get.local_path, &st);
	if (ret == 0) {
		printf("destination already exists at %s\n",
		       cli_args->get.local_path);
		ret = -EEXIST;
		goto err_out;
	}

	/* open without create or dir flags */
	ret = elasto_fopen(&cli_args->auth, cli_args->path, 0, NULL, &fh);
	if (ret < 0) {
		printf("%s path open failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}

	/* statfs to determine whether remote is sparse */
	ret = elasto_fstatfs(fh, &fstatfs);
	if (ret < 0) {
		printf("fstatfs failed: %s\n", strerror(-ret));
		goto err_fclose;
	}

	/* stat to determine size to retrieve */
	ret = elasto_fstat(fh, &fstat);
	if (ret < 0) {
		printf("stat failed with: %s\n", strerror(-ret));
		goto err_fclose;
	}

	ret = cli_get_data_ctx_setup(fh, cli_args->get.local_path, fstat.size,
				     &data_ctx);
	if (ret < 0) {
		goto err_fclose;
	}

	if (fstatfs.cap_flags | ELASTO_FSTATFS_CAP_SPARSE) {
		/*
		 * perform space efficient download by only getting allocated
		 * regions.
		 */
		ret = elasto_flist_ranges(fh, 0, fstat.size, 0,
					  data_ctx, cli_get_range_cb);
		if (ret < 0) {
			printf("list ranges failed with: %s\n", strerror(-ret));
			goto err_data_ctx_cleanup;
		}
	} else {
		struct cli_get_range_ctx *range_ctx;

		printf("getting %" PRIu64 " bytes from %s for %s\n",
		       fstat.size, cli_args->path, cli_args->get.local_path);

		ret = cli_get_range_ctx_setup(data_ctx, 0, fstat.size,
					      &range_ctx);
		if (ret < 0) {
			goto err_data_ctx_cleanup;
		}

		ret = elasto_fread_cb(fh, 0, fstat.size, range_ctx,
				      cli_get_range_data_in_cb);
		if (ret < 0) {
			goto err_data_ctx_cleanup;
		}
	}

	ret = 0;
err_data_ctx_cleanup:
	cli_get_data_ctx_free(data_ctx);
err_fclose:
	if (elasto_fclose(fh) < 0) {
		printf("close failed\n");
	}
err_out:
	return ret;
}
