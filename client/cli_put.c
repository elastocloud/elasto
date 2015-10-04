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

#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "cli_common.h"
#include "cli_put.h"

/* split any blob over 10MB into separate blocks */
#define BLOCK_THRESHOLD (10 * 1024 * 1024)

void
cli_put_args_free(struct cli_args *cli_args)
{
	free(cli_args->path);
	free(cli_args->put.local_path);
}

int
cli_put_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;

	cli_args->put.local_path = strdup(argv[1]);
	if (cli_args->put.local_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* path is parsed by libfile on open */
	cli_args->path = strdup(argv[2]);
	if (cli_args->path == NULL) {
		ret = -ENOMEM;
		goto err_local_free;
	}

	cli_args->cmd = CLI_CMD_PUT;
	return 0;

err_local_free:
	free(cli_args->put.local_path);
err_out:
	return ret;
}

struct cli_put_data_ctx {
	int fd;
	char *path;
	uint64_t len;
};

static int
cli_put_data_out_cb(uint64_t stream_off,
		    uint64_t need,
		    uint8_t **_out_buf,
		    uint64_t *buf_len,
		    void *priv)
{
	struct cli_put_data_ctx *data_ctx = priv;
	uint8_t *out_buf;
	size_t read;
	int ret;

	if (need > data_ctx->len) {
		printf("bogus need len in data cb\n");
		ret = -EINVAL;
		goto err_out;
	}

	out_buf = malloc(need);
	if (out_buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	read = pread(data_ctx->fd, out_buf, need, stream_off);
	if ((read == -1) || (read != need)) {
		printf("read callback failed: %s\n", strerror(errno));
		ret = -EBADF;
		goto err_buf_free;
	}

	/* connection layer will free @out_buf when sent */
	*_out_buf = out_buf;
	*buf_len = need;
	return 0;

err_buf_free:
	free(out_buf);
err_out:
	return ret;
}

static int
cli_put_data_setup(const char *path,
		   uint64_t len,
		   struct elasto_data **_data)
{
	struct elasto_data *data;
	struct cli_put_data_ctx *data_ctx;
	int ret;

	data_ctx = malloc(sizeof(*data_ctx));
	if (data_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	data_ctx->fd = open(path, O_RDONLY);
	if (data_ctx->fd == -1) {
		ret = -errno;
		goto err_ctx_free;
	}

	data_ctx->path = strdup(path);
	if (data_ctx->path == NULL) {
		ret = -ENOMEM;
		goto err_fd_close;
	}
	data_ctx->len = len;

	ret = elasto_data_cb_new(len, cli_put_data_out_cb,
				 0, NULL,
				 data_ctx, &data);
	if (ret < 0) {
		goto err_path_free;
	}

	*_data = data;

	return 0;

err_path_free:
	free(data_ctx->path);
err_fd_close:
	close(data_ctx->fd);
err_ctx_free:
	free(data_ctx);
err_out:
	return ret;
}

static void
cli_put_data_free(struct elasto_data *data)
{
	/* TODO implement and use elasto_data_cbpriv_out */
	struct cli_put_data_ctx *data_ctx = data->cb.priv;

	free(data_ctx->path);
	if (close(data_ctx->fd) == -1) {
		printf("close failed: %s\n", strerror(errno));
	}
	free(data_ctx);
	elasto_data_free(data);
}

static int
cli_put_file_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_data *src_data;
	struct stat st;
	int ret;

	/* open with exclusive create flags */
	ret = elasto_fopen(&cli_args->auth, cli_args->path,
			   ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL,
			   NULL, &fh);
	if (ret < 0) {
		printf("%s path open failed with: %s\n",
		       cli_args->path, strerror(-ret));
		goto err_out;
	}

	ret = stat(cli_args->put.local_path, &st);
	if (ret < 0) {
		printf("failed to stat %s\n", cli_args->put.local_path);
		goto err_fclose;
	}

	printf("putting %ld bytes from %s to %s\n",
	       (long int)st.st_size, cli_args->put.local_path, cli_args->path);

	ret = cli_put_data_setup(cli_args->put.local_path, st.st_size,
				 &src_data);
	if (ret < 0) {
		goto err_fclose;
	}

	ret = elasto_fwrite(fh, 0, st.st_size, src_data);
	if (ret < 0) {
		printf("write failed with: %s\n", strerror(-ret));
		goto err_data_cleanup;
	}

	ret = 0;
err_data_cleanup:
	cli_put_data_free(src_data);
err_fclose:
	if (elasto_fclose(fh) < 0) {
		printf("close failed\n");
	}
err_out:
	return ret;
}

int
cli_put_handle(struct cli_args *cli_args)
{
	if ((cli_args->auth.type == ELASTO_FILE_ABB)
					|| (cli_args->auth.type == ELASTO_FILE_AFS)
					|| (cli_args->auth.type == ELASTO_FILE_S3)) {
		return cli_put_file_handle(cli_args);
	}

	return -ENOTSUP;
}
