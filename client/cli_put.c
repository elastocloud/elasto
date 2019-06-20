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
#include "elasto/file.h"
#include "cli_common.h"
#include "cli_mime.h"
#include "cli_open.h"

/* split any blob over 10MB into separate blocks */
#define BLOCK_THRESHOLD (10 * 1024 * 1024)

struct cli_put_args {
    char *local_path;
    char *remote_path;
};

static void
_cli_put_args_free(struct cli_put_args *put_args) {
	if (put_args == NULL) {
		return;
	}

	free(put_args->local_path);
	free(put_args->remote_path);
	free(put_args);
}

static void
cli_put_args_free(struct cli_args *cli_args)
{
	_cli_put_args_free(cli_args->cmd_priv);
	cli_args->cmd_priv = NULL;
}

static int
cli_put_args_parse(int argc,
		   char * const *argv,
		   struct cli_args *cli_args)
{
	int ret;
	struct cli_put_args *put_args = NULL;

	if ((cli_args->auth.type != ELASTO_FILE_ABB)
	 && (cli_args->auth.type != ELASTO_FILE_APB)
	 && (cli_args->auth.type != ELASTO_FILE_AFS)
	 && (cli_args->auth.type != ELASTO_FILE_S3)) {
		ret = -ENOTSUP;
		goto err_out;
	}

	put_args = calloc(1, sizeof(*put_args));
	if (put_args == NULL) {
		goto err_out;
	}

	put_args->local_path = strdup(argv[1]);
	if (put_args->local_path == NULL) {
		ret = -ENOMEM;
		goto err_free;
	}

	/* path is parsed by libfile on open */
	ret = cli_path_realize(cli_args->cwd, argv[2], &put_args->remote_path);
	if (ret < 0) {
		goto err_free;
	}
	cli_args->cmd_priv = put_args;

	return 0;

err_free:
	_cli_put_args_free(put_args);
err_out:
	return ret;
}

struct cli_put_data_ctx {
	struct elasto_fh *elasto_fh;
	int fd;
	char *path;
	uint64_t total_len;
	uint64_t num_ranges;
	struct list_head ranges;
};

struct cli_put_range_ctx {
	struct list_node list;
	struct cli_put_data_ctx *data_ctx;
	uint64_t off;
	uint64_t len;
};

static int
cli_put_data_out_cb(uint64_t stream_off,
		    uint64_t need,
		    uint8_t **_out_buf,
		    uint64_t *buf_len,
		    void *priv)
{
	struct cli_put_range_ctx *range_ctx = priv;
	struct cli_put_data_ctx *data_ctx = range_ctx->data_ctx;
	uint8_t *out_buf;
	size_t read;
	int ret;

	if (need > data_ctx->total_len) {
		printf("bogus need len in data cb (need=%" PRIu64 ", total=%"
		       PRIu64 "\n", need, data_ctx->total_len);
		ret = -EINVAL;
		goto err_out;
	}

	out_buf = malloc(need);
	if (out_buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	read = pread(data_ctx->fd, out_buf, need, range_ctx->off + stream_off);
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
cli_put_range_ctx_setup(struct cli_put_data_ctx *data_ctx,
			uint64_t range_off,
			uint64_t range_len,
			struct cli_put_range_ctx **_range_ctx)
{
	struct cli_put_range_ctx *range_ctx;

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
cli_put_data_ctx_setup(struct elasto_fh *fh,
		       const char *path,
		       uint64_t len,
		       struct cli_put_data_ctx **_data_ctx)
{
	struct cli_put_data_ctx *data_ctx;
	int ret;

	data_ctx = malloc(sizeof(*data_ctx));
	if (data_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(data_ctx, 0, sizeof(*data_ctx));

	data_ctx->elasto_fh = fh;

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
cli_put_data_ctx_free(struct cli_put_data_ctx *data_ctx)
{
	struct cli_put_range_ctx *range_ctx;
	struct cli_put_range_ctx *range_ctx_n;

	free(data_ctx->path);
	if (close(data_ctx->fd) == -1) {
		printf("close failed: %s\n", strerror(errno));
	}
	list_for_each_safe(&data_ctx->ranges, range_ctx, range_ctx_n, list) {
		free(range_ctx);
	}
	free(data_ctx);
}

static int
cli_seek_data_put(struct cli_put_data_ctx *data_ctx)
{
	int ret;
	off_t data_start;
	off_t data_end;
	off_t data_cur = 0;

	if (data_ctx->total_len == 0) {
		return 0;
	}

	do {
		off_t next_hole;
		off_t range_len;
		struct cli_put_range_ctx *range_ctx;

		data_start = lseek(data_ctx->fd, data_cur, SEEK_DATA);
		if (data_start == (off_t)-1) {
			ret = -errno;
			if (ret == -ENXIO) {
				break;
			}
			printf("lseek DATA failed: %s\n", strerror(-ret));
			goto err_out;
		}

		if (data_start >= data_ctx->total_len) {
			break;
		}

		next_hole = lseek(data_ctx->fd, data_start + 1, SEEK_HOLE);
		if (next_hole == (off_t)-1) {
			ret = -errno;
			if (ret == -ENXIO) {
				break;
			}
			printf("lseek HOLE failed: %s\n", strerror(-ret));
			goto err_out;
		}

		if (next_hole >= data_ctx->total_len) {
			data_end = data_ctx->total_len - 1;
		} else {
			data_end = next_hole - 1;
		}

		assert(data_end >= data_start);
		range_len = data_end - data_start + 1;

		ret = cli_put_range_ctx_setup(data_ctx, data_start, range_len,
					      &range_ctx);
		if (ret < 0) {
			goto err_out;
		}

		printf("putting allocated range of %" PRIu64 "@%" PRIu64 " bytes "
		       "to %s\n",
		       range_ctx->len, range_ctx->off, range_ctx->data_ctx->path);

		ret = elasto_fwrite_cb(data_ctx->elasto_fh, range_ctx->off,
				       range_ctx->len, range_ctx,
				       cli_put_data_out_cb);
		if (ret < 0) {
			printf("write failed with: %s\n", strerror(-ret));
			goto err_out;
		}
		data_cur = data_end + 1;
	} while (data_cur < data_ctx->total_len);

	ret = 0;
err_out:
	return ret;
}

static int
cli_put_handle(struct cli_args *cli_args)
{
	struct elasto_fh *fh;
	struct elasto_fstatfs fstatfs;
	struct cli_put_data_ctx *data_ctx;
	struct cli_put_args *put_args = cli_args->cmd_priv;
	struct stat st;
	int ret;
	const char *content_type;
	struct elasto_ftoken_list *toks = NULL;

	ret = stat(put_args->local_path, &st);
	if (ret < 0) {
		printf("failed to stat %s\n", put_args->local_path);
		goto err_out;
	}

	content_type = cli_mime_type_lookup(put_args->local_path);
	if (content_type != NULL) {
		ret = elasto_ftoken_add(ELASTO_FOPEN_TOK_CREATE_CONTENT_TYPE,
					content_type, &toks);
		if (ret < 0) {
			goto err_out;
		}
	}

	/* open with exclusive create flags */
	ret = cli_open_efh(cli_args, put_args->remote_path,
			   ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL,
			   toks, &fh);
	if (ret < 0) {
		printf("%s path open failed with: %s\n",
		       put_args->remote_path, strerror(-ret));
		goto err_out;
	}

	/* statfs to determine whether sparse uploads are possible */
	ret = elasto_fstatfs(fh, &fstatfs);
	if (ret < 0) {
		printf("fstatfs failed: %s\n", strerror(-ret));
		goto err_fclose;
	}

	ret = cli_put_data_ctx_setup(fh, put_args->local_path, st.st_size,
				     &data_ctx);
	if (ret < 0) {
		goto err_fclose;
	}

	if (fstatfs.cap_flags & ELASTO_FSTATFS_CAP_SPARSE) {
		ret = elasto_ftruncate(fh, st.st_size);
		if (ret < 0) {
			printf("truncate failed with: %s\n", strerror(-ret));
			goto err_data_ctx_cleanup;
		}

		ret = cli_seek_data_put(data_ctx);
		if (ret < 0) {
			goto err_data_ctx_cleanup;
		}
	} else {
		struct cli_put_range_ctx *range_ctx;

		printf("putting %ld bytes from %s to %s\n",
		       (long int)st.st_size, put_args->local_path,
		       put_args->remote_path);

		ret = cli_put_range_ctx_setup(data_ctx, 0, st.st_size,
					      &range_ctx);
		if (ret < 0) {
			goto err_data_ctx_cleanup;
		}

		ret = elasto_fwrite_cb(fh, 0, st.st_size, range_ctx,
				       cli_put_data_out_cb);
		if (ret < 0) {
			printf("write failed with: %s\n", strerror(-ret));
			goto err_data_ctx_cleanup;
		}
	}

	ret = 0;
err_data_ctx_cleanup:
	cli_put_data_ctx_free(data_ctx);
err_fclose:
	if (elasto_fclose(fh) < 0) {
		printf("close failed\n");
	}
err_out:
	return ret;
}

static struct cli_cmd_spec spec = {
	.name = "put",
	.generic_help = "<local path> <cloud path>",
	.az_help = "<local path> <account>/<container>/<blob>",
	.afs_help = "<local path> <account>/<share>/<file path>",
	.s3_help = "<local path> <bucket>/<object>",
	.arg_min = 2,
	.arg_max = 2,
	.args_parse = &cli_put_args_parse,
	.handle = &cli_put_handle,
	.args_free = &cli_put_args_free,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG
				| CLI_FL_CLOUD_MASK_ALL,
};

static cli_cmd_init cli_put_init(void)
{
	cli_cmd_register(&spec);
}

static cli_cmd_deinit cli_put_deinit(void)
{
	cli_cmd_unregister(&spec);
}
