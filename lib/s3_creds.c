/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "util.h"
#include "s3_creds.h"

enum {
	S3_CREDS_CSV_OFF_HDR_USER = 0,
	S3_CREDS_CSV_OFF_HDR_KEY_ID = 1,
	S3_CREDS_CSV_OFF_HDR_KEY_SEC = 2,
	S3_CREDS_CSV_OFF_VAL_USER = 3,
	S3_CREDS_CSV_OFF_VAL_KEY_ID = 4,
	S3_CREDS_CSV_OFF_VAL_KEY_SEC = 5,
	S3_CREDS_CSV_OFF_END = 6,	/* must be last */
};

static int
slurp_file(const char *path,
	   char **_buf,
	   uint64_t *_len)
{
	int ret;
	uint64_t off;
	char *buf;
	int fd;
	struct stat st;

	ret = stat(path, &st);
	if (ret < 0) {
		dbg(0, "failed to stat %s\n", path);
		ret = -errno;
		goto err_out;
	}

	if (st.st_size > 2048) {
		dbg(0, "file too large to slurp\n");
		ret = -E2BIG;
		goto err_out;
	}

	/* +1 for null terminator */
	buf = malloc(st.st_size + 1);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		dbg(0, "failed to open %s\n", path);
		ret = -errno;
		goto err_free;
	}

	off = 0;
	while (off < st.st_size) {
		ssize_t got;
		size_t to_read = MIN(st.st_size - off, 1024);

		got = read(fd, buf + off, to_read);
		if (got < 0) {
		} else if (got == 0) {
			break;
		}
		off += got;
	}

	ret = close(fd);
	if (ret < 0) {
		ret = -errno;
		goto err_free;
	}

	/* null terminate, not included in length */
	buf[off] = '\0';

	*_buf = buf;
	*_len = off;
	return 0;
err_free:
	free(buf);
err_out:
	return ret;
}

/*
 * Process Amazon credentials.csv file
 *
 * @creds_file:		Amazon IAM credentials.csv file from:
 *			https://console.aws.amazon.com/iam/home?#users
 *			-> User -> Security Credentials
 * @user_name:		IAM user name obtained from @creds_file.
 * @access_key_id:	IAM Access Key ID
 * @secret_access_key:	IAM Secret Access Key
 */
int
s3_creds_csv_process(const char *creds_file,
		     char **_user_name,
		     char **_access_key_id,
		     char **_secret_access_key)
{
	int ret;
	int i;
	char *buf;
	uint64_t len;
	char *user = NULL;
	char *key_id = NULL;
	char *key_secret = NULL;

	ret = slurp_file(creds_file, &buf, &len);
	if (ret < 0) {
		goto err_out;
	}

	for (i = 0; i < S3_CREDS_CSV_OFF_END; i++) {
		char *tok;
		char *save;
		size_t soff;

		if (i == 0) {
			tok = strtok_r(buf, ",\r\n", &save);
		} else {
			tok = strtok_r(NULL, ",\r\n", &save);
		}
		if (tok == NULL) {
			break;
		}

		switch (i) {
		case S3_CREDS_CSV_OFF_HDR_USER:
			if (strcmp(tok, "User Name") != 0) {
				dbg(0, "unexpected IAM user hdr: %s\n", tok);
				ret = -EINVAL;
				goto err_buf_free;
			}
			break;
		case S3_CREDS_CSV_OFF_HDR_KEY_ID:
			if (strcmp(tok, "Access Key Id") != 0) {
				dbg(0, "unexpected IAM key ID hdr: %s\n", tok);
				ret = -EINVAL;
				goto err_buf_free;
			}
			break;
		case S3_CREDS_CSV_OFF_HDR_KEY_SEC:
			if (strcmp(tok, "Secret Access Key") != 0) {
				dbg(0, "unexpected key secret hdr: %s\n", tok);
				ret = -EINVAL;
				goto err_buf_free;
			}
			break;
		case S3_CREDS_CSV_OFF_VAL_USER:
			/* trim leading and trailing quotes, if present */
			if (tok[0] == '\"')
				tok++;
			user = strdup(tok);
			if (user == NULL) {
				ret = -ENOMEM;
				goto err_buf_free;
			}
			soff = strlen(user);
			if ((soff > 0) && (user[soff - 1] == '\"'))
				user[soff - 1] = '\0';
			break;
		case S3_CREDS_CSV_OFF_VAL_KEY_ID:
			key_id = strdup(tok);
			if (key_id == NULL) {
				ret = -ENOMEM;
				goto err_buf_free;
			}
			break;
		case S3_CREDS_CSV_OFF_VAL_KEY_SEC:
			key_secret = strdup(tok);
			if (key_secret == NULL) {
				ret = -ENOMEM;
				goto err_buf_free;
			}
			break;
		default:
			dbg(0, "unhandeled CSV offset!\n");
			ret = -EINVAL;
			goto err_buf_free;
			break;
		}
	}

	dbg(4, "successfully parsed S3 creds for %s\n", user);
	free(buf);
	*_user_name = user;
	*_access_key_id = key_id;
	*_secret_access_key = key_secret;
	return 0;

err_buf_free:
	free(buf);
	free(user);
	free(key_id);
	free(key_secret);
err_out:
	return ret;
}
