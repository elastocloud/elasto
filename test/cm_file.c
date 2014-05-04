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
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "cm_test.h"
#include "lib/util.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"

static void
cm_file_mkdir(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fmkdir(&auth,
			    path);
	assert_false(ret < 0);
}

static void
cm_file_rmdir(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);
	cm_us->ctnr_suffix++; /* ensure future creations don't conflict */

	ret = elasto_frmdir(&auth,
			    path);
	assert_false(ret < 0);
}

static void
cm_file_create(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/create_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_false(ret < 0);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_int_equal(ret, -EEXIST);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   &fh);
	assert_false(ret < 0);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   &fh);
	assert_false(ret < 0);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
}

static void
cm_file_buf_fill(uint8_t *buf,
		 size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		buf[i] = (i & 0xff);
	}
}

static void
cm_file_buf_check(uint8_t *buf,
		  size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		assert_true(buf[i] == (i & 0xff));
	}
}


static void
cm_file_io(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct elasto_data *data;
	uint8_t buf[1024];

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/io_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   &fh);
	assert_false(ret < 0);

	/* must truncate to size writing to the range */
	ret = elasto_ftruncate(fh, (1024 * 1024 * 1024));
	assert_false(ret < 0);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf));
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), 0, false, &data);
	assert_false(ret < 0);

	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), data);
	assert_false(ret < 0);

	data->iov.buf = NULL;
	elasto_data_free(data);

	memset(buf, 0, ARRAY_SIZE(buf));

	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), 0, false, &data);
	assert_false(ret < 0);

	ret = elasto_fread(fh, 0, ARRAY_SIZE(buf), data);
	assert_false(ret < 0);

	cm_file_buf_check(buf, ARRAY_SIZE(buf));
	data->iov.buf = NULL;
	elasto_data_free(data);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
}

static void
cm_file_lease_basic(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/lease_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_false(ret < 0);

	ret = elasto_flease_acquire(fh, -1);
	assert_int_equal(ret, 0);

	ret = elasto_flease_release(fh);
	assert_int_equal(ret, 0);

	ret = elasto_fclose(fh);
	assert_int_equal(ret, 0);
}

static const UnitTest cm_file_tests[] = {
	unit_test_setup_teardown(cm_file_create, cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_io, cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_lease_basic, cm_file_mkdir, cm_file_rmdir),
};

int
cm_file_run(void)
{
	return run_tests(cm_file_tests);
}
