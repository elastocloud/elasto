/*
 * Copyright (C) SUSE LINUX GmbH 2013-2015, all rights reserved.
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
	free(path);
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
	free(path);
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
	free(path);
}

void
cm_file_buf_fill(uint8_t *buf,
		 size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		buf[i] = (i & 0xff);
	}
}

void
cm_file_buf_check(uint8_t *buf,
		  size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		assert_int_equal(buf[i], (i & 0xff));
	}
}

void
cm_file_buf_check_zero(uint8_t *buf,
		       size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		assert_int_equal(buf[i], 0);
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
	free(path);
}

static void
cm_file_lease_basic(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
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

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_flease_acquire(fh, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_LOCKED);

	ret = elasto_flease_release(fh);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_lease_multi(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh1;
	struct elasto_fh *fh2;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/lease_multi_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh1);
	assert_false(ret < 0);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   &fh2);
	assert_false(ret < 0);

	ret = elasto_flease_acquire(fh2, -1);
	assert_true(ret < 0);

	ret = elasto_flease_release(fh1);
	assert_int_equal(ret, 0);

	ret = elasto_flease_acquire(fh2, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh1, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_LOCKED);

	ret = elasto_fclose(fh2);
	assert_int_equal(ret, 0);

	/* close should have dropped lock */
	ret = elasto_fstat(fh1, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh1);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_lease_break(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh1;
	struct elasto_fh *fh2;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/lease_multi_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh1);
	assert_false(ret < 0);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   &fh2);
	assert_false(ret < 0);

	ret = elasto_flease_acquire(fh2, -1);
	assert_true(ret < 0);

	ret = elasto_fstat(fh2, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_LOCKED);

	ret = elasto_flease_break(fh2);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh2, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_flease_acquire(fh2, -1);
	assert_int_equal(ret, 0);

	/* will attempt and fail to release fh1's broken lease */
	ret = elasto_fclose(fh1);
	assert_int_equal(ret, 0);

	ret = elasto_fclose(fh2);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_truncate_basic(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/truncate_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_false(ret < 0);

	ret = elasto_fstat(fh, &fstat);
	assert_false(ret < 0);

	assert_int_equal(fstat.size, 0);

	ret = elasto_ftruncate(fh, (1024 * 1024 * 1024));
	assert_false(ret < 0);

	ret = elasto_fstat(fh, &fstat);
	assert_false(ret < 0);

	assert_int_equal(fstat.size, (1024 * 1024 * 1024));

	ret = elasto_ftruncate(fh, (1024 * 1024));
	assert_false(ret < 0);

	ret = elasto_fstat(fh, &fstat);
	assert_false(ret < 0);

	assert_int_equal(fstat.size, (1024 * 1024));

	ret = elasto_fclose(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_stat_basic(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct elasto_fstatfs fstatfs;
	int i;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d/stat_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_false(ret < 0);

	ret = elasto_fstat(fh, &fstat);
	assert_false(ret < 0);

	assert_int_equal(fstat.size, 0);

	ret = elasto_fstatfs(fh, &fstatfs);
	assert_false(ret < 0);

	assert_int_equal(fstat.size, 0);
	assert_true(fstatfs.iosize_min > 0);
	assert_true(fstatfs.iosize_optimal >= fstatfs.iosize_min);
	for (i = 0; i < fstatfs.num_regions; i++) {
		assert_non_null(fstatfs.regions[i].region);
		assert_non_null(fstatfs.regions[i].location);
	}

	ret = elasto_fclose(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_dir_open(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	/* open root */
	ret = elasto_fopen(&auth,
			   "/",
			   ELASTO_FOPEN_DIRECTORY,
			   &fh);
	assert_true(ret >= 0);
	elasto_fclose(fh);

	/* open root without dir flag */
	ret = elasto_fopen(&auth,
			   "/",
			   0,
			   &fh);
	assert_int_equal(ret, -EINVAL);

	/* open root with create flags - should fail */
	ret = elasto_fopen(&auth,
			   "/",
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_int_equal(ret, -EINVAL);

	/* open existing account */
	ret = asprintf(&path, "/%s", cm_us->acc);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   &fh);
	assert_true(ret >= 0);
	ret = elasto_fclose(fh);
	assert_true(ret >= 0);

	/* account without dir flag */
	ret = elasto_fopen(&auth,
			   path,
			   0,
			   &fh);
	assert_true(ret < 0);

	/* account with create flags - already exists */
	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_true(ret < 0);
	free(path);

	/* open non-existent ctnr without create flags */
	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_true(ret >= 0);
	cm_us->ctnr_suffix++;

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   &fh);
	assert_true(ret < 0);

	/* open non-existent ctnr with create flags */
	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   &fh);
	assert_true(ret >= 0);
	ret = elasto_fclose(fh);
	assert_true(ret >= 0);

	ret = elasto_frmdir(&auth,
			    path);
	assert_false(ret < 0);
	free(path);

	/* open root with invalid flags */
	ret = elasto_fopen(&auth,
			   "/",
			   ~ELASTO_FOPEN_FLAGS_MASK,
			   &fh);
	assert_int_equal(ret, -EINVAL);
}

static void
cm_file_dir_lease_basic(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   &fh);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask | ELASTO_FSTAT_FIELD_LEASE);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_flease_acquire(fh, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask | ELASTO_FSTAT_FIELD_LEASE);
	assert_true(fstat.lease_status == ELASTO_FLEASE_LOCKED);

	ret = elasto_flease_release(fh);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask | ELASTO_FSTAT_FIELD_LEASE);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static const UnitTest cm_file_tests[] = {
	unit_test_setup_teardown(cm_file_create,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_io,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_lease_basic,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_lease_multi,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_lease_break,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_truncate_basic,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_stat_basic,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_dir_open, NULL, NULL),
	unit_test_setup_teardown(cm_file_dir_lease_basic,
				 cm_file_mkdir, cm_file_rmdir),
};

int
cm_file_run(void)
{
	return run_tests(cm_file_tests);
}
