/*
 * Copyright (C) SUSE LINUX GmbH 2013-2016, all rights reserved.
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

	ret = asprintf(&path, "/%s/%s%d",
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

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);
	cm_us->ctnr_suffix++; /* ensure future creations don't conflict */

	ret = elasto_frmdir(&auth,
			    path);
	assert_false(ret < 0);
	free(path);
}

static void
cm_file_share_create(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct elasto_fh *fh = NULL;

	auth.type = ELASTO_FILE_AFS;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth, path, ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL
				        | ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);
}

static void
cm_file_share_del(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct elasto_fh *fh = NULL;

	auth.type = ELASTO_FILE_AFS;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);
	cm_us->share_suffix++; /* ensure future creations don't conflict */

	ret = elasto_fopen(&auth, path, ELASTO_FOPEN_DIRECTORY, NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_funlink_close(fh);
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

	ret = asprintf(&path, "/%s/%s%d/create_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, -EEXIST);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);
	assert_false(ret < 0);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);
}

void
cm_file_buf_fill(uint8_t *buf,
		 size_t len,
		 int pattern_off)
{
	int i;

	for (i = 0; i < len; i++, pattern_off++) {
		buf[i] = (pattern_off & 0xff);
	}
}

void
cm_file_buf_check(uint8_t *buf,
		  size_t len,
		  int pattern_off)
{
	int i;

	for (i = 0; i < len; i++, pattern_off++) {
		assert_int_equal(buf[i], (pattern_off & 0xff));
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
	uint8_t buf[1024];

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/io_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	/* must truncate to size writing to the range */
	ret = elasto_ftruncate(fh, (1024 * 1024 * 1024));
	assert_false(ret < 0);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	memset(buf, 0, ARRAY_SIZE(buf));
	ret = elasto_fread(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);

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

	ret = asprintf(&path, "/%s/%s%d/lease_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

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

	ret = asprintf(&path, "/%s/%s%d/lease_multi_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh1);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   NULL, &fh2);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

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

	ret = asprintf(&path, "/%s/%s%d/lease_multi_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh1);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   0,
			   NULL, &fh2);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

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

	ret = asprintf(&path, "/%s/%s%d/truncate_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

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

	ret = asprintf(&path, "/%s/%s%d/stat_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

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
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);
	elasto_fclose(fh);

	/* open root without dir flag */
	ret = elasto_fopen(&auth,
			   "/",
			   0,
			   NULL, &fh);
	assert_int_equal(ret, -EINVAL);

	/* open root with create flags - should fail */
	ret = elasto_fopen(&auth,
			   "/",
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, -EINVAL);

	/* open existing account */
	ret = asprintf(&path, "/%s", cm_us->acc);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);
	ret = elasto_fclose(fh);
	assert_true(ret >= 0);

	/* account without dir flag */
	ret = elasto_fopen(&auth,
			   path,
			   0,
			   NULL, &fh);
	assert_true(ret < 0);

	/* account with create flags - already exists */
	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
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
			   NULL, &fh);
	assert_true(ret < 0);

	/* open non-existent ctnr with create flags */
	ret = elasto_fopen(&auth,
			   path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);
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
			   NULL, &fh);
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

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

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

static void
cm_file_dir_lease_multi(void **state)
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

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh1);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh2);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_flease_acquire(fh2, -1);
	assert_true(ret < 0);

	ret = elasto_flease_release(fh1);
	assert_int_equal(ret, 0);

	ret = elasto_flease_acquire(fh2, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fstat(fh1, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask | ELASTO_FSTAT_FIELD_LEASE);
	assert_true(fstat.lease_status == ELASTO_FLEASE_LOCKED);

	ret = elasto_fclose(fh2);
	assert_int_equal(ret, 0);

	/* close should have dropped lock */
	ret = elasto_fstat(fh1, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask | ELASTO_FSTAT_FIELD_LEASE);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh1);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_dir_lease_break(void **state)
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

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh1);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_flease_acquire(fh1, -1);
	assert_int_equal(ret, 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh2);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

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

static int
cm_file_dir_readdir_finder_dent_cb(struct elasto_dent *dent,
				   void *priv)
{
	struct elasto_dent *finder_dent = priv;

	if (!strcmp(dent->name, finder_dent->name)) {
		finder_dent->fstat = dent->fstat;
	}

	return 0;
}

static void
cm_file_dir_readdir(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *acc_path = NULL;
	char *ctnr_name = NULL;
	char *ctnr_path = NULL;
	char *blob_path = NULL;
	struct elasto_fh *fh_root;
	struct elasto_fh *fh_acc;
	struct elasto_fh *fh_ctnr;
	struct elasto_fh *fh_blob;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct elasto_dent finder_dent;

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = elasto_fopen(&auth,
			   "/",
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh_root);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	/* readdir root, and expect test account entry */
	memset(&finder_dent, 0, sizeof(finder_dent));
	finder_dent.name = cm_us->acc;
	ret = elasto_freaddir(fh_root, &finder_dent,
			      cm_file_dir_readdir_finder_dent_cb);
	assert_int_equal(ret, 0);
	elasto_fclose(fh_root);

	assert_true(finder_dent.fstat.field_mask == (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_BSIZE));
	assert_true(finder_dent.fstat.ent_type == ELASTO_FSTAT_ENT_DIR);
	assert_true(finder_dent.fstat.blksize == 512);


	/* create a new ctnr nested under the account */
	ret = asprintf(&ctnr_name, "%s%d", cm_us->ctnr, cm_us->ctnr_suffix);
	assert_true(ret >= 0);
	cm_us->ctnr_suffix++;
	ret = asprintf(&ctnr_path, "/%s/%s", cm_us->acc, ctnr_name);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   ctnr_path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh_ctnr);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	/* open the account */
	ret = asprintf(&acc_path, "/%s", cm_us->acc);
	assert_true(ret >= 0);
	ret = elasto_fopen(&auth,
			   acc_path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh_acc);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	/* check that the new ctnr appears in account readdir */
	memset(&finder_dent, 0, sizeof(finder_dent));
	finder_dent.name = ctnr_name;
	ret = elasto_freaddir(fh_acc, &finder_dent,
			      cm_file_dir_readdir_finder_dent_cb);
	assert_int_equal(ret, 0);
	ret = elasto_fclose(fh_acc);
	assert_true(ret >= 0);

	assert_true(finder_dent.fstat.field_mask == (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_BSIZE
						| ELASTO_FSTAT_FIELD_LEASE));
	assert_true(finder_dent.fstat.ent_type == ELASTO_FSTAT_ENT_DIR);
	assert_true(finder_dent.fstat.blksize == 512);
	assert_true(finder_dent.fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	/* create a new blob */
	ret = asprintf(&blob_path, "/%s/%s/readdir", cm_us->acc, ctnr_name);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   blob_path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh_blob);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);
	ret = elasto_fclose(fh_blob);
	assert_true(ret >= 0);

	/* readdir ctnr and expect blob entry */
	memset(&finder_dent, 0, sizeof(finder_dent));
	finder_dent.name = "readdir";
	ret = elasto_freaddir(fh_ctnr, &finder_dent,
			      cm_file_dir_readdir_finder_dent_cb);
	assert_int_equal(ret, 0);

	assert_true(finder_dent.fstat.field_mask == (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_SIZE
						| ELASTO_FSTAT_FIELD_BSIZE
						| ELASTO_FSTAT_FIELD_LEASE));
	assert_true(finder_dent.fstat.ent_type == ELASTO_FSTAT_ENT_FILE);
	assert_true(finder_dent.fstat.size == 0);
	assert_true(finder_dent.fstat.blksize == 512);
	assert_true(finder_dent.fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh_ctnr);
	assert_true(ret >= 0);

	ret = elasto_frmdir(&auth,
			    ctnr_path);
	assert_false(ret < 0);
	free(acc_path);
	free(ctnr_path);
}

static void
cm_file_dir_stat(void **state)
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

	/* stat root */
	ret = elasto_fopen(&auth,
			   "/",
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask == ELASTO_FSTAT_FIELD_TYPE);
	assert_true(fstat.ent_type == (ELASTO_FSTAT_ENT_DIR
					| ELASTO_FSTAT_ENT_ROOT));

	ret = elasto_fclose(fh);
	assert_true(ret >= 0);


	/* stat existing account */
	ret = asprintf(&path, "/%s", cm_us->acc);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask == ELASTO_FSTAT_FIELD_TYPE);
	assert_true(fstat.ent_type == ELASTO_FSTAT_ENT_DIR);

	ret = elasto_fclose(fh);
	assert_true(ret >= 0);
	free(path);

	/* stat existing ctnr */
	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_true(ret >= 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_fstat(fh, &fstat);
	assert_int_equal(ret, 0);
	assert_true(fstat.field_mask == (ELASTO_FSTAT_FIELD_TYPE
					| ELASTO_FSTAT_FIELD_LEASE));
	assert_true(fstat.ent_type == ELASTO_FSTAT_ENT_DIR);
	assert_true(fstat.lease_status == ELASTO_FLEASE_UNLOCKED);

	ret = elasto_fclose(fh);
	assert_true(ret >= 0);
	free(path);
}

/*
 * Azure block blobs are different to page blobs, in that writes at arbitrary
 * offsets aren't supported.
 */
static void
cm_file_abb_io(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	uint8_t buf[1024];
	uint64_t half;

	auth.type = ELASTO_FILE_ABB;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/abb_io_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	memset(buf, 0, ARRAY_SIZE(buf));
	/* read at arbitrary offsets, first half then second */
	half = ARRAY_SIZE(buf) / 2;
	ret = elasto_fread(fh, 0, half, buf);
	assert_false(ret < 0);

	cm_file_buf_check(buf, half, 0);

	memset(buf, 0, ARRAY_SIZE(buf));
	ret = elasto_fread(fh, half, half, buf);
	assert_false(ret < 0);

	cm_file_buf_check(buf, half, half);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);
}

static int
cm_file_data_out_cb(uint64_t stream_off,
		    uint64_t need,
		    uint8_t **_out_buf,
		    uint64_t *buf_len,
		    void *priv)
{
	uint8_t *buf = malloc(need);
	assert_false(buf == NULL);

	assert_false(_out_buf == NULL);
	assert_true(*_out_buf == NULL);
	assert_false(buf_len == NULL);

	cm_file_buf_fill(buf, need, stream_off);
	*_out_buf = buf;
	*buf_len = need;

	return 0;
}

static int
cm_file_data_in_cb(uint64_t stream_off,
		   uint64_t got,
		   uint8_t *in_buf,
		   uint64_t buf_len,
		   void *priv)
{
	cm_file_buf_check(in_buf, buf_len, stream_off);

	return 0;
}

static void
cm_file_data_cb(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	auth.type = ELASTO_FILE_ABB;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/cb_io_test",
		       cm_us->acc, cm_us->ctnr, cm_us->ctnr_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fwrite_cb(fh, 0, 1024, NULL, cm_file_data_out_cb);
	assert_false(ret < 0);

	ret = elasto_fread_cb(fh, 0, 1024, NULL, cm_file_data_in_cb);
	assert_false(ret < 0);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);
}

static void
cm_file_afs_io(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	uint8_t buf[1024];

	auth.type = ELASTO_FILE_AFS;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/afs_io_test",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	/* leave a 1k hole between first and second write */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), ARRAY_SIZE(buf));
	ret = elasto_fwrite(fh, ARRAY_SIZE(buf) * 2, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	memset(buf, 0, ARRAY_SIZE(buf));
	/* check first, hole zeros, then last chunk */
	ret = elasto_fread(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);

	ret = elasto_fread(fh, ARRAY_SIZE(buf), ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_buf_check_zero(buf, ARRAY_SIZE(buf));

	ret = elasto_fread(fh, ARRAY_SIZE(buf) * 2, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), ARRAY_SIZE(buf));

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
	free(path);
}

static int
cm_file_afs_path_encoding_dent_cb(struct elasto_dent *dent,
				  void *priv)
{
	int *cb_called = priv;

	(*cb_called)++;
	if ((strcmp(dent->name, "afs$") == 0)
			&& (dent->fstat.ent_type == ELASTO_FSTAT_ENT_DIR)) {
		return 0;
	} else if ((strcmp(dent->name, "afs encoding test") == 0)
			&& (dent->fstat.ent_type == ELASTO_FSTAT_ENT_FILE)) {
		return 0;
	}
	printf("unexpected dent: %s\n", dent->name);
	return -1;
}

static void
cm_file_afs_path_encoding(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	int cb_called;

	auth.type = ELASTO_FILE_AFS;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/afs encoding test",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);

	ret = asprintf(&path, "/%s/%s%d/afs$",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL
			   | ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);

	/* Azure FS supports '/' and '\' as directory path separators */
	ret = asprintf(&path, "/%s/%s%d/afs$\\both path separators",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL
			   | ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
	free(path);

	ret = asprintf(&path, "/%s/%s%d",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	cb_called = 0;
	ret = elasto_freaddir(fh, &cb_called, cm_file_afs_path_encoding_dent_cb);
	assert_false(ret < 0);
	assert_int_equal(cb_called, 2);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);
	free(path);
}

static int
cm_file_afs_list_ranges_cb(struct elasto_frange *frange,
			   void *priv)
{
	int *num_cbs = priv;

	assert_int_equal(frange->file_size, BYTES_IN_GB);
	if ((frange->off == 0) || (frange->off == 2 * BYTES_IN_KB)) {
		assert_int_equal(frange->len, BYTES_IN_KB);
	}
	(*num_cbs)++;

	return 0;
}

static void
cm_file_afs_list_ranges(void **state)
{
	int ret;
	struct elasto_fauth auth;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	uint8_t buf[1024];
	int num_cbs = 0;

	auth.type = ELASTO_FILE_AFS;
	auth.az.ps_path = cm_us->ps_file;
	auth.insecure_http = cm_us->insecure_http;

	ret = asprintf(&path, "/%s/%s%d/afs_io_test",
		       cm_us->acc, cm_us->share, cm_us->share_suffix);
	assert_false(ret < 0);

	ret = elasto_fopen(&auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	/* leave a 2k hole between start of file and write */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 2 * ARRAY_SIZE(buf));
	ret = elasto_fwrite(fh, ARRAY_SIZE(buf) * 2, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	/* ftruncate file to 1GB (unallocated after write) */
	ret = elasto_ftruncate(fh, BYTES_IN_GB);
	assert_true(ret >= 0);

	/* ensure written sections are the only allocated ranges */
	ret = elasto_flist_ranges(fh, 0, BYTES_IN_GB, 0, &num_cbs,
				  cm_file_afs_list_ranges_cb);
	assert_true(ret >= 0);

	assert_int_equal(num_cbs, 2);

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
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
	unit_test_setup_teardown(cm_file_dir_lease_multi,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_dir_lease_break,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_dir_readdir, NULL, NULL),
	unit_test_setup_teardown(cm_file_dir_stat,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_abb_io,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_data_cb,
				 cm_file_mkdir, cm_file_rmdir),
	unit_test_setup_teardown(cm_file_afs_io,
				 cm_file_share_create, cm_file_share_del),
	unit_test_setup_teardown(cm_file_afs_path_encoding,
				 cm_file_share_create, cm_file_share_del),
	unit_test_setup_teardown(cm_file_afs_list_ranges,
				 cm_file_share_create, cm_file_share_del),
};

int
cm_file_run(void)
{
	return run_tests(cm_file_tests);
}
