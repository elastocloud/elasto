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

#include "elasto/file.h"
#include "cm_test.h"
#include "lib/util.h"

static void
cm_file_local_create(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	ret = asprintf(&path, "%s/create_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_int_equal(ret, -EEXIST);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   0,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	ret = elasto_fclose(fh);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);
	assert_false(ret < 0);

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
	free(path);
}

void
cm_file_local_buf_fill(uint8_t *buf,
		 size_t len,
		 int pattern_off)
{
	int i;

	for (i = 0; i < len; i++, pattern_off++) {
		buf[i] = (pattern_off & 0xff);
	}
}

void
cm_file_local_buf_check(uint8_t *buf,
		  size_t len,
		  int pattern_off)
{
	int i;

	for (i = 0; i < len; i++, pattern_off++) {
		assert_int_equal(buf[i], (pattern_off & 0xff));
	}
}

void
cm_file_local_buf_check_zero(uint8_t *buf,
		       size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		assert_int_equal(buf[i], 0);
	}
}

static void
cm_file_local_io(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	uint8_t buf[1024];

	ret = asprintf(&path, "%s/io_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	cm_file_local_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_fwrite(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	/* leave a 1k hole between first and second write */
	cm_file_local_buf_fill(buf, ARRAY_SIZE(buf), ARRAY_SIZE(buf));
	ret = elasto_fwrite(fh, ARRAY_SIZE(buf) * 2, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	memset(buf, 0, ARRAY_SIZE(buf));
	/* check first, hole zeros, then last chunk */
	ret = elasto_fread(fh, 0, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_local_buf_check(buf, ARRAY_SIZE(buf), 0);

	ret = elasto_fread(fh, ARRAY_SIZE(buf), ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_local_buf_check_zero(buf, ARRAY_SIZE(buf));

	ret = elasto_fread(fh, ARRAY_SIZE(buf) * 2, ARRAY_SIZE(buf), buf);
	assert_false(ret < 0);

	cm_file_local_buf_check(buf, ARRAY_SIZE(buf), ARRAY_SIZE(buf));

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
	free(path);
}

static void
cm_file_local_truncate_basic(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	ret = asprintf(&path, "%s/truncate_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
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

	ret = elasto_funlink_close(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_local_stat_basic(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct elasto_fstatfs fstatfs;
	int i;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	ret = asprintf(&path, "%s/stat_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
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

	ret = elasto_funlink_close(fh);
	assert_int_equal(ret, 0);
	free(path);
}

static void
cm_file_local_dir_open(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	/* open existing tmpdir */
	ret = asprintf(&path, "%s", cm_us->local_tmpdir);
	assert_true(ret >= 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);
	ret = elasto_fclose(fh);
	assert_true(ret >= 0);

	/* tmpdir without dir flag */
	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   0,
			   NULL, &fh);
	assert_true(ret < 0);

	/* tmpdir with create flags - already exists */
	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh);
	assert_true(ret < 0);

	/* open tmpdir with invalid flags */
	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ~ELASTO_FOPEN_FLAGS_MASK,
			   NULL, &fh);
	assert_int_equal(ret, -EINVAL);
	free(path);

	/* open non-existent path without create flags */
	ret = asprintf(&path, "%s/non-existent", cm_us->local_tmpdir);
	assert_true(ret >= 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh);
	assert_true(ret < 0);
	free(path);
}

static int
cm_file_local_dir_readdir_finder_dent_cb(struct elasto_dent *dent,
				   void *priv)
{
	struct elasto_dent *finder_dent = priv;

	if (!strcmp(dent->name, finder_dent->name)) {
		finder_dent->fstat = dent->fstat;
	}

	return 0;
}

static void
cm_file_local_dir_readdir(void **state)
{
	int ret;
	char *subdir_path = NULL;
	char *file_path = NULL;
	struct elasto_fh *fh_tmpdir;
	struct elasto_fh *fh_subdir;
	struct elasto_fh *fh_file;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct elasto_dent finder_dent;

	/* create a new subdir nested under tmpdir */
	ret = asprintf(&subdir_path, "%s/readdir_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   subdir_path,
			   (ELASTO_FOPEN_DIRECTORY | ELASTO_FOPEN_CREATE
			    | ELASTO_FOPEN_EXCL),
			   NULL, &fh_subdir);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	/* open the tmpdir */
	ret = elasto_fopen(&cm_us->local_auth,
			   cm_us->local_tmpdir,
			   ELASTO_FOPEN_DIRECTORY,
			   NULL, &fh_tmpdir);
	assert_int_equal(ret, ELASTO_FOPEN_RET_EXISTED);

	/* check that the new subdir appears in tmpdir readdir */
	memset(&finder_dent, 0, sizeof(finder_dent));
	finder_dent.name = "readdir_test";
	ret = elasto_freaddir(fh_tmpdir, &finder_dent,
			      cm_file_local_dir_readdir_finder_dent_cb);
	assert_int_equal(ret, 0);
	ret = elasto_fclose(fh_tmpdir);
	assert_true(ret >= 0);

	assert_true(finder_dent.fstat.field_mask == ELASTO_FSTAT_FIELD_TYPE);
	assert_true(finder_dent.fstat.ent_type == ELASTO_FSTAT_ENT_DIR);

	/* create a new file under subdir */
	ret = asprintf(&file_path, "%s/readdir_file", subdir_path);
	assert_true(ret >= 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   file_path,
			   (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL),
			   NULL, &fh_file);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	/* readdir expect file entry */
	memset(&finder_dent, 0, sizeof(finder_dent));
	finder_dent.name = "readdir_file";
	ret = elasto_freaddir(fh_subdir, &finder_dent,
			      cm_file_local_dir_readdir_finder_dent_cb);
	assert_int_equal(ret, 0);

	assert_true(finder_dent.fstat.field_mask == (ELASTO_FSTAT_FIELD_TYPE
						| ELASTO_FSTAT_FIELD_SIZE
						| ELASTO_FSTAT_FIELD_BSIZE));
	assert_true(finder_dent.fstat.ent_type == ELASTO_FSTAT_ENT_FILE);
	assert_true(finder_dent.fstat.size == 0);
	assert_true(finder_dent.fstat.blksize != 0);

	ret = elasto_funlink_close(fh_file);
	assert_true(ret >= 0);

	ret = elasto_funlink_close(fh_subdir);
	assert_true(ret >= 0);

	free(subdir_path);
	free(file_path);
}

static void
cm_file_local_dir_stat(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct elasto_fstat fstat;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	ret = elasto_fopen(&cm_us->local_auth,
			   cm_us->local_tmpdir,
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
}

static int
cm_file_local_data_out_cb(uint64_t stream_off,
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

	cm_file_local_buf_fill(buf, need, stream_off);
	*_out_buf = buf;
	*buf_len = need;

	return 0;
}

static int
cm_file_local_data_in_cb(uint64_t stream_off,
		   uint64_t got,
		   uint8_t *in_buf,
		   uint64_t buf_len,
		   void *priv)
{
	cm_file_local_buf_check(in_buf, buf_len, stream_off);

	return 0;
}

static void
cm_file_local_data_cb(void **state)
{
	int ret;
	char *path = NULL;
	struct elasto_fh *fh;
	struct cm_unity_state *cm_us = cm_unity_state_get();

	ret = asprintf(&path, "%s/cb_io_test", cm_us->local_tmpdir);
	assert_false(ret < 0);

	ret = elasto_fopen(&cm_us->local_auth,
			   path,
			   ELASTO_FOPEN_CREATE,
			   NULL, &fh);
	assert_int_equal(ret, ELASTO_FOPEN_RET_CREATED);

	ret = elasto_fwrite_cb(fh, 0, 1024, NULL, cm_file_local_data_out_cb);
	assert_false(ret < 0);

	ret = elasto_fread_cb(fh, 0, 1024, NULL, cm_file_local_data_in_cb);
	assert_false(ret < 0);

	ret = elasto_funlink_close(fh);
	assert_false(ret < 0);
	free(path);
}

static const UnitTest cm_file_local_tests[] = {
	unit_test_setup_teardown(cm_file_local_create, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_io, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_truncate_basic, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_stat_basic, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_dir_open, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_dir_readdir, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_dir_stat, NULL, NULL),
	unit_test_setup_teardown(cm_file_local_data_cb, NULL, NULL),
};

int
cm_file_local_run(void)
{
	return run_tests(cm_file_local_tests);
}

