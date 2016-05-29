/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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

#include "ccan/list/list.h"
#include "azure_fs_path.h"
#include "dbg.h"

static void
cm_az_fs_path_root(void **state)
{
	int ret;
	struct az_fs_path path = { 0 };

	ret = az_fs_path_parse("/", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ROOT);
	assert_null(path.acc);
	assert_null(path.share);
	assert_null(path.parent_dir);
	assert_null(path.fs_ent);
	az_fs_path_free(&path);
	/* double free should be ok */
	az_fs_path_free(&path);

	ret = az_fs_path_parse("///", &path);
	assert_int_equal(path.type, AZ_FS_PATH_ROOT);
	assert_true(ret >= 0);
	az_fs_path_free(&path);

	ret = az_fs_path_parse("", &path);
	assert_true(ret < 0);
}

static void
cm_az_fs_path_acc(void **state)
{
	int ret;
	struct az_fs_path path = { 0 };

	ret = az_fs_path_parse("/acc", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ACC);
	assert_string_equal(path.acc, "acc");
	assert_null(path.share);
	assert_null(path.parent_dir);
	assert_null(path.fs_ent);
	az_fs_path_free(&path);

	ret = az_fs_path_parse("//ace///", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ACC);
	assert_string_equal(path.acc, "ace");
	az_fs_path_free(&path);

	/* no leading slash */
	ret = az_fs_path_parse("aoo", &path);
	assert_true(ret < 0);

	/* upper case invalid */
	ret = az_fs_path_parse("/AOO", &path);
	assert_true(ret < 0);
}

static void
cm_az_fs_path_share(void **state)
{
	int ret;
	struct az_fs_path path = { 0 };

	ret = az_fs_path_parse("/acc/share", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_SHARE);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.share, "share");
	assert_null(path.parent_dir);
	assert_null(path.fs_ent);
	az_fs_path_free(&path);

	ret = az_fs_path_parse("//ace///sh-re//", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_SHARE);
	assert_string_equal(path.acc, "ace");
	assert_string_equal(path.share, "sh-re");
	az_fs_path_free(&path);

	ret = az_fs_path_parse("aoo/soo", &path);
	assert_true(ret < 0);

	/* upper case invalid */
	ret = az_fs_path_parse("/aoo/soO", &path);
	assert_true(ret < 0);

	/* hyphens invalid */
	ret = az_fs_path_parse("/aoo/-share", &path);
	assert_true(ret < 0);
	ret = az_fs_path_parse("/aoo/sh--re", &path);
	assert_true(ret < 0);
}

static void
cm_az_fs_path_file(void **state)
{
	int ret;
	struct az_fs_path path = { 0 };

	ret = az_fs_path_parse("/acc/share/file", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ENT);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.share, "share");
	assert_string_equal(path.file, "file");
	az_fs_path_free(&path);

	ret = az_fs_path_parse("//ace///shre//fie", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ENT);
	assert_string_equal(path.acc, "ace");
	assert_string_equal(path.share, "shre");
	assert_string_equal(path.file, "fie");
	az_fs_path_free(&path);

	ret = az_fs_path_parse("/acc/share/parent/path/file", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_FS_PATH_ENT);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.share, "share");
	assert_string_equal(path.parent_dir, "parent/path");
	assert_string_equal(path.file, "file");
	az_fs_path_free(&path);

	ret = az_fs_path_parse("aoo/soo/fo", &path);
	assert_true(ret < 0);

	/* trailing slash not *currently* allowed */
	ret = az_fs_path_parse("/aoo/soo/fo/", &path);
	assert_true(ret < 0);
}

static void
cm_az_fs_path_dup(void **state)
{
	int ret;
	struct az_fs_path path = { 0 };
	struct az_fs_path path_dup = { 0 };

	ret = az_fs_path_parse("/acc/share/parent_dir/file", &path);
	assert_true(ret >= 0);
	ret = az_fs_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, AZ_FS_PATH_ENT);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.share, "share");
	assert_string_equal(path.parent_dir, "parent_dir");
	assert_string_equal(path.file, "file");
	az_fs_path_free(&path);

	assert_int_equal(path_dup.type, AZ_FS_PATH_ENT);
	assert_string_equal(path_dup.acc, "acc");
	assert_string_equal(path_dup.share, "share");
	assert_string_equal(path_dup.parent_dir, "parent_dir");
	assert_string_equal(path_dup.file, "file");
	az_fs_path_free(&path_dup);
}

static const UnitTest cm_az_fs_path_tests[] = {
	unit_test(cm_az_fs_path_root),
	unit_test(cm_az_fs_path_acc),
	unit_test(cm_az_fs_path_share),
	unit_test(cm_az_fs_path_file),
	unit_test(cm_az_fs_path_dup),
};

int
cm_az_fs_path_run(void)
{
	return run_tests(cm_az_fs_path_tests);
}
