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
#include "s3_path.h"
#include "dbg.h"

static void
cm_s3_path_root(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse(NULL, 0, "/", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_string_equal(path.host, S3_PATH_HOST_DEFAULT);
	assert_false(path.host_is_custom);
	assert_int_equal(path.port, 443);
	assert_null(path.bkt);
	assert_null(path.obj);
	s3_path_free(&path);
	/* double free should be ok */
	s3_path_free(&path);

	ret = s3_path_parse(NULL, 0, "///", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_int_equal(path.port, 443);
	s3_path_free(&path);

	ret = s3_path_parse("myhost", 0, "/", true, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_string_equal(path.host, "myhost");
	assert_true(path.host_is_custom);
	assert_int_equal(path.port, 80);
	s3_path_free(&path);

	ret = s3_path_parse(NULL, 0, "", false, &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_bkt(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse(NULL, 0, "/bkt", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_BKT);
	assert_string_equal(path.bkt, "bkt");
	assert_null(path.obj);
	s3_path_free(&path);

	ret = s3_path_parse(NULL, 0, "//bkt///", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_BKT);
	assert_string_equal(path.bkt, "bkt");
	s3_path_free(&path);

	/* no leading slash */
	ret = s3_path_parse(NULL, 0, "bo", false, &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_obj(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse(NULL, 0, "/bkt/obj", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	ret = s3_path_parse(NULL, 0, "//bkt///obe", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obe");
	s3_path_free(&path);

	ret = s3_path_parse(NULL, 0, "bo/oo", false, &path);
	assert_true(ret < 0);

	/* trailing garbage */
	ret = s3_path_parse(NULL, 0, "/bo/oo/", false, &path);
	assert_true(ret < 0);
	ret = s3_path_parse(NULL, 0, "/bo/oo/asdf", false, &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_dup(void **state)
{
	int ret;
	struct s3_path path = { 0 };
	struct s3_path path_dup = { 0 };

	ret = s3_path_parse(NULL, 0, "/bkt/obj", false, &path);
	assert_true(ret >= 0);
	ret = s3_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	assert_int_equal(path_dup.type, S3_PATH_OBJ);
	assert_string_equal(path_dup.bkt, "bkt");
	assert_int_equal(path_dup.port, 443);
	assert_string_equal(path_dup.obj, "obj");
	s3_path_free(&path_dup);

	ret = s3_path_parse("hosty", 515, "/bkt/obj", true, &path);
	assert_true(ret >= 0);
	ret = s3_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.host, "hosty");
	assert_true(path.host_is_custom);
	assert_int_equal(path.port, 515);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	assert_int_equal(path_dup.type, S3_PATH_OBJ);
	assert_string_equal(path_dup.host, "hosty");
	assert_true(path_dup.host_is_custom);
	assert_int_equal(path_dup.port, 515);
	assert_string_equal(path_dup.bkt, "bkt");
	assert_string_equal(path_dup.obj, "obj");
	s3_path_free(&path_dup);
}

static void
cm_s3_path_host(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse("hosty.elasto.cloud", 1, "//bkt/obj", false, &path);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.host, "hosty.elasto.cloud");
	assert_true(path.host_is_custom);
	assert_int_equal(path.port, 1);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	ret = s3_path_parse("hosty", 2, "//bkt/obj", true, &path);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.host, "hosty");
	assert_true(path.host_is_custom);
	assert_int_equal(path.port, 2);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	ret = s3_path_parse("hosty", 0, "//bkt/obj", false, &path);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.host, "hosty");
	assert_true(path.host_is_custom);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	ret = s3_path_parse("hosty", 2, "//bkt/obj/stuff", true, &path);
	assert_true(ret < 0);
}

static const UnitTest cm_s3_path_tests[] = {
	unit_test(cm_s3_path_root),
	unit_test(cm_s3_path_bkt),
	unit_test(cm_s3_path_obj),
	unit_test(cm_s3_path_dup),
	unit_test(cm_s3_path_host),
};

int
cm_s3_path_run(void)
{
	return run_tests(cm_s3_path_tests);
}
