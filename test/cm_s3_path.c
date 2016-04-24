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

	ret = s3_path_parse("/", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_string_equal(path.host, S3_PATH_HOST_DEFAULT);
	assert_null(path.bkt);
	assert_null(path.obj);
	s3_path_free(&path);
	/* double free should be ok */
	s3_path_free(&path);

	ret = s3_path_parse("///", &path);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_true(ret >= 0);
	s3_path_free(&path);

	/* XXX S3 currently handles a URI with host */
	ret = s3_path_parse("s3://myhost/", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_ROOT);
	assert_string_equal(path.host, "myhost");
	assert_true(ret >= 0);
	s3_path_free(&path);

	ret = s3_path_parse("", &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_bkt(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse("/bkt", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_BKT);
	assert_string_equal(path.bkt, "bkt");
	assert_null(path.obj);
	s3_path_free(&path);

	ret = s3_path_parse("//bkt///", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_BKT);
	assert_string_equal(path.bkt, "bkt");
	s3_path_free(&path);

	/* no leading slash */
	ret = s3_path_parse("bo", &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_obj(void **state)
{
	int ret;
	struct s3_path path = { 0 };

	ret = s3_path_parse("/bkt/obj", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	ret = s3_path_parse("//bkt///obe", &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obe");
	s3_path_free(&path);

	ret = s3_path_parse("bo/oo", &path);
	assert_true(ret < 0);

	/* trailing garbage */
	ret = s3_path_parse("/bo/oo/", &path);
	assert_true(ret < 0);
	ret = s3_path_parse("/bo/oo/asdf", &path);
	assert_true(ret < 0);
}

static void
cm_s3_path_dup(void **state)
{
	int ret;
	struct s3_path path = { 0 };
	struct s3_path path_dup = { 0 };

	ret = s3_path_parse("/bkt/obj", &path);
	assert_true(ret >= 0);
	ret = s3_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	assert_int_equal(path_dup.type, S3_PATH_OBJ);
	assert_string_equal(path_dup.bkt, "bkt");
	assert_string_equal(path_dup.obj, "obj");
	s3_path_free(&path_dup);

	ret = s3_path_parse("s3://hosty/bkt/obj", &path);
	assert_true(ret >= 0);
	ret = s3_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, S3_PATH_OBJ);
	assert_string_equal(path.host, "hosty");
	assert_string_equal(path.bkt, "bkt");
	assert_string_equal(path.obj, "obj");
	s3_path_free(&path);

	assert_int_equal(path_dup.type, S3_PATH_OBJ);
	assert_string_equal(path_dup.host, "hosty");
	assert_string_equal(path_dup.bkt, "bkt");
	assert_string_equal(path_dup.obj, "obj");
	s3_path_free(&path_dup);
}

static const UnitTest cm_s3_path_tests[] = {
	unit_test(cm_s3_path_root),
	unit_test(cm_s3_path_bkt),
	unit_test(cm_s3_path_obj),
	unit_test(cm_s3_path_dup),
};

int
cm_s3_path_run(void)
{
	return run_tests(cm_s3_path_tests);
}
