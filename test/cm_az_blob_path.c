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
#include "lib/util.h"
#include "azure_blob_path.h"
#include "dbg.h"

static void
cm_az_blob_path_root(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };

	ret = az_blob_path_parse(NULL, 0, "/", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_ROOT);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, AZ_BLOB_PATH_HOST_MGMT);
	assert_int_equal(path.port, 443);
	assert_null(path.acc);
	assert_null(path.ctnr);
	assert_null(path.blob);
	az_blob_path_free(&path);
	/* double free should be ok */
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "///", false, &path);
	assert_int_equal(path.type, AZ_BLOB_PATH_ROOT);
	assert_true(ret >= 0);
	az_blob_path_free(&path);

	ret = az_blob_path_parse("hosty", 0, "/", true, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_ROOT);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty");
	assert_int_equal(path.port, 80);
	assert_null(path.acc);
	assert_null(path.ctnr);
	assert_null(path.blob);
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "", false, &path);
	assert_true(ret < 0);
}

static void
cm_az_blob_path_acc(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };
	char oversize[30];

	ret = az_blob_path_parse(NULL, 0, "/acc", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_ACC);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, "acc." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.acc, "acc");
	assert_null(path.ctnr);
	assert_null(path.blob);
	az_blob_path_free(&path);

	ret = az_blob_path_parse("hosty", 42, "/acc", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_ACC);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty");
	assert_int_equal(path.port, 42);
	assert_string_equal(path.acc, "acc");
	assert_null(path.ctnr);
	assert_null(path.blob);
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "//ace///", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_ACC);
	assert_string_equal(path.acc, "ace");
	az_blob_path_free(&path);

	/* no leading slash */
	ret = az_blob_path_parse(NULL, 0, "aoo", false, &path);
	assert_true(ret < 0);

	/* upper case invalid */
	ret = az_blob_path_parse(NULL, 0, "/AOO", false, &path);
	assert_true(ret < 0);

	/* too short */
	ret = az_blob_path_parse(NULL, 0, "/ao", false, &path);
	assert_int_equal(ret, -EINVAL);

	/* too long */
	memset(oversize, 'a', ARRAY_SIZE(oversize));
	oversize[0] = '/';
	oversize[ARRAY_SIZE(oversize) - 1] = '\0';
	ret = az_blob_path_parse(NULL, 0, oversize, false, &path);
	assert_int_equal(ret, -EINVAL);
}

static void
cm_az_blob_path_ctnr(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };
	char oversize[70];
	char *huge_path;

	ret = az_blob_path_parse(NULL, 0, "/acc/ctnr", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_CTNR);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, "acc." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.ctnr, "ctnr");
	assert_null(path.blob);
	az_blob_path_free(&path);

	ret = az_blob_path_parse("hosty", 42, "/acc/ctnr", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_CTNR);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty");
	assert_int_equal(path.port, 42);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.ctnr, "ctnr");
	assert_null(path.blob);
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "//ace///ct-ne//", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_CTNR);
	assert_string_equal(path.acc, "ace");
	assert_string_equal(path.ctnr, "ct-ne");
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "aoo/coo", false, &path);
	assert_true(ret < 0);

	/* upper case invalid */
	ret = az_blob_path_parse(NULL, 0, "/aoo/COO", false, &path);
	assert_true(ret < 0);

	/* hyphens invalid */
	ret = az_blob_path_parse(NULL, 0, "/aoo/-ctnr", false, &path);
	assert_true(ret < 0);
	ret = az_blob_path_parse(NULL, 0, "/aoo/ct--nr", false, &path);
	assert_true(ret < 0);

	/* too short */
	ret = az_blob_path_parse(NULL, 0, "/aoo/ct", false, &path);
	assert_int_equal(ret, -EINVAL);

	/* too long */
	memset(oversize, 'c', ARRAY_SIZE(oversize));
	oversize[ARRAY_SIZE(oversize) - 1] = '\0';
	asprintf(&huge_path, "/aoo/%s", oversize);
	ret = az_blob_path_parse(NULL, 0, huge_path, false, &path);
	assert_int_equal(ret, -EINVAL);
	free(huge_path);
}

static void
cm_az_blob_path_blob(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };
	char oversize[1030];
	char *huge_path;

	ret = az_blob_path_parse(NULL, 0, "/acc/ctnr/blob", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_BLOB);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, "acc." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.ctnr, "ctnr");
	assert_string_equal(path.blob, "blob");
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "//ace///ctne//bloe", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_BLOB);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, "ace." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.acc, "ace");
	assert_string_equal(path.ctnr, "ctne");
	assert_string_equal(path.blob, "bloe");
	az_blob_path_free(&path);

	ret = az_blob_path_parse("hosty", 0, "//ace///ctne//bloe", true, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.type, AZ_BLOB_PATH_BLOB);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty");
	assert_int_equal(path.port, 80);
	assert_string_equal(path.acc, "ace");
	assert_string_equal(path.ctnr, "ctne");
	assert_string_equal(path.blob, "bloe");
	az_blob_path_free(&path);

	ret = az_blob_path_parse(NULL, 0, "aoo/coo/bo", false, &path);
	assert_true(ret < 0);

	/* trailing garbage */
	ret = az_blob_path_parse(NULL, 0, "/aoo/coo/bo/", false, &path);
	assert_true(ret < 0);
	ret = az_blob_path_parse(NULL, 0, "/aoo/coo/bo/asdf", false, &path);
	assert_true(ret < 0);

	/* too long */
	memset(oversize, 'b', ARRAY_SIZE(oversize));
	oversize[ARRAY_SIZE(oversize) - 1] = '\0';
	asprintf(&huge_path, "/aoo/coo/%s", oversize);
	ret = az_blob_path_parse(NULL, 0, huge_path, false, &path);
	assert_int_equal(ret, -EINVAL);
	free(huge_path);
}

static void
cm_az_blob_path_dup(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };
	struct az_blob_path path_dup = { 0 };

	ret = az_blob_path_parse(NULL, 0, "/acc/ctnr/blob", false, &path);
	assert_true(ret >= 0);
	ret = az_blob_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, AZ_BLOB_PATH_BLOB);
	assert_false(path.host_is_custom);
	assert_string_equal(path.host, "acc." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path.port, 443);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.ctnr, "ctnr");
	assert_string_equal(path.blob, "blob");
	az_blob_path_free(&path);

	assert_int_equal(path_dup.type, AZ_BLOB_PATH_BLOB);
	assert_false(path_dup.host_is_custom);
	assert_string_equal(path_dup.host, "acc." AZ_BLOB_PATH_HOST_DEFAULT);
	assert_int_equal(path_dup.port, 443);
	assert_string_equal(path_dup.acc, "acc");
	assert_string_equal(path_dup.ctnr, "ctnr");
	assert_string_equal(path_dup.blob, "blob");
	az_blob_path_free(&path_dup);

	ret = az_blob_path_parse("hosty", 42, "/acc/ctnr/blob", true, &path);
	assert_true(ret >= 0);
	ret = az_blob_path_dup(&path, &path_dup);
	assert_true(ret >= 0);

	assert_int_equal(path.type, AZ_BLOB_PATH_BLOB);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty");
	assert_int_equal(path.port, 42);
	assert_string_equal(path.acc, "acc");
	assert_string_equal(path.ctnr, "ctnr");
	assert_string_equal(path.blob, "blob");
	az_blob_path_free(&path);

	assert_int_equal(path_dup.type, AZ_BLOB_PATH_BLOB);
	assert_true(path_dup.host_is_custom);
	assert_string_equal(path_dup.host, "hosty");
	assert_int_equal(path_dup.port, 42);
	assert_string_equal(path_dup.acc, "acc");
	assert_string_equal(path_dup.ctnr, "ctnr");
	assert_string_equal(path_dup.blob, "blob");
	az_blob_path_free(&path_dup);
}

static void
cm_az_blob_path_host(void **state)
{
	int ret;
	struct az_blob_path path = { 0 };

	ret = az_blob_path_parse("hosty.elasto.cloud", 0, "/acc/ctnr/blob", false, &path);
	assert_true(ret >= 0);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "hosty.elasto.cloud");
	assert_int_equal(path.port, 443);
	az_blob_path_free(&path);

	ret = az_blob_path_parse("192.168.0.1", 255, "/acc/ctnr/blob", false, &path);
	assert_true(ret >= 0);
	assert_true(path.host_is_custom);
	assert_string_equal(path.host, "192.168.0.1");
	assert_int_equal(path.port, 255);
	az_blob_path_free(&path);

	ret = az_blob_path_parse("192.168.0.1", UINT16_MAX, "/acc/ctnr/blob", false, &path);
	assert_true(ret >= 0);
	assert_int_equal(path.port, UINT16_MAX);
}

static const UnitTest cm_az_blob_path_tests[] = {
	unit_test(cm_az_blob_path_root),
	unit_test(cm_az_blob_path_acc),
	unit_test(cm_az_blob_path_ctnr),
	unit_test(cm_az_blob_path_blob),
	unit_test(cm_az_blob_path_dup),
	unit_test(cm_az_blob_path_host),
};

int
cm_az_blob_path_run(void)
{
	return run_tests(cm_az_blob_path_tests);
}
