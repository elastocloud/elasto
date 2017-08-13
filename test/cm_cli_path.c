/*
 * Copyright (C) SUSE LINUX GmbH 2016-2017, all rights reserved.
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
#include "lib/file/file_api.h"
#include "client/cli_common.h"
#include "dbg.h"

static void
cm_cli_path_usr_absolute(void **state)
{
	int ret;
	char *path;

	/* cwd should be ignored when the usr path is absolute */
	ret = cli_path_realize("/a/b/c", "/d/e/f", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", "//d////e/f/", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", "/./d//./../e/f/", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/e/f");
	free(path);

	ret = cli_path_realize("/", "/", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/");
	free(path);

	ret = cli_path_realize("/", "/a/b../", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b..");
	free(path);

	/* cwd should always be present */
	ret = cli_path_realize("", "/a/b/c", &path);
	assert_true(ret == -EINVAL);

	ret = cli_path_realize(NULL, "/a/b/c", &path);
	assert_true(ret == -EINVAL);
}

static void
cm_cli_path_usr_relative(void **state)
{
	int ret;
	char *path;

	ret = cli_path_realize("/a/b/c", "d/e/f", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/c/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", "./d/e/f", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/c/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", ".//d////e/f/", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/c/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", "..//d//.//e/f/", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/d/e/f");
	free(path);

	ret = cli_path_realize("/a/b/c", "../../..", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/");
	free(path);

	/* past root */
	ret = cli_path_realize("/a/b/c", "../../../..", &path);
	assert_true(ret == -EINVAL);

	ret = cli_path_realize("/", "../", &path);
	assert_true(ret == -EINVAL);

	/* relative path isn't mandatory */
	ret = cli_path_realize("/a/b/c", "", &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/c");
	free(path);

	ret = cli_path_realize("/a/b/c", NULL, &path);
	assert_true(ret == 0);
	assert_string_equal(path, "/a/b/c");
	free(path);
}

static void
cm_cli_path_uri(void **state)
{
	int ret;
	enum elasto_ftype type;
	char *host;
	uint16_t port;
	char *uri;

	ret = cli_path_uri_parse("s3://host/", &type, &host, &port);
	assert_true(ret == 0);
	assert_int_equal(type, ELASTO_FILE_S3);
	assert_string_equal(host, "host");
	assert_int_equal(port, 0);
	free(host);

	ret = cli_path_uri_parse("afs://host:5", &type, &host, &port);
	assert_true(ret == 0);
	assert_int_equal(type, ELASTO_FILE_AFS);
	assert_string_equal(host, "host");
	assert_int_equal(port, 5);
	free(host);

	ret = cli_path_uri_parse("apb://host", &type, &host, &port);
	assert_true(ret == 0);
	assert_int_equal(type, ELASTO_FILE_APB);
	assert_string_equal(host, "host");
	assert_int_equal(port, 0);
	free(host);

	ret = cli_path_uri_parse("abb://", &type, &host, &port);
	assert_int_equal(type, ELASTO_FILE_ABB);
	assert_null(host);
	assert_int_equal(port, 0);
	free(host);

	ret = asprintf(&uri, "s3://host:%d", UINT16_MAX + 1);
	assert_true(ret >= 0);
	ret = cli_path_uri_parse(uri, &type, &host, &port);
	free(uri);
	assert_int_equal(ret, -EINVAL);	/* port too big */

	ret = cli_path_uri_parse("stuff://host", &type, &host, &port);
	assert_int_equal(ret, -EINVAL);	/* bad scheme */

	ret = cli_path_uri_parse("s3://host/asdf", &type, &host, &port);
	assert_int_equal(ret, -EINVAL);	/* trailing path */

	ret = cli_path_uri_parse("s3://host/?a", &type, &host, &port);
	assert_true(ret == -EINVAL);	/* query string */

	ret = cli_path_uri_parse("s3://host/#a", &type, &host, &port);
	assert_true(ret == -EINVAL);	/* fragment string */

	ret = cli_path_uri_parse("s3://user@host/", &type, &host, &port);
	assert_true(ret == -EINVAL);	/* user string */
}

static const UnitTest cm_cli_path_tests[] = {
	unit_test(cm_cli_path_usr_absolute),
	unit_test(cm_cli_path_usr_relative),
	unit_test(cm_cli_path_uri),
};

int
cm_cli_path_run(void)
{
	return run_tests(cm_cli_path_tests);
}
