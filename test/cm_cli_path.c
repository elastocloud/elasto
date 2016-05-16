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

static const UnitTest cm_cli_path_tests[] = {
	unit_test(cm_cli_path_usr_absolute),
	unit_test(cm_cli_path_usr_relative),
};

int
cm_cli_path_run(void)
{
	return run_tests(cm_cli_path_tests);
}
