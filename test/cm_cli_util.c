/*
 * Copyright (C) SUSE LINUX GmbH 2017, all rights reserved.
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
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/util.h"
#include "client/cli_util.h"

static void
cm_cli_util_progress(void **state)
{
	char tmp[] = "/tmp/elasto_cm_cli_util_XXXXXX";
	char buf[256];
	int read_off = 0;
	int ret;
	int fd;
	FILE *stream;
	int len;

	fd = mkstemp(tmp);
	assert_true(fd > 0);

	stream = fdopen(fd, "w+");
	assert_true(stream != NULL);

	len = cli_progress_print(stream, 0);
	assert_true(len < ARRAY_SIZE(buf));
	ret = pread(fd, buf, len, read_off);
	assert(ret == len);
	read_off += ret;
	assert_memory_equal(buf,
"\r  0\% [                                                                  ]",
			    len);

	len = cli_progress_print(stream, (double)1/2);
	assert_true(len < ARRAY_SIZE(buf));
	ret = pread(fd, buf, len, read_off);
	assert(ret == len);
	read_off += ret;
	assert_memory_equal(buf,
"\r 50\% [#################################                                 ]",
			    len);

	len = cli_progress_print(stream, (double)1);
	assert_true(len < ARRAY_SIZE(buf));
	ret = pread(fd, buf, len, read_off);
	assert(ret == len);
	read_off += ret;
	assert_memory_equal(buf,
"\r100\% [##################################################################]",
			    len);

	ret = fclose(stream);
	assert_true(ret == 0);
	ret = unlink(tmp);
	assert_true(ret == 0);
}

static void
cm_cli_util_human_size(void **state)
{
	char buf[256];

	cli_human_size(0, buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "0 B");

	cli_human_size(512, buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "512 B");

	cli_human_size((double)1124 , buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "1.1 K");

	cli_human_size((double)(1024 * 1024 + 4096), buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "1.00 M");

	cli_human_size((double)(1024 * 1024 * 1024 - 1), buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "1024.00 M");

	cli_human_size((double)(1024 * 1024 * 1024), buf, ARRAY_SIZE(buf));
	assert_string_equal(buf, "1.000 G");

	memset(buf, 0, ARRAY_SIZE(buf));
	cli_human_size((double)1024, buf, 0);
	assert_string_equal(buf, "");

	memset(buf, 0, ARRAY_SIZE(buf));
	cli_human_size((double)1024, buf, 2);
	assert_string_equal(buf, "1");
}

static const UnitTest cm_cli_util_tests[] = {
	unit_test(cm_cli_util_progress),
	unit_test(cm_cli_util_human_size),
};

int
cm_cli_util_run(void)
{
	return run_tests(cm_cli_util_tests);
}
