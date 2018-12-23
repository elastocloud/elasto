/*
 * Copyright (C) SUSE LINUX GmbH 2018, all rights reserved.
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
#include "client/cli_mime.h"

static void
cm_cli_mime_type_lookup(void **state)
{
	const char *mt = NULL;

	mt = cli_mime_type_lookup("a.txt");
	assert_string_equal(mt, "text/plain");
	mt = cli_mime_type_lookup("txt");
	assert_null(mt);

	mt = cli_mime_type_lookup("a.unknown");
	assert_null(mt);

	mt = cli_mime_type_lookup("a.tar");
	assert_string_equal(mt, "application/x-tar");

	mt = cli_mime_type_lookup("a.jpeg");
	assert_string_equal(mt, "image/jpeg");
}

static const UnitTest cm_cli_mime_tests[] = {
	unit_test(cm_cli_mime_type_lookup),
};

int
cm_cli_mime_run(void)
{
	return run_tests(cm_cli_mime_tests);
}
