/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
#define _GNU_SOURCE
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
#include <linux/limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cmocka.h>

#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "util.h"
#include "xml.h"

static char *cm_xml_data_basic = "<outer><inner1><str>val</str></inner1></outer>";

/*
 * CMocka unit tests for Elasto XML decoding
 */
static void
cm_xml_basic_str(void **state)
{
	int ret;
	apr_status_t rv;
	apr_pool_t *pool;
	struct apr_xml_doc *xdoc;
	char *val;

	rv = apr_initialize();
	assert_true(rv == APR_SUCCESS);

	rv = apr_pool_create(&pool, NULL);
	assert_true(rv == APR_SUCCESS);

	ret = xml_slurp(pool, false, (uint8_t *)cm_xml_data_basic,
			strlen(cm_xml_data_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = xml_path_get(xdoc->root,
			   "/outer/inner1/str",
			   &val);
	assert_int_equal(ret, 0);
	assert_string_equal(val, "val");
}

static const UnitTest cm_xml_tests[] = {
	unit_test(cm_xml_basic_str),
};

int
cm_xml_run(void)
{
	return run_tests(cm_xml_tests);
}
