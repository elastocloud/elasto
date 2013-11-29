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

#include "ccan/list/list.h"
#include "dbg.h"
#include "util.h"
#include "exml.h"

static char *cm_xml_data_str_basic
	= "<outer><inner1><str>val</str></inner1><str>blah</str></outer>";
static char *cm_xml_data_num_basic
	= "<outer><num>100</num><inner1><neg>-100</neg></inner1>"
	  "<huge>18446744073709551615</huge></outer>";
static char *cm_xml_data_bool_basic
	= "<outer><inner1><bool>true</bool></inner1><next>false</next></outer>";
static char *cm_xml_data_b64_basic
	= "<outer><Label1>dGhpcyBpcyBhIGxhYmVs</Label1>"
	  "<Label2>aXN0Z3Q=</Label2></outer>";

/*
 * TODO test:
 * - duplicate paths, mem-leak return last
 * - empty values
 * - attributes
 */

/*
 * CMocka unit tests for Elasto XML decoding
 */
static void
cm_xml_str_basic(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	char *val = NULL;

	ret = exml_slurp(cm_xml_data_str_basic,
			strlen(cm_xml_data_str_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_str_want(xdoc,
			   "/outer/inner1/str",
			   true,
			   &val,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);

	assert_non_null(val);
	assert_string_equal(val, "val");

	exml_free(xdoc);
	free(val);
}

static void
cm_xml_two_str(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	char *val1 = NULL;
	char *val2 = NULL;
	bool val2_present = false;

	ret = exml_slurp(cm_xml_data_str_basic,
			strlen(cm_xml_data_str_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_str_want(xdoc,
			   "/outer/inner1/str",
			   true,
			   &val1,
			   NULL);
	assert_int_equal(ret, 0);

	/* not required */
	ret = exml_str_want(xdoc,
			   "/outer/str",
			   false,
			   &val2,
			   &val2_present);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);

	exml_free(xdoc);

	assert_non_null(val1);
	assert_string_equal(val1, "val");
	assert_true(val2_present);
	assert_non_null(val2);
	assert_string_equal(val2, "blah");
	free(val1);
	free(val2);
}

static void
cm_xml_num_basic(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	int32_t val1;
	int64_t val2;
	uint64_t val3;

	ret = exml_slurp(cm_xml_data_num_basic,
			strlen(cm_xml_data_num_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_int32_want(xdoc,
			   "/outer/num",
			   true,
			   &val1,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_int64_want(xdoc,
			   "/outer/inner1/neg",
			   true,
			   &val2,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_uint64_want(xdoc,
			   "/outer/huge",
			   true,
			   &val3,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);
	exml_free(xdoc);

	assert_true(val1 == 100);
	assert_true(val2 == -100);
	assert_true(val3 == 18446744073709551615ULL);
}

static void
cm_xml_bool_basic(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	bool val1;
	bool val2;

	ret = exml_slurp(cm_xml_data_bool_basic,
			strlen(cm_xml_data_bool_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_bool_want(xdoc,
			   "/outer/inner1/bool",
			   true,
			   &val1,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_bool_want(xdoc,
			   "/outer/next",
			   true,
			   &val2,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);

	exml_free(xdoc);

	assert_true(val1);
	assert_false(val2);
}

static void
cm_xml_base64_basic(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	char *val1 = NULL;
	char *val2 = NULL;

	ret = exml_slurp(cm_xml_data_b64_basic,
			strlen(cm_xml_data_b64_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_base64_want(xdoc,
			   "/outer/Label1",
			   true,
			   &val1,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_base64_want(xdoc,
			   "/outer/Label2",
			   true,
			   &val2,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);

	exml_free(xdoc);

	assert_non_null(val1);
	assert_string_equal(val1, "this is a label");
	assert_non_null(val2);
	assert_string_equal(val2, "istgt");
	free(val1);
	free(val2);
}

int cm_xml_want_cb(struct xml_doc *xdoc,
		   const char *path,
		   const char *val,
		   void *cb_data)
{
	char **str = cb_data;

	asprintf(str, "got: %s", val);
	return 0;
}

static void
cm_xml_cb_basic(void **state)
{
	int ret;
	struct xml_doc *xdoc;
	char *val = NULL;

	ret = exml_slurp(cm_xml_data_str_basic,
			strlen(cm_xml_data_str_basic), &xdoc);
	assert_int_equal(ret, 0);

	ret = exml_cb_want(xdoc,
			   "/outer/inner1/str",
			   true,
			   cm_xml_want_cb,
			   &val,
			   NULL);
	assert_int_equal(ret, 0);

	ret = exml_parse(xdoc);
	assert_int_equal(ret, 0);

	assert_non_null(val);
	assert_string_equal(val, "got: val");

	exml_free(xdoc);
	free(val);
}

static const UnitTest cm_xml_tests[] = {
	unit_test(cm_xml_str_basic),
	unit_test(cm_xml_two_str),
	unit_test(cm_xml_num_basic),
	unit_test(cm_xml_bool_basic),
	unit_test(cm_xml_base64_basic),
	unit_test(cm_xml_cb_basic),
};

int
cm_xml_run(void)
{
	return run_tests(cm_xml_tests);
}
