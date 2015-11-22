/*
 * Copyright (C) SUSE LINUX GmbH 2013-2015, all rights reserved.
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
#include "data_api.h"

/*
 * CMocka unit tests for Elasto data structures
 */
static void
cm_data_iovec(void **state)
{
	int ret;
	struct elasto_data *data;
	uint8_t buf[100];

	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_int_equal(ret, 0);
	assert_true(data->type == ELASTO_DATA_IOV);
	assert_true(data->len == ARRAY_SIZE(buf));
	assert_true(data->off == 0);
	assert_true(data->iov.buf == buf);
	/* data_free() doesn't free foreign buffers */
	elasto_data_free(data);

	ret = elasto_data_iov_new(NULL, 100, true, &data);
	assert_int_equal(ret, 0);
	assert_true(data->type == ELASTO_DATA_IOV);
	assert_true(data->len == 100);
	assert_true(data->off == 0);
	assert_true(data->iov.buf != NULL);

	ret = elasto_data_iov_grow(data, 100);
	assert_int_equal(ret, 0);
	assert_true(data->len == 200);
	/* data_free() frees data_iov_new() allocted buffers */
	elasto_data_free(data);

	/* allocate and grow a zero length buffer */
	ret = elasto_data_iov_new(NULL, 0, true, &data);
	assert_int_equal(ret, 0);
	ret = elasto_data_iov_grow(data, 100);
	assert_int_equal(ret, 0);
	assert_true(data->len == 100);
	elasto_data_free(data);

	/* attempt to grow a foreign buffer */
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_int_equal(ret, 0);
	ret = elasto_data_iov_grow(data, 100);
	assert_int_not_equal(ret, 0);
	elasto_data_free(data);
}

static const UnitTest cm_data_tests[] = {
	unit_test(cm_data_iovec),
};

int
cm_data_run(void)
{
	return run_tests(cm_data_tests);
}
