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
	uint8_t *buf_alloc = NULL;

	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), 50, false, &data);
	assert_int_equal(ret, 0);
	assert_true(data->type == ELASTO_DATA_IOV);
	assert_true(data->len == ARRAY_SIZE(buf));
	assert_true(data->off == 0);
	assert_true(data->base_off == 50);
	assert_true(data->iov.buf == buf);
	data->iov.buf = NULL;	/* don't free stack */
	elasto_data_free(data);

	ret = elasto_data_iov_new(buf_alloc, 100, 0, true, &data);
	assert_int_equal(ret, 0);
	assert_true(data->type == ELASTO_DATA_IOV);
	assert_true(data->len == 100);
	assert_true(data->off == 0);
	assert_true(data->base_off == 0);
	assert_true(data->iov.buf != NULL);

	ret = elasto_data_iov_grow(data, 100);
	assert_int_equal(ret, 0);
	assert_true(data->len == 200);
	elasto_data_free(data);
}

static void
cm_data_file(void **state)
{
	int ret;
	struct elasto_data *data;
	char dir_path[PATH_MAX];
	char file_path[PATH_MAX];
	struct stat st;

	strncpy(dir_path, "/tmp/elasto_cm_data_file_XXXXXX", PATH_MAX);
	char *dir = mkdtemp(dir_path);
	assert_true(dir != NULL);

	snprintf(file_path, PATH_MAX, "%s/cm_data_file0", dir);

	ret = elasto_data_file_new(file_path, 0, 0,
				   O_CREAT | O_WRONLY,
				   (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH),
				   &data),
	assert_int_equal(ret, 0);
	assert_string_equal(file_path, data->file.path);

	ret = fstat(data->file.fd, &st);
	assert_int_equal(ret, 0);
	assert_true((st.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
			== (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
	elasto_data_free(data);

	/* elasto_data_free() should have closed file, confirm */
	ret = stat(file_path, &st);
	assert_int_equal(ret, 0);
	unlink(file_path);
	rmdir(dir_path);

	/*
	 * TODO test (unimplemented) file truncation on open
	 */
}

static const UnitTest cm_data_tests[] = {
	unit_test(cm_data_iovec),
	unit_test(cm_data_file),
};

int
cm_data_run(void)
{
	return run_tests(cm_data_tests);
}
