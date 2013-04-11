/*
 * Copyright (C) SUSE LINUX Products GmbH 2012, all rights reserved.
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

/* ugly: include .c files to generate UnitTest arrays */
#include "cm_sign_s3.c"
#include "cm_sign_azure.c"

int
main(void)
{
	int ret;

	dbg_level_set(10);
	sign_init();
	ret = run_tests(cm_sign_s3_tests);
	ret = run_tests(cm_sign_azure_tests);
	sign_deinit();
	return ret;
}
