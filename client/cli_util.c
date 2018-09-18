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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "client/cli_util.h"

void
cli_human_size(double bytes,
	       char *buf,
	       size_t buflen)
{
	int i = 0;
	const char* units[] = {"B", "K", "M", "G", "T", "P", "E", "Z"};

	while ((bytes >= 1024) && (i < ARRAY_SIZE(units) - 1)) {
		bytes /= 1024;
		i++;
	}
	snprintf(buf, buflen, "%.*f %s", i, bytes, units[i]);
}

int
cli_progress_print(FILE *stream,
		   double pcnt_fract)
{
	char bar_str[CLI_PROGRESS_MAX_LEN]
				= "#################################"
				  "#################################";
	int pcnt = (int)(pcnt_fract * 100);
	int lpad = (int)(pcnt_fract * ARRAY_SIZE(bar_str));
	int rpad = ARRAY_SIZE(bar_str) - lpad;
	int len;

	len = fprintf(stream, "\r%3d%% [%.*s%*s]",
		      pcnt, lpad, bar_str, rpad, "");
	fflush(stream);

	return len;
}
