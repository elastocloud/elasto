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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a,b) ((a)<(b)?(a):(b))

#define BYTES_IN_KB (uint64_t)1024
#define BYTES_IN_MB (uint64_t)(BYTES_IN_KB * 1024)
#define BYTES_IN_GB (uint64_t)(BYTES_IN_MB * 1024)
#define BYTES_IN_TB (uint64_t)(BYTES_IN_GB * 1024)

int
slurp_file(const char *path,
	   char **_buf,
	   uint64_t *_len);
