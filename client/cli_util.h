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
#ifndef _CLI_UTIL_H_
#define _CLI_UTIL_H_

void
cli_human_size(double bytes,
	       char *buf,
	       size_t buflen);

#define CLI_PROGRESS_MAX_LEN 66
int
cli_progress_print(FILE *stream,
		   double pcnt_fract);

#endif /* ifdef _CLI_UTIL_H_ */
