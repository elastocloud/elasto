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
#include <sys/types.h>
#include <pwd.h>
#include <linux/limits.h>

#include "ccan/list/list.h"
#include "lib/file/file_api.h"
#include "cli_common.h"
#include "cli_open.h"

int
cli_open_efh(const struct cli_args *cli_args,
	     const char *elasto_path,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks,
	     struct elasto_fh **_fh)
{
	if (cli_args->host == NULL) {
		/* no explicit host provided, use cloud-provider default */
		return elasto_fopen(&cli_args->auth, elasto_path, flags,
				    open_toks, _fh);
	}

	return elasto_fopen_host(&cli_args->auth, cli_args->host,
				 cli_args->port, elasto_path, flags, open_toks,
				 _fh);
}
