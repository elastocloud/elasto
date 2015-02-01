/*
 * Copyright (C) SUSE LINUX GmbH 2014-2015, all rights reserved.
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
#include <inttypes.h>
#include <sys/stat.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "file_api.h"
#include "handle.h"
#include "xmit.h"

int
elasto_fstat(struct elasto_fh *fh,
	     struct elasto_fstat *fstat)
{
	int ret;

	ret = elasto_fh_validate(fh);
	if (ret < 0) {
		goto err_out;
	}

	if (fstat == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = fh->ops.stat(fh->mod_priv, fh->conn, fstat);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}
