/*
 * Copyright (C) SUSE LINUX GmbH 2013-2017, all rights reserved.
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
#include "xmit.h"

int
elasto_fop_err_code_map(uint32_t err_code)
{
	int ret;

	ret = -EIO;
	switch (err_code) {
	case 403:
		ret = -EPERM;
		break;
	case 404:
		ret = -ENOENT;
		break;
	default:
		break;
	}

	dbg(1, "response error %u, mapped to errno %d\n", err_code, ret);

	return ret;
}

int
elasto_fop_send_recv(struct elasto_conn *conn,
		     struct op *op)
{
	int ret;

	if (conn == NULL) {
		dbg(0, "attempt to send request with NULL conn\n");
		return -EINVAL;
	}

	ret = elasto_conn_op_txrx(conn, op);
	if (ret < 0) {
		return ret;
	}

	if (op->rsp.is_error) {
		return elasto_fop_err_code_map(op->rsp.err_code);
	}

	return 0;
}
