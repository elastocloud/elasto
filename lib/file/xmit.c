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

#include <curl/curl.h>
#include <apr-1/apr_general.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "xmit.h"

int
elasto_fop_send_recv(struct elasto_conn *conn,
		     struct azure_op *op)
{
	int ret;

	ret = elasto_conn_send_op(conn, op);
	if (ret < 0) {
		return ret;
	}

	ret = azure_rsp_process(op);
	if (ret < 0) {
		return ret;
	}

	if (op->rsp.is_error) {
		dbg(0, "failed response: %d\n", op->rsp.err_code);
		return -EIO;
	}

	return 0;
}
