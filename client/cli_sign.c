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
 *
 * Author: David Disseldorp <ddiss@suse.de>
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

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/azure_conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"


int
cli_sign_conn_setup(struct azure_conn *aconn,
		    const char *blob_acc,
		    const char *sub_id)
{
	int ret;
	struct azure_op op;

	memset(&op, 0, sizeof(op));
	ret = azure_op_acc_keys_get(sub_id, blob_acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	printf("primary key: %s\n"
	       "secondary key: %s\n",
	       op.rsp.acc_keys_get.primary,
	       op.rsp.acc_keys_get.secondary);

	ret = azure_conn_sign_setkey(aconn, blob_acc,
				     op.rsp.acc_keys_get.primary);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}
