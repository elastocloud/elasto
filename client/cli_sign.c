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
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/xml.h"
#include "lib/data_api.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"


int
cli_sign_conn_setup(struct elasto_conn *econn,
		    const char *blob_acc,
		    const char *sub_id)
{
	int ret;
	struct op *op;
	struct az_rsp_acc_keys_get *acc_keys_get_rsp;

	ret = az_req_acc_keys_get(sub_id, blob_acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_op_txrx(econn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op->rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op->rsp.err_code);
		goto err_op_free;
	}

	acc_keys_get_rsp = az_rsp_acc_keys_get(op);
	if (acc_keys_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	ret = elasto_conn_sign_setkey(econn, blob_acc,
				      acc_keys_get_rsp->primary);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}
