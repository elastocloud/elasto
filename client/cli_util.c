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
#include <sys/stat.h>

#include <curl/curl.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/data_api.h"
#include "lib/op.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "cli_common.h"
#include "cli_sign.h"
#include "cli_util.h"

#define CLI_OP_POLL_PERIOD 2
#define CLI_OP_POLL_TIMEOUT 10	/* multiplied by CLI_OP_POLL_PERIOD */
int
cli_op_wait(struct elasto_conn *econn,
	    const char *sub_id,
	    const char *req_id,
	    enum az_req_status *status,
	    int *err_code)
{
	struct op *op;
	struct az_mgmt_rsp_status_get *sts_get_rsp;
	int ret;
	int i;

	for (i = 0; i < CLI_OP_POLL_TIMEOUT; i++) {
		ret = az_mgmt_req_status_get(sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_conn_op_txrx(econn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.is_error) {
			ret = -EIO;
			printf("failed get status response: %d\n",
			       op->rsp.err_code);
			goto err_op_free;
		}

		sts_get_rsp = az_mgmt_rsp_status_get(op);
		if (sts_get_rsp == NULL) {
			ret = -ENOMEM;
			goto err_op_free;
		}

		if (sts_get_rsp->status != AOP_STATUS_IN_PROGRESS) {
			*status = sts_get_rsp->status;
			if (sts_get_rsp->status == AOP_STATUS_FAILED) {
				*err_code = sts_get_rsp->err.code;
			}
			op_free(op);
			break;
		}

		op_free(op);

		sleep(CLI_OP_POLL_PERIOD);
	}

	if (i >= CLI_OP_POLL_TIMEOUT) {
		printf("timeout waiting for req %s to complete\n", req_id);
		ret = -ETIMEDOUT;
		goto err_out;
	}

	return 0;

err_op_free:
	op_free(op);
err_out:
	return ret;
}
