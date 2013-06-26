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
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
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
	    enum azure_op_status *status,
	    int *err_code)
{
	struct azure_op op;
	int ret;
	int i;

	for (i = 0; i < CLI_OP_POLL_TIMEOUT; i++) {
		ret = azure_op_status_get(sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_conn_send_op(econn, &op);
		if (ret < 0) {
			goto err_op_free;
		}

		ret = azure_rsp_process(&op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op.rsp.is_error) {
			ret = -EIO;
			printf("failed get status response: %d\n",
			       op.rsp.err_code);
			goto err_op_free;
		}

		if (op.rsp.sts_get.status != AOP_STATUS_IN_PROGRESS) {
			*status = op.rsp.sts_get.status;
			if (op.rsp.sts_get.status == AOP_STATUS_FAILED) {
				*err_code = op.rsp.sts_get.err.code;
			}
			azure_op_free(&op);
			break;
		}

		azure_op_free(&op);

		sleep(CLI_OP_POLL_PERIOD);
	}

	if (i >= CLI_OP_POLL_TIMEOUT) {
		printf("timeout waiting for req %s to complete\n", req_id);
		ret = -ETIMEDOUT;
		goto err_out;
	}

	return 0;

err_op_free:
	azure_op_free(&op);
err_out:
	return ret;
}
