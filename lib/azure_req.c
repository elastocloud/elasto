/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "exml.h"
#include "data.h"
#include "op.h"
#include "sign.h"
#include "azure_req.h"

int
az_req_sign(const char *acc,
	    const uint8_t *key,
	    int key_len,
	    struct op *op)
{
	int ret;
	char *sig_str;
	char *hdr_str;

	if (key == NULL) {
		dbg(0, "key missing in sign callback\n");
		return -EINVAL;
	}

	ret = sign_gen_lite_azure(acc, key, key_len,
				  op, &op->sig_src, &sig_str);
	if (ret < 0) {
		dbg(0, "Azure signing failed: %s\n",
		    strerror(-ret));
		return ret;
	}
	ret = asprintf(&hdr_str, "SharedKeyLite %s:%s",
		       acc, sig_str);
	free(sig_str);
	if (ret < 0) {
		return -ENOMEM;
	}

	ret = op_req_hdr_add(op, "Authorization", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static char *
gen_date_str(void)
{
	char buf[200];
	time_t now;
	struct tm utc_tm;
	size_t ret;

	time(&now);
	gmtime_r(&now, &utc_tm);
	/* Sun, 11 Oct 2009 21:49:13 GMT */
	ret = strftime(buf, sizeof(buf), "%a, %d %b %Y %T GMT", &utc_tm);
	if (ret == 0)
		return NULL;
	return strdup(buf);
}

#define AZ_API_VERS_MGMT "2012-03-01"
#define AZ_API_VERS_BLOB "2015-02-21"

int
az_req_common_hdr_fill(struct op *op,
		       bool mgmt)
{
	int ret;
	char *date_str;

	if (mgmt) {
		ret = op_req_hdr_add(op, "x-ms-version", AZ_API_VERS_MGMT);
		if (ret < 0) {
			goto err_out;
		}
		return 0;
	}

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = op_req_hdr_add(op, "x-ms-date", date_str);
	free(date_str);
	if (ret < 0) {
		goto err_out;
	}
	/* different to the version in management */
	ret = op_req_hdr_add(op, "x-ms-version", AZ_API_VERS_BLOB);
	if (ret < 0) {
		goto err_hdrs_free;
	}
	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

static const struct {
	const char *status_str;
	enum az_cp_status status;
} az_rsp_cp_status[] = {
	{"pending", AOP_CP_STATUS_PENDING},
	{"success", AOP_CP_STATUS_SUCCESS},
	{"aborted", AOP_CP_STATUS_ABORTED},
	{"failed", AOP_CP_STATUS_FAILED},
};

int
az_rsp_cp_status_map(const char *status_str,
		     enum az_cp_status *_status)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(az_rsp_cp_status); i++) {
		if (!strcmp(status_str, az_rsp_cp_status[i].status_str)) {
			*_status = az_rsp_cp_status[i].status;
			return 0;
		}
	}
	dbg(1, "invalid copy status string: %s\n", status_str);
	return -EINVAL;
}
