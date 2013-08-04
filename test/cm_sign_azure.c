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
#define _GNU_SOURCE
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ccan/list/list.h"
#include "base64.h"
#include "op.h"
#include "azure_req.h"
#include "dbg.h"
#include "sign.h"

/*
 * CMocka unit tests for Azure request signing
 */
#define AZ_KEY	"ElastoUnitTests"
#define AZ_ACC	"ddiss"

static void
cm_sign_az_list(void **state)
{
	int ret;
	struct op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	list_head_init(&op.req.hdrs);
	op.method = REQ_METHOD_GET;
	op.url_host = strdup("ddiss.blob.core.windows.net");
	op.url_path = strdup("/test?restype=container&comp=list");
	ret = op_req_hdr_add(&op, "Accept", "*/*");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-date",
				   "Thu, 11 Apr 2013 11:28:15 GMT");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-version", "2009-09-19");
	assert_int_equal(ret, 0);

	ret = sign_gen_lite_azure(AZ_ACC,
				  (const uint8_t *)AZ_KEY,
				  (sizeof(AZ_KEY) - 1),
				  &op,
				  &sig_src,
				  &sig_str);
	assert_false(ret < 0);	/* returns strlen(sig_str) on success */

	assert_string_equal(sig_src, "GET\n\n\n\n"
			    "x-ms-date:Thu, 11 Apr 2013 11:28:15 GMT\n"
			    "x-ms-version:2009-09-19\n"
			    "/ddiss/test?comp=list");
	assert_string_equal(sig_str,
			    "UZqdIQCl+6/E/Ptp+q49bsKTtrXft2fHjvu9Qf+Ys+0=");
}

static const UnitTest cm_sign_azure_tests[] = {
	unit_test(cm_sign_az_list),
};
