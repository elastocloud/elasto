/*
 * Copyright (C) SUSE LINUX GmbH 2012-2016, all rights reserved.
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
	free(sig_src);
	free(sig_str);
	op_hdrs_free(&op.req.hdrs);
	free(op.url_path);
	free(op.url_host);
}

/* don't bother... these creds aren't valid */
#define CM_SIGN_AZ_KEY_B64	"+1edLNEPv8S78ZwrovQVRLfv14wxu4M6qiINe2ef/b25W" \
				"MBUzgGh9xtqLmSGsEhb50rOctb/krw8b+8HVyQKDQ=="
#define CM_SIGN_AZ_ACC	"invalid"

static void
cm_sign_az_shared_key_head(void **state)
{
	int ret;
	struct op op;
	char *sig_src = NULL;
	char *sig_str = NULL;
	char *key[sizeof(CM_SIGN_AZ_KEY_B64)];
	int key_len;

	memset(&op, 0, sizeof(op));
	list_head_init(&op.req.hdrs);
	op.method = REQ_METHOD_HEAD;
	op.url_host = strdup("invalid.blob.core.windows.net");
	op.url_path = strdup("/test-put-get-md5/zeros");
	ret = op_req_hdr_add(&op, "x-ms-date", "Sun, 04 Sep 2016 20:55:01 GMT");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-version", "2015-12-11");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "Content-Length", "0");
	assert_int_equal(ret, 0);

	key_len = base64_decode(CM_SIGN_AZ_KEY_B64, key);
	assert_true(key_len > 0);

	ret = sign_gen_shared_azure(CM_SIGN_AZ_ACC,
				  (const uint8_t *)key,
				  key_len,
				  &op,
				  &sig_src,
				  &sig_str);
	assert_false(ret < 0);	/* returns strlen(sig_str) on success */

	assert_string_equal(sig_src,
			    "HEAD\n\n\n\n\n\n\n\n\n\n\n\n"
			    "x-ms-date:Sun, 04 Sep 2016 20:55:01 GMT\n"
			    "x-ms-version:2015-12-11\n"
			    "/invalid/test-put-get-md5/zeros");
	assert_string_equal(sig_str,
			    "ZyZvE8Xw9sQlWahD9ItcPAl5+69gRvDiY1+SYFpM7uI=");
	free(sig_src);
	free(sig_str);
	op_hdrs_free(&op.req.hdrs);
	free(op.url_path);
	free(op.url_host);
}

static void
cm_sign_az_shared_key_put(void **state)
{
	int ret;
	struct op op;
	char *sig_src = NULL;
	char *sig_str = NULL;
	char *key[sizeof(CM_SIGN_AZ_KEY_B64)];
	int key_len;

	memset(&op, 0, sizeof(op));
	list_head_init(&op.req.hdrs);
	op.method = REQ_METHOD_PUT;
	op.url_host = strdup("invalid.blob.core.windows.net");
	op.url_path = strdup("/test-put-get-md5/zeros");
	ret = op_req_hdr_add(&op, "x-ms-date", "Sun, 04 Sep 2016 20:55:01 GMT");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-version", "2015-12-11");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-blob-type", "PageBlob");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "x-ms-blob-content-length", "0");
	assert_int_equal(ret, 0);
	ret = op_req_hdr_add(&op, "Content-Length", "0");
	assert_int_equal(ret, 0);

	key_len = base64_decode(CM_SIGN_AZ_KEY_B64, key);
	assert_true(key_len > 0);

	ret = sign_gen_shared_azure(CM_SIGN_AZ_ACC,
				  (const uint8_t *)key,
				  key_len,
				  &op,
				  &sig_src,
				  &sig_str);
	assert_false(ret < 0);	/* returns strlen(sig_str) on success */

	assert_string_equal(sig_src,
			    "PUT\n\n\n\n\n\n\n\n\n\n\n\n"
			    "x-ms-blob-content-length:0\n"
			    "x-ms-blob-type:PageBlob\n"
			    "x-ms-date:Sun, 04 Sep 2016 20:55:01 GMT\n"
			    "x-ms-version:2015-12-11\n"
			    "/invalid/test-put-get-md5/zeros");
	assert_string_equal(sig_str,
			    "gcM/D9Bdk55e4ko5ZbFwQTHfbhKqLXabctbF53TOmBU=");
	free(sig_src);
	free(sig_str);
	op_hdrs_free(&op.req.hdrs);
	free(op.url_path);
	free(op.url_host);
}

static const UnitTest cm_sign_azure_tests[] = {
	unit_test(cm_sign_az_list),
	unit_test(cm_sign_az_shared_key_head),
	unit_test(cm_sign_az_shared_key_put),
};

int
cm_sign_azure_run(void)
{
	return run_tests(cm_sign_azure_tests);
}
