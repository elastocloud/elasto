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
#include <curl/curl.h>
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
#include "azure_req.h"
#include "dbg.h"
#include "sign.h"

/*
 * CMocka unit tests for Amazon S3 request signing, based on examples provided
 * at:
 * http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
 */
#define S3_KEY_ID	"AKIAIOSFODNN7EXAMPLE"
#define S3_SECRET	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

static void
cm_sign_s3_object_get(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_GET;
	op.url = "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 19:36:42 +0000");
	assert_non_null(op.http_hdr);

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);

	assert_string_equal(sig_src, "GET\n\n\n"
				     "Tue, 27 Mar 2007 19:36:42 +0000\n"
				     "/johnsmith/photos/puppy.jpg");
	assert_string_equal(sig_str, "bWq2s1WEIj+Ydj0vQ697zp+IXMU=");
}

static void
cm_sign_s3_object_put(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_PUT;
	op.url = "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Content-Type: image/jpeg");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Content-Length: 94328");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 21:15:45 +0000");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "MyyxeRY7whkBe+bq8fHCL/2kKUg=");
}

static void
cm_sign_s3_list(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_GET;
	op.url = "https://johnsmith.s3.amazonaws.com/?prefix=photos&max-keys=50&marker=puppy";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"User-Agent: Mozilla/5.0");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 19:42:41 +0000");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "htDYFYduRNen8P9ZfE/s9SuKy0U=");
}

int
main(void)
{
	int ret;
	const UnitTest cm_sign_s3_tests[] = {
		unit_test(cm_sign_s3_object_get),
		unit_test(cm_sign_s3_object_put),
		unit_test(cm_sign_s3_list),
	};

	dbg_level_set(10);
	sign_init();
	ret = run_tests(cm_sign_s3_tests);
	sign_deinit();
	return ret;
}
