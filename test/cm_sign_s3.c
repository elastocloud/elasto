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

static void
cm_sign_s3_fetch(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_GET;
	op.url = "https://johnsmith.s3.amazonaws.com/?acl";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 19:44:46 +0000");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "c2WLPFtWHVgbEmeEG93a4cG37dM=");
}

static void
cm_sign_s3_object_del(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_DELETE;
	op.url = "https://s3.amazonaws.com/johnsmith/photos/puppy.jpg";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"User-Agent: dotnet");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 21:20:27 +0000");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"x-amz-date: Tue, 27 Mar 2007 21:20:26 +0000");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "lx3byBScXR6KzyMaifNkardMwNk=");
}

static void
cm_sign_s3_object_upload(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_PUT;
	op.url = "http://static.johnsmith.net:8080/db-backup.dat.gz";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"User-Agent: curl/7.15.5");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Tue, 27 Mar 2007 21:06:08 +0000");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"x-amz-acl: public-read");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"content-type: application/x-download");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"X-Amz-Meta-ReviewedBy: joe@johnsmith.net");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"X-Amz-Meta-ReviewedBy: jane@johnsmith.net");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"X-Amz-Meta-FileChecksum: 0x02661779");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"X-Amz-Meta-ChecksumAlgorithm: crc32");
	op.http_hdr = curl_slist_append(op.http_hdr,
		"Content-Disposition: attachment; filename=database.dat");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Content-Encoding: gzip");
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Content-Length: 5913339");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "ilyl83RwaSoYIEdixDQcA4OnAnc=");
}

static void
cm_sign_s3_bucket_list_all(void **state)
{
	int ret;
	struct azure_op op;
	char *sig_src = NULL;
	char *sig_str = NULL;

	memset(&op, 0, sizeof(op));
	op.method = REQ_METHOD_GET;
	op.url = "https://s3.amazonaws.com/";
	op.http_hdr = curl_slist_append(op.http_hdr,
				"Date: Wed, 28 Mar 2007 01:29:59 +0000");

	ret = sign_gen_s3((const uint8_t *)S3_SECRET,
			  sizeof(S3_SECRET) - 1,
			  &op,
			  &sig_src,
			  &sig_str);
	assert_int_equal(ret, 0);
	assert_string_equal(sig_str, "qGdzdERIC03wnaRNKh6OqZehG9s=");
}

int
main(void)
{
	int ret;
	const UnitTest cm_sign_s3_tests[] = {
		unit_test(cm_sign_s3_object_get),
		unit_test(cm_sign_s3_object_put),
		unit_test(cm_sign_s3_list),
		unit_test(cm_sign_s3_fetch),
		unit_test(cm_sign_s3_object_del),
		unit_test(cm_sign_s3_object_upload),
		unit_test(cm_sign_s3_bucket_list_all),
	};

	dbg_level_set(10);
	sign_init();
	ret = run_tests(cm_sign_s3_tests);
	sign_deinit();
	return ret;
}
