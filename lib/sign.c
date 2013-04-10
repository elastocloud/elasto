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

#include "ccan/list/list.h"
#include "base64.h"
#include "azure_req.h"
#include "sign.h"

static int
hmac_sha(const EVP_MD *type, const uint8_t *key, int key_len,
	 const uint8_t *msg, int msg_len,
	 uint8_t **md, int *md_len)
{
	HMAC_CTX ctx;
	uint8_t *md_buf;
	unsigned int len = 32;

	md_buf = malloc(len);
	if (md_buf == NULL)
		return -ENOMEM;

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, key_len, type, NULL);
	HMAC_Update(&ctx, msg, msg_len);
	HMAC_Final(&ctx, md_buf, &len);
	HMAC_CTX_cleanup(&ctx);

	*md = md_buf;
	*md_len = len;
	return 0;
}

static void
hdr_tolower(char *hdr)
{
	char *colon;
	colon = strchr(hdr, ':');
	assert(colon != NULL);
	for (; hdr < colon; hdr++)
		*hdr = tolower(*hdr);
}

static void
hdr_trim_ws(char *hdr)
{
	char *colon;
	char *s;
	colon = strchr(hdr, ':');
	assert(colon != NULL);

	/* trim after the colon */
	for (s = colon + 1; *s == ' '; s++);
	if (s > colon + 1) {
		int len = strlen(s);
		memmove(colon + 1, s, len);
		*(colon + 1 + len) = '\0';
	}

	/* trim before the colon */
	for (s = colon - 1; *s == ' '; s--);
	assert(s >= hdr);
	memmove(s + 1, colon, strlen(colon) + 1);
}

static int
str_cmp_lexi(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, *(char * const *)p2);
}

/*
 * http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
 * http://msdn.microsoft.com/en-us/library/windowsazure/dd179428
 * To construct the CanonicalizedHeaders portion of the signature string,
 * follow these steps:
 *
 * Retrieve all headers for the resource that begin with @hdr_vendor_pfx -
 * 'x-ms-' for Azure, 'x-amz-' for S3.
 *
 * Convert each HTTP header name to lowercase.
 *
 * Sort the headers lexicographically by header name, in ascending order. Note
 * that each header may appear only once in the string.
 *
 * Unfold the string by replacing any breaking white space with a single space.
 *
 * Trim any white space around the colon in the header.
 *
 * Finally, append a new line character to each canonicalized header in the
 * resulting list. Construct the CanonicalizedHeaders string by concatenating
 * all headers in this list into a single string.
 */
static int
canon_hdrs_gen(struct curl_slist *http_hdr,
	       const char *hdr_vendor_pfx,
	       char **canon_hdrs_out,
	       char **content_type_out,
	       char **content_md5_out,
	       char **date_out)
{
	struct curl_slist *l;
	int count = 0;
	int i;
	int ret;
	char **hdr_array;
	char *hdr_str;
	char *ctype = NULL;
	char *md5 = NULL;
	char *date = NULL;
	char *s;
	int hdr_str_len = 0;

	for (l = http_hdr; l != NULL; l = l->next) {
		/*
		 * TODO add counter alongside op->http_hdr to avoid this
		 * also, a stack alloced array could be used.
		 */
		count++;
	}
	if (count == 0) {
		hdr_str = strdup("");
		if (hdr_str == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto out_empty;
	}

	hdr_array = malloc(count * sizeof(char *));
	if (hdr_array == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	i = 0;
	for (l = http_hdr; l != NULL; l = l->next) {
		if (strncasecmp(l->data, hdr_vendor_pfx,
				strlen(hdr_vendor_pfx)) == 0) {
			hdr_array[i] = strdup(l->data);
			if (hdr_array[i] == NULL) {
				count = i;
				ret = -ENOMEM;
				goto err_array_free;
			}
			hdr_tolower(hdr_array[i]);
			hdr_trim_ws(hdr_array[i]);
			hdr_str_len += (strlen(hdr_array[i])
					   + 1);	/* newline */
			i++;
		} else if (strncasecmp(l->data, "Content-Type",
				       sizeof("Content-Type") - 1) == 0) {
			for (s = strchr(l->data, ':');
			     s && ((*s == ' ' ) || (*s == ':'));
			     s++);
			assert(s != NULL);
			assert(ctype == NULL);
			ctype = strdup(s);
			if (ctype == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
		} else if (strncasecmp(l->data, "Content-MD5",
				       sizeof("Content-MD5") - 1) == 0) {
			for (s = strchr(l->data, ':');
			     s && ((*s == ' ' ) || (*s == ':'));
			     s++);
			assert(s != NULL);
			assert(md5 == NULL);
			md5 = strdup(s);
			if (md5 == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
		} else if (strncasecmp(l->data, "Date",
				       sizeof("Date") - 1) == 0) {
			for (s = strchr(l->data, ':');
			     s && ((*s == ' ' ) || (*s == ':'));
			     s++);
			assert(s != NULL);
			assert(date == NULL);
			date = strdup(s);
			if (date == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
		}
	}
	count = i;
	if (count == 0) {
		free(hdr_array);
		hdr_str = strdup("");
		if (hdr_str == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto out_empty;
	}

	qsort(hdr_array, count, sizeof(char *), str_cmp_lexi);

	/* TODO combine duplicate headers and "Unfold" long headers! */

	hdr_str = malloc(hdr_str_len + 1);
	if (hdr_str == NULL) {
		ret = -ENOMEM;
		goto err_array_free;
	}

	s = hdr_str;
	for (i = 0; i < count; i++) {
		int len = strlen(hdr_array[i]);
		memcpy(s, hdr_array[i], len);
		*(s + len) = '\n';
		s += (len + 1);
		free(hdr_array[i]);
	}
	*s = '\0';
	free(hdr_array);
out_empty:
	*canon_hdrs_out = hdr_str;
	if (content_type_out != NULL)
		*content_type_out = ctype;
	if (content_md5_out != NULL)
		*content_md5_out = md5;
	if (date_out != NULL)
		*date_out = date;

	return 0;

err_array_free:
	free(ctype);
	free(md5);
	free(date);
	for (i = 0; i < count; i++)
		free(hdr_array[i]);
	free(hdr_array);
err_out:
	return ret;
}

/*
 * This format supports Shared Key and Shared Key Lite for all versions of the
 * Table service, and Shared Key Lite for the 2009-09-19 version of the Blob
 * and Queue services. This format is identical to that used with previous
 * versions of the storage services. Construct the CanonicalizedResource string
 * in this format as follows:
 *
 * Beginning with an empty string (""), append a forward slash (/), followed by
 * the name of the account that owns the resource being accessed.
 *
 * Append the resource's encoded URI path. If the request URI addresses a
 * component of the resource, append the appropriate query string. The query
 * string should include the question mark and the comp parameter (for example,
 * ?comp=metadata). No other parameters should be included on the query string.
 * ----
 *
 * @url is modified in place to pull out the comp parameter. Could be optimized
 * greatly, but simple code is nicer.
 */
static char *
canon_rsc_gen_lite(const char *account,
		   const char *url)
{
	int ret;
	char *s;
	char *q;
	char *comp;
	char *rsc_str = NULL;

	/* find the first forward slash after the protocol */
	s = strstr(url, "://");
	assert(s != NULL);
	s += sizeof("://") - 1;
	s = strchrnul(s, '/');

	q = strchr(s, '?');
	if (q == NULL) {
		/* no parameters, nice and easy */
		ret = asprintf(&rsc_str, "/%s%s", account, s);
		if (ret < 0) {
			rsc_str = NULL;
		}
		return rsc_str;
	}

	*q = '\0';
	comp = strstr(q + 1, "comp=");
	if (comp) {
		char *amp = strchr(comp, '&');
		if (amp)
			*amp = '\0';
		ret = asprintf(&rsc_str, "/%s%s?%s", account, s, comp);
		if (amp)
			*amp = '&';
	} else {
		ret = asprintf(&rsc_str, "/%s%s", account, s);
	}
	*q = '?';
	if (ret < 0) {
		rsc_str = NULL;
	}

	return rsc_str;
}

/* generate base64 encoded signature string for @op */
#define HDR_PREFIX_AZ "x-ms-"
#define HDR_PREFIX_S3 "x-amz-"
int
sign_gen_lite_azure(const char *account,
		    const uint8_t *key,
		    int key_len,
		    struct azure_op *op,
		    char **sig_src,
		    char **sig_str)
{
	int ret;
	char *canon_hdrs;
	char *content_type = NULL;
	char *canon_rsc;
	char *str_to_sign = NULL;
	uint8_t *md;
	int md_len;
	char *md_b64;

	ret = canon_hdrs_gen(op->http_hdr, HDR_PREFIX_AZ, &canon_hdrs,
			     &content_type, NULL, NULL);
	if (ret < 0) {
		goto err_out;
	}

	canon_rsc = canon_rsc_gen_lite(account, op->url);
	if (canon_rsc == NULL) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}

	ret = asprintf(&str_to_sign,
		       "%s\n"	/* VERB */
		       "\n"	/* Content-MD5 (not supported) */
		       "%s\n"	/* Content-Type */
		       "\n"	/* Date (not supported) */
		       "%s"	/* CanonicalizedHeaders */
		       "%s",	/* CanonicalizedResource */
		       op->method,
		       content_type ? content_type : "",
		       canon_hdrs, canon_rsc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_rsc_free;
	}

	ret = hmac_sha(EVP_sha256(), key, key_len,
		       (uint8_t *)str_to_sign, strlen(str_to_sign),
		       &md, &md_len);
	if (ret < 0) {
		goto err_str_free;
	}

	ret = base64_encode(md, md_len, &md_b64);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_md_free;
	}
	*sig_str = md_b64;
	*sig_src = str_to_sign;
	str_to_sign = NULL;

err_md_free:
	free(md);
err_str_free:
	free(str_to_sign);
err_rsc_free:
	free(canon_rsc);
err_hdrs_free:
	free(canon_hdrs);
err_out:
	return ret;
}

void
sign_init(void)
{
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
}

void
sign_deinit(void)
{
	ENGINE_cleanup();
}
