/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
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
#include "azure_sign.h"

static int
hmac_sha256(const uint8_t *key, int key_len,
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
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), NULL);
	HMAC_Update(&ctx, msg, msg_len);
	HMAC_Final(&ctx, md_buf, &len);
	HMAC_CTX_cleanup(&ctx);

	*md = md_buf;
	*md_len = len;
	return 0;
}

static void
ms_hdr_tolower(char *ms_hdr)
{
	char *colon;
	colon = strchr(ms_hdr, ':');
	assert(colon != NULL);
	for (; ms_hdr < colon; ms_hdr++)
		*ms_hdr = tolower(*ms_hdr);
}

static void
ms_hdr_trim_ws(char *ms_hdr)
{
	char *colon;
	char *s;
	colon = strchr(ms_hdr, ':');
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
	assert(s >= ms_hdr);
	memmove(s + 1, colon, strlen(colon) + 1);
}

static int
str_cmp_lexi(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, *(char * const *)p2);
}

/*
 * http://msdn.microsoft.com/en-us/library/windowsazure/dd179428
 * To construct the CanonicalizedHeaders portion of the signature string,
 * follow these steps:
 *
 * Retrieve all headers for the resource that begin with x-ms-, including the
 * x-ms-date header.
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
static char *
canon_hdrs_gen(struct curl_slist *http_hdr)
{
	struct curl_slist *l;
	int count = 0;
	int i;
	char **ms_hdr_array;
	char *ms_hdr_str;
	char *s;
	int ms_hdr_str_len = 0;

	for (l = http_hdr; l != NULL; l = l->next) {
		/*
		 * TODO add counter alongside req->http_hdr to avoid this
		 * also, a stack alloced array could be used.
		 */
		count++;
	}
	if (count == 0)
		return strdup("");

	ms_hdr_array = malloc(count * sizeof(char *));
	if (ms_hdr_array == NULL) {
		goto err_out;
	}

	i = 0;
	for (l = http_hdr; l != NULL; l = l->next) {
		if (strncasecmp(l->data, "x-ms-", sizeof("x-ms-") - 1) == 0) {
			ms_hdr_array[i] = strdup(l->data);
			if (ms_hdr_array[i] == NULL) {
				count = i;
				goto err_array_free;
			}
			ms_hdr_tolower(ms_hdr_array[i]);
			ms_hdr_trim_ws(ms_hdr_array[i]);
			ms_hdr_str_len += (strlen(ms_hdr_array[i])
					   + 1);	/* newline */
			i++;
		}
	}
	count = i;
	if (count == 0) {
		free(ms_hdr_array);
		return strdup("");
	}

	qsort(ms_hdr_array, count, sizeof(char *), str_cmp_lexi);

	ms_hdr_str = malloc(ms_hdr_str_len + 1);
	if (ms_hdr_str == NULL) {
		goto err_array_free;
	}

	s = ms_hdr_str;
	for (i = 0; i < count; i++) {
		int len = strlen(ms_hdr_array[i]);
		memcpy(s, ms_hdr_array[i], len);
		*(s + len) = '\n';
		s += (len + 1);
	}
	*s = '\0';

	return ms_hdr_str;

err_array_free:
	for (i = 0; i < count; i++)
		free(ms_hdr_array[i]);
	free(ms_hdr_array);
err_out:
	return NULL;
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
 */
static char *
canon_rsc_gen_lite(const char *account,
		   const char *url)
{
	int ret;
	char *s;
	char *q;
	char *trim_pos = NULL;
	char saved;
	char *rsc_str = NULL;

	/* find the first forward slash after the protocol */
	s = strstr(url, "://");
	assert(s != NULL);
	s += sizeof("://") - 1;
	s = strchrnul(s, '/');

	q = strstr(url, "?comp=");
	if (q) {
		trim_pos = strchr(q, '&');
		if (trim_pos) {
			*trim_pos = '\0';
			saved = '&';
		}
	} else {
		/* no comp param, but may have others */
		trim_pos = strchr(url, '?');
		if (trim_pos) {
			*trim_pos = '\0';
			saved = '?';
		}
	}

	ret = asprintf(&rsc_str, "/%s%s", account, s);
	if (ret < 0) {
		rsc_str = NULL;
	}
	if (trim_pos)
		*trim_pos = saved;

	return rsc_str;
}

/* generate base64 encoded signature string for @req */
int
azure_sign_gen_lite(const char *account,
		    const uint8_t *key,
		    int key_len,
		    struct azure_req *req,
		    char **sig_src,
		    char **sig_str)
{
	int ret;
	char *canon_hdrs;
	char *canon_rsc;
	char *str_to_sign = NULL;
	uint8_t *md;
	int md_len;
	char *md_b64;

	canon_hdrs = canon_hdrs_gen(req->http_hdr);
	if (canon_hdrs == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	canon_rsc = canon_rsc_gen_lite(account, req->url);
	if (canon_rsc == NULL) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}

	ret = asprintf(&str_to_sign,
		       "%s\n"	/* VERB */
		       "\n"	/* Content-MD5 (not supported) */
		       "\n"	/* Content-Type (not supported) */
		       "\n"	/* Date (not supported) */
		       "%s"	/* CanonicalizedHeaders */
		       "%s",	/* CanonicalizedResource */
		       req->method, canon_hdrs, canon_rsc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_rsc_free;
	}

	ret = hmac_sha256(key, key_len,
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
azure_sign_init(void)
{
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
}

void
azure_sign_deinit(void)
{
	ENGINE_cleanup();
}
