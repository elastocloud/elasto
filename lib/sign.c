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

#include "ccan/list/list.h"
#include "base64.h"
#include "op.h"
#include "dbg.h"
#include "util.h"
#include "sign.h"

static int
hmac_sha(const EVP_MD *type, const uint8_t *key, int key_len,
	 const uint8_t *msg, int msg_len,
	 uint8_t **md, int *md_len)
{
	HMAC_CTX ctx;
	uint8_t *md_buf;
	unsigned int len;

	if (type == EVP_sha1()) {
		len = 20;
	} else {
		/* assume sha256 */
		len = 32;
	}

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

/*
 * Both Azure and S3 allow for "x-ms-date:" and "x-amz-date:" headers
 * respectively, as opposed to the standard HTTP Date header.
 */
static bool
key_is_vendor_date(const char *key,
		   const char *key_vendor_pfx)
{
	const char *key_sfx = key + strlen(key_vendor_pfx);
	return (strcasecmp(key_sfx, "date") == 0);
}

static int
str_cmp_lexi(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static int
hdr_key_lexi_cmp(const void *p1, const void *p2)
{
	const char *str1 = *(char * const *)p1;
	const char *str2 = *(char * const *)p2;
	size_t str1_key_len = strchr(str1, ':') - str1;
	size_t str2_key_len = strchr(str2, ':') - str2;
	return strncmp(str1, str2, MIN(str1_key_len, str2_key_len));
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
canon_hdrs_gen(uint32_t num_hdrs,
	       struct list_head *hdrs,
	       const char *hdr_vendor_pfx,
	       bool vendor_date_trumps,
	       char **canon_hdrs_out,
	       char **content_type_out,
	       char **content_md5_out,
	       char **date_out)
{
	struct op_hdr *hdr;
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

	if (num_hdrs == 0) {
		hdr_str = strdup("");
		if (hdr_str == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto out_empty;
	}

	hdr_array = malloc(num_hdrs * sizeof(char *));
	if (hdr_array == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	i = 0;
	count = 0;
	list_for_each(hdrs, hdr, list) {
		if (strncasecmp(hdr->key, hdr_vendor_pfx,
				strlen(hdr_vendor_pfx)) == 0) {
			bool is_vd;
			ret = asprintf(&hdr_array[i], "%s:%s",
				       hdr->key, hdr->val);
			if (ret < 0) {
				ret = -ENOMEM;
				goto err_array_free;
			}
			hdr_tolower(hdr_array[i]);
			is_vd = key_is_vendor_date(hdr->key, hdr_vendor_pfx);
			if (is_vd && vendor_date_trumps) {
				if (date != NULL) {
					dbg(3, "Date already set by standard "
					    "header!\n");
					free(date);
				}
				date = strdup(hdr->val);
				if (date == NULL) {
					ret = -ENOMEM;
					goto err_array_free;
				}
				dbg(6, "vendor date hdr trumps HTTP date\n");
				free(hdr_array[i]);
				continue;
			}
			hdr_str_len += (strlen(hdr_array[i])
					   + 1);	/* newline */
			dbg(6, "got vendor hdr: %s\n", hdr_array[i]);
			i++;
			count = i;
		} else if (strcasecmp(hdr->key, "Content-Type") == 0) {
			assert(ctype == NULL);
			ctype = strdup(hdr->val);
			if (ctype == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
			dbg(6, "got Content-Type hdr: %s\n", ctype);
		} else if (strcasecmp(hdr->key, "Content-MD5") == 0) {
			assert(md5 == NULL);
			md5 = strdup(hdr->val);
			if (md5 == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
			dbg(6, "got Content-MD5 hdr: %s\n", md5);
		} else if (strcasecmp(hdr->key, "Date") == 0) {
			if (date != NULL) {
				dbg(3, "Date already set by vendor header!\n");
				continue;
			}
			date = strdup(hdr->val);
			if (date == NULL) {
				ret = -ENOMEM;
				goto err_array_free;
			}
			dbg(6, "got Date hdr: %s\n", date);
		}
	}
	if (count == 0) {
		free(hdr_array);
		hdr_str = strdup("");
		if (hdr_str == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto out_empty;
	}

	qsort(hdr_array, count, sizeof(char *), hdr_key_lexi_cmp);

	/* TODO "Unfold" long headers! */

	hdr_str = malloc(hdr_str_len + 1);
	if (hdr_str == NULL) {
		ret = -ENOMEM;
		goto err_array_free;
	}

	s = hdr_str;
	for (i = 0; i < count; i++) {
		int len;
		int dup_val_off = 0;;
		if ((i > 0)
		 && (hdr_key_lexi_cmp(&hdr_array[i - 1], &hdr_array[i]) == 0)) {
			dbg(4, "collapsing duplicate header \"%s\"\n",
			    hdr_array[i]);
			/* duplicate headers, append value */
			*(s - 1) = ',';	/* overwrite newline */
			dup_val_off = (strchr(hdr_array[i], ':') + 1
							- hdr_array[i]);
		}

		len = strlen(hdr_array[i] + dup_val_off);
		memcpy(s, hdr_array[i] + dup_val_off, len);
		free(hdr_array[i]);
		hdr_array[i] = s;	/* needed for cmp */
		*(s + len) = '\n';
		s += (len + 1);
		*s = '\0';	/* needed for cmp */
	}
	free(hdr_array);
out_empty:
	*canon_hdrs_out = hdr_str;
	if (content_type_out != NULL) {
		*content_type_out = ctype;
	} else {
		free(ctype);
	}
	if (content_md5_out != NULL) {
		*content_md5_out = md5;
	} else {
		free(md5);
	}
	if (date_out != NULL) {
		*date_out = date;
	} else {
		free(date);
	}

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
 * @url_path is modified in place to pull out the comp parameter. Could be
 * optimized greatly, but simple code is nicer.
 */
static char *
canon_rsc_gen_lite(const char *account,
		   const char *url_path)
{
	int ret;
	char *s;
	char *q;
	char *comp;
	char *rsc_str = NULL;

	/* find the first forward slash after the protocol */
	s = strchrnul(url_path, '/');

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
		    struct op *op,
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
	const char *method_str;

	method_str = op_method_str(op->method);
	if (method_str == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = canon_hdrs_gen(op->req.num_hdrs, &op->req.hdrs,
			     HDR_PREFIX_AZ, false,
			     &canon_hdrs, &content_type, NULL, NULL);
	if (ret < 0) {
		goto err_out;
	}

	canon_rsc = canon_rsc_gen_lite(account, op->url_path);
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
		       method_str,
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

/*
 * @slash_after_hostname points to the first forward slash after the hostname
 */
static char *
canon_rsc_path_get(const char *slash_after_hostname)
{
	char *q;
	char *path_part;

	/* up-to but not including the query string. */
	q = strchr(slash_after_hostname, '?');
	if (q == NULL) {
		path_part = strdup(slash_after_hostname);
	} else {
		path_part = strndup(slash_after_hostname,
				    (q - slash_after_hostname));
	}
	return path_part;
}

/*
 * @url_host points to the hostname after the protocol prefix
 */
static char *
canon_rsc_bucket_get(const char *bkt_name,
		     const char *url_host)
{
	int buf_len;
	char *buf;
	char *d;

	if (bkt_name == NULL) {
		/* assume base URL only */
		return strdup("");
	}

	/* add 2 for '/' prefix and zero-term */
	buf_len = strlen(url_host) + 2;
	buf = malloc(buf_len);
	if (buf == NULL) {
		return NULL;
	}
	buf[0] = '/';

	/* find the first dot, up to which may be the bucket name */
	d = strchr(url_host, '.');
	if ((d != NULL)
	 && (strncmp(url_host, bkt_name, d - url_host) == 0)) {
		dbg(6, "bucket prefix in S3 host path\n");
		/*
		 * There is a bucket name before the aws hostname, ensure the
		 * required '/' prefix is included in the bucket string.
		 */
		assert(1 + d - url_host < buf_len);
		strncpy(buf + 1, url_host, d - url_host);
		buf[1 + d - url_host] = '\0';
		return buf;
	} else {
		const char *sep = NULL;
		dbg(2, "non S3 host, assuming CNAME bucket alias\n");
		/* copy up to port, path or query sep */
		sep = strchr(url_host + 1, ':');
		if (sep == NULL) {
			strcpy(buf + 1, url_host);
			return buf;
		} else {
			assert(1 + sep - url_host < buf_len);
			strncpy(buf + 1, url_host, sep - url_host);
			buf[1 + sep - url_host] = '\0';
			return buf;
		}
	}
	dbg(0, "rsc bucket unhandled!\n");
	return NULL;
}

/*
 * The list of sub-resources that must be included when constructing the
 * CanonicalizedResource Element are:
 */
static char *s3_sub_resources[] = {"acl", "lifecycle",
				   "location", "logging",
				   "notification",
				   "partNumber", "policy",
				   "requestPayment", "torrent",
				   "uploadId", "uploads",
				   "versionId", "versioning",
				   "versions", "website"};
#define CANON_RSC_SUB_MAX ARRAY_SIZE(s3_sub_resources)
/*
 * @sub_rsc may include trailing resources (after '&'), or values (after '=').
 * @sub_rsc_single_out: single resource string returned on success
 * @value_out: value for resource string, including '=' prefix
 *
 * @return: -ENOMEM on alloc failure
 *	    -ENOENT if sub-resource should not be considered for the signature
 *	    0 if sub-resource is valid for the signature calculation, fill _outs
 */
static int
canon_rsc_sub_included(const char *sub_rsc,
		       char **sub_rsc_single_out,
		       char **value_out)
{
	int i;
	char *eq = strchr(sub_rsc, '=');
	char *amp = strchr(sub_rsc, '&');
	char *sep = NULL;
	char *sub_rsc_single;
	char *value_str = NULL;

	if (amp == NULL) {
		/* no element afterwards, '=' is separator if present */
		sep = eq;
	} else {
		/* element afterwards, '=' is separator only if before '&' */
		if ((eq != NULL) && (eq < amp)) {
			sep = eq;
		} else {
			sep = amp;
		}
	}

	if (sep == NULL) {
		sub_rsc_single = strdup(sub_rsc);
	} else {
		if (sep == eq) {
			/* save value for later */
			if (amp == NULL) {
				value_str = strdup(eq);
			} else {
				value_str = strndup(eq, amp - eq);
			}
			if (value_str == NULL) {
				return -ENOMEM;
			}
		}
		sub_rsc_single = strndup(sub_rsc, sep - sub_rsc);
	}
	if (sub_rsc_single == NULL) {
		free(value_str);
		return -ENOMEM;
	}

	for (i = 0; i < CANON_RSC_SUB_MAX; i++) {
		if (strcmp(sub_rsc_single, s3_sub_resources[i]) == 0) {
			dbg(4, "sub rsc \"%s\" valid for signature\n", sub_rsc_single);
			*sub_rsc_single_out = sub_rsc_single;
			*value_out = value_str;
			return 0;
		}
	}
	dbg(4, "sub rsc \"%s\" ignored for signature\n", sub_rsc_single);
	free(sub_rsc_single);
	free(value_str);
	return -ENOENT;
}

/*
 * @question_after_path points to the question mark after the hostname and path
 */
static char *
canon_rsc_sub_get(const char *question_after_path)
{
	const char *a;
	char *s;
	int i;
	int j;
	int total_bytes;
	char *sub_rsc[CANON_RSC_SUB_MAX];
	char *sub_rsc_sorted;
	int ret;

	total_bytes = 0;
	i = 0;
	a = question_after_path;
	while (*(++a) != '\0') {
		char *sub_rsc_key = NULL;
		char *sub_rsc_value = NULL;

		ret = canon_rsc_sub_included(a, &sub_rsc_key, &sub_rsc_value);
		if (ret == -ENOMEM) {
			goto err_cleanup;
		} else if (ret == 0) {
			ret = asprintf(&sub_rsc[i], "%s%s", sub_rsc_key,
				       (sub_rsc_value ? sub_rsc_value : ""));
			free(sub_rsc_key);
			free(sub_rsc_value);
			if (ret < 0) {
				goto err_cleanup;
			}
			total_bytes += ret;
			i++;
		}
		a = strchr(a, '&');
		if (a == NULL)
			break;
	}

	if (i == 0) {
		return strdup("");
	}

	/* +i for '&' separators, +2 for '?' prefix and nullterm */
	sub_rsc_sorted = malloc(total_bytes + i + 2);
	if (sub_rsc_sorted == NULL) {
		goto err_cleanup;
	}

	/* sub-resources must be lexicographically sorted by name... */
	qsort(sub_rsc, i, sizeof(char *), str_cmp_lexi);
	s = sub_rsc_sorted;
	for (j = 0; j < i; j++) {
		size_t len = strlen(sub_rsc[j]);
		if (j == 0) {
			*s = '?';
			s++;
		} else {
			/* ...and separated by '&'. e.g. ?acl&versionId=value */
			*s = '&';
			s++;
		}
		strncpy(s, sub_rsc[j], len);
		free(sub_rsc[j]);
		s += len;
	}
	*s = '\0';

	return sub_rsc_sorted;

err_cleanup:
	for (j = 0; j < i; j++) {
		free(sub_rsc[j]);
	}
	return NULL;
}

static char *
canon_rsc_gen_s3(const char *bkt_name,
		 const char *url_host,
		 const char *url_path)
{
	int ret;
	char *s;
	char *bucket = NULL;
	char *path_part = NULL;
	char *sub_rsc_part = NULL;
	char *rsc_str = NULL;

	bucket = canon_rsc_bucket_get(bkt_name, url_host);
	if (bucket == NULL) {
		dbg(0, "error generating resource bucket string");
		goto err_out;
	}

	dbg(4, "got resource bucket: \"%s\"\n", bucket);

	/* find the first forward slash after the protocol */
	s = strchrnul(url_path, '/');
	if (s != NULL) {
		path_part = canon_rsc_path_get(s);
		if (path_part == NULL) {
			dbg(0, "error generating resource path string\n");
			goto err_bucket_free;
		}
		dbg(4, "got resource path: \"%s\"\n", path_part);
	}

	/* find the sub-resource */
	s = strchr(url_path, '?');
	if (s != NULL) {
		sub_rsc_part = canon_rsc_sub_get(s);
		if (sub_rsc_part == NULL) {
			dbg(0, "error generating sub resource path string\n");
			goto err_path_free;
		}
		dbg(4, "got sub-resource string: \"%s\"\n", sub_rsc_part);
	}

	/* TODO handle query string parameters! */

	ret = asprintf(&rsc_str, "%s%s%s", bucket,
		       (path_part ? path_part : "/"),
		       (sub_rsc_part ? sub_rsc_part : ""));
	if (ret < 0) {
		rsc_str = NULL;
		goto err_sub_rsc_free;
	}
	dbg(3, "final signing resource string: \"%s\"\n", rsc_str);

err_sub_rsc_free:
	free(sub_rsc_part);
err_path_free:
	free(path_part);
err_bucket_free:
	free(bucket);
err_out:
	return rsc_str;
}

int
sign_gen_s3(const char *bkt_name,
	    const uint8_t *secret,
	    int secret_len,
	    struct op *op,
	    char **sig_src,
	    char **sig_str)
{
	int ret;
	char *canon_hdrs = NULL;
	char *content_type = NULL;
	char *content_md5 = NULL;
	char *date = NULL;
	char *canon_rsc;
	char *str_to_sign = NULL;
	size_t str_to_sign_len;
	uint8_t *md;
	int md_len;
	char *md_b64;
	const char *method_str;

	method_str = op_method_str(op->method);
	if (method_str == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	canon_rsc = canon_rsc_gen_s3(bkt_name, op->url_host, op->url_path);
	if (canon_rsc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = canon_hdrs_gen(op->req.num_hdrs, &op->req.hdrs,
			     HDR_PREFIX_S3, true,
			     &canon_hdrs, &content_type, &content_md5, &date);
	if (ret < 0) {
		dbg(0, "failed to generate canon hdrs: %s\n",
		    strerror(-ret));
		goto err_rsc_free;
	}

	ret = asprintf(&str_to_sign,
		       "%s\n"	/* VERB */
		       "%s\n"	/* Content-MD5 */
		       "%s\n"	/* Content-Type */
		       "%s\n"	/* Date */
		       "%s"	/* CanonicalizedHeaders */
		       "%s",	/* CanonicalizedResource */
		       method_str,
		       content_md5 ? content_md5 : "",
		       content_type ? content_type : "",
		       date ? date : "",
		       canon_hdrs, canon_rsc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	dbg(4, "str to sign is: \"%s\"\n", str_to_sign);

	str_to_sign_len = ret;
	assert(ret == strlen(str_to_sign));

	ret = hmac_sha(EVP_sha1(), secret, secret_len,
		       (uint8_t *)str_to_sign, str_to_sign_len,
		       &md, &md_len);
	if (ret < 0) {
		dbg(0, "failed to generate sha\n");
		goto err_str_free;
	}

	ret = base64_encode(md, md_len, &md_b64);
	if (ret < 0) {
		dbg(0, "failed to encode digenst\n");
		ret = -EINVAL;
		goto err_md_free;
	}
	*sig_str = md_b64;
	*sig_src = str_to_sign;
	str_to_sign = NULL;
	ret = 0;

err_md_free:
	free(md);
err_str_free:
	free(str_to_sign);
err_hdrs_free:
	free(canon_hdrs);
	free(content_type);
	free(content_md5);
	free(date);
err_rsc_free:
	free(canon_rsc);
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
