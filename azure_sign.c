/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 */
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "base64.h"
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

#if 0
int
main(int argc, char *argv[])
{
//	char *key = "+FbJP2MNperUnvBFVwFT68yvVVW81+YbEQ1pQAWgj/0j3Ha6pYV5MwlfjIHGo/m4a6sdiKi6fz4uV//nFv3Psg==";
//	char *msg = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Sun, 11 Oct 2009 21:49:13 GMT\nx-ms-version:2009-09-19\n/myaccount/myaccount/mycontainered\ncomp:metadata\nrestype:container\ntimeout:20";
	char *b64_key;
	uint8_t *key;
	int key_len;
	char *msg;
	char *b64_md;
	int b64_len;
	uint8_t *md;
	int md_len;
	int ret;

	if (argc != 3) {
		printf("Usage: %s <base64_key> <msg>\n", argv[0]);
		return -EINVAL;
	}
	b64_key = argv[1];
	msg = argv[2];
	msg = "GET\n\n\n\n\nx-ms-version: 2011-10-01\nx-ms-date:Tue, 24 Jul 2012 12:39:13 GMT\n/ddiss/\ncomp:list";

	/* openssl init */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	/* need to b64_decode key first? */
	key = malloc(strlen(b64_key));
	if (key == NULL)
		goto err_engine;

	key_len = base64_decode(b64_key, key);
	if (key_len < 0) {
		ret = -EINVAL;
		goto err_key;
	}

	printf("key b64 len: %d, bin len: %d\n", strlen(b64_key), key_len);

	ret = hmac_sha256(key, key_len, msg, strlen(msg), &md, &md_len);
	if (ret < 0)
		goto err_key;

	b64_len = base64_encode(md, md_len, &b64_md);
	if (b64_len < 0) {
		ret = -EINVAL;
		goto err_md;
	}

	printf("key: \'%s\'\n"
	       "result: \'%s\'\n", b64_key, b64_md);
	ret = 0;

	free(b64_md);
err_md:
	free(md);
err_key:
	free(key);
err_engine:
	ENGINE_cleanup();

	if (ret < 0)
		printf("Failed with: %s\n", strerror(-ret));
	return ret;
}
#endif
