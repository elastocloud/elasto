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
 *
 * Author: David Disseldorp <ddiss@suse.de>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <libgen.h>

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include "ccan/list/list.h"
#include "base64.h"
#include "azure_xml.h"
#include "azure_req.h"
#include "azure_conn.h"

static int
azure_ssl_pem_write(char *mcert_b64, char *pem_file)
{
	uint8_t *mcert;
	EVP_PKEY *pkey;
	X509 *cert;
	PKCS12 *p12;
	FILE *fp;
	BIO *bmem;
	int ret;

	mcert = malloc(strlen(mcert_b64));
	if (mcert == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = base64_decode(mcert_b64, mcert);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_mc_free;
	}

	bmem = BIO_new_mem_buf((void *)mcert, ret);

	p12 = d2i_PKCS12_bio(bmem, NULL);
	if (!p12) {
		printf("Error reading PKCS#12 data\n");
		ret = -EBADF;
		goto err_mc_free;
	}

	/* no passphrase, ignore CAs */
	ret = PKCS12_parse(p12, NULL, &pkey, &cert, NULL);
	PKCS12_free(p12);
	if (!ret) {
		ret = -EBADF;
		goto err_mc_free;
	}

	/* write output pem */
	fp = fopen(pem_file, "w");
	if (fp == NULL) {
		printf("Error opening file %s\n", pem_file);
		ret = -errno;
		goto err_mc_free;
	}
	if (pkey) {
		ret = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
		if (!ret) {
			ret = -EBADF;
			goto err_fp_close;
		}
	}
	if (cert) {
		ret = PEM_write_X509_AUX(fp, cert);
		if (!ret) {
			ret = -EBADF;
			goto err_fp_close;
		}
	}

	ret = 0;
err_fp_close:
	fclose(fp);
err_mc_free:
	free(mcert);
err_out:
	return ret;
}

/*
 * Process Azure publishsettings XML
 *
 * @ps_file:	Azure publishsettings file from
 *		https://windows.azure.com/download/publishprofile.aspx
 * @pem_file:	Private key pem file generated from @ps_file source. It is
 *		written to the path @ps_file.
 */
int
azure_ssl_pubset_process(const char *ps_file,
			 char **pem_file,
			 char **sub_id,
			 char **sub_name)
{
	int ret;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;
	char *ps_path;
	char *pem_file_path;
	char *sid;
	char *sname;
	char *mcert_b64;

	ps_path = strdup(ps_file);
	if (ps_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = azure_xml_slurp(true, (uint8_t *)ps_file, strlen(ps_file),
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_ps_free;
	}

	ret = azure_xml_get_path(xp_ctx,
		"//PublishData/PublishProfile/Subscription", "Id",
	       	&sid);
	if (ret < 0) {
		printf("Failed to read Azure Subscription ID from %s\n",
		       ps_file);
		goto err_xml_free;
	}

	ret = azure_xml_get_path(xp_ctx,
		"//PublishData/PublishProfile/Subscription", "Name",
		&sname);
	if (ret < 0) {
		printf("Failed to read Azure Subscription Name from %s\n",
		       ps_file);
		goto err_sid_free;
	}

	ret = azure_xml_get_path(xp_ctx,
		"//PublishData/PublishProfile", "ManagementCertificate",
		&mcert_b64);
	if (ret < 0) {
		printf("Failed to read Azure ManagementCertificate from %s\n",
		       ps_file);
		goto err_sname_free;
	}

	ret = asprintf(&pem_file_path, "%s/%s.pem", dirname(ps_path), sid);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_mc64_free;
	}

	ret = azure_ssl_pem_write(mcert_b64, pem_file_path);
	if (ret < 0) {
		goto err_pem_free;
	}

	free(mcert_b64);
	*pem_file = pem_file_path;
	*sub_id = sid;
	*sub_name = sname;
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
	free(ps_path);

	return 0;
err_pem_free:
	free(pem_file_path);
err_mc64_free:
	free(mcert_b64);
err_sname_free:
	free(sname);
err_sid_free:
	free(sid);
err_xml_free:
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_ps_free:
	free(ps_path);
err_out:
	return ret;
}
