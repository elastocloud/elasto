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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "exml.h"
#include "op.h"
#include "conn.h"
#include "util.h"
#include "lib/azure_ssl.h"

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
	mode_t umask_old;

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
	if (bmem == NULL) {
		ret = -ENOMEM;
		goto err_mc_free;
	}

	p12 = d2i_PKCS12_bio(bmem, NULL);
	if (p12 == NULL) {
		dbg(0, "Error reading PKCS#12 data\n");
		ret = -EBADF;
		goto err_bio_free;
	}

	/* no passphrase, ignore CAs */
	ret = PKCS12_parse(p12, NULL, &pkey, &cert, NULL);
	PKCS12_free(p12);
	if (!ret) {
		dbg(0, "Error parsing PKCS#12 data  - openssl initialised?\n");
		ret = -EBADF;
		goto err_bio_free;
	}

	/* write output pem */
	umask_old = umask(S_IRWXG | S_IRWXO);
	fp = fopen(pem_file, "w");
	umask(umask_old);
	if (fp == NULL) {
		dbg(0, "Error opening file %s\n", pem_file);
		ret = -errno;
		goto err_pkey_free;
	}
	if (pkey != NULL) {
		ret = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
		if (!ret) {
			dbg(0, "Error writing key file %s\n", pem_file);
			ret = -EBADF;
			goto err_fp_close;
		}
	}
	if (cert != NULL) {
		ret = PEM_write_X509_AUX(fp, cert);
		if (!ret) {
			dbg(0, "Error writing cert file %s\n", pem_file);
			ret = -EBADF;
			goto err_fp_close;
		}
	}

	ret = 0;
err_fp_close:
	fclose(fp);
err_pkey_free:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (cert != NULL)
		X509_free(cert);
err_bio_free:
	BIO_free(bmem);
err_mc_free:
	free(mcert);
err_out:
	return ret;
}

static int
azure_ssl_pubset_want_v1(struct xml_doc *xdoc,
			 char **_sid,
			 char **_sname,
			 char **_mcert_b64)
{
	int ret;

	ret = exml_str_want(xdoc,
			    "/PublishData/PublishProfile/Subscription[@Id]",
			    true, _sid, NULL);
	if (ret < 0) {
		return ret;
	}

	ret = exml_str_want(xdoc,
			    "/PublishData/PublishProfile/Subscription[@Name]",
			    true, _sname, NULL);
	if (ret < 0) {
		return ret;
	}

	ret = exml_str_want(xdoc,
			  "/PublishData/PublishProfile[@ManagementCertificate]",
			    true, _mcert_b64, NULL);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int
azure_ssl_pubset_want_v2(struct xml_doc *xdoc,
			 char **_sid,
			 char **_sname,
			 char **_mcert_b64)
{
	int ret;

	ret = exml_str_want(xdoc,
			    "/PublishData/PublishProfile/Subscription[@Id]",
			    true, _sid, NULL);
	if (ret < 0) {
		return ret;
	}

	ret = exml_str_want(xdoc,
			    "/PublishData/PublishProfile/Subscription[@Name]",
			    true, _sname, NULL);
	if (ret < 0) {
		return ret;
	}

	ret = exml_str_want(xdoc,
	     "/PublishData/PublishProfile/Subscription[@ManagementCertificate]",
			    true, _mcert_b64, NULL);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/*
 * Process Azure publishsettings XML
 *
 * @ps_file:	Azure publishsettings file from
 *		https://windows.azure.com/download/publishprofile.aspx
 * @pem_file:	Private key pem file generated from @ps_file source. It is
 *		written to a private /tmp/elasto-XXXXXX/sub_id.pem path.
 * @sub_id:	Subscriber identity, as present in the publishsettings file.
 * @sub_name:	Subscriber name, as present in the publishsettings file.
 */
int
azure_ssl_pubset_process(const char *ps_file,
			 char **pem_file,
			 char **sub_id,
			 char **sub_name)
{
	int ret;
	struct xml_doc *xdoc;
	char *fbuf = NULL;
	uint64_t len = 0;
	char *ps_path = NULL;
	char pem_dir[] = "/tmp/elasto-XXXXXX";
	char *pem_file_path = NULL;
	char *schema_vers = NULL;
	bool vers_present = false;
	char *sid = NULL;
	char *sname = NULL;
	char *mcert_b64 = NULL;

	ps_path = strdup(ps_file);
	if (ps_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = slurp_file(ps_file, &fbuf, &len);
	if (ret < 0) {
		goto err_ps_free;
	}

	ret = exml_slurp(fbuf, len, &xdoc);
	if (ret < 0) {
		goto err_fbuf_free;
	}

	ret = exml_str_want(xdoc,
			    "/PublishData/PublishProfile[@SchemaVersion]",
			    false, &schema_vers, &vers_present);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		dbg(0, "Failed to parse Azure Subscription data from %s\n",
		    ps_file);
		goto err_xdoc_free;
	}

	/* need to free before parsing again */
	exml_free(xdoc);

	ret = exml_slurp(fbuf, len, &xdoc);
	if (ret < 0) {
		goto err_fbuf_free;
	}

	/*
	 * Version 2 and Version 1 (no SchemaVersion) publishsettings formats
	 * supported
	 */
	if (vers_present && (strcmp(schema_vers, AZURE_SSL_PUBSET_VERS_2) == 0)) {
		ret = azure_ssl_pubset_want_v2(xdoc, &sid, &sname,
					       &mcert_b64);
	} else if (!vers_present) {
		ret = azure_ssl_pubset_want_v1(xdoc, &sid, &sname,
					       &mcert_b64);
	} else {
		dbg(0, "unsupported PublishSettings SchemaVersion: %s\n",
		    schema_vers);
		ret = -EINVAL;
	}
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		dbg(0, "Failed to parse Azure Subscription data from %s\n",
		    ps_file);
		goto err_xdoc_free;
	}

	pem_file_path = mkdtemp(pem_dir);
	if (pem_file_path == NULL) {
		dbg(0, "Failed to create temp directory\n");
		goto err_sub_free;
	}

	ret = asprintf(&pem_file_path, "%s/%s.pem", pem_dir, sid);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_rmdir;
	}

	ret = azure_ssl_pem_write(mcert_b64, pem_file_path);
	if (ret < 0) {
		goto err_pem_free;
	}

	free(mcert_b64);
	*pem_file = pem_file_path;
	*sub_id = sid;
	*sub_name = sname;
	free(schema_vers);
	exml_free(xdoc);
	free(fbuf);
	free(ps_path);

	return 0;
err_pem_free:
	free(pem_file_path);
err_rmdir:
	rmdir(pem_dir);
err_sub_free:
	free(mcert_b64);
	free(sname);
	free(sid);
err_xdoc_free:
	free(schema_vers);
	exml_free(xdoc);
err_fbuf_free:
	free(fbuf);
err_ps_free:
	free(ps_path);
err_out:
	return ret;
}

/*
 * Cleanup state associated with pem_file creation
 *
 * @pem_file:	Private key pem path generated by azure_ssl_pubset_process().
 */
int
azure_ssl_pubset_cleanup(const char *pem_file)
{
	int ret;
	char *pem_path;

	if (pem_file == NULL) {
		return -EINVAL;
	}

	pem_path = strdup(pem_file);
	if (pem_path == NULL) {
		return -ENOMEM;
	}

	ret = unlink(pem_path);
	if (ret < 0) {
		dbg(0, "failed to unlink pem file at %s\n", pem_path);
		ret = -errno;
		goto err_path_free;
	}

	ret = rmdir(dirname(pem_path));
	if (ret < 0) {
		dbg(0, "failed to remove pem dir at %s\n", dirname(pem_path));
		ret = -errno;
		goto err_path_free;
	}

	ret = 0;
err_path_free:
	free(pem_path);
	return ret;
}
