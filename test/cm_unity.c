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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <setjmp.h>
#include <cmocka.h>

#include "ccan/list/list.h"
#include "lib/file/file_api.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/sign.h"
#include "lib/azure_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/azure_blob_path.h"
#include "lib/azure_blob_req.h"
#include "lib/s3_path.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/dbg.h"
#include "cm_test.h"

struct cm_unity_state *cm_ustate;

struct cm_unity_state *
cm_unity_state_get(void)
{
	assert_non_null(cm_ustate);
	return cm_ustate;
}

static int
cm_unity_state_init(void)
{
	char tmpdir[] = "/tmp/elasto-test-XXXXXX";
	char *tmpd;
	unsigned int seedy = time(NULL);

	cm_ustate = malloc(sizeof(*cm_ustate));
	assert(cm_ustate != NULL);
	memset(cm_ustate, 0, sizeof(*cm_ustate));
	cm_ustate->insecure_http = false;
	cm_ustate->ctnr = strdup("testctnr");
	assert(cm_ustate->ctnr != NULL);
	srand(seedy);
	cm_ustate->ctnr_suffix = rand();
	cm_ustate->share = strdup("testshare");
	assert(cm_ustate->share != NULL);
	cm_ustate->share_suffix = rand();

	tmpd = mkdtemp(tmpdir);
	assert(tmpd != NULL);
	cm_ustate->local_tmpdir = strdup(tmpd);
	assert(cm_ustate->local_tmpdir != NULL);
	cm_ustate->local_auth.type = ELASTO_FILE_LOCAL;

	return 0;
}

static void
cm_unity_auth_state_init(void)
{
	/* az_auth.type set by test suites */
	if (cm_ustate->az_access_key != NULL) {
		cm_ustate->az_auth.az.access_key = cm_ustate->az_access_key;
	} else {
		assert(cm_ustate->ps_file != NULL);
		cm_ustate->az_auth.az.ps_path = cm_ustate->ps_file;
	}
	cm_ustate->az_auth.az.ps_path = cm_ustate->ps_file;
	cm_ustate->az_auth.insecure_http = cm_ustate->insecure_http;
}

static void
cm_unity_state_free(void)
{
	int ret;

	ret = rmdir(cm_ustate->local_tmpdir);
	if (ret < 0) {
		ret = -errno;
		printf("failed to cleanup %s: %s\n",
		       cm_ustate->local_tmpdir, strerror(-ret));
	}
	free(cm_ustate->local_tmpdir);

	free(cm_ustate->acc);
	free(cm_ustate->ctnr);
	free(cm_ustate->share);
	free(cm_ustate->ps_file);
	free(cm_ustate->az_access_key);
	free(cm_ustate->s3_id);
	free(cm_ustate->s3_secret);
	free(cm_ustate);
}

static void
cm_unity_usage(const char *progname)
{
	printf("Usage: %s [-s Azure publish settings] [-K Azure access key] "
	       "[-A Azure account] [-k S3 key-duo] [-d debug_level] [-i]\n",
	       progname);
}

int
main(int argc,
     char * const *argv)
{
	int ret;
	int opt;
	extern char *optarg;
	extern int optind;
	int debug_level = 0;

	ret = cm_unity_state_init();
	if (ret < 0) {
		goto err_out;
	}

	while ((opt = getopt(argc, argv, "s:K:A:k:d:?i")) != -1) {
		char *sep;
		switch (opt) {
		case 's':
			cm_ustate->ps_file = strdup(optarg);
			if (cm_ustate->ps_file == NULL) {
				ret = -ENOMEM;
				goto err_state_free;
			}
			break;
		case 'K':
			cm_ustate->az_access_key = strdup(optarg);
			if (cm_ustate->az_access_key == NULL) {
				ret = -ENOMEM;
				goto err_state_free;
			}
			break;
		case 'A':
			cm_ustate->acc = strdup(optarg);
			if (cm_ustate->acc == NULL) {
				ret = -ENOMEM;
				goto err_state_free;
			}
			break;
		case 'k':
			cm_ustate->s3_id = strdup(optarg);
			if (cm_ustate->s3_id == NULL) {
				ret = -ENOMEM;
				goto err_state_free;
			}
			sep = strchr(cm_ustate->s3_id, ',');
			if (sep == NULL) {
				break;
			}
			if (strlen(sep) <= 1) {
				ret = -EINVAL;
				goto err_state_free;
			}
			cm_ustate->s3_secret = strdup(sep + 1);
			if (cm_ustate->s3_secret == NULL) {
				ret = -ENOMEM;
				goto err_state_free;
			}
			*sep = 0;
			break;
		case 'd':
			debug_level = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'i':
			cm_ustate->insecure_http = true;
			break;
		case '?':
		default:
			cm_unity_usage(argv[0]);
			ret = -EINVAL;
			goto err_state_free;
			break;
		}
	}

	if ((cm_ustate->s3_id != NULL) && (cm_ustate->s3_secret == NULL)) {
		char *sak;
		sak = getpass("S3 secret access key: ");
		if (sak == NULL) {
			ret = -EINVAL;
			goto err_state_free;
		}
		cm_ustate->s3_secret = strdup(sak);
		if (cm_ustate->s3_secret == NULL) {
			ret = -ENOMEM;
			goto err_state_free;
		}
	}

	if (((cm_ustate->ps_file != NULL) || (cm_ustate->az_access_key != NULL))
						&& (cm_ustate->acc == NULL)) {
		printf("An account must be provided with Azure credentials\n");
		cm_unity_usage(argv[0]);
		ret = -EINVAL;
		goto err_state_free;
	}

	dbg_level_set(debug_level);
	sign_init();
	cm_sign_s3_run();
	cm_sign_azure_run();
	cm_data_run();
	cm_xml_run();
	cm_az_blob_path_run();
	cm_az_fs_path_run();
	cm_s3_path_run();
	cm_cli_path_run();
	cm_cli_util_run();
	cm_cli_mime_run();
	cm_file_local_run();
	if ((cm_ustate->ps_file == NULL)
					&& (cm_ustate->az_access_key == NULL)) {
		printf("skipping Azure cloud IO tests, no credentials "
		       "provided\n");
	} else {
		cm_unity_auth_state_init();
		cm_file_run();
		cm_az_fs_req_run();
		cm_az_blob_req_run();
	}
	sign_deinit();
	ret = 0;
err_state_free:
	cm_unity_state_free();
err_out:
	return ret;
}
