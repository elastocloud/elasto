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
#include <unistd.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <apr-1/apr_general.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/xml.h"
#include "lib/op.h"
#include "lib/sign.h"
#include "lib/azure_req.h"
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/dbg.h"
#include "cm_test.h"

void cm_unity_usage(const char *progname)
{
	printf("Usage: %s [-s publish settings] [-k S3 key-duo]"
	       " [-d debug_level] [-i]\n", progname);
}

int
main(int argc,
     char * const *argv)
{
	int ret;
	int opt;
	extern char *optarg;
	extern int optind;
	int debug_level = 1;
	char *pub_settings = NULL;
	char *s3_id = NULL;
	char *s3_secret = NULL;
	bool insecure_http = false;

	while ((opt = getopt(argc, argv, "s:k:d:?i")) != -1) {
		char *sep;
		switch (opt) {
		case 's':
			pub_settings = strdup(optarg);
			if (pub_settings == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'k':
			s3_id = strdup(optarg);
			if (s3_id == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			sep = strchr(s3_id, ',');
			if (sep == NULL) {
				break;
			}
			if (strlen(sep) <= 1) {
				ret = -EINVAL;
				goto err_out;
			}
			s3_secret = strdup(sep + 1);
			if (s3_secret == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			*sep = 0;
			break;
		case 'd':
			debug_level = (uint32_t)strtol(optarg, NULL, 10);
			break;
		case 'i':
			insecure_http = true;
			break;
		case '?':
		default:
			cm_unity_usage(argv[0]);
			ret = -EINVAL;
			goto err_out;
			break;
		}
	}

	if ((s3_id != NULL) && (s3_secret == NULL)) {
		char *sak;
		sak = getpass("S3 secret access key: ");
		if (sak == NULL) {
			ret = -EINVAL;
			goto err_out;
		}
		s3_secret = strdup(sak);
		if (s3_secret == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	dbg_level_set(debug_level);
	sign_init();
	cm_sign_s3_run();
	cm_sign_azure_run();
	cm_data_run();
	sign_deinit();

err_out:
	return ret;
}
