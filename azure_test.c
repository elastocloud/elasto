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

#include <curl/curl.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/azure_conn.h"
#include "lib/azure_ssl.h"

static void
test_args_usage(const char *progname)
{

	fprintf(stderr, "Usage: %s -s publish_settings "
				  "-a storage_account "
				  "[-l storage_location] [-g]\n\n"
		"-s publish_settings:	Azure PublishSettings file\n"
		"-a storage_account:	Storage account, created if needed\n"
		"-l storage_location:	Storage geographic location\n"
		"-g:			Enable geographic redundancy\n",
		progname);
}

static int
test_args_parse(int argc,
		char * const *argv,
		char **ps_file,
		char **blob_acc)
{
	int opt;
	int ret;
	extern char *optarg;
	char *pub_settings;
	char *store_acc = NULL;
	char *store_loc = NULL;	/* not yet supported */
	bool store_geo = false;	/* not yet supported */

	while ((opt = getopt(argc, argv, "s:a:l:g")) != -1) {
		switch (opt) {
		case 's':
			pub_settings = strdup(optarg);
			if (pub_settings == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'a':
			store_acc = strdup(optarg);
			if (store_acc == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'l':
			store_loc = strdup(optarg);
			if (store_loc == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'g':
			store_geo = true;
			break;
		default: /* '?' */
			test_args_usage(argv[0]);
			ret = -EINVAL;
			goto err_out;
			break;
		}
	}
	if ((pub_settings == NULL) || (store_acc == NULL)) {
		test_args_usage(argv[0]);
		ret = -EINVAL;
		goto err_out;
	}

	*ps_file = pub_settings;
	*blob_acc = store_acc;

	return 0;
err_out:
	free(pub_settings);
	free(store_acc);
	free(store_loc);

	return ret;
}

int
main(int argc, char * const *argv)
{
	struct azure_conn *aconn;
	struct azure_op op;
	char *ps_file;
	char *pem_file;
	char *sub_id;
	char *sub_name;
	char *blob_acc;
	const char *blob_container = "target1";
	const char *blob_name = "test";
	struct azure_ctnr *ctnr;
	bool ctnr_exists;
	int ret;

	ret = test_args_parse(argc, argv, &ps_file, &blob_acc);
	if (ret < 0) {
		goto err_out;
	}

	ret = azure_conn_subsys_init();
	if (ret < 0) {
		goto err_acc_free;
	}

	memset(&op, 0, sizeof(op));

	ret = azure_ssl_pubset_process(ps_file, &pem_file, &sub_id, &sub_name);
	if (ret < 0) {
		goto err_global_clean;
	}

	ret = azure_conn_init(pem_file, NULL, &aconn);
	if (ret < 0) {
		goto err_sub_info_free;
	}

	ret = azure_op_acc_keys_get(sub_id, blob_acc, &op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	printf("primary key: %s\n"
	       "secondary key: %s\n",
	       op.rsp.acc_keys_get.primary,
	       op.rsp.acc_keys_get.secondary);

	ret = azure_conn_sign_setkey(aconn, blob_acc,
				     op.rsp.acc_keys_get.primary);
	if (ret < 0) {
		goto err_op_free;
	}

	azure_op_free(&op);

	ret = azure_op_ctnr_list(blob_acc, &op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	ctnr_exists = false;
	list_for_each(&op.rsp.ctnr_list.ctnrs, ctnr, list) {
		if (strcmp(ctnr->name, blob_container) == 0) {
			ctnr_exists = true;
			break;
		}
	}

	azure_op_free(&op);

	if (ctnr_exists == false) {
		ret = azure_op_ctnr_create(blob_acc, blob_container, &op);
		if (ret < 0) {
			goto err_conn_free;
		}
		/*
		 * returns:
		 * < HTTP/1.1 201 Created
		 * < HTTP/1.1 409 The specified container already exists.
		 */

		ret = azure_conn_send_op(aconn, &op);
		if (ret < 0) {
			goto err_op_free;
		}

		ret = azure_rsp_process(&op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op.rsp.is_error) {
			ret = -EIO;
			printf("failed response: %d\n", op.rsp.err_code);
			goto err_op_free;
		}

		azure_op_free(&op);
	}

	ret = azure_op_blob_put(blob_acc, blob_container, blob_name,
				false, (uint8_t *)strdup("hello world"),
				sizeof("hello world"),
				false,
				&op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	azure_op_free(&op);

	ret = azure_op_blob_get(blob_acc, blob_container, blob_name,
				false, AOP_DATA_NONE, NULL, 0, 0, false, &op);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_op(aconn, &op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = azure_rsp_process(&op);
	if (ret < 0) {
		goto err_op_free;
	}

	if (op.rsp.is_error) {
		ret = -EIO;
		printf("failed response: %d\n", op.rsp.err_code);
		goto err_op_free;
	}

	printf("data consistency test: %s\n",
	       strcmp((char *)op.rsp.data->buf, "hello world") ? "failed" : "passed");

	ret = 0;
err_op_free:
	azure_op_free(&op);
err_conn_free:
	azure_conn_free(aconn);
err_sub_info_free:
	free(pem_file);
	free(sub_id);
	free(sub_name);
err_global_clean:
	azure_conn_subsys_deinit();
err_acc_free:
	free(ps_file);
	free(blob_acc);
err_out:
	return ret;
}
