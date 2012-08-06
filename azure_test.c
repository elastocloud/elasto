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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ccan/list/list.h"
#include "azure_xml.h"
#include "azure_req.h"
#include "azure_conn.h"
#include "azure_ssl.h"

int main(void)
{
	struct azure_conn aconn;
	struct azure_req req;
	const char *ps_file = "/home/ddiss/azure/Windows Azure MSDN - Visual Studio Ultimate-7-20-2012-credentials.publishsettings";
	char *pem_file;
	char *sub_id;
	char *sub_name;
	const char *blob_acc = "istgt";
	const char *blob_container = "target1";
	const char *blob_name = "test";
	struct azure_ctnr *ctnr;
	bool ctnr_exists;
	int ret;

	azure_conn_subsys_init();
	azure_xml_subsys_init();

	memset(&req, 0, sizeof(req));

	ret = azure_ssl_pubset_process(ps_file, &pem_file, &sub_id, &sub_name);
	if (ret < 0) {
		goto err_global_clean;
	}

	ret = azure_conn_init(pem_file, NULL, &aconn);
	if (ret < 0) {
		/* FIXME */
		goto err_global_clean;
	}

	ret = azure_req_mgmt_get_sa_keys(sub_id, blob_acc, &req);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_req(&aconn, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	ret = azure_req_mgmt_get_sa_keys_rsp(&req);
	if (ret < 0) {
		goto err_req_free;
	}

	printf("primary key: %s\n"
	       "secondary key: %s\n",
	       req.mgmt_get_sa_keys.out.primary,
	       req.mgmt_get_sa_keys.out.secondary);

	ret = azure_conn_sign_setkey(&aconn, blob_acc,
				     req.mgmt_get_sa_keys.out.primary);
	if (ret < 0) {
		goto err_req_free;
	}

	azure_req_free(&req);

	ret = azure_req_ctnr_list(blob_acc, &req);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_req(&aconn, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	if (req.rsp_code != 0) {
		ret = -EIO;
		printf("failed response: %d\n", req.rsp_code);
		goto err_req_free;
	}

	ret = azure_req_ctnr_list_rsp(&req);
	if (ret < 0) {
		goto err_req_free;
	}

	ctnr_exists = false;
	list_for_each(&req.ctnr_list.out.ctnrs, ctnr, list) {
		if (strcmp(ctnr->name, blob_container) == 0) {
			ctnr_exists = true;
			break;
		}
	}

	azure_req_free(&req);

	if (ctnr_exists == false) {
		ret = azure_req_ctnr_create(blob_acc, blob_container, &req);
		if (ret < 0) {
			goto err_conn_free;
		}
		/*
		 * returns:
		 * < HTTP/1.1 201 Created
		 * < HTTP/1.1 409 The specified container already exists.
		 */

		ret = azure_conn_send_req(&aconn, &req);
		if (ret < 0) {
			goto err_req_free;
		}

		if (req.rsp_code != 0) {
			ret = -EIO;
			printf("failed response: %d\n", req.rsp_code);
			goto err_req_free;
		}

		azure_req_free(&req);
	}

	ret = azure_req_blob_put(blob_acc, blob_container, blob_name,
				 false, 0,
				 (uint8_t *)strdup("hello world"),
				 sizeof("hello world"),
				 &req);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_req(&aconn, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	if (req.rsp_code != 0) {
		ret = -EIO;
		printf("failed response: %d\n", req.rsp_code);
		goto err_req_free;
	}

	azure_req_free(&req);

	ret = azure_req_blob_get(blob_acc, blob_container, blob_name, &req);
	if (ret < 0) {
		goto err_conn_free;
	}

	ret = azure_conn_send_req(&aconn, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	if (req.rsp_code != 0) {
		ret = -EIO;
		printf("failed response: %d\n", req.rsp_code);
		goto err_req_free;
	}

	printf("data consistency test: %s\n",
	       strcmp((char *)req.iov_in.buf, "hello world") ? "failed" : "passed");

	ret = 0;
err_req_free:
	azure_req_free(&req);
err_conn_free:
	azure_conn_free(&aconn);
err_global_clean:
	azure_xml_subsys_deinit();
	azure_conn_subsys_deinit();

	return ret;
}
