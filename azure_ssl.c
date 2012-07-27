/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
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

#include "azure_xml.h"
#include "azure_req.h"
#include "azure_conn.h"

int main(void)
{
	struct azure_conn aconn;
	struct azure_req req;
	const char *pem_file = "/home/ddiss/azure/privateKey.pem";
	const char *pem_pword = "disso";
	const char *subscriber_id = "9baf7f32-66ae-42ca-9ad7-220050765863";
	int ret;

	azure_conn_subsys_init();
	azure_xml_subsys_init();

	memset(&req, 0, sizeof(req));

	ret = azure_conn_init(pem_file, pem_pword, &aconn);
	if (ret < 0) {
		goto err_global_clean;
	}

	ret = azure_req_mgmt_get_sa_keys_init(subscriber_id, "ddiss", &req);
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
