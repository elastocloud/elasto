/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/file/file_api.h"
#include "cm_test.h"
#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/azure_blob_path.h"
#include "lib/azure_blob_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/data.h"

static struct {
	char *pem_file;
	char *sub_id;
	char *sub_name;
	struct elasto_conn *io_conn;
	char *ctnr;
} cm_op_az_blob_req_state = {
	.pem_file = NULL,
	.sub_id = NULL,
	.sub_name = NULL,
	.io_conn = NULL,
	.ctnr = NULL,
};

/* initialise test container used for testing */
static void
cm_az_blob_req_init(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp;
	char *mgmt_host;
	char *url_host;
	struct elasto_conn *mgmt_conn;
	struct op *op;
	struct az_blob_path path = { 0 };

	ret = elasto_conn_subsys_init();
	assert_true(ret >= 0);

	ret = azure_ssl_pubset_process(cm_us->ps_file,
				       &cm_op_az_blob_req_state.pem_file,
				       &cm_op_az_blob_req_state.sub_id,
				       &cm_op_az_blob_req_state.sub_name);
	assert_true(ret >= 0);

	ret = az_mgmt_req_hostname_get(&mgmt_host);
	assert_true(ret >= 0);

	ret = elasto_conn_init_az(cm_op_az_blob_req_state.pem_file,
				  false,	/* mgmt must use https */
				  mgmt_host,
				  &mgmt_conn);
	assert_true(ret >= 0);

	ret = az_mgmt_req_acc_keys_get(cm_op_az_blob_req_state.sub_id,
				       cm_us->acc, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(mgmt_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	/* mgmt_conn is no longer needed for IO */
	elasto_conn_free(mgmt_conn);

	acc_keys_get_rsp = az_mgmt_rsp_acc_keys_get(op);
	assert_true(acc_keys_get_rsp != NULL);

	ret = az_blob_req_hostname_get(cm_us->acc, &url_host);
	assert_true(ret >= 0);

	ret = elasto_conn_init_az(NULL,
				  cm_us->insecure_http, url_host,
				  &cm_op_az_blob_req_state.io_conn);
	assert_true(ret >= 0);
	free(url_host);

	ret = elasto_conn_sign_setkey(cm_op_az_blob_req_state.io_conn,
				      cm_us->acc,
				      acc_keys_get_rsp->primary);
	assert_true(ret >= 0);
	op_free(op);

	ret = asprintf(&cm_op_az_blob_req_state.ctnr, "%s%d",
		       cm_us->ctnr, cm_us->ctnr_suffix);
	assert_true(ret >= 0);

	path.type = AZ_BLOB_PATH_CTNR;
	path.acc = cm_us->acc,
	path.ctnr = cm_op_az_blob_req_state.ctnr,
	ret = az_req_ctnr_create(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_us->ctnr_suffix++;

	op_free(op);
}

/* cleanup test ctnr used for fs testing */
static void
cm_az_blob_req_deinit(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_CTNR,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
	};
	ret = az_req_ctnr_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	op_free(op);
	free(cm_op_az_blob_req_state.ctnr);

	elasto_conn_free(cm_op_az_blob_req_state.io_conn);
	elasto_conn_subsys_deinit();
	azure_ssl_pubset_cleanup(cm_op_az_blob_req_state.pem_file);
	free(cm_op_az_blob_req_state.pem_file);
	free(cm_op_az_blob_req_state.sub_id);
	free(cm_op_az_blob_req_state.sub_name);
}

static void
cm_az_blob_req_ctnrs_list(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_rsp_ctnr_list *ctnr_list_rsp;
	struct azure_ctnr *ctnr;
	bool found_ctnr;
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_ACC,
		.acc = cm_us->acc,
	};
	ret = az_req_ctnr_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	ctnr_list_rsp = az_rsp_ctnr_list(op);

	found_ctnr = false;
	list_for_each(&ctnr_list_rsp->ctnrs, ctnr, list) {
		if (strcmp(ctnr->name, cm_op_az_blob_req_state.ctnr) == 0) {
			found_ctnr = true;
		}
	}

	assert_true(found_ctnr);
	op_free(op);
}

static void
cm_az_blob_req_ctnr_props(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_rsp_ctnr_prop_get *ctnr_prop_get;
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_CTNR,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
	};
	ret = az_req_ctnr_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	ctnr_prop_get = az_rsp_ctnr_prop_get(op);
	assert_true(ctnr_prop_get->lease_status == AOP_LEASE_STATUS_UNLOCKED);
	assert_true(ctnr_prop_get->lease_state == AOP_LEASE_STATE_AVAILABLE);

	op_free(op);
}

static void
cm_az_blob_req_blob_create(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_rsp_blob_list *blob_list_rsp;
	struct azure_blob *blob;
	struct az_blob_path path;

	/* put 1TB page blob */
	memset(&path, 0, sizeof(path));
	path.type = AZ_BLOB_PATH_BLOB;
	path.acc = cm_us->acc;
	path.ctnr = cm_op_az_blob_req_state.ctnr;
	path.blob = "blob1";
	ret = az_req_blob_put(&path, NULL, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm new blob exists */
	memset(&path, 0, sizeof(path));
	path.type = AZ_BLOB_PATH_CTNR;
	path.acc = cm_us->acc;
	path.ctnr = cm_op_az_blob_req_state.ctnr;
	ret = az_req_blob_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	blob_list_rsp = az_rsp_blob_list(op);
	assert_true(blob_list_rsp != NULL);
	assert_true(blob_list_rsp->num_blobs == 1);
	list_for_each(&blob_list_rsp->blobs, blob, list) {
		assert_true(blob->is_page);
		assert_string_equal(blob->name, "blob1");
		assert_int_equal(blob->len, BYTES_IN_TB);
	}
	op_free(op);

	/* cleanup */
	memset(&path, 0, sizeof(path));
	path.type = AZ_BLOB_PATH_BLOB;
	path.acc = cm_us->acc;
	path.ctnr = cm_op_az_blob_req_state.ctnr;
	path.blob = "blob1";
	ret = az_req_blob_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_blob_req_page_blob_io(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_BLOB,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
		.blob = "blob1",
	};

	/* create base blob */
	ret = az_req_blob_put(&path, NULL, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_page_put(&path, data, 0, ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	/* won't free the @buf, as we didn't allocate */
	op_free(op);

	memset(buf, 0, ARRAY_SIZE(buf));

	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_blob_get(&path, true, data, 0, ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);
	op_free(op);

	/* read from offset after allocated range, should be zero */
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_blob_get(&path, true, data, ARRAY_SIZE(buf),
			      ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check_zero(buf, ARRAY_SIZE(buf));
	op_free(op);

	/* cleanup base blob */
	ret = az_req_blob_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_blob_req_blob_props(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get;
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_BLOB,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
		.blob = "blob1",
	};

	ret = az_req_blob_put(&path, NULL, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	ret = az_req_blob_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	blob_prop_get = az_rsp_blob_prop_get(op);
	assert_true(blob_prop_get->is_page);
	assert_true(blob_prop_get->len == BYTES_IN_TB);
	assert_string_equal(blob_prop_get->content_type,
			    "application/octet-stream");

	op_free(op);

	ret = az_req_blob_prop_set(&path, true, BYTES_IN_GB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	ret = az_req_blob_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	blob_prop_get = az_rsp_blob_prop_get(op);
	assert_true(blob_prop_get->is_page);
	assert_true(blob_prop_get->len == BYTES_IN_GB);

	op_free(op);
}

static void
cm_az_blob_req_blob_cp(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_blob_path src_path = {
		.type = AZ_BLOB_PATH_BLOB,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
		.blob = "blob1",
	};
	struct az_blob_path dst_path = {
		.type = AZ_BLOB_PATH_BLOB,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
		.blob = "blob2",
	};

	/* put source blob with pattern data */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_blob_put(&src_path, data,
			      0,	/* page_len - ignored */
			      &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	op_free(op);

	/* copy blob1 data to blob2 */
	ret = az_req_blob_cp(&src_path, &dst_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	/* read back copied data */
	memset(buf, 0, ARRAY_SIZE(buf));
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_blob_get(&dst_path, false, data, 0, ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);
	op_free(op);

	/* cleanup base blob */
	ret = az_req_blob_del(&src_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* cleanup cp dest blob */
	ret = az_req_blob_del(&dst_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_blob_req_page_ranges(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_rsp_page_ranges_get *page_ranges_get_rsp;
	struct az_page_range *page_range;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_blob_path path = {
		.type = AZ_BLOB_PATH_BLOB,
		.acc = cm_us->acc,
		.ctnr = cm_op_az_blob_req_state.ctnr,
		.blob = "blob1",
	};

	/* create base page blob */
	ret = az_req_blob_put(&path, NULL, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that the page doesn't have any allocated ranges */
	ret = az_req_page_ranges_get(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	page_ranges_get_rsp = az_rsp_page_ranges_get(op);
	assert_int_equal(page_ranges_get_rsp->blob_len, BYTES_IN_TB);
	assert_int_equal(page_ranges_get_rsp->num_ranges, 0);
	assert_true(list_empty(&page_ranges_get_rsp->ranges));
	op_free(op);

	/* write pattern at 1GB offset */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_req_page_put(&path, data, BYTES_IN_GB, ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that pattern is now allocated */
	ret = az_req_page_ranges_get(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	page_ranges_get_rsp = az_rsp_page_ranges_get(op);
	assert_int_equal(page_ranges_get_rsp->blob_len, BYTES_IN_TB);
	assert_int_equal(page_ranges_get_rsp->num_ranges, 1);
	page_range = list_tail(&page_ranges_get_rsp->ranges,
			       struct az_page_range, list);
	assert_int_equal(page_range->start_byte, BYTES_IN_GB);
	assert_int_equal(page_range->end_byte,
			 page_range->start_byte + 1024 - 1);
	op_free(op);

	/* check range that covers first half of the extent */
	ret = az_req_page_ranges_get(&path, 0, BYTES_IN_GB + 512, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	page_ranges_get_rsp = az_rsp_page_ranges_get(op);
	assert_int_equal(page_ranges_get_rsp->blob_len, BYTES_IN_TB);
	assert_int_equal(page_ranges_get_rsp->num_ranges, 1);
	page_range = list_tail(&page_ranges_get_rsp->ranges,
			       struct az_page_range, list);
	assert_int_equal(page_range->start_byte, BYTES_IN_GB);
	assert_int_equal(page_range->end_byte,
			 page_range->start_byte + 512 - 1);
	op_free(op);

	/* punch hole covering previous extent */
	ret = az_req_page_put(&path, NULL, BYTES_IN_GB, ARRAY_SIZE(buf), &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that pattern is now allocated */
	ret = az_req_page_ranges_get(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	page_ranges_get_rsp = az_rsp_page_ranges_get(op);
	assert_int_equal(page_ranges_get_rsp->blob_len, BYTES_IN_TB);
	assert_int_equal(page_ranges_get_rsp->num_ranges, 0);
	assert_true(list_empty(&page_ranges_get_rsp->ranges));
	op_free(op);

	/* cleanup base blob */
	ret = az_req_blob_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_blob_req_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static const UnitTest cm_az_blob_req_tests[] = {
	unit_test_setup_teardown(cm_az_blob_req_ctnrs_list,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_ctnr_props,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_blob_create,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_page_blob_io,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_blob_props,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_blob_cp,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
	unit_test_setup_teardown(cm_az_blob_req_page_ranges,
				 cm_az_blob_req_init, cm_az_blob_req_deinit),
};

int
cm_az_blob_req_run(void)
{
	return run_tests(cm_az_blob_req_tests);
}
