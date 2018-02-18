/*
 * Copyright (C) SUSE LINUX GmbH 2014-2016, all rights reserved.
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
#include <event2/event.h>

#include "lib/file/file_api.h"
#include "cm_test.h"
#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/azure_fs_path.h"
#include "lib/azure_fs_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/data.h"

static struct {
	char *pem_file;
	char *sub_id;
	char *sub_name;
	struct event_base *ev_base;
	struct elasto_conn *io_conn;
	char *share;
} cm_op_az_fs_state = {
	.pem_file = NULL,
	.sub_id = NULL,
	.sub_name = NULL,
	.ev_base = NULL,
	.io_conn = NULL,
	.share = NULL,
};

/* initialise test share used for fs testing */
static void
cm_az_fs_req_init(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	char *sign_key;
	char *url_host;
	struct elasto_conn *mgmt_conn;
	struct op *op;
	struct az_fs_path path = { 0 };

	ret = elasto_conn_subsys_init();
	assert_true(ret >= 0);

	cm_op_az_fs_state.ev_base = event_base_new();
	assert_true(cm_op_az_fs_state.ev_base != NULL);

	if (cm_us->ps_file != NULL) {
		struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp;

		/* publish settings based auth */
		ret = azure_ssl_pubset_process(cm_us->ps_file,
					       &cm_op_az_fs_state.pem_file,
					       &cm_op_az_fs_state.sub_id,
					       &cm_op_az_fs_state.sub_name);
		assert_true(ret >= 0);

		ret = elasto_conn_init_az(cm_op_az_fs_state.ev_base,
					  cm_op_az_fs_state.pem_file,
					  false,	/* mgmt must use https */
					  "management.core.windows.net",
					  443,
					  &mgmt_conn);
		assert_true(ret >= 0);

		ret = az_mgmt_req_acc_keys_get(cm_op_az_fs_state.sub_id, cm_us->acc,
					       &op);
		assert_true(ret >= 0);

		ret = elasto_conn_op_txrx(mgmt_conn, op);
		assert_true(ret >= 0);
		assert_true(!op->rsp.is_error);

		/* mgmt_conn is no longer needed for AFS IO */
		elasto_conn_free(mgmt_conn);

		acc_keys_get_rsp = az_mgmt_rsp_acc_keys_get(op);
		assert_true(acc_keys_get_rsp != NULL);

		sign_key = strdup(acc_keys_get_rsp->primary);
		op_free(op);
	} else {
		assert(cm_us->az_access_key != NULL);
		sign_key = strdup(cm_us->az_access_key);
	}
	assert_non_null(sign_key);

	ret = az_fs_req_hostname_get(cm_us->acc, &url_host);
	assert_true(ret >= 0);

	ret = elasto_conn_init_az(cm_op_az_fs_state.ev_base, NULL,
				  cm_us->insecure_http, url_host,
				  (cm_us->insecure_http ? 80 : 443),
				  &cm_op_az_fs_state.io_conn);
	assert_true(ret >= 0);
	free(url_host);

	ret = elasto_conn_sign_setkey(cm_op_az_fs_state.io_conn, cm_us->acc,
				      sign_key);
	assert_true(ret >= 0);
	free(sign_key);

	ret = asprintf(&cm_op_az_fs_state.share, "%s%d",
		       cm_us->ctnr, cm_us->ctnr_suffix);
	assert_true(ret >= 0);

	path.type = AZ_FS_PATH_SHARE;
	path.acc = cm_us->acc,
	path.share = cm_op_az_fs_state.share,
	ret = az_fs_req_share_create(&path, AZ_FS_SHARE_QUOTA_MAX_GB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_us->ctnr_suffix++;

	op_free(op);
}

/* cleanup test share used for fs testing */
static void
cm_az_fs_req_deinit(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_path path = {
		.type = AZ_FS_PATH_SHARE,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
	};
	ret = az_fs_req_share_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	op_free(op);
	free(cm_op_az_fs_state.share);

	elasto_conn_free(cm_op_az_fs_state.io_conn);
	elasto_conn_subsys_deinit();
	azure_ssl_pubset_cleanup(cm_op_az_fs_state.pem_file);
	free(cm_op_az_fs_state.pem_file);
	free(cm_op_az_fs_state.sub_id);
	free(cm_op_az_fs_state.sub_name);
	event_base_free(cm_op_az_fs_state.ev_base);
}

static void
cm_az_fs_req_shares_list(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_shares_list *shares_list_rsp;
	struct az_fs_share *share;
	bool found_share;
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ACC,
		.acc = cm_us->acc,
	};
	ret = az_fs_req_shares_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	shares_list_rsp = az_fs_rsp_shares_list(op);

	found_share = false;
	list_for_each(&shares_list_rsp->shares, share, list) {
		if (strcmp(share->name, cm_op_az_fs_state.share) == 0) {
			found_share = true;
		}
		assert_true(share->last_mod != 0);
	}

	assert_true(found_share);

	op_free(op);
}

static void
cm_az_fs_req_share_props(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_share_prop_get *share_prop_get;
	struct az_fs_path path = {
		.type = AZ_FS_PATH_SHARE,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
	};
	ret = az_fs_req_share_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	share_prop_get = az_fs_rsp_share_prop_get(op);
	assert_true(share_prop_get->last_mod != 0);

	op_free(op);
}

static void
cm_az_fs_req_dir_create(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp;
	struct az_fs_ent *ent;
	struct az_fs_path path = { 0 };

	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "truth";
	ret = az_fs_req_dir_create(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* check that the newly created directory exists in the base share */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_SHARE;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	ret = az_fs_req_dirs_files_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	assert_true(dirs_files_list_rsp != NULL);
	assert_true(dirs_files_list_rsp->num_ents == 1);
	ent = list_tail(&dirs_files_list_rsp->ents, struct az_fs_ent, list);
	assert_int_equal(ent->type, AZ_FS_ENT_TYPE_DIR);
	assert_string_equal(ent->dir.name, "truth");
	op_free(op);

	/* create nested subdirectory */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.parent_dir = "truth";
	path.dir = "is";
	ret = az_fs_req_dir_create(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm new subdir exists */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "truth";
	ret = az_fs_req_dirs_files_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	assert_true(dirs_files_list_rsp != NULL);
	assert_true(dirs_files_list_rsp->num_ents == 1);
	ent = list_tail(&dirs_files_list_rsp->ents, struct az_fs_ent, list);
	assert_int_equal(ent->type, AZ_FS_ENT_TYPE_DIR);
	assert_string_equal(ent->dir.name, "is");
	op_free(op);

	/* confirm new subdir is empty */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.parent_dir = "truth";
	path.dir = "is";
	ret = az_fs_req_dirs_files_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	assert_true(dirs_files_list_rsp != NULL);
	assert_true(dirs_files_list_rsp->num_ents == 0);
	op_free(op);

	/* cleanup subdir */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.parent_dir = "truth";
	path.dir = "is";
	ret = az_fs_req_dir_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* cleanup parent */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "truth";
	ret = az_fs_req_dir_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* check that share is now empty - this time use a NULL dir component */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_SHARE;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	ret = az_fs_req_dirs_files_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	assert_true(dirs_files_list_rsp != NULL);
	assert_true(dirs_files_list_rsp->num_ents == 0);
	op_free(op);
}

static void
cm_az_fs_req_dir_props(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_dir_prop_get *dir_prop_get;
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.dir = "dir1",
	};

	ret = az_fs_req_dir_create(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	ret = az_fs_req_dir_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dir_prop_get = az_fs_rsp_dir_prop_get(op);
	assert_true(dir_prop_get->last_mod != 0);

	op_free(op);
}

static void
cm_az_fs_req_file_create(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_dirs_files_list *dirs_files_list_rsp;
	struct az_fs_ent *ent;
	struct az_fs_path path = { 0 };

	/* create base file and directory */
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.file = "file1";
	ret = az_fs_req_file_create(&path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "dir1";
	ret = az_fs_req_dir_create(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* create nested file */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.parent_dir = "dir1";
	path.file = "file2";
	ret = az_fs_req_file_create(&path, BYTES_IN_MB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm new entries exists */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_SHARE;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	ret = az_fs_req_dirs_files_list(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	dirs_files_list_rsp = az_fs_rsp_dirs_files_list(op);
	assert_true(dirs_files_list_rsp != NULL);
	assert_true(dirs_files_list_rsp->num_ents == 2);
	list_for_each(&dirs_files_list_rsp->ents, ent, list) {
		if (ent->type == AZ_FS_ENT_TYPE_DIR) {
			assert_string_equal(ent->dir.name, "dir1");
		} else {
			assert_int_equal(ent->type, AZ_FS_ENT_TYPE_FILE);
			assert_string_equal(ent->file.name, "file1");
			assert_int_equal(ent->file.size, BYTES_IN_TB);
		}
	}
	op_free(op);

	/* cleanup dir, not empty */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "dir1";
	ret = az_fs_req_dir_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(op->rsp.is_error);
	assert_int_equal(op->rsp.err_code, 409);
	op_free(op);

	/* cleanup nested file */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.parent_dir = "dir1";
	path.file = "file2";
	ret = az_fs_req_file_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* cleanup dir, now empty */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.dir = "dir1";
	ret = az_fs_req_dir_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* cleanup base file */
	memset(&path, 0, sizeof(path));
	path.type = AZ_FS_PATH_ENT;
	path.acc = cm_us->acc;
	path.share = cm_op_az_fs_state.share;
	path.file = "file1";
	ret = az_fs_req_file_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_fs_req_file_io(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file1",
	};

	/* create base file and directory */
	ret = az_fs_req_file_create(&path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_put(&path, 0, ARRAY_SIZE(buf), data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	/* won't free the @buf, as we didn't allocate */
	op_free(op);

	memset(buf, 0, ARRAY_SIZE(buf));

	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_get(&path, 0, ARRAY_SIZE(buf), data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);
	op_free(op);

	/* read from offset after allocated range, should be zero */
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_get(&path, ARRAY_SIZE(buf), ARRAY_SIZE(buf),
				 data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check_zero(buf, ARRAY_SIZE(buf));
	op_free(op);

	/* cleanup base file */
	ret = az_fs_req_file_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_fs_req_file_props(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_file_prop_get *file_prop_get;
	uint64_t relevant;
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file1",
	};

	ret = az_fs_req_file_create(&path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	ret = az_fs_req_file_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_prop_get = az_fs_rsp_file_prop_get(op);
	assert_true(file_prop_get->len == BYTES_IN_TB);
	assert_string_equal(file_prop_get->content_type,
			    "application/octet-stream");

	op_free(op);

	relevant = (AZ_FS_FILE_PROP_LEN | AZ_FS_FILE_PROP_CTYPE);
	ret = az_fs_req_file_prop_set(&path, relevant, BYTES_IN_GB, "text/plain",
				      &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	ret = az_fs_req_file_prop_get(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_prop_get = az_fs_rsp_file_prop_get(op);
	assert_true(file_prop_get->relevant
			== (AZ_FS_FILE_PROP_LEN | AZ_FS_FILE_PROP_CTYPE));
	assert_true(file_prop_get->len == BYTES_IN_GB);
	assert_string_equal(file_prop_get->content_type, "text/plain");

	op_free(op);
}

static void
cm_az_fs_req_file_cp(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_fs_rsp_file_cp *file_cp;
	struct az_fs_path src_path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file1",
	};
	struct az_fs_path dst_path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file2",
	};

	/* create base file and directory */
	ret = az_fs_req_file_create(&src_path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_put(&src_path, 0, ARRAY_SIZE(buf), data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	op_free(op);

	/* create copy destination file */
	ret = az_fs_req_file_create(&dst_path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* copy file1 data to file2 */
	ret = az_fs_req_file_cp(&src_path, &dst_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_cp = az_fs_rsp_file_cp(op);
	/* FIXME - handle AOP_CP_STATUS_PENDING */
	assert_true(file_cp->cp_status == AOP_CP_STATUS_SUCCESS);
	op_free(op);

	/* read back copied data */
	memset(buf, 0, ARRAY_SIZE(buf));
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_get(&dst_path, 0, ARRAY_SIZE(buf), data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check(buf, ARRAY_SIZE(buf), 0);
	op_free(op);

	/* cleanup base file */
	ret = az_fs_req_file_del(&src_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* cleanup cp dest file */
	ret = az_fs_req_file_del(&dst_path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static void
cm_az_fs_req_file_ranges(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_file_ranges_list *file_ranges_list_rsp;
	struct az_file_range *file_range;
	struct elasto_data *data;
	uint8_t buf[1024];
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file1",
	};

	/* create base file */
	ret = az_fs_req_file_create(&path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that the file doesn't have any allocated ranges */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 0);
	assert_true(list_empty(&file_ranges_list_rsp->ranges));
	op_free(op);

	/* write pattern at 1GB offset */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_put(&path, BYTES_IN_GB, ARRAY_SIZE(buf), data,
				 &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that pattern is now allocated */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 1);
	file_range = list_tail(&file_ranges_list_rsp->ranges,
			       struct az_file_range, list);
	assert_int_equal(file_range->start_byte, BYTES_IN_GB);
	assert_int_equal(file_range->end_byte,
			 file_range->start_byte + 1024 - 1);
	op_free(op);

	/* check range that covers first half of the extent */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_GB + 512, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 1);
	file_range = list_tail(&file_ranges_list_rsp->ranges,
			       struct az_file_range, list);
	assert_int_equal(file_range->start_byte, BYTES_IN_GB);
	assert_int_equal(file_range->end_byte,
			 file_range->start_byte + 512 - 1);
	op_free(op);

	/* punch hole covering previous extent */
	ret = az_fs_req_file_put(&path, BYTES_IN_GB, ARRAY_SIZE(buf), NULL,
				 &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* confirm that pattern is now allocated */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 0);
	assert_true(list_empty(&file_ranges_list_rsp->ranges));
	op_free(op);

	/* cleanup base file */
	ret = az_fs_req_file_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

/*
 * XXX this test assumes specific 512 byte alignment behaviour from Azure, which
 * is not part of the API specification, but interesting to observe.
 */
static void
cm_az_fs_req_file_ranges_unaligned(void **state)
{
	int ret;
	struct cm_unity_state *cm_us = cm_unity_state_get();
	struct op *op;
	struct az_fs_rsp_file_ranges_list *file_ranges_list_rsp;
	struct az_file_range *file_range;
	struct elasto_data *data;
	uint8_t buf[1024];
	uint8_t aligned_buf[1024 + 512];
	struct az_fs_path path = {
		.type = AZ_FS_PATH_ENT,
		.acc = cm_us->acc,
		.share = cm_op_az_fs_state.share,
		.file = "file1",
	};
	uint64_t unaligned_off_start = BYTES_IN_GB + 256;
	uint64_t aligned_off_start = BYTES_IN_GB;
	uint64_t aligned_off_end = BYTES_IN_GB + ARRAY_SIZE(buf) + 512 - 1;

	/* create base file */
	ret = az_fs_req_file_create(&path, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* write pattern at unaligned offset */
	cm_file_buf_fill(buf, ARRAY_SIZE(buf), 0);
	ret = elasto_data_iov_new(buf, ARRAY_SIZE(buf), false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_put(&path, unaligned_off_start, ARRAY_SIZE(buf),
				 data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* allocated extent should now be 512 byte aligned */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 1);
	file_range = list_tail(&file_ranges_list_rsp->ranges,
			       struct az_file_range, list);
	assert_int_equal(file_range->start_byte, aligned_off_start);
	assert_int_equal(file_range->end_byte, aligned_off_end);
	op_free(op);

	/* punch hole covering unaligned range */
	ret = az_fs_req_file_put(&path, unaligned_off_start, ARRAY_SIZE(buf),
				 NULL, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);

	/* Azure keeps the partially used blocks at start and end allocated */
	ret = az_fs_req_file_ranges_list(&path, 0, BYTES_IN_TB, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	file_ranges_list_rsp = az_fs_rsp_file_ranges_list(op);
	assert_int_equal(file_ranges_list_rsp->file_len, BYTES_IN_TB);
	assert_int_equal(file_ranges_list_rsp->num_ranges, 2);

	file_range = list_top(&file_ranges_list_rsp->ranges,
			       struct az_file_range, list);
	assert_int_equal(file_range->start_byte, aligned_off_start);
	assert_int_equal(file_range->end_byte, aligned_off_start + 512 - 1);

	file_range = list_tail(&file_ranges_list_rsp->ranges,
			       struct az_file_range, list);
	assert_int_equal(file_range->start_byte, aligned_off_end - 512 + 1);
	assert_int_equal(file_range->end_byte, aligned_off_end);
	op_free(op);

	/* read across allocated ranges to confirm all is zero */
	ret = elasto_data_iov_new(aligned_buf, ARRAY_SIZE(aligned_buf),
				  false, &data);
	assert_true(ret >= 0);

	ret = az_fs_req_file_get(&path, aligned_off_start,
				 ARRAY_SIZE(aligned_buf), data, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);

	cm_file_buf_check_zero(aligned_buf, ARRAY_SIZE(aligned_buf));
	op_free(op);

	/* cleanup base file */
	ret = az_fs_req_file_del(&path, &op);
	assert_true(ret >= 0);

	ret = elasto_conn_op_txrx(cm_op_az_fs_state.io_conn, op);
	assert_true(ret >= 0);
	assert_true(!op->rsp.is_error);
	op_free(op);
}

static const UnitTest cm_az_fs_req_tests[] = {
	unit_test_setup_teardown(cm_az_fs_req_shares_list,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_share_props,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_dir_create,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_dir_props,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_create,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_io,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_props,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_cp,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_ranges,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
	unit_test_setup_teardown(cm_az_fs_req_file_ranges_unaligned,
				 cm_az_fs_req_init, cm_az_fs_req_deinit),
};

int
cm_az_fs_req_run(void)
{
	return run_tests(cm_az_fs_req_tests);
}
