/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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
#ifndef _AZURE_MGMT_REQ_H_
#define _AZURE_MGMT_REQ_H_

enum az_mgmt_opcode {
	AOP_MGMT_ACC_KEYS_GET = 201,
	AOP_MGMT_ACC_LIST,
	AOP_MGMT_ACC_CREATE,
	AOP_MGMT_ACC_DEL,
	AOP_MGMT_ACC_PROP_GET,
	AOP_MGMT_STATUS_GET,
};

struct az_mgmt_req_acc_keys_get {
	char *sub_id;
	char *service_name;
};
struct az_mgmt_rsp_acc_keys_get {
	char *primary;
	char *secondary;
};

/* azure storage account descriptor */
struct azure_account {
	struct list_node list;
	char *svc_name;
	char *label;
	char *url;
	char *desc;
	char *affin_grp;
	char *location;
};

struct az_mgmt_req_acc_list {
	char *sub_id;
};

/* @accs is a list of struct azure_account */
struct az_mgmt_rsp_acc_list {
	int num_accs;
	struct list_head accs;
};

struct az_mgmt_req_acc_create {
	char *sub_id;
	struct azure_account acc;
};

struct az_mgmt_req_acc_del {
	char *sub_id;
	char *account;
};

struct az_mgmt_req_acc_prop_get {
	char *sub_id;
	char *acc;
};

struct az_mgmt_rsp_acc_prop_get {
	struct azure_account acc_desc;
};

struct az_mgmt_req_status_get {
	char *sub_id;
	char *req_id;
};

enum az_req_status {
	AOP_STATUS_IN_PROGRESS,
	AOP_STATUS_SUCCEEDED,
	AOP_STATUS_FAILED,
};

struct az_mgmt_rsp_status_get {
	enum az_req_status status;
	union {
		struct {
			int http_code;
		} ok;
		struct {
			int http_code;
			int code;
			char *msg;
		} err;
	};
};

struct az_mgmt_req {
	union {
		struct az_mgmt_req_acc_keys_get acc_keys_get;
		struct az_mgmt_req_acc_list acc_list;
		struct az_mgmt_req_acc_create acc_create;
		struct az_mgmt_req_acc_del acc_del;
		struct az_mgmt_req_acc_prop_get acc_prop_get;
		struct az_mgmt_req_status_get sts_get;
	};
};

struct az_mgmt_rsp {
	union {
		struct az_mgmt_rsp_acc_keys_get acc_keys_get;
		struct az_mgmt_rsp_acc_list acc_list;
		struct az_mgmt_rsp_acc_prop_get acc_prop_get;
		struct az_mgmt_rsp_status_get sts_get;
		/*
		 * No response specific data handled yet:
		 * struct az_mgmt_rsp_acc_create acc_create;
		 * struct az_mgmt_rsp_acc_del acc_del;
		 */
	};
};

int
az_mgmt_req_acc_keys_get(const char *sub_id,
			 const char *service_name,
			 struct op **_op);

int
az_mgmt_req_acc_list(const char *sub_id,
		     struct op **_op);

int
az_mgmt_req_acc_create(const char *sub_id,
		       const char *svc_name,
		       const char *label,
		       const char *desc,
		       const char *affin_grp,
		       const char *location,
		       struct op **_op);

int
az_mgmt_req_acc_del(const char *sub_id,
		    const char *account,
		    struct op **_op);

int
az_mgmt_req_acc_prop_get(const char *sub_id,
			 const char *acc,
			 struct op **_op);

int
az_mgmt_req_status_get(const char *sub_id,
		       const char *req_id,
		       struct op **_op);

struct az_mgmt_rsp_acc_keys_get *
az_mgmt_rsp_acc_keys_get(struct op *op);

struct az_mgmt_rsp_acc_list *
az_mgmt_rsp_acc_list(struct op *op);

struct az_mgmt_rsp_acc_prop_get *
az_mgmt_rsp_acc_prop_get(struct op *op);

struct az_mgmt_rsp_status_get *
az_mgmt_rsp_status_get(struct op *op);
#endif /* ifdef _AZURE_MGMT_REQ_H_ */
