/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2014, all rights reserved.
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "exml.h"
#include "data_api.h"
#include "op.h"
#include "sign.h"
#include "azure_req.h"
#include "azure_fs_req.h"

/*
 * primary Elasto-Backend Op structure for Azure File Service requests
 */
struct az_fs_ebo {
	enum az_fs_opcode opcode;
	struct az_fs_req req;
	struct az_fs_rsp rsp;
	struct op op;
};

static void
az_fs_req_free(struct op *op);
static void
az_fs_rsp_free(struct op *op);
static int
az_fs_rsp_process(struct op *op);

static void
az_fs_ebo_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	free(ebo);
}

static int
az_fs_ebo_init(enum az_fs_opcode opcode,
	       struct az_fs_ebo **_ebo)
{
	struct az_fs_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_free = az_fs_req_free;
	ebo->op.rsp_free = az_fs_rsp_free;
	ebo->op.rsp_process = az_fs_rsp_process;
	ebo->op.ebo_free = az_fs_ebo_free;
	/* sign callback set conditionally per-op */
	*_ebo = ebo;
	return 0;
}

static void
az_fs_req_share_create_free(struct az_fs_req_share_create *share_create_req)
{
	free(share_create_req->acc);
	free(share_create_req->share);
}

int
az_fs_req_share_create(const char *acc,
		       const char *share,
		       struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_create *share_create_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	share_create_req = &ebo->req.share_create;

	share_create_req->acc = strdup(acc);
	if (share_create_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	share_create_req->share = strdup(share);
	if (share_create_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_share_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=share",
		       share);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_share_free:
	free(share_create_req->share);
err_acc_free:
	free(share_create_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_share_del_free(struct az_fs_req_share_del *share_del_req)
{
	free(share_del_req->acc);
	free(share_del_req->share);
}

int
az_fs_req_share_del(const char *acc,
		    const char *share,
		    struct op **_op)
{
	int ret;
	struct az_fs_ebo *ebo;
	struct op *op;
	struct az_fs_req_share_del *share_del_req;

	if ((acc == NULL) || (share == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_ebo_init(AOP_FS_SHARE_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	share_del_req = &ebo->req.share_del;

	share_del_req->acc = strdup(acc);
	if (share_del_req->acc == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	share_del_req->share = strdup(share);
	if (share_del_req->share == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host,
		       "%s.file.core.windows.net", acc);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_share_free;
	}
	ret = asprintf(&op->url_path, "/%s?restype=share",
		       share);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_upath_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_share_free:
	free(share_del_req->share);
err_acc_free:
	free(share_del_req->acc);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_fs_req_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	switch (ebo->opcode) {
	case AOP_FS_SHARE_CREATE:
		az_fs_req_share_create_free(&ebo->req.share_create);
		break;
	case AOP_FS_SHARE_DEL:
		az_fs_req_share_del_free(&ebo->req.share_del);
		break;
	default:
		assert(false);
		break;
	};
}

static void
az_fs_rsp_free(struct op *op)
{
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	switch (ebo->opcode) {
	case AOP_FS_SHARE_CREATE:
	case AOP_FS_SHARE_DEL:
		/* nothing to do */
		break;
	default:
		assert(false);
		break;
	};
}

/*
 * unmarshall response data
 */
int
az_fs_rsp_process(struct op *op)
{
	int ret;
	struct az_fs_ebo *ebo = container_of(op, struct az_fs_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_FS_SHARE_CREATE:
	case AOP_FS_SHARE_DEL:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}
