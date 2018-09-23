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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

/* for encoding */
#include <event2/http.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "exml.h"
#include "data.h"
#include "op.h"
#include "sign.h"
#include "azure_req.h"
#include "azure_blob_path.h"
#include "azure_blob_req.h"

/*
 * primary Elasto-Backend Op structure for Azure blob service requests
 */
struct az_blob_ebo {
	enum az_blob_opcode opcode;
	struct az_blob_req req;
	struct az_blob_rsp rsp;
	struct op op;
};

static void
az_blob_req_free(struct op *op);
static void
az_blob_rsp_free(struct op *op);
static int
az_blob_rsp_process(struct op *op);

static void
az_blob_ebo_free(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);

	free(ebo);
}

static int
az_blob_ebo_init(enum az_blob_opcode opcode,
		 struct az_blob_ebo **_ebo)
{
	struct az_blob_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_free = az_blob_req_free;
	ebo->op.rsp_free = az_blob_rsp_free;
	ebo->op.rsp_process = az_blob_rsp_process;
	ebo->op.ebo_free = az_blob_ebo_free;
	/* sign callback set conditionally per-op */
	*_ebo = ebo;
	return 0;
}

static int
az_blob_req_url_path_gen(const struct az_blob_path *path,
			 const char *url_params,
			 char **_url_path)
{
	int ret;
	const char *params_str = url_params ? url_params : "";
	char *url_path;
	char *blob_encoded = NULL;


	switch (path->type) {
	case AZ_BLOB_PATH_ACC:
		if (path->host_is_custom) {
			ret = asprintf(&url_path, "/%s%s",
				       path->acc, params_str);
			break;
		}
		/* acc is a server hostname prefix */
		ret = asprintf(&url_path, "/%s", params_str);
		break;
	case AZ_BLOB_PATH_CTNR:
		if (path->host_is_custom) {
			ret = asprintf(&url_path, "/%s/%s%s",
				       path->acc, path->ctnr, params_str);
			break;
		}
		ret = asprintf(&url_path, "/%s%s", path->ctnr, params_str);
		break;
	case AZ_BLOB_PATH_BLOB:
		blob_encoded = evhttp_encode_uri(path->blob);
		if (blob_encoded == NULL) {
			return -ENOMEM;
		}
		if (path->host_is_custom) {
			ret = asprintf(&url_path, "/%s/%s/%s%s", path->acc,
				       path->ctnr, blob_encoded, params_str);
		} else {
			ret = asprintf(&url_path, "/%s/%s%s",
				       path->ctnr, blob_encoded, params_str);
		}
		free(blob_encoded);
		break;
	default:
		dbg(0, "can't encode Azure Blob Service path URL\n");
		return -EINVAL;
	}
	if (ret < 0) {
		/* asprintf error */
		return -ENOMEM;
	}
	*_url_path = url_path;

	return 0;
}

static int
az_blob_req_url_encode(const struct az_blob_path *path,
		       const char *url_params,
		       char **_url_host,
		       char **_url_path)
{
	int ret;
	char *url_host;
	char *url_path;

	url_host = strdup(path->host);
	if (url_host == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = az_blob_req_url_path_gen(path, url_params, &url_path);
	if (ret < 0) {
		goto err_uhost_free;
	}

	*_url_host = url_host;
	*_url_path = url_path;
	return 0;

err_uhost_free:
	free(url_host);
err_out:
	return ret;
}

static const struct {
	const char *state_str;
	enum az_lease_state state;
} az_rsp_lease_state_map[] = {
	{"available", AOP_LEASE_STATE_AVAILABLE},
	{"leased", AOP_LEASE_STATE_LEASED},
	{"expired", AOP_LEASE_STATE_EXPIRED},
	{"breaking", AOP_LEASE_STATE_BREAKING},
	{"broken", AOP_LEASE_STATE_BROKEN},
};

static int
az_rsp_lease_state(const char *state_str,
		   enum az_lease_state *_state)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(az_rsp_lease_state_map); i++) {
		if (!strcmp(state_str, az_rsp_lease_state_map[i].state_str)) {
			*_state = az_rsp_lease_state_map[i].state;
			return 0;
		}
	}
	dbg(1, "invalid lease state string: %s\n", state_str);
	return -EINVAL;
}

static const struct {
	const char *status_str;
	enum az_lease_status status;
} az_rsp_lease_status_map[] = {
	{"locked", AOP_LEASE_STATUS_LOCKED},
	{"unlocked", AOP_LEASE_STATUS_UNLOCKED},
};

static int
az_rsp_lease_status(const char *status_str,
		    enum az_lease_status *_status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(az_rsp_lease_status_map); i++) {
		if (!strcmp(status_str,
			    az_rsp_lease_status_map[i].status_str)) {
			*_status = az_rsp_lease_status_map[i].status;
			return 0;
		}
	}
	dbg(1, "invalid lease status string: %s\n", status_str);
	return -EINVAL;
}

static struct {
	enum az_lease_action action_enum;
	const char *action_str;
} action_enum_name_map[] = {
	{AOP_LEASE_ACTION_ACQUIRE, "acquire"},
	{AOP_LEASE_ACTION_RENEW, "renew"},
	{AOP_LEASE_ACTION_CHANGE, "change"},
	{AOP_LEASE_ACTION_RELEASE, "release"},
	{AOP_LEASE_ACTION_BREAK, "break"},
};

static const char *
az_req_lease_actn_enum_map(enum az_lease_action action_enum)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(action_enum_name_map); i++) {
		if (action_enum_name_map[i].action_enum == action_enum) {
			return action_enum_name_map[i].action_str;
		}
	}
	dbg(0, "invalid lease action enum: %u\n", action_enum);
	return NULL;
}

static void
az_rsp_ctnr_list_free(struct az_rsp_ctnr_list *ctnr_list_rsp)
{
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	if (ctnr_list_rsp->num_ctnrs <= 0)
		return;

	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
}

int
az_req_ctnr_list(const struct az_blob_path *path,
		 struct op **_op)
{

	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_ACC(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_CONTAINER_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	ret = az_blob_req_url_encode(path, "?comp=list",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}
	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_iter_lease_status_process(struct xml_doc *xdoc,
				 const char *path,
				 const char *val,
				 void *cb_data)
{
	enum az_lease_status *lease_status = (enum az_lease_status *)cb_data;

	if (val == NULL) {
		return -EINVAL;
	}
	return az_rsp_lease_status(val, lease_status);
}

static int
az_rsp_ctnr_iter_process(struct xml_doc *xdoc,
			 const char *path,
			 const char *val,
			 void *cb_data)
{
	int ret;
	struct az_rsp_ctnr_list *ctnr_list_rsp =
					(struct az_rsp_ctnr_list *)cb_data;
	struct azure_ctnr *ctnr;

	/* request callback for subsequent containers */
	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Containers/Container",
				false, az_rsp_ctnr_iter_process, ctnr_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	ctnr = malloc(sizeof(*ctnr));
	if (ctnr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(ctnr, 0, sizeof(*ctnr));

	ret = exml_str_want(xdoc, "./Name", true, &ctnr->name, NULL);
	if (ret < 0) {
		goto err_ctnr_free;
	}

	/* lease status is present in API versions >= 2012-02-12 */
	ret = exml_val_cb_want(xdoc, "./Properties/LeaseStatus", true,
			       az_rsp_iter_lease_status_process,
			       &ctnr->lease_status, NULL);
	if (ret < 0) {
		goto err_ctnr_free;
	}

	list_add_tail(&ctnr_list_rsp->ctnrs, &ctnr->list);
	ctnr_list_rsp->num_ctnrs++;

	return 0;

err_ctnr_free:
	free(ctnr);
err_out:
	return ret;
}

static int
az_rsp_ctnr_list_process(struct op *op,
			 struct az_rsp_ctnr_list *ctnr_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	assert(op->opcode == AOP_CONTAINER_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&ctnr_list_rsp->ctnrs);

	ret = exml_path_cb_want(xdoc,
				"/EnumerationResults/Containers/Container",
				false, az_rsp_ctnr_iter_process, ctnr_list_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	/*
	 * Returns up to 5000 records (maxresults default),
	 */
	ret = exml_parse(xdoc);
	if (ret < 0) {
		/* need to walk list in case cb fired */
		goto err_ctnrs_free;
	}

	exml_free(xdoc);
	return 0;

err_ctnrs_free:
	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

int
az_req_ctnr_create(const struct az_blob_path *path,
		   struct op **_op)
{

	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_CTNR(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_CONTAINER_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, "?restype=container",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_req_ctnr_del(const struct az_blob_path *path,
		struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_CTNR(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_CONTAINER_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = az_blob_req_url_encode(path, "?restype=container",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

int
az_req_ctnr_prop_get(const struct az_blob_path *path,
		     struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_CTNR(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_CONTAINER_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_HEAD;
	ret = az_blob_req_url_encode(path, "?restype=container",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_ctnr_prop_get_process(struct op *op,
			     struct az_rsp_ctnr_prop_get *ctnr_prop_get_rsp)
{
	int ret;
	char *hdr_val;

	assert(op->opcode == AOP_CONTAINER_PROP_GET);

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-state",
				&hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_rsp_lease_state(hdr_val, &ctnr_prop_get_rsp->lease_state);
	free(hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-status",
				&hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_rsp_lease_status(hdr_val, &ctnr_prop_get_rsp->lease_status);
	free(hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static void
az_req_ctnr_lease_free(struct az_req_ctnr_lease *ctnr_lease_req)
{
	free(ctnr_lease_req->lid);
}

static void
az_rsp_ctnr_lease_free(struct az_rsp_ctnr_lease *ctnr_lease_rsp)
{
	free(ctnr_lease_rsp->lid);
}

/* XXX could be refactored into common ctnr/blob lease code */
static int
az_req_ctnr_lease_hdr_fill(struct az_req_ctnr_lease *ctnr_lease_req,
			   const char *action_str,
			   struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_req_hdr_add(op, "x-ms-lease-action", action_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	if (ctnr_lease_req->action == AOP_LEASE_ACTION_ACQUIRE) {
		ret = asprintf(&hdr_str, "%d", ctnr_lease_req->duration);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-duration", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else if (ctnr_lease_req->action == AOP_LEASE_ACTION_BREAK) {
		ret = asprintf(&hdr_str, "%d", ctnr_lease_req->break_period);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-break-period", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (ctnr_lease_req->lid != NULL) {
		ret = op_req_hdr_add(op, "x-ms-lease-id", ctnr_lease_req->lid);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * @duration is the lease duration if @action=AOP_LEASE_ACTION_ACQUIRE.
 * It can either be -1 (indefinite), or between 15 and 60 seconds.
 * For @action=AOP_LEASE_ACTION_BREAK, @duration corresponds to the number of
 * seconds that the lease should continue before it is broken.
 */
int
az_req_ctnr_lease(const struct az_blob_path *path,
		  const char *lid,
		  const char *lid_proposed,
		  enum az_lease_action action,
		  int32_t duration,
		  struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_ctnr_lease *ctnr_lease_req;
	const char *action_str;

	action_str = az_req_lease_actn_enum_map(action);
	if (action_str == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	/* duration is only valid for AQUIRE and BREAK (as break period) */
	if ((action == AOP_LEASE_ACTION_ACQUIRE)
	 && ((duration != -1) && ((duration < 15) || (duration > 60)))) {
		dbg(1, "invalid lease duration: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	/* break period must be between 0 and 60 */
	if ((action == AOP_LEASE_ACTION_BREAK)
	 && ((duration < 0) || (duration > 60))) {
		dbg(1, "invalid break period: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	if ((action == AOP_LEASE_ACTION_CHANGE) && (lid_proposed == NULL)) {
		dbg(1, "proposed lease ID required with action=change\n");
		ret = -EINVAL;
		goto err_out;
	} else if ((action != AOP_LEASE_ACTION_CHANGE)
			&& (action != AOP_LEASE_ACTION_ACQUIRE)
			&& (lid_proposed != NULL)) {
		dbg(1, "proposed lease ID only valid with "
		    "action=aquire|change\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (((action == AOP_LEASE_ACTION_RENEW)
			|| (action == AOP_LEASE_ACTION_CHANGE)
			|| (action == AOP_LEASE_ACTION_RELEASE))
							&& (lid == NULL)) {
		dbg(1, "lease ID required with action=renew|change|release\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* TODO validate lid GUID format */

	ret = az_blob_ebo_init(AOP_CONTAINER_LEASE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	ctnr_lease_req = &ebo->req.ctnr_lease;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	if (lid != NULL) {
		ctnr_lease_req->lid = strdup(lid);
		if (ctnr_lease_req->lid == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

	if (lid_proposed != NULL) {
		ctnr_lease_req->lid_proposed = strdup(lid_proposed);
		if (ctnr_lease_req->lid_proposed == NULL) {
			ret = -ENOMEM;
			goto err_lid_free;
		}
	}

	ctnr_lease_req->action = action;
	if (action == AOP_LEASE_ACTION_ACQUIRE) {
		ctnr_lease_req->duration = duration;
	} else if (action == AOP_LEASE_ACTION_BREAK) {
		ctnr_lease_req->break_period = duration;
	} else if (duration != 0) {
		dbg(0, "ignoring lease duration %d with action %s\n",
		    duration, action_str);
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;
	ret = az_blob_req_url_encode(path, "?comp=lease&restype=container",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_lid_prop_free;
	}

	ret = az_req_ctnr_lease_hdr_fill(ctnr_lease_req, action_str, op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_lid_prop_free:
	free(ctnr_lease_req->lid_proposed);
err_lid_free:
	free(ctnr_lease_req->lid);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_ctnr_lease_process(struct op *op,
			  struct az_rsp_ctnr_lease *ctnr_lease_rsp)
{
	int ret;

	assert(op->opcode == AOP_CONTAINER_LEASE);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "x-ms-lease-time",
				    &ctnr_lease_rsp->time_remaining);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}
	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-id",
				&ctnr_lease_rsp->lid);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static void
az_rsp_blob_list_free(struct az_rsp_blob_list *blob_list_rsp)
{
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	if (blob_list_rsp->num_blobs == 0) {
		return;
	}

	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob->content_type);
		free(blob);
	}
}

int
az_req_blob_list(const struct az_blob_path *path,
		 struct op **_op)
{

	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_CTNR(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	ret = az_blob_req_url_encode(path, "?restype=container&comp=list",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}
	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;

err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blob_iter_type_process(struct xml_doc *xdoc,
			      const char *path,
			      const char *val,
			      void *cb_data)
{
	struct azure_blob *blob = (struct azure_blob *)cb_data;

	if (val == NULL) {
		return -EINVAL;
	}
	blob->is_page = (strcmp(val, BLOB_TYPE_PAGE) == 0);
	return 0;
}

/*
 * process a single blob list iteration at @iter, return -ENOENT if no such
 * iteration exists
 */
static int
az_rsp_blob_iter_process(struct xml_doc *xdoc,
			 const char *path,
			 const char *val,
			 void *cb_data)
{
	int ret;
	struct az_rsp_blob_list *blob_list_rsp
				= (struct az_rsp_blob_list *)cb_data;
	struct azure_blob *blob;

	/* request callback for subsequent blobs */
	ret = exml_path_cb_want(xdoc, "/EnumerationResults/Blobs/Blob",
				false, az_rsp_blob_iter_process,
				blob_list_rsp, NULL);
	if (ret < 0) {
		goto err_out;
	}

	blob = malloc(sizeof(*blob));
	if (blob == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(blob, 0, sizeof(*blob));

	ret = exml_str_want(xdoc, "./Name", true, &blob->name, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_uint64_want(xdoc, "./Properties/Content-Length", true,
			       &blob->len, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_val_cb_want(xdoc, "./Properties/BlobType", true,
			       az_rsp_blob_iter_type_process, blob, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	/* lease status is absent in snapshots */
	blob->lease_status = AOP_LEASE_STATUS_UNLOCKED;
	ret = exml_val_cb_want(xdoc, "./Properties/LeaseStatus", false,
			       az_rsp_iter_lease_status_process,
			       &blob->lease_status, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_date_time_want(xdoc, "./Properties/Last-Modified", true,
				  &blob->last_mod, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	ret = exml_str_want(xdoc, "./Properties/Content-Type", true,
			    &blob->content_type, NULL);
	if (ret < 0) {
		goto err_blob_free;
	}

	list_add_tail(&blob_list_rsp->blobs, &blob->list);
	blob_list_rsp->num_blobs++;

	return 0;

err_blob_free:
	free(blob);
err_out:
	return ret;
}

static int
az_rsp_blob_list_process(struct op *op,
			 struct az_rsp_blob_list *blob_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	assert(op->opcode == AOP_BLOB_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&blob_list_rsp->blobs);

	ret = exml_path_cb_want(xdoc, "/EnumerationResults/Blobs/Blob",
				false, az_rsp_blob_iter_process,
				blob_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_blobs_free;
	}

	exml_free(xdoc);
	return 0;

err_blobs_free:
	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob->content_type);
		free(blob);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static int
az_req_blob_put_hdr_fill(struct az_req_blob_put *blob_put_req,
			 const char *content_type,
			 struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}
	if (strcmp(blob_put_req->type, BLOB_TYPE_PAGE) == 0) {
		char *hdr_str;
		ret = op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = asprintf(&hdr_str, "%" PRIu64,
			       blob_put_req->pg_len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-blob-content-length",
					   hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (content_type != NULL) {
		/* XXX could also use Content-Type header */
		ret = op_req_hdr_add(op, "x-ms-blob-content-type",
				     content_type);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * if @data is NULL, then @page_len corresponds to the page blob length,
 * otherwise it is ignored and @data is uploaded as a block blob.
 */
int
az_req_blob_put(const struct az_blob_path *path,
		struct elasto_data *data,
		uint64_t page_len,
		const char *content_type,
		struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_blob_put *blob_put_req;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if ((data == NULL)
	 && (((page_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != page_len)) {
		ret = -EINVAL;
		goto err_out;
	} else if ((data != NULL) && (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_put_req = &ebo->req.blob_put;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	if (data == NULL) {
		blob_put_req->type = BLOB_TYPE_PAGE;
		blob_put_req->pg_len = page_len;
	} else {
		blob_put_req->type = BLOB_TYPE_BLOCK;
		op->req.data = data;
		/* TODO add a foreign flag so @req.data is not freed with @op */
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, NULL, &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_put_hdr_fill(blob_put_req, content_type, op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_req_blob_get_hdr_fill(struct az_req_blob_get *blob_get_req,
			 struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (blob_get_req->len > 0) {
		char *hdr_str;
		ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
			       blob_get_req->off,
			       (blob_get_req->off + blob_get_req->len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (strcmp(blob_get_req->type, BLOB_TYPE_PAGE) == 0) {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "PageBlob");
	} else {
		ret = op_req_hdr_add(op, "x-ms-blob-type", "BlockBlob");
	}
	if (ret < 0) {
		goto err_hdrs_free;
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * if @src_len is zero then ignore @req_off and retrieve entire blob
 */
int
az_req_blob_get(const struct az_blob_path *path,
		bool is_page,
		struct elasto_data *dest_data,
		uint64_t src_off,
		uint64_t src_len,
		struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_blob_get *blob_get_req;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	/* check for correct alignment */
	if (is_page
	 && ((((src_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != src_len)
	  || (((src_off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != src_off))) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_get_req = &ebo->req.blob_get;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	if (is_page) {
		blob_get_req->type = BLOB_TYPE_PAGE;
	} else {
		blob_get_req->type = BLOB_TYPE_BLOCK;
	}
	if (src_len > 0) {
		/* retrieve a specific range */
		blob_get_req->off = src_off;
		blob_get_req->len = src_len;
	}

	if (dest_data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = dest_data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	ret = az_blob_req_url_encode(path, NULL, &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_get_hdr_fill(blob_get_req, op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_req_page_put_hdr_fill(struct az_req_page_put *page_put_req,
			 struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
		       page_put_req->off,
		       (page_put_req->off + page_put_req->len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	if (page_put_req->clear_data) {
		ret = op_req_hdr_add(op, "x-ms-page-write", "clear");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else {
		ret = op_req_hdr_add(op, "x-ms-page-write", "update");
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}
/*
 * update or clear @dest_len bytes of page data at @dest_off.
 * if @src_data is null then clear the byte range, otherwise update.
 */
int
az_req_page_put(const struct az_blob_path *path,
		struct elasto_data *src_data,
		uint64_t dest_off,
		uint64_t dest_len,
		struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_page_put *page_put_req;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	/* check for correct alignment */
	if (((dest_len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != dest_len) {
		ret = -EINVAL;
		goto err_out;
	}
	if (((dest_off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != dest_off) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_PAGE_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	page_put_req = &ebo->req.page_put;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	page_put_req->off = dest_off;
	page_put_req->len = dest_len;
	if (src_data == NULL) {
		page_put_req->clear_data = true;
	} else {
		page_put_req->clear_data = false;
		op->req.data = src_data;
		/* TODO add a foreign flag so @req.data is not freed with @op */
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, "?comp=page",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_data_close;
	}

	ret = az_req_page_put_hdr_fill(page_put_req, op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data = NULL;
	}
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_block_put_free(struct az_req_block_put *blk_put_req)
{
	free(blk_put_req->blk_id);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV.
 * Note: For a given blob, the length of the value specified for the blockid
 *	 parameter must be the same size for each block.
 */
int
az_req_block_put(const struct az_blob_path *path,
		 const char *blk_id,
		 struct elasto_data *data,
		 struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_block_put *blk_put_req;
	char *b64_blk_id;
	char *url_params;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}
	if ((blk_id == NULL) || (strlen(blk_id) > 64)) {
		/*
		 * Prior to encoding, the string must be less than or equal to
		 * 64 bytes in size.
		 */
		dbg(0, "invalid blk_id: %s\n", blk_id);
		ret = -EINVAL;
		goto err_out;
	}
	if (data->len > BLOB_BLOCK_MAX) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOCK_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blk_put_req = &ebo->req.block_put;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	blk_put_req->blk_id = strdup(blk_id);
	if (blk_put_req->blk_id == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	ret = base64_html_encode(blk_id, strlen(blk_id), &b64_blk_id);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_data_close;
	}
	ret = asprintf(&url_params, "?comp=block&blockid=%s", b64_blk_id);
	free(b64_blk_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, url_params,
				     &op->url_host, &op->url_path);
	free(url_params);
	if (ret < 0) {
		goto err_data_close;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_data_close:
	op->req.data = NULL;
	free(blk_put_req->blk_id);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_req_block_list_put_hdr_fill(const char *content_type,
			       struct op *op)
{
	int ret;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (content_type != NULL) {
		/* XXX could also use Content-Type header */
		ret = op_req_hdr_add(op, "x-ms-blob-content-type",
				     content_type);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

#define AZ_REQ_BLK_LIST_PUT_PFX \
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>" \
		"<BlockList>"
/*
 * Prior to encoding, the blockid string must be less than or equal to 64 bytes
 * in size.
 */
#define AZ_REQ_BLK_LIST_PUT_ENT_MAXLEN ((64 * 4 / 3 + 4) \
					+ (2 * sizeof("</Uncommitted>")))
#define AZ_REQ_BLK_LIST_PUT_SFX "</BlockList>"

static int
az_req_block_list_put_body_fill(uint64_t num_blks,
				struct list_head *blks,
				struct elasto_data **req_data_out)
{
	int ret;
	struct azure_block *blk;
	char *xml_data;
	uint64_t buf_remain;
	struct elasto_data *req_data;

	buf_remain = sizeof(AZ_REQ_BLK_LIST_PUT_PFX)
				+ (num_blks * AZ_REQ_BLK_LIST_PUT_ENT_MAXLEN)
				+ sizeof(AZ_REQ_BLK_LIST_PUT_SFX);
	dbg(4, "allocating block list XML buffer len: %" PRIu64 "\n",
	    buf_remain);

	ret = elasto_data_iov_new(NULL, buf_remain, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	xml_data = (char *)req_data->iov.buf;
	ret = snprintf(xml_data, buf_remain, AZ_REQ_BLK_LIST_PUT_PFX);
	if ((ret < 0) || (ret >= buf_remain)) {
		dbg(0, "failed to fill blks-put prefix\n");
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	list_for_each(blks, blk, list) {
		const char *state;
		char *b64_id;

		switch(blk->state) {
		case BLOCK_STATE_COMMITED:
			state = "Committed";
			break;
		case BLOCK_STATE_UNCOMMITED:
			state = "Uncommitted";
			break;
		case BLOCK_STATE_LATEST:
			state = "Latest";
			break;
		default:
			ret = -EINVAL;
			goto err_buf_free;
			break;
		}
		ret = base64_encode(blk->id, strlen(blk->id), &b64_id);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_buf_free;
		}
		ret = snprintf(xml_data, buf_remain,
			       "<%s>%s</%s>", state, b64_id, state);
		free(b64_id);
		if ((ret < 0) || (ret >= buf_remain)) {
			dbg(0, "failed to fill blks-put entry\n");
			ret = -E2BIG;
			goto err_buf_free;
		}

		xml_data += ret;
		buf_remain -= ret;
	}

	ret = snprintf(xml_data, buf_remain, AZ_REQ_BLK_LIST_PUT_SFX);
	if ((ret < 0) || (ret >= buf_remain)) {
		dbg(0, "failed to fill blks-put suffix\n");
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending put block list req data: %s\n",
	    (char *)req_data->iov.buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_free(req_data);
err_out:
	return ret;
}

/*
 * @blks is a list of blocks to commit. It is not retained with the request.
 */
int
az_req_block_list_put(const struct az_blob_path *path,
		      uint64_t num_blks,
		      struct list_head *blks,
		      const char *content_type,
		      struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOCK_LIST_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, "?comp=blocklist",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_block_list_put_hdr_fill(content_type, op);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = az_req_block_list_put_body_fill(num_blks, blks, &op->req.data);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_rsp_block_list_get_free(struct az_rsp_block_list_get *blk_list_get_rsp)
{
	struct azure_block *blk;
	struct azure_block *blk_n;

	if (blk_list_get_rsp->num_blks == 0) {
		return;
	}

	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
}

/* request a list of all committed and uncommited blocks for @blob */
int
az_req_block_list_get(const struct az_blob_path *path,
		      struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOCK_LIST_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	ret = az_blob_req_url_encode(path, "?comp=blocklist&blocklisttype=all",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blk_iter_process(struct xml_doc *xdoc,
			const char *path,
			const char *val,
			void *cb_data)
{
	struct az_rsp_block_list_get *blk_list_get_rsp
			= (struct az_rsp_block_list_get *)cb_data;
	int ret;
	struct azure_block *blk;

	/* request callback for subsequent Block descriptors */
	ret = exml_path_cb_want(xdoc, "/BlockList/*/Block", false,
				az_rsp_blk_iter_process, blk_list_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	blk = malloc(sizeof(*blk));
	if (blk == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(blk, 0, sizeof(*blk));

	if (strstr(path, "/CommittedBlocks[") != NULL) {
		blk->state = BLOCK_STATE_COMMITED;
	} else if (strstr(path, "/UncommittedBlocks[") != NULL) {
		blk->state = BLOCK_STATE_UNCOMMITED;
	} else {
		dbg(0, "Unknown block state: %s\n", path);
		ret = -EINVAL;
		goto err_blk_free;
	}

	ret = exml_base64_want(xdoc, "./Name", true, &blk->id, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	ret = exml_uint64_want(xdoc, "./Size", true, &blk->len, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	list_add_tail(&blk_list_get_rsp->blks, &blk->list);
	blk_list_get_rsp->num_blks++;

	return 0;

err_blk_free:
	free(blk);
err_out:
	return ret;
}

static int
az_rsp_block_list_get_process(struct op *op,
			      struct az_rsp_block_list_get *blk_list_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct azure_block *blk;
	struct azure_block *blk_n;

	assert(op->opcode == AOP_BLOCK_LIST_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&blk_list_get_rsp->blks);

	/* trigger path callback for CommittedBlocks and UncommittedBlocks */
	ret = exml_path_cb_want(xdoc, "/BlockList/*/Block", false,
				az_rsp_blk_iter_process, blk_list_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_blks_free;
	}

	exml_free(xdoc);

	return 0;

err_blks_free:
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

int
az_req_blob_del(const struct az_blob_path *path,
		struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = az_blob_req_url_encode(path, NULL, &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_cp_free(struct az_req_blob_cp *blob_cp_req)
{
	az_blob_path_free(&blob_cp_req->src_path);
}

static int
az_req_blob_cp_hdr_fill(struct az_req_blob_cp *blob_cp_req,
			struct op *op)
{
	int ret;
	char *hdr_str;
	char *src_url_host = NULL;
	char *src_url_path = NULL;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = az_blob_req_url_encode(&blob_cp_req->src_path, NULL,
				     &src_url_host, &src_url_path);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	/*
	 * tell server to always use https when dealing with the src blob
	 * TODO: support copying from the file service
	 */
	ret = asprintf(&hdr_str, "https://%s%s", src_url_host, src_url_path);
	free(src_url_host);
	free(src_url_path);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-copy-source", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}
	/* common headers and signature added later */

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_req_blob_cp(const struct az_blob_path *src_path,
	       const struct az_blob_path *dst_path,
	       struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_blob_cp *blob_cp_req;

	if (!AZ_BLOB_PATH_IS_BLOB(src_path) || !AZ_BLOB_PATH_IS_BLOB(dst_path)
	 || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_CP, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_cp_req = &ebo->req.blob_cp;

	ret = az_blob_path_dup(src_path, &blob_cp_req->src_path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	ret = az_blob_path_dup(dst_path, &ebo->req.path);
	if (ret < 0) {
		goto err_src_path_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(dst_path, NULL,
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_dst_path_free;
	}

	ret = az_req_blob_cp_hdr_fill(blob_cp_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_dst_path_free:
	az_blob_path_free(&ebo->req.path);
err_src_path_free:
	az_blob_path_free(&blob_cp_req->src_path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_rsp_blob_prop_get_free(struct az_rsp_blob_prop_get *blob_prop_get_rsp)
{
	free(blob_prop_get_rsp->cp_id);
	free(blob_prop_get_rsp->content_type);
}

int
az_req_blob_prop_get(const struct az_blob_path *path,
		     struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_PROP_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_HEAD;
	ret = az_blob_req_url_encode(path, NULL, &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blob_prop_get_process(struct op *op,
			     struct az_rsp_blob_prop_get *blob_prop_get_rsp)
{
	int ret;
	char *hdr_val;

	assert(op->opcode == AOP_BLOB_PROP_GET);

	ret = op_hdr_date_time_val_lookup(&op->rsp.hdrs, "Last-Modified",
					  &blob_prop_get_rsp->last_mod);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-blob-type",
				&hdr_val);
	if (ret < 0) {
		goto err_out;
	}

	if (!strcmp(hdr_val, BLOB_TYPE_BLOCK)) {
		blob_prop_get_rsp->is_page = false;
	} else if (!strcmp(hdr_val, BLOB_TYPE_PAGE)) {
		blob_prop_get_rsp->is_page = true;
	} else {
		dbg(0, "unknown blob type %s\n", hdr_val);
		free(hdr_val);
		ret = -ENOTSUP;
		goto err_out;
	}
	free(hdr_val);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "Content-Length",
				    &blob_prop_get_rsp->len);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"Content-Type",
				&blob_prop_get_rsp->content_type);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-state",
				&hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = az_rsp_lease_state(hdr_val, &blob_prop_get_rsp->lease_state);
	free(hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-status",
				&hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = az_rsp_lease_status(hdr_val, &blob_prop_get_rsp->lease_status);
	free(hdr_val);
	if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-id",
				&blob_prop_get_rsp->cp_id);
	if (ret == -ENOENT) {
		/* cp ID only present if blob was a cp destination */
		goto done;
	} else if (ret < 0) {
		goto err_ctype_free;
	}

	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-copy-status",
				&hdr_val);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_cid_free;
	} else if (ret == 0) {
		ret = az_rsp_cp_status_map(hdr_val,
					   &blob_prop_get_rsp->cp_status);
		free(hdr_val);
		if (ret < 0) {
			goto err_cid_free;
		}
	}
done:
	return 0;

err_cid_free:
	free(blob_prop_get_rsp->cp_id);
err_ctype_free:
	free(blob_prop_get_rsp->content_type);
err_out:
	return ret;
}

static int
az_req_blob_prop_set_hdr_fill(struct az_req_blob_prop_set *blob_prop_set_req,
			      struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	if (blob_prop_set_req->is_page) {
		ret = asprintf(&hdr_str, "%" PRIu64, blob_prop_set_req->len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-blob-content-length", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/* page blob truncated to @len if @is_page is set, otherwise ignored */
int
az_req_blob_prop_set(const struct az_blob_path *path,
		     bool is_page,
		     uint64_t len,
		     struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_blob_prop_set *blob_prop_set_req;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (!is_page && (len != 0)) {
		dbg(0, "non-zero len for block blob invalid\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_BLOB_PROP_SET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_prop_set_req = &ebo->req.blob_prop_set;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	blob_prop_set_req->is_page = is_page;
	blob_prop_set_req->len = len;

	op->method = REQ_METHOD_PUT;
	ret = az_blob_req_url_encode(path, "?comp=properties",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_blob_prop_set_hdr_fill(blob_prop_set_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_req_blob_lease_free(struct az_req_blob_lease *blob_lease_req)
{
	free(blob_lease_req->lid);
}

static void
az_rsp_blob_lease_free(struct az_rsp_blob_lease *blob_lease_rsp)
{
	free(blob_lease_rsp->lid);
}

static int
az_req_blob_lease_hdr_fill(struct az_req_blob_lease *blob_lease_req,
			   const char *action_str,
			   struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = op_req_hdr_add(op, "x-ms-lease-action", action_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	if (blob_lease_req->action == AOP_LEASE_ACTION_ACQUIRE) {
		ret = asprintf(&hdr_str, "%d", blob_lease_req->duration);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-duration", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	} else if (blob_lease_req->action == AOP_LEASE_ACTION_BREAK) {
		ret = asprintf(&hdr_str, "%d", blob_lease_req->break_period);
		if (ret < 0) {
			goto err_hdrs_free;
		}
		ret = op_req_hdr_add(op, "x-ms-lease-break-period", hdr_str);
		free(hdr_str);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	if (blob_lease_req->lid != NULL) {
		ret = op_req_hdr_add(op, "x-ms-lease-id", blob_lease_req->lid);
		if (ret < 0) {
			goto err_hdrs_free;
		}
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

/*
 * @duration is the lease duration if @action=AOP_LEASE_ACTION_ACQUIRE.
 * It can either be -1 (indefinite), or between 15 and 60 seconds.
 * For @action=AOP_LEASE_ACTION_BREAK, @duration corresponds to the number of
 * seconds that the lease should continue before it is broken.
 */
int
az_req_blob_lease(const struct az_blob_path *path,
		  const char *lid,
		  const char *lid_proposed,
		  enum az_lease_action action,
		  int32_t duration,
		  struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct op *op;
	struct az_req_blob_lease *blob_lease_req;
	const char *action_str;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	action_str = az_req_lease_actn_enum_map(action);
	if (action_str == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	/* duration is only valid for AQUIRE and BREAK (as break period) */
	if ((action == AOP_LEASE_ACTION_ACQUIRE)
	 && ((duration != -1) && ((duration < 15) || (duration > 60)))) {
		dbg(1, "invalid lease duration: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	/* break period must be between 0 and 60 */
	if ((action == AOP_LEASE_ACTION_BREAK)
	 && ((duration < 0) || (duration > 60))) {
		dbg(1, "invalid break period: %d\n", duration);
		ret = -EINVAL;
		goto err_out;
	}

	if ((action == AOP_LEASE_ACTION_CHANGE) && (lid_proposed == NULL)) {
		dbg(1, "proposed lease ID required with action=change\n");
		ret = -EINVAL;
		goto err_out;
	} else if ((action != AOP_LEASE_ACTION_CHANGE)
			&& (action != AOP_LEASE_ACTION_ACQUIRE)
			&& (lid_proposed != NULL)) {
		dbg(1, "proposed lease ID only valid with "
		    "action=aquire|change\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (((action == AOP_LEASE_ACTION_RENEW)
			|| (action == AOP_LEASE_ACTION_CHANGE)
			|| (action == AOP_LEASE_ACTION_RELEASE))
							&& (lid == NULL)) {
		dbg(1, "lease ID required with action=renew|change|release\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* TODO validate lid GUID format */

	ret = az_blob_ebo_init(AOP_BLOB_LEASE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	blob_lease_req = &ebo->req.blob_lease;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	if (lid != NULL) {
		blob_lease_req->lid = strdup(lid);
		if (blob_lease_req->lid == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}
	}

	if (lid_proposed != NULL) {
		blob_lease_req->lid_proposed = strdup(lid_proposed);
		if (blob_lease_req->lid_proposed == NULL) {
			ret = -ENOMEM;
			goto err_lid_free;
		}
	}

	blob_lease_req->action = action;
	if (action == AOP_LEASE_ACTION_ACQUIRE) {
		blob_lease_req->duration = duration;
	} else if (action == AOP_LEASE_ACTION_BREAK) {
		blob_lease_req->break_period = duration;
	} else if (duration != 0) {
		dbg(0, "ignoring lease duration %d with action %s\n",
		    duration, action_str);
	}

	op->method = REQ_METHOD_PUT;
	op->url_https_only = false;
	ret = az_blob_req_url_encode(path, "?comp=lease",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_lid_prop_free;
	}

	ret = az_req_blob_lease_hdr_fill(blob_lease_req, action_str, op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_lid_prop_free:
	free(blob_lease_req->lid_proposed);
err_lid_free:
	free(blob_lease_req->lid);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
az_rsp_blob_lease_process(struct op *op,
			  struct az_rsp_blob_lease *blob_lease_rsp)
{
	int ret;

	assert(op->opcode == AOP_BLOB_LEASE);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "x-ms-lease-time",
				    &blob_lease_rsp->time_remaining);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}
	ret = op_hdr_val_lookup(&op->rsp.hdrs,
				"x-ms-lease-id",
				&blob_lease_rsp->lid);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static int
az_req_page_ranges_get_hdr_fill(
			struct az_req_page_ranges_get *page_ranges_get_req,
			struct op *op)
{
	int ret;
	char *hdr_str;

	ret = az_req_common_hdr_fill(op, false);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "bytes=%" PRIu64 "-%" PRIu64,
		       page_ranges_get_req->off,
		(page_ranges_get_req->off + page_ranges_get_req->len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_hdrs_free;
	}
	ret = op_req_hdr_add(op, "x-ms-range", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_hdrs_free;
	}

	return 0;

err_hdrs_free:
	op_hdrs_free(&op->req.hdrs);
err_out:
	return ret;
}

int
az_req_page_ranges_get(const struct az_blob_path *path,
		       uint64_t off,
		       uint64_t len,
		       struct op **_op)
{
	int ret;
	struct az_blob_ebo *ebo;
	struct az_req_page_ranges_get *page_ranges_get_req;
	struct op *op;

	if (!AZ_BLOB_PATH_IS_BLOB(path) || (_op == NULL) || (len == 0)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_blob_ebo_init(AOP_PAGE_RANGES_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	page_ranges_get_req = &ebo->req.page_ranges_get;

	ret = az_blob_path_dup(path, &ebo->req.path);
	if (ret < 0) {
		goto err_ebo_free;
	}

	page_ranges_get_req->off = off;
	page_ranges_get_req->len = len;

	op->method = REQ_METHOD_GET;
	ret = az_blob_req_url_encode(path, "?comp=pagelist",
				     &op->url_host, &op->url_path);
	if (ret < 0) {
		goto err_path_free;
	}

	ret = az_req_page_ranges_get_hdr_fill(page_ranges_get_req, op);
	if (ret < 0) {
		goto err_url_free;
	}

	op->req_sign = az_req_sign;

	*_op = op;
	return 0;
err_url_free:
	free(op->url_path);
	free(op->url_host);
err_path_free:
	az_blob_path_free(&ebo->req.path);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
az_rsp_page_ranges_get_free(struct az_rsp_page_ranges_get *page_ranges_get_rsp)
{
	struct az_page_range *range;
	struct az_page_range *range_n;

	if (page_ranges_get_rsp->num_ranges == 0) {
		return;
	}

	list_for_each_safe(&page_ranges_get_rsp->ranges, range, range_n, list) {
		free(range);
	}
}

static int
az_rsp_range_iter_process(struct xml_doc *xdoc,
			  const char *path,
			  const char *val,
			  void *cb_data)
{
	struct az_rsp_page_ranges_get *page_ranges_get_rsp
			= (struct az_rsp_page_ranges_get *)cb_data;
	int ret;
	struct az_page_range *range;

	/* request callback for subsequent PageRange entries */
	ret = exml_path_cb_want(xdoc, "/PageList/PageRange", false,
				az_rsp_range_iter_process, page_ranges_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_out;
	}

	range = malloc(sizeof(*range));
	if (range == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(range, 0, sizeof(*range));

	ret = exml_uint64_want(xdoc, "./Start", true, &range->start_byte, NULL);
	if (ret < 0) {
		goto err_range_free;
	}

	ret = exml_uint64_want(xdoc, "./End", true, &range->end_byte, NULL);
	if (ret < 0) {
		goto err_range_free;
	}

	list_add_tail(&page_ranges_get_rsp->ranges, &range->list);
	page_ranges_get_rsp->num_ranges++;

	return 0;

err_range_free:
	free(range);
err_out:
	return ret;
}

static int
az_rsp_page_ranges_get_process(struct op *op,
			struct az_rsp_page_ranges_get *page_ranges_get_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == AOP_PAGE_RANGES_GET);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	ret = op_hdr_u64_val_lookup(&op->rsp.hdrs,
				    "x-ms-blob-content-length",
				    &page_ranges_get_rsp->blob_len);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	list_head_init(&page_ranges_get_rsp->ranges);

	/* trigger path callback for first PageRange */
	ret = exml_path_cb_want(xdoc, "/PageList/PageRange", false,
				az_rsp_range_iter_process, page_ranges_get_rsp,
				NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_ranges_free;
	}

	exml_free(xdoc);

	return 0;

err_ranges_free:
	az_rsp_page_ranges_get_free(page_ranges_get_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
az_blob_req_free(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);

	az_blob_path_free(&ebo->req.path);

	switch (ebo->opcode) {
	case AOP_CONTAINER_LEASE:
		az_req_ctnr_lease_free(&ebo->req.ctnr_lease);
		break;
	case AOP_BLOCK_PUT:
		az_req_block_put_free(&ebo->req.block_put);
		break;
	case AOP_BLOB_CP:
		az_req_blob_cp_free(&ebo->req.blob_cp);
		break;
	case AOP_BLOB_LEASE:
		az_req_blob_lease_free(&ebo->req.blob_lease);
		break;
	case AOP_CONTAINER_LIST:
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_CONTAINER_PROP_GET:
	case AOP_BLOB_LIST:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOCK_LIST_GET:
	case AOP_BLOB_DEL:
	case AOP_BLOB_PROP_GET:
	case AOP_BLOB_PROP_SET:
	case AOP_PAGE_RANGES_GET:
		/* nothing more to free */
		break;
	default:
		assert(false);
		break;
	};
}

static void
az_blob_rsp_free(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);

	switch (ebo->opcode) {
	case AOP_CONTAINER_LIST:
		az_rsp_ctnr_list_free(&ebo->rsp.ctnr_list);
		break;
	case AOP_CONTAINER_LEASE:
		az_rsp_ctnr_lease_free(&ebo->rsp.ctnr_lease);
		break;
	case AOP_BLOB_LIST:
		az_rsp_blob_list_free(&ebo->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		az_rsp_block_list_get_free(&ebo->rsp.block_list_get);
		break;
	case AOP_BLOB_PROP_GET:
		az_rsp_blob_prop_get_free(&ebo->rsp.blob_prop_get);
		break;
	case AOP_BLOB_LEASE:
		az_rsp_blob_lease_free(&ebo->rsp.blob_lease);
		break;
	case AOP_PAGE_RANGES_GET:
		az_rsp_page_ranges_get_free(&ebo->rsp.page_ranges_get);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_CONTAINER_PROP_GET:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
	case AOP_BLOB_CP:
	case AOP_BLOB_PROP_SET:
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
az_blob_rsp_process(struct op *op)
{
	int ret;
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-ms-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case AOP_CONTAINER_LIST:
		ret = az_rsp_ctnr_list_process(op, &ebo->rsp.ctnr_list);
		break;
	case AOP_CONTAINER_PROP_GET:
		ret = az_rsp_ctnr_prop_get_process(op, &ebo->rsp.ctnr_prop_get);
		break;
	case AOP_CONTAINER_LEASE:
		ret = az_rsp_ctnr_lease_process(op, &ebo->rsp.ctnr_lease);
		break;
	case AOP_BLOB_LIST:
		ret = az_rsp_blob_list_process(op, &ebo->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		ret = az_rsp_block_list_get_process(op,
						    &ebo->rsp.block_list_get);
		break;
	case AOP_BLOB_PROP_GET:
		ret = az_rsp_blob_prop_get_process(op, &ebo->rsp.blob_prop_get);
		break;
	case AOP_BLOB_LEASE:
		ret = az_rsp_blob_lease_process(op, &ebo->rsp.blob_lease);
		break;
	case AOP_PAGE_RANGES_GET:
		ret = az_rsp_page_ranges_get_process(op,
						     &ebo->rsp.page_ranges_get);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
	case AOP_BLOB_CP:
	case AOP_BLOB_PROP_SET:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}

struct az_rsp_ctnr_list *
az_rsp_ctnr_list(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.ctnr_list;
}

struct az_rsp_ctnr_prop_get *
az_rsp_ctnr_prop_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.ctnr_prop_get;
}

struct az_rsp_ctnr_lease *
az_rsp_ctnr_lease_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.ctnr_lease;
}

struct az_rsp_blob_list *
az_rsp_blob_list(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.blob_list;
}

struct az_rsp_block_list_get *
az_rsp_block_list_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.block_list_get;
}

struct az_rsp_blob_prop_get *
az_rsp_blob_prop_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.blob_prop_get;
}

struct az_rsp_blob_lease *
az_rsp_blob_lease_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.blob_lease;
}

struct az_rsp_page_ranges_get *
az_rsp_page_ranges_get(struct op *op)
{
	struct az_blob_ebo *ebo = container_of(op, struct az_blob_ebo, op);
	return &ebo->rsp.page_ranges_get;
}
