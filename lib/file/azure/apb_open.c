/*
 * Copyright (C) SUSE LINUX GmbH 2015-2016, all rights reserved.
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
#include <inttypes.h>
#include <sys/stat.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/azure_req.h"
#include "lib/azure_blob_path.h"
#include "lib/azure_blob_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "elasto/file.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "apb_handle.h"
#include "apb_open.h"

#define APB_FOPEN_LOCATION_DEFAULT "West Europe"

static int
apb_acc_key_get(struct apb_fh *apb_fh,
		char **_acc_key)
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp;
	char *acc_key;

	if (apb_fh->mgmt_conn == NULL) {
		dbg(0, "mgmt connection required for Azure IO conn\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_req_acc_keys_get(apb_fh->sub_id, apb_fh->path.acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	acc_keys_get_rsp = az_mgmt_rsp_acc_keys_get(op);

	acc_key = strdup(acc_keys_get_rsp->primary);
	if (acc_key == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	*_acc_key = acc_key;
	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_io_conn_init(struct event_base *ev_base,
		 struct apb_fh *apb_fh,
		 struct elasto_conn **_io_conn)
{
	int ret;
	struct elasto_conn *io_conn;

	if ((apb_fh->acc_access_key == NULL) && (apb_fh->mgmt_conn != NULL)) {
		ret = apb_acc_key_get(apb_fh, &apb_fh->acc_access_key);
		if (ret < 0) {
			dbg(0, "failed to get account access key\n");
			goto err_out;
		}
		/* access key freed with apb_fh */
	} else if (apb_fh->acc_access_key == NULL) {
		dbg(0, "no account access key available for IO conn\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* pem_file not needed for IO conn */
	ret = elasto_conn_init_az(ev_base, NULL, apb_fh->insecure_http,
				  apb_fh->path.host, apb_fh->path.port,
				  &io_conn);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_sign_setkey(io_conn, apb_fh->path.acc,
				      apb_fh->acc_access_key);
	if (ret < 0) {
		goto err_conn_free;
	}

	*_io_conn = io_conn;

	return 0;

err_conn_free:
	elasto_conn_free(io_conn);
err_out:
	return ret;
}

static int
apb_fopen_blob(struct apb_fh *apb_fh,
	       uint64_t flags,
	       struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;
	bool created = false;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open blob with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_prop_get(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		const char *content_type = NULL;

		dbg(4, "path not found, creating\n");
		op_free(op);

		ret = elasto_ftoken_find(open_toks,
					 ELASTO_FOPEN_TOK_CREATE_CONTENT_TYPE,
					 &content_type);
		if ((ret < 0) && (ret != -ENOENT)) {
			goto err_out;
		}
		/* content_type remains NULL on -ENOENT */

		ret = az_req_blob_put(&apb_fh->path, NULL, 0, content_type, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(apb_fh->io_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		created = true;
		goto done;
	} else if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		goto err_op_free;
	}

	if (!blob_prop_get_rsp->is_page) {
		dbg(0, "invalid request to open non-page blob via page blob "
		    "backend\n");
		ret = -EINVAL;
		goto err_op_free;
	}

done:
	ret = (created ? ELASTO_FOPEN_RET_CREATED : ELASTO_FOPEN_RET_EXISTED);
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
abb_fopen_blob(struct apb_fh *apb_fh,
	       uint64_t flags,
	       struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;
	struct az_rsp_blob_prop_get *blob_prop_get_rsp;
	bool created = false;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open blob with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_blob_prop_get(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		struct elasto_data *data;
		const char *content_type = NULL;

		/* put a zero length block blob */
		dbg(4, "path not found, creating\n");
		op_free(op);

		ret = elasto_ftoken_find(open_toks,
					 ELASTO_FOPEN_TOK_CREATE_CONTENT_TYPE,
					 &content_type);
		if ((ret < 0) && (ret != -ENOENT)) {
			goto err_out;
		}
		/* content_type remains NULL on -ENOENT */

		ret = elasto_data_iov_new(NULL, 0, false, &data);
		if (ret < 0) {
			goto err_out;
		}
		ret = az_req_blob_put(&apb_fh->path, data, 0, content_type,
				      &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(apb_fh->io_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		created = true;
		goto done;
	} else if (ret < 0) {
		goto err_op_free;
	}

	blob_prop_get_rsp = az_rsp_blob_prop_get(op);
	if (blob_prop_get_rsp == NULL) {
		ret = -ENOMEM;
		goto err_op_free;
	}

	if (blob_prop_get_rsp->is_page) {
		dbg(0, "invalid request to open page blob via block blob "
		    "backend\n");
		ret = -EINVAL;
		goto err_op_free;
	}

done:
	ret = (created ? ELASTO_FOPEN_RET_CREATED : ELASTO_FOPEN_RET_EXISTED);
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fopen_ctnr(struct apb_fh *apb_fh,
	       uint64_t flags)
{
	int ret;
	struct op *op;
	bool created = false;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open container without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_ctnr_prop_get(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_req_ctnr_create(&apb_fh->path, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(apb_fh->io_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		created = true;
	} else if (ret < 0) {
		goto err_op_free;
	}

	ret = (created ? ELASTO_FOPEN_RET_CREATED : ELASTO_FOPEN_RET_EXISTED);
err_op_free:
	op_free(op);
err_out:
	return ret;
}

#define APB_OP_POLL_PERIOD 2
#define APB_OP_POLL_TIMEOUT 10	/* multiplied by APB_OP_POLL_PERIOD */

/* FIXME duplicate of cli_op_wait() */
static int
apb_fopen_acc_create_wait(struct apb_fh *apb_fh,
			  const char *req_id)
{
	struct op *op;
	int i;
	enum az_req_status status;
	int err_code;
	int ret;

	for (i = 0; i < APB_OP_POLL_TIMEOUT; i++) {
		struct az_mgmt_rsp_status_get *sts_get_rsp;

		ret = az_mgmt_req_status_get(apb_fh->sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_conn_op_txrx(apb_fh->mgmt_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.is_error) {
			ret = -EIO;
			dbg(0, "failed get status response: %d\n",
			       op->rsp.err_code);
			goto err_op_free;
		}

		sts_get_rsp = az_mgmt_rsp_status_get(op);
		if (sts_get_rsp == NULL) {
			ret = -ENOMEM;
			goto err_op_free;
		}

		if (sts_get_rsp->status != AOP_STATUS_IN_PROGRESS) {
			status = sts_get_rsp->status;
			if (sts_get_rsp->status == AOP_STATUS_FAILED) {
				err_code = sts_get_rsp->err.code;
			}
			op_free(op);
			break;
		}

		op_free(op);

		sleep(APB_OP_POLL_PERIOD);
	}

	if (i >= APB_OP_POLL_TIMEOUT) {
		dbg(0, "timeout waiting for req %s to complete\n", req_id);
		ret = -ETIMEDOUT;
		goto err_out;
	}
	if (status == AOP_STATUS_FAILED) {
		ret = -EIO;
		dbg(0, "failed async response: %d\n", err_code);
		goto err_out;
	} else {
		dbg(3, "create completed successfully\n");
	}

	return 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fopen_acc_create(struct apb_fh *apb_fh,
		     uint64_t flags,
		     struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;

	assert(flags & ELASTO_FOPEN_CREATE);

	if (apb_fh->mgmt_conn == NULL) {
		dbg(0, "Account creation requires Publish Settings "
		       "credentials\n");
		ret = -EINVAL;
		goto err_out;
	}

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open account without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_req_acc_prop_get(apb_fh->sub_id, apb_fh->path.acc,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if (ret == -ENOENT) {
		const char *location;

		dbg(4, "path not found, creating\n");
		op_free(op);

		ret = elasto_ftoken_find(open_toks,
					 ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					 &location);
		if (ret == -ENOENT) {
			location = APB_FOPEN_LOCATION_DEFAULT;
			dbg(1, "location token not specified for new account "
			    "%s, using default: %s\n",
			    apb_fh->path.acc, location);
		} else if (ret < 0) {
			goto err_out;
		}

		ret = az_mgmt_req_acc_create(apb_fh->sub_id,
					     apb_fh->path.acc,
					     apb_fh->path.acc, /* label */
					     NULL,	       /* description */
					     NULL,	       /* affin group */
					     location,
					     &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.err_code == 202) {
			ret = apb_fopen_acc_create_wait(apb_fh,
							op->rsp.req_id);
			if (ret < 0) {
				goto err_op_free;
			}
		}
	} else if (ret < 0) {
		dbg(4, "failed to retrieve account properties: %s\n",
		    strerror(-ret));
		goto err_op_free;
	}

	ret = ELASTO_FOPEN_RET_CREATED;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fopen_acc_existing(struct apb_fh *apb_fh,
		       uint64_t flags,
		       struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;

	assert((flags & ELASTO_FOPEN_CREATE) == 0);

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open account without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_req_ctnr_list(&apb_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->io_conn, op);
	if (ret < 0) {
		dbg(4, "failed to list account on open: %s\n", strerror(-ret));
		goto err_op_free;
	}

	ret = ELASTO_FOPEN_RET_EXISTED;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_fopen_root(struct apb_fh *apb_fh,
	       uint64_t flags)
{
	int ret;
	struct op *op;

	if (apb_fh->mgmt_conn == NULL) {
		dbg(0, "Root open requires Publish Settings credentials\n");
		ret = -EINVAL;
		goto err_out;
	}

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open account without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	if (flags & (ELASTO_FOPEN_CREATE | ELASTO_FOPEN_EXCL)) {
		dbg(1, "invalid flag for root open\n");
		ret = -EINVAL;
		goto err_out;
	}

	/*
	 * XXX use the heavy-weight List Storage Accounts request to check that
	 * the subscription information is correct at open time.
	 */
	ret = az_mgmt_req_acc_list(apb_fh->sub_id, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(apb_fh->mgmt_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = ELASTO_FOPEN_RET_EXISTED;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
apb_abb_fopen(struct event_base *ev_base,
	      void *mod_priv,
	      const char *host,
	      uint16_t port,
	      const char *path,
	      uint64_t flags,
	      struct elasto_ftoken_list *open_toks,
	      bool page_blob)
{
	int ret;
	struct apb_fh *apb_fh = mod_priv;

	/* apb_fh->insecure_http set in fh_init */
	ret = az_blob_path_parse(host, port, path, apb_fh->insecure_http,
				 &apb_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (apb_fh->pem_path != NULL) {
		/*
		 * for Publish Settings credentials, a mgmt connection is
		 * required to obtain account keys, or perform root / account
		 * manipulation.
		 * A connection to the account host for ctnr / blob IO is
		 * opened later if needed (non-root).
		 */
		if (apb_fh->path.host_is_custom) {
			dbg(0, "custom host not supported with PEM auth\n");
			ret = -EINVAL;
			goto err_path_free;
		}

		ret = elasto_conn_init_az(ev_base, apb_fh->pem_path, false,
					  AZ_BLOB_PATH_HOST_MGMT, 443,
					  &apb_fh->mgmt_conn);
		if (ret < 0) {
			goto err_path_free;
		}
	} else {
		/* checked in apb_fh_init() */
		assert(apb_fh->acc_access_key != NULL);
	}

	if (apb_fh->path.blob != NULL) {
		ret = apb_io_conn_init(ev_base, apb_fh, &apb_fh->io_conn);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		if (page_blob) {
			ret = apb_fopen_blob(apb_fh, flags, open_toks);
		} else {
			ret = abb_fopen_blob(apb_fh, flags, open_toks);
		}
		if (ret < 0) {
			goto err_io_conn_free;
		}
	} else if (apb_fh->path.ctnr != NULL) {
		ret = apb_io_conn_init(ev_base, apb_fh, &apb_fh->io_conn);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		ret = apb_fopen_ctnr(apb_fh, flags);
		if (ret < 0) {
			goto err_io_conn_free;
		}
	} else if (apb_fh->path.acc != NULL) {
		if (flags & ELASTO_FOPEN_CREATE) {
			ret = apb_fopen_acc_create(apb_fh, flags, open_toks);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}

			ret = apb_io_conn_init(ev_base, apb_fh,
					       &apb_fh->io_conn);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}
			ret = ELASTO_FOPEN_RET_CREATED;
		} else {
			ret = apb_io_conn_init(ev_base, apb_fh,
					       &apb_fh->io_conn);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}

			ret = apb_fopen_acc_existing(apb_fh, flags, open_toks);
			if (ret < 0) {
				goto err_io_conn_free;
			}
			ret = ELASTO_FOPEN_RET_EXISTED;
		}
	} else {
		ret = apb_fopen_root(apb_fh, flags);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		/* IO conn not needed */
	}

	return ret;

err_io_conn_free:
	elasto_conn_free(apb_fh->io_conn);
err_mgmt_conn_free:
	elasto_conn_free(apb_fh->mgmt_conn);
err_path_free:
	az_blob_path_free(&apb_fh->path);
err_out:
	return ret;
}

int
apb_fopen(struct event_base *ev_base,
	  void *mod_priv,
	  const char *host,
	  uint16_t port,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	return apb_abb_fopen(ev_base, mod_priv, host, port, path, flags,
			     open_toks, true);
}

int
apb_fclose(void *mod_priv)
{
	struct apb_fh *apb_fh = mod_priv;

	/* @io_conn may be null (root opens) */
	elasto_conn_free(apb_fh->io_conn);
	elasto_conn_free(apb_fh->mgmt_conn);
	az_blob_path_free(&apb_fh->path);

	return 0;
}

int
abb_fopen(struct event_base *ev_base,
	  void *mod_priv,
	  const char *host,
	  uint16_t port,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	return apb_abb_fopen(ev_base, mod_priv, host, port, path, flags,
			     open_toks, false);
}
