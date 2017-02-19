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
#include "lib/azure_fs_path.h"
#include "lib/azure_fs_req.h"
#include "lib/azure_mgmt_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "afs_handle.h"
#include "afs_open.h"

#define AFS_FOPEN_LOCATION_DEFAULT "West Europe"

static int
afs_acc_key_get(struct afs_fh *afs_fh,
		char **_acc_key)
{
	int ret;
	struct op *op;
	struct az_mgmt_rsp_acc_keys_get *acc_keys_get_rsp;
	char *acc_key;

	if (afs_fh->mgmt_conn == NULL) {
		dbg(0, "mgmt connection required for Azure IO conn\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_mgmt_req_acc_keys_get(afs_fh->sub_id, afs_fh->path.acc, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
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
afs_io_conn_init(struct event_base *ev_base,
		 struct afs_fh *afs_fh,
		 struct elasto_conn **_io_conn)
{
	int ret;
	char *url_host;
	struct elasto_conn *io_conn;

	if ((afs_fh->acc_access_key == NULL) && (afs_fh->mgmt_conn != NULL)) {
		ret = afs_acc_key_get(afs_fh, &afs_fh->acc_access_key);
		if (ret < 0) {
			dbg(0, "failed to get account access key\n");
			goto err_out;
		}
		/* access key freed with afs_fh */
	} else if (afs_fh->acc_access_key == NULL) {
		dbg(0, "no account access key available for AFS IO conn\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_hostname_get(afs_fh->path.acc, &url_host);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_init_az(ev_base, NULL, afs_fh->insecure_http,
				  url_host, &io_conn);
	free(url_host);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_conn_sign_setkey(io_conn, afs_fh->path.acc,
				      afs_fh->acc_access_key);
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
afs_fopen_file(struct afs_fh *afs_fh,
	       uint64_t flags)
{
	int ret;
	struct op *op;
	bool created = false;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open file with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_file_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "file already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "file not found, creating\n");
		op_free(op);
		ret = az_fs_req_file_create(&afs_fh->path,
					    0,	/* initial size */
					    &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(afs_fh->io_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		created = true;
		goto done;
	} else if (ret < 0) {
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
afs_fopen_dir(struct afs_fh *afs_fh,
	      uint64_t flags)
{
	int ret;
	struct op *op;
	bool created = false;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open dir without directory flag\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_dir_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_fs_req_dir_create(&afs_fh->path, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(afs_fh->io_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
		created = true;
		goto done;
	} else if (ret < 0) {
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
afs_fopen_share(struct afs_fh *afs_fh,
		uint64_t flags)
{
	int ret;
	struct op *op;
	bool created = false;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open share without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = az_fs_req_share_prop_get(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret == -ENOENT) && (flags & ELASTO_FOPEN_CREATE)) {
		dbg(4, "path not found, creating\n");
		op_free(op);
		ret = az_fs_req_share_create(&afs_fh->path,
					     AZ_FS_SHARE_QUOTA_MAX_GB, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(afs_fh->io_conn, op);
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

static int
afs_fopen_acc_create_wait(struct afs_fh *afs_fh,
			  const char *req_id)
{
	struct op *op;
	int i;
	enum az_req_status status;
	int err_code;
	int ret;

	for (i = 0; i < APB_OP_POLL_TIMEOUT; i++) {
		struct az_mgmt_rsp_status_get *sts_get_rsp;

		ret = az_mgmt_req_status_get(afs_fh->sub_id, req_id, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
		if (ret < 0) {
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

/* FIXME duplicate of apb_fopen_acc */
static int
afs_fopen_acc_create(struct afs_fh *afs_fh,
		     uint64_t flags,
		     struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;

	assert(flags & ELASTO_FOPEN_CREATE);

	if (afs_fh->mgmt_conn == NULL) {
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

	ret = az_mgmt_req_acc_prop_get(afs_fh->sub_id, afs_fh->path.acc,
				       &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
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
			location = AFS_FOPEN_LOCATION_DEFAULT;
			dbg(1, "location token not specified for new account "
			    "%s, using default: %s\n",
			    afs_fh->path.acc, location);
		}

		ret = az_mgmt_req_acc_create(afs_fh->sub_id,
					     afs_fh->path.acc,
					     afs_fh->path.acc, /* label */
					     NULL,	       /* description */
					     NULL,	       /* affin group */
					     location,
					     &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
		if (ret < 0) {
			goto err_op_free;
		}

		if (op->rsp.err_code == 202) {
			ret = afs_fopen_acc_create_wait(afs_fh,
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

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
afs_fopen_acc_existing(struct afs_fh *afs_fh,
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

	ret = az_fs_req_shares_list(&afs_fh->path, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->io_conn, op);
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
afs_fopen_root(struct afs_fh *afs_fh,
	       uint64_t flags)
{
	int ret;
	struct op *op;

	if (afs_fh->mgmt_conn == NULL) {
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
	ret = az_mgmt_req_acc_list(afs_fh->sub_id, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(afs_fh->mgmt_conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = ELASTO_FOPEN_RET_EXISTED;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
afs_fopen(struct event_base *ev_base,
	  void *mod_priv,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct afs_fh *afs_fh = mod_priv;

	ret = az_fs_path_parse(path, &afs_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (afs_fh->pem_path != NULL) {
		char *mgmt_host;
		/*
		 * for Publish Settings credentials, a mgmt connection is
		 * required to obtain account keys, or perform root / account
		 * manipulation.
		 * A connection to the account host for share / file IO is
		 * opened later if needed (non-root).
		 */
		ret = az_mgmt_req_hostname_get(&mgmt_host);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_conn_init_az(ev_base, afs_fh->pem_path, false,
					  mgmt_host, &afs_fh->mgmt_conn);
		free(mgmt_host);
		if (ret < 0) {
			goto err_path_free;
		}
	} else {
		/* checked in afs_fh_init() */
		assert(afs_fh->acc_access_key != NULL);
	}

	if (afs_fh->path.fs_ent != NULL) {
		ret = afs_io_conn_init(ev_base, afs_fh, &afs_fh->io_conn);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		if (flags & ELASTO_FOPEN_DIRECTORY) {
			ret = afs_fopen_dir(afs_fh, flags);
		} else {
			ret = afs_fopen_file(afs_fh, flags);
		}
		if (ret < 0) {
			goto err_io_conn_free;
		}
	} else if (afs_fh->path.share != NULL) {
		ret = afs_io_conn_init(ev_base, afs_fh, &afs_fh->io_conn);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		ret = afs_fopen_share(afs_fh, flags);
		if (ret < 0) {
			goto err_io_conn_free;
		}
	} else if (afs_fh->path.acc != NULL) {
		if (flags & ELASTO_FOPEN_CREATE) {
			ret = afs_fopen_acc_create(afs_fh, flags, open_toks);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}

			/*
			 * IO conn not needed for mgmt reqs, but in case of readdir
			 * (List Shares).
			 */
			ret = afs_io_conn_init(ev_base, afs_fh,
					       &afs_fh->io_conn);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}
			ret = ELASTO_FOPEN_RET_CREATED;
		} else {
			ret = afs_io_conn_init(ev_base, afs_fh,
					       &afs_fh->io_conn);
			if (ret < 0) {
				goto err_mgmt_conn_free;
			}

			ret = afs_fopen_acc_existing(afs_fh, flags, open_toks);
			if (ret < 0) {
				goto err_io_conn_free;
			}
			ret = ELASTO_FOPEN_RET_EXISTED;
		}
	} else {
		ret = afs_fopen_root(afs_fh, flags);
		if (ret < 0) {
			goto err_mgmt_conn_free;
		}

		/* IO conn not needed */
	}
	afs_fh->open_flags = flags;

	return ret;

err_io_conn_free:
	elasto_conn_free(afs_fh->io_conn);
err_mgmt_conn_free:
	elasto_conn_free(afs_fh->mgmt_conn);
err_path_free:
	az_fs_path_free(&afs_fh->path);
err_out:
	return ret;
}

int
afs_fclose(void *mod_priv)
{
	struct afs_fh *afs_fh = mod_priv;

	/* @io_conn may be null (root opens) */
	elasto_conn_free(afs_fh->io_conn);
	elasto_conn_free(afs_fh->mgmt_conn);
	az_fs_path_free(&afs_fh->path);

	return 0;
}
