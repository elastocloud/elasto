/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#include "lib/s3_req.h"
#include "lib/conn.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "lib/data_api.h"
#include "lib/file/file_api.h"
#include "lib/file/xmit.h"
#include "lib/file/handle.h"
#include "lib/file/token.h"
#include "s3_handle.h"
#include "s3_open.h"

#define S3_FOPEN_LOCATION_DEFAULT "eu-central-1"
/* default host. bkt is normally added as prefix for bkt and obj operations */
#define S3_FOPEN_HOST_DEFAULT "s3.amazonaws.com"

#define S3_URI_PREFIX "s3://"

/* _very_ basic URI host component parser. Doesn't come close to RFC 3986 */
static int
s3_fpath_uri_pull(const char *path,
		  char **_host,
		  char **_after_host)
{
	int ret;
	char *host;
	char *s = (char *)path;

	if (strncmp(s, S3_URI_PREFIX, sizeof(S3_URI_PREFIX) - 1) != 0) {
		ret = -EINVAL;
		goto err_out;
	}

	s += (sizeof(S3_URI_PREFIX) - 1);

	while (*s == '/')
		s++;

	if (*s == '\0') {
		ret = -EINVAL;
		goto err_out;
	}

	host = strdup(s);
	if (host == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(host, '/');
	if (s == NULL) {
		/* host only */
		ret = -EINVAL;
		goto err_host_free;
	}

	*(s++) = '\0';	/* null term for host */
	*_host = host;
	*_after_host = s;

	return 0;

err_host_free:
	free(host);
err_out:
	return ret;
}

int
s3_fpath_parse(const char *path,
	       struct elasto_fh_s3_path *s3_path)
{
	int ret;
	char *s;
	char *host = NULL;
	char *comp1 = NULL;
	char *comp2 = NULL;

	if ((path == NULL) || (s3_path == NULL)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (strstr(path, "://")) {
		char *after_host;
		ret = s3_fpath_uri_pull(path, &host, &after_host);
		if (ret < 0) {
			goto err_out;
		}
		s = after_host;
	} else {
		s = (char *)path;

		host = strdup(S3_FOPEN_HOST_DEFAULT);
		if (host == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		goto done;
	}

	comp1 = strdup(s);
	if (comp1 == NULL) {
		ret = -ENOMEM;
		goto err_host_free;
	}

	s = strchr(comp1, '/');
	if (s == NULL) {
		/* bucket only */
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* bucket + slashes only */
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s != NULL) {
		dbg(0, "Invalid remote path: S3 object has trailing garbage");
		ret = -EINVAL;
		goto err_2_free;
	}
done:
	s3_path->host = host;
	s3_path->bkt = comp1;
	s3_path->obj = comp2;
	dbg(2, "parsed %s as S3 path: host=%s, bkt=%s, obj=%s\n",
	    path, s3_path->host, (s3_path->bkt ? s3_path->bkt : ""),
	    (s3_path->obj ? s3_path->obj : ""));

	return 0;

err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_host_free:
	free(comp1);
err_out:
	return ret;
}

void
s3_fpath_free(struct elasto_fh_s3_path *s3_path)
{
	free(s3_path->host);
	s3_path->host = NULL;
	free(s3_path->bkt);
	s3_path->bkt = NULL;
	free(s3_path->obj);
	s3_path->obj = NULL;
}

static int
s3_fopen_obj(struct s3_fh *s3_fh,
	     struct elasto_conn *conn,
	     uint64_t flags)
{
	int ret;
	struct op *op;

	if (flags & ELASTO_FOPEN_DIRECTORY) {
		dbg(1, "attempt to open object with directory flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = s3_req_obj_head(s3_fh->path.bkt,
			      s3_fh->path.obj,
			      &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret < 0) && op_rsp_error_match(op, 404)
					&& (flags & ELASTO_FOPEN_CREATE)) {
		struct elasto_data data;

		/* put a zero length object */
		dbg(4, "path not found, creating\n");
		op_free(op);
		memset(&data, 0, sizeof(data));
		data.type = ELASTO_DATA_IOV;
		ret = s3_req_obj_put(s3_fh->path.bkt, s3_fh->path.obj,
				     &data, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
	} else if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fopen_bkt(struct s3_fh *s3_fh,
	     struct elasto_conn *conn,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct op *op;

	if ((flags & ELASTO_FOPEN_DIRECTORY) == 0) {
		dbg(1, "attempt to open bucket without dir flag set\n");
		ret = -EINVAL;
		goto err_out;
	}

	ret = s3_req_bkt_loc_get(s3_fh->path.bkt, &op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if ((ret == 0) && (flags & ELASTO_FOPEN_CREATE)
					&& (flags & ELASTO_FOPEN_EXCL)) {
		dbg(1, "path already exists, but exclusive create specified\n");
		ret = -EEXIST;
		goto err_op_free;
	} else if ((ret < 0) && op_rsp_error_match(op, 404)
					&& (flags & ELASTO_FOPEN_CREATE)) {
		const char *location;

		dbg(4, "path not found, creating\n");
		op_free(op);

		ret = elasto_ftoken_find(open_toks,
					 ELASTO_FOPEN_TOK_CREATE_AT_LOCATION,
					 &location);
		if (ret == -ENOENT) {
			location = S3_FOPEN_LOCATION_DEFAULT;
			dbg(1, "location token not specified for new bucket "
			    "%s, using default: %s\n",
			    s3_fh->path.bkt, location);
		}

		ret = s3_req_bkt_create(s3_fh->path.bkt,
					location, &op);
		if (ret < 0) {
			goto err_out;
		}

		ret = elasto_fop_send_recv(conn, op);
		if (ret < 0) {
			goto err_op_free;
		}
	} else if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

static int
s3_fopen_root(struct s3_fh *s3_fh,
	      struct elasto_conn *conn,
	      uint64_t flags)
{
	int ret;
	struct op *op;

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
	 * XXX use the heavy-weight GET Service request to check that
	 * the subscription information is correct at open time.
	 */
	ret = s3_req_svc_list(&op);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_fop_send_recv(conn, op);
	if (ret < 0) {
		goto err_op_free;
	}

	ret = 0;
err_op_free:
	op_free(op);
err_out:
	return ret;
}

int
s3_fopen(void *mod_priv,
	 struct elasto_conn *conn,
	 const char *path,
	 uint64_t flags,
	 struct elasto_ftoken_list *open_toks)
{
	int ret;
	struct s3_fh *s3_fh = mod_priv;

	ret = s3_fpath_parse(path, &s3_fh->path);
	if (ret < 0) {
		goto err_out;
	}

	if (s3_fh->path.obj != NULL) {
		ret = s3_fopen_obj(s3_fh, conn, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	} else if (s3_fh->path.bkt != NULL) {
		ret = s3_fopen_bkt(s3_fh, conn, flags, open_toks);
		if (ret < 0) {
			goto err_path_free;
		}
	} else {
		ret = s3_fopen_root(s3_fh, conn, flags);
		if (ret < 0) {
			goto err_path_free;
		}
	}

	return 0;

err_path_free:
	s3_fpath_free(&s3_fh->path);
err_out:
	return ret;
}

int
s3_fclose(void *mod_priv,
	  struct elasto_conn *conn)
{
	struct s3_fh *s3_fh = mod_priv;

	s3_fpath_free(&s3_fh->path);

	return 0;
}
