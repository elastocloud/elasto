/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
#ifndef _HANDLE_H_
#define _HANDLE_H_

struct elasto_fh_az_path {
	char *acc;
	char *ctnr;
	char *blob;
};

struct elasto_fh_s3_path {
	char *bkt;
	char *obj;
};

#define ELASTO_FH_MAGIC "ElastoF"

struct elasto_fh_priv {
	char magic[8];
	struct elasto_conn *conn;
	enum elasto_ftype type;
	union {
		struct {
			struct elasto_fh_az_path path;
			char *pem_path;
			char *sub_id;
			char *sub_name;
			char *lid;
		} az;
		struct {
			struct elasto_fh_s3_path path;
		} s3;
	};
	uint64_t len;
	enum {
		ELASTO_FH_LEASE_NONE = 0,
		ELASTO_FH_LEASE_ACQUIRED,
	} lease_state;
};

int
elasto_fh_init(const char *ps_path,
	       bool insecure_http,
	       struct elasto_fh **_fh);

void
elasto_fh_free(struct elasto_fh *fh);

struct elasto_fh_priv *
elasto_fh_validate(struct elasto_fh *fh);

#endif /* _HANDLE_H_ */
