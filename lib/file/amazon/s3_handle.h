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
#ifndef _S3_HANDLE_H_
#define _S3_HANDLE_H_

struct s3_fh {
	struct elasto_s3_path path;
	char *iam_user;
	char *key_id;
	char *secret;
	bool insecure_http;
	struct elasto_conn *conn;
};

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_conn **_conn,
			struct elasto_fh_mod_ops *mod_ops);

void
s3_fh_free(void *mod_priv);

#endif /* _S3_HANDLE_H_ */
