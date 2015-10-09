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
#ifndef _APB_HANDLE_H_
#define _APB_HANDLE_H_

struct elasto_fh_az_path {
	char *acc;
	char *ctnr;
	char *blob;
};

/**
 * Azure Blob Service private handle
 *
 * @path: componentised path.
 * @pem_path: local path to PEM Publish Settings credentials file. May be NULL
 *	      if access key was provided instead of Publish Settings file.
 * @sub_id: Subscription ID. NULL if access key auth.
 * @sub_name: Subscription name. NULL if access key auth.
 * @acc_access_key: Account access key.
 * @insecure_http: Use HTTP instead of HTTPS where applicable.
 * @mgmt_conn: Connection to Management service. NULL if access key auth.
 * @io_conn: Connection to Azure File Service.
 */
struct apb_fh {
	struct elasto_fh_az_path path;
	char *pem_path;
	char *sub_id;
	char *sub_name;
	char *acc_access_key;
	bool insecure_http;
	struct elasto_conn *mgmt_conn;
	struct elasto_conn *io_conn;
};

/* module entry point */
int
elasto_file_mod_fh_init(const struct elasto_fauth *auth,
			void **_fh_priv,
			struct elasto_fh_mod_ops *mod_ops);

void
apb_fh_free(void *mod_priv);

#endif /* _APB_HANDLE_H_ */
