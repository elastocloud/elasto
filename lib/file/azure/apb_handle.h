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

struct apb_fh {
	struct elasto_fh_az_path path;
	char *pem_path;
	char *sub_id;
	char *sub_name;
};

int
apb_fh_init(const struct elasto_fauth *auth,
	    void **_fh_priv,
	    struct elasto_conn **_conn,
	    struct elasto_fh_mod_ops *mod_ops);

void
apb_fh_free(void *mod_priv);

#endif /* _APB_HANDLE_H_ */
