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
#ifndef _APB_OPEN_H_
#define _APB_OPEN_H_

int
apb_fpath_parse(const char *path,
		struct elasto_fh_az_path *az_path);

void
apb_fpath_free(struct elasto_fh_az_path *az_path);

int
apb_fsign_conn_setup(struct elasto_conn *conn,
		     const char *sub_id,
		     const char *acc);

int
apb_fopen(void *mod_priv,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *toks);

int
apb_fclose(void *mod_priv);

/* block blobs */
int
abb_fopen(void *mod_priv,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *open_toks);

#endif /* _APB_OPEN_H_ */
