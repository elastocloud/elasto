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
#ifndef _AFS_OPEN_H_
#define _AFS_OPEN_H_

int
afs_fpath_parse(const char *path,
		struct elasto_fh_afs_path *afs_path);

void
afs_fpath_free(struct elasto_fh_afs_path *afs_path);

int
afs_fopen(void *mod_priv,
	  struct elasto_conn *conn,
	  const char *path,
	  uint64_t flags,
	  struct elasto_ftoken_list *toks);

int
afs_fclose(void *mod_priv,
	   struct elasto_conn *conn);

#endif /* _AFS_OPEN_H_ */
