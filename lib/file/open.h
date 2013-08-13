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
#ifndef _OPEN_H_
#define _OPEN_H_

int
elasto_fpath_az_parse(const char *path,
		      struct elasto_fh_az_path *az_path);

void
elasto_fpath_az_free(struct elasto_fh_az_path *az_path);

int
elasto_fsign_conn_setup(struct elasto_conn *econn,
			const char *sub_id,
			const char *acc);

#endif /* _OPEN_H_ */
