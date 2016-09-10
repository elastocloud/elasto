/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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
#ifndef _LOCAL_PATH_H_
#define _LOCAL_PATH_H_

enum local_path_type {
	LOCAL_PATH_ENT = 1,
	LOCAL_PATH_FILE,
	LOCAL_PATH_DIR,
};

struct local_path {
	enum local_path_type type;
	char *path;
};

int
local_path_parse(const char *path,
		 struct local_path *local_path);

void
local_path_free(struct local_path *local_path);

int
local_path_dup(const struct local_path *path_orig,
	       struct local_path *path_dup);

#endif /* _LOCAL_PATH_H_ */
