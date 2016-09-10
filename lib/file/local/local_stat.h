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
#ifndef _LOCAL_STAT_H_
#define _LOCAL_STAT_H_

int
local_fstat(void *mod_priv,
	 struct elasto_fstat *fstat);

int
local_fstatvfs(void *mod_priv,
	    struct elasto_fstatfs *fstatfs);

#endif /* _LOCAL_STAT_H_ */
