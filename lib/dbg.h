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
#ifndef _DBG_H_
#define _DBG_H_

extern uint32_t dbg_level;

#define dbg(lev, fmt, ...) \
	do { \
		if (lev <= dbg_level) \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
				__LINE__, __func__, ##__VA_ARGS__); \
	} while (0)

void
dbg_level_set(uint32_t level);

#endif /* ifdef _DBG_H_ */
