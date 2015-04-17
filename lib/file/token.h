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
#ifndef _TOKEN_H_
#define _TOKEN_H_

struct elasto_kv {
	struct list_node list;
	uint64_t key;
	char *val;
};

struct elasto_ftoken_list {
	int num_kvs;
	struct list_head kvs;
};

int
elasto_ftoken_find(struct elasto_ftoken_list *toks,
		   uint64_t key,
		   const char **_val);

#endif /* _TOKEN_H_ */
