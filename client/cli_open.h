/*
 * Copyright (C) SUSE LINUX GmbH 2017, all rights reserved.
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
#ifndef _CLI_OPEN_H_
#define _CLI_OPEN_H_

int
cli_open_efh(const struct cli_args *cli_args,
	     const char *elasto_path,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks,
	     struct elasto_fh **_fh);

#endif /* ifdef _CLI_OPEN_H_ */
