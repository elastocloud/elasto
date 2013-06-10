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
#ifndef _CLI_CP_H_
#define _CLI_CP_H_

void
cli_cp_args_free(struct cli_args *cli_args);

int
cli_cp_args_parse(int argc,
		  char * const *argv,
		  struct cli_args *cli_args);

int
cli_cp_handle(struct cli_args *cli_args);

#endif /* ifdef _CLI_CP_H_ */