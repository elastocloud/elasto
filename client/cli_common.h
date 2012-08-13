/*
 * Copyright (C) SUSE LINUX Products GmbH 2012, all rights reserved.
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
 *
 * Author: David Disseldorp <ddiss@suse.de>
 */
#ifndef _CLI_COMMON_H_
#define _CLI_COMMON_H_

enum cli_cmd {
	CLI_CMD_NONE = 0,
	CLI_CMD_LS,
	CLI_CMD_PUT,
	CLI_CMD_GET,
	CLI_CMD_DEL,
};

struct cli_args {
	char *ps_file;
	char *blob_acc;
	char *blob_loc;
	bool blob_geo;
	enum cli_cmd cmd;
	union {
		struct {
			char *ctnr_name;
		} ls;
		struct {
			char *local_path;
			char *ctnr_name;
			char *blob_name;
		} put;
		struct {
			char *ctnr_name;
			char *blob_name;
			char *local_path;
		} get;
		struct {
			char *ctnr_name;
			char *blob_name;
		} del;
	};
};

void
cli_args_usage(const char *progname,
	       const char *msg);

#endif /* ifdef _CLI_COMMON_H_ */
