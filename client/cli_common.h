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
	CLI_CMD_CREATE,
};

struct cli_args {
	char *ps_file;
	char *sub_id;
	enum cli_cmd cmd;
	union {
		struct {
			char *blob_acc;
			char *ctnr_name;
			char *blob_name;
		} ls;
		struct {
			char *local_path;
			char *blob_acc;
			char *ctnr_name;
			char *blob_name;
		} put;
		struct {
			char *blob_acc;
			char *ctnr_name;
			char *blob_name;
			char *local_path;
		} get;
		struct {
			char *blob_acc;
			char *ctnr_name;
			char *blob_name;
		} del;
		struct {
			char *blob_acc;
			char *ctnr_name;
			char *label;
			char *desc;
			char *affin_grp;
			char *location;
		} create;
	};
};

int
cli_args_azure_path_parse(const char *progname,
			  const char *apath,
			  char **acc_r,
			  char **ctnr_r,
			  char **blob_r);

void
cli_args_usage(const char *progname,
	       const char *msg);

#endif /* ifdef _CLI_COMMON_H_ */
