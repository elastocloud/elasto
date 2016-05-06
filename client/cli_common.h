/*
 * Copyright (C) SUSE LINUX GmbH 2012-2015, all rights reserved.
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
#ifndef _CLI_COMMON_H_
#define _CLI_COMMON_H_

/**
 * @CLI_FL_BIN_ARG:	run as argument to binary
 * @CLI_FL_PROMPT:	run from elasto> prompt
 * @CLI_FL_AZ:		command can be run against Azure Blob Service
 * @CLI_FL_S3:		command can be run against Amazon S3
 * @CLI_FL_AFS:		command can be run against Azure File Service
 */
enum cli_fl {
	CLI_FL_BIN_ARG	= 0x00000001,
	CLI_FL_PROMPT	= 0x00000002,
	CLI_FL_AZ	= 0x00000004,
	CLI_FL_S3	= 0x00000008,
	CLI_FL_AFS	= 0x00000010,
};

/*
 * @flags: features available to this instance
 */
struct cli_args {
	char *progname;
	enum cli_fl flags;
	/* unparsed path for libfile */
	char *path;
	struct elasto_fauth auth;
	char *history_file;
	union {
		struct {
		} ls;
		struct {
			char *local_path;
		} put;
		struct {
			char *local_path;
		} get;
		struct {
		} del;
		struct {
			char *src_path;
		} cp;
		struct {
			char *location;
		} create;
	};
};

void
cli_args_usage(const char *progname,
	       enum cli_fl flags,
	       const char *msg);

#endif /* ifdef _CLI_COMMON_H_ */
