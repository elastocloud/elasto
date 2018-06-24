/*
 * Copyright (C) SUSE LINUX GmbH 2012-2017, all rights reserved.
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
 * @CLI_FL_CLOUD_ABS:	command can be run against Azure Blob Service
 * @CLI_FL_CLOUD_S3:	command can be run against Amazon S3
 * @CLI_FL_CLOUD_AFS:	command can be run against Azure File Service
 * @CLI_FL_CLOUD_MASK_ALL:	mask covering all cloud backends
 */
enum cli_fl {
	CLI_FL_BIN_ARG		= 0x00000001,
	CLI_FL_PROMPT		= 0x00000002,
	CLI_FL_CLOUD_ABS	= 0x00000004,
	CLI_FL_CLOUD_S3		= 0x00000008,
	CLI_FL_CLOUD_AFS	= 0x00000010,
	CLI_FL_CLOUD_MASK_ALL	= (CLI_FL_CLOUD_ABS | CLI_FL_CLOUD_S3
				   | CLI_FL_CLOUD_AFS),
};

/*
 * @progname: client binary path, as invoked
 * @flags: features available to this instance
 * @cwd: realized current working dir (always '/', cd isn't yet implemented)
 * @host: custom host endpoint
 * @port: custom port endpoint
 * @path: per-command absolute realized path, to be passed to libelasto_file
 * @auth: authentication information
 * @history_file: path where client command history is preserved
 */
struct cli_args {
	char *progname;
	enum cli_fl flags;
	char *cwd;
	char *host;
	uint16_t port;
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

struct cli_cmd_spec {
	struct list_node list;
	char *name;
	char *az_help;
	char *afs_help;
	char *s3_help;
	int arg_min;
	int arg_max;
	int (*args_parse)(int argc,
			  char * const *argv,
			  struct cli_args *cli_args);
	int (*handle)(struct cli_args *);
	void (*args_free)(struct cli_args *);
	enum cli_fl feature_flags;
};

void
cli_cmd_register(struct cli_cmd_spec *spec);

void
cli_cmd_unregister(struct cli_cmd_spec *spec);

void
cli_args_usage(const char *progname,
	       enum cli_fl flags,
	       const char *msg);

#define cli_cmd_init void __attribute__((constructor (101)))
#define cli_cmd_deinit void __attribute__((destructor (101)))

int
cli_path_realize(const char *real_cwd,
		 const char *usr_path,
		 char **_real_abs_path);

int
cli_path_uri_parse(const char *uri,
		   enum elasto_ftype *_type,
		   char **_host,
		   uint16_t *_port);

#endif /* ifdef _CLI_COMMON_H_ */
