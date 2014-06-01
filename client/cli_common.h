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
 */
#ifndef _CLI_COMMON_H_
#define _CLI_COMMON_H_

enum cli_cmd {
	CLI_CMD_NONE = 0,
	CLI_CMD_LS,
	CLI_CMD_PUT,
	CLI_CMD_GET,
	CLI_CMD_DEL,
	CLI_CMD_CP,
	CLI_CMD_CREATE,
	CLI_CMD_HELP,
	CLI_CMD_EXIT,
};

enum cli_type {
	CLI_TYPE_AZURE = 1,
	CLI_TYPE_S3,
};

/*
 * @CLI_FL_BIN_ARG:	run as argument to binary
 * @CLI_FL_PROMPT:	run from elasto> prompt
 * @CLI_FL_AZ:		command can be run against Azure
 * @CLI_FL_S3:		command can be run against Amazon S3
 */
enum cli_fl {
	CLI_FL_BIN_ARG	= 0x00000001,
	CLI_FL_PROMPT	= 0x00000002,
	CLI_FL_AZ	= 0x00000004,
	CLI_FL_S3	= 0x00000008,
};

/*
 * @flags: features available to this instance
 */
struct cli_args {
	char *progname;
	enum cli_type type;
	enum cli_fl flags;
	union {
		struct {
			char *ps_file;
			char *pem_file;
			char *sub_name;
			char *sub_id;
			char *blob_acc;
			char *ctnr_name;
			char *blob_name;
		} az;
		struct {
			char *creds_file;
			char *iam_user;
			char *key_id;
			char *secret;
			char *bkt_name;
			char *obj_name;
		} s3;
	};
	bool insecure_http;
	char *history_file;
	enum cli_cmd cmd;
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
			union {
				struct {
					char *src_acc;
					char *src_ctnr;
					char *src_blob;
				} az;
				struct {
					char *src_bkt;
					char *src_obj;
				} s3;
			};
		} cp;
		struct {
			enum {
				CLI_CMD_CREATE_ACC = 0,
				CLI_CMD_CREATE_CTNR,
				CLI_CMD_CREATE_SHARE,
			} type;
			char *label;
			char *desc;
			char *affin_grp;
			char *location;
		} create;
	};
};

int
cli_args_path_parse(const char *progname,
		    enum cli_fl flags,
		    const char *path,
		    char **comp1_out,
		    char **comp2_out,
		    char **comp3_out);

void
cli_args_usage(const char *progname,
	       enum cli_fl flags,
	       const char *msg);

#endif /* ifdef _CLI_COMMON_H_ */
