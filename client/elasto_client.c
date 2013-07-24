/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2013, all rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <apr-1/apr_general.h>
#include <apr-1/apr_xml.h>

#include "ccan/list/list.h"
#include "lib/azure_xml.h"
#include "lib/azure_req.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/dbg.h"
#include "linenoise.h"
#include "cli_common.h"
#include "cli_ls.h"
#include "cli_put.h"
#include "cli_get.h"
#include "cli_del.h"
#include "cli_cp.h"
#include "cli_create.h"

int
cli_exit_handle(struct cli_args *cli_args)
{
	exit(0);
	/* not reached */
	return 0;
}

int
cli_help_handle(struct cli_args *cli_args)
{
	cli_args_usage(cli_args->progname, cli_args->flags, NULL);
	return 0;
}

struct cli_cmd_spec {
	enum cli_cmd id;
	char *name;
	char *help;
	int arg_min;
	int arg_max;
	int (*args_parse)(int argc,
			  char * const *argv,
			  struct cli_args *cli_args);
	int (*handle)(struct cli_args *);
	void (*args_free)(struct cli_args *);
	enum cli_fl feature_flags;
} cli_cmd_specs[] = {
	{
		.id = CLI_CMD_LS,
		.name = "ls",
		.help = "[<account>[/container[/blob]]]\n"
			"\t\t[<bucket>]",
		.arg_min = 0,
		.arg_max = 1,
		.args_parse = &cli_ls_args_parse,
		.handle = &cli_ls_handle,
		.args_free = &cli_ls_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_PUT,
		.name = "put",
		.help = "<local path> <account>/<container>/<blob>\n"
			"\t\t<local path> <bucket>/<object>",
		.arg_min = 2,
		.arg_max = 2,
		.args_parse = &cli_put_args_parse,
		.handle = &cli_put_handle,
		.args_free = &cli_put_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_GET,
		.name = "get",
		.help = "<account>/<container>/<blob> <local path>\n"
			"\t\t<bucket>/<object> <local path>",
		.arg_min = 2,
		.arg_max = 2,
		.args_parse = &cli_get_args_parse,
		.handle = &cli_get_handle,
		.args_free = &cli_get_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_DEL,
		.name = "del",
		.help = "<account>[/<container>[/<blob>]]\n"
			"\t\t<bucket>[/<object>]",
		.arg_min = 1,
		.arg_max = 1,
		.args_parse = &cli_del_args_parse,
		.handle = &cli_del_handle,
		.args_free = &cli_del_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_CP,
		.name = "cp",
		.help = "<src_acc>/<src_ctnr>/<src_blob> "
			"<dst_acc>/<dst_ctnr>/<dst_blob>\n"
			"\t\t<bucket>/<object> <bucket>/<object>",
		.arg_min = 2,
		.arg_max = 2,
		.args_parse = &cli_cp_args_parse,
		.handle = &cli_cp_handle,
		.args_free = &cli_cp_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_CREATE,
		.name = "create",
		.help = "-l <label> [-d <desc>] [-L <location>] "
			"[-A <affinity group>] <account>\n"
			"\t\t<account>/<container>\n"
			"\t\t[-L <location>] <bucket>",
		.arg_min = 1,
		.arg_max = 7,
		.args_parse = &cli_create_args_parse,
		.handle = &cli_create_handle,
		.args_free = &cli_create_args_free,
		.feature_flags = CLI_FL_PROMPT | CLI_FL_BIN_ARG,
	},
	{
		.id = CLI_CMD_HELP,
		.name = "help",
		.help = "",
		.handle = &cli_help_handle,
		.feature_flags = CLI_FL_PROMPT,
	},
	{
		.id = CLI_CMD_EXIT,
		.name = "exit",
		.help = "",
		.handle = &cli_exit_handle,
		/* alias for quit, never display */
		.feature_flags = 0,
	},
	{
		.id = CLI_CMD_EXIT,
		.name = "quit",
		.help = "",
		.handle = &cli_exit_handle,
		.feature_flags = CLI_FL_PROMPT,
	},
	{
		/* must be last entry */
		.id = CLI_CMD_NONE,
	},
};

void
cli_args_usage(const char *progname,
	       enum cli_fl flags,
	       const char *msg)
{
	struct cli_cmd_spec *cmd;

	if (msg != NULL) {
		fprintf(stderr, "%s\n\n", msg);
	}

	if (flags & CLI_FL_BIN_ARG) {
		fprintf(stderr,
"Usage: %s [options] <cmd> <cmd args>\n\n"
"Options:\n"
"-s publish_settings:	Azure PublishSettings file\n"
"-k s3_key_id,secret:	Amazon S3 access key ID and secret access key duo\n"
"-d log_level:		Log debug messages (default: 0)\n"
"-i			Insecure, use HTTP where possible "
"(default: HTTPS only)\n\n",
			progname);
	}

	fprintf(stderr, "Commands:\n");
	for (cmd = cli_cmd_specs; cmd->id != CLI_CMD_NONE; cmd++) {
		/*
		 * filter listing based on whether run from elasto> prompt or as
		 * binary arg. Show only applicable commands
		 */
		if ((cmd->feature_flags & flags & CLI_FL_BIN_ARG)
		 || (cmd->feature_flags & flags & CLI_FL_PROMPT)) {
			fprintf(stderr, "\t%s\t%s\n", cmd->name, cmd->help);
		}
	}
}

static const struct cli_cmd_spec *
cli_cmd_lookup(const char *name)
{
	struct cli_cmd_spec *cmd;

	for (cmd = cli_cmd_specs; cmd->id != CLI_CMD_NONE; cmd++) {
		if (strcmp(cmd->name, name) == 0)
			return cmd;
	}
	return NULL;
}

/*
 * parse an azure or S3 path in the format:
 *	/account/container/blob
 *	or
 *	/bucket/object
 * return NULL for any components that do not exist, otherwise strdup.
 * handle corner cases such as double or missing '/'.
 */
int
cli_args_path_parse(const char *progname,
		    enum cli_fl flags,
		    const char *path,
		    char **comp1_out,
		    char **comp2_out,
		    char **comp3_out)
{
	int ret;
	char *s;
	char *comp1 = NULL;
	char *comp2 = NULL;
	char *comp3 = NULL;

	if (path == NULL) {
		cli_args_usage(progname, flags, "Empty remote path");
		return -EINVAL;
	}

	s = (char *)path;
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* empty or leading slashes only */
		goto done;
	}

	comp1 = strdup(s);
	if (comp1 == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strchr(comp1, '/');
	if (s == NULL) {
		/* account only */
		goto done;
	}

	*(s++) = '\0';	/* null term for acc */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* account + slashes only */
		goto done;
	}

	comp2 = strdup(s);
	if (comp2 == NULL) {
		ret = -ENOMEM;
		goto err_1_free;
	}

	s = strchr(comp2, '/');
	if (s == NULL) {
		/* ctnr only */
		goto done;
	}

	*(s++) = '\0';	/* null term for ctnr */
	while (*s == '/')
		s++;

	if (*s == '\0') {
		/* container + slashes only */
		goto done;
	}

	comp3 = strdup(s);
	if (comp3 == NULL) {
		ret = -ENOMEM;
		goto err_2_free;
	}

	s = strchr(comp3, '/');
	if (s != NULL) {
		/* blob has a trailing slash */
		cli_args_usage(progname, flags,
			"Invalid remote path: blob has trailing garbage");
		ret = -EINVAL;
		goto err_3_free;
	}
done:
	if ((comp1_out == NULL) && (comp1 != NULL)) {
		cli_args_usage(progname, flags,
			"Invalid remote path: unexpected 1st component");
		ret = -EINVAL;
		goto err_3_free;
	} else if (comp1_out != NULL) {
		*comp1_out = comp1;
	}
	if ((comp2_out == NULL) && (comp2 != NULL)) {
		cli_args_usage(progname, flags,
			"Invalid remote path: unexpected 2nd component");
		ret = -EINVAL;
		goto err_3_free;
	} else if (comp2_out != NULL) {
		*comp2_out = comp2;
	}
	if ((comp3_out == NULL) && (comp3 != NULL)) {
		cli_args_usage(progname, flags,
			"Invalid remote path: unexpected 3rd component");
		ret = -EINVAL;
		goto err_3_free;
	} else if (comp3_out != NULL) {
		*comp3_out = comp3;
	}
	return 0;

err_3_free:
	free(comp3);
err_2_free:
	free(comp2);
err_1_free:
	free(comp1);
err_out:
	return ret;
}

static int
cli_cmd_parse(int argc,
	      char * const *argv,
	      struct cli_args *cli_args,
	      const struct cli_cmd_spec **cmd_spec)
{
	int ret;
	const struct cli_cmd_spec *cmd;

	if (argc == 0) {
		cli_args_usage(cli_args->progname, cli_args->flags, NULL);
		ret = -EINVAL;
		goto err_out;
	}

	cmd = cli_cmd_lookup(argv[0]);
	if (cmd == NULL) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "command not found");
		ret = -EINVAL;
		goto err_out;
	}

	if (argc - 1 < cmd->arg_min) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "too few arguments for command");
		ret = -EINVAL;
		goto err_out;
	}

	if (argc - 1 > cmd->arg_max) {
		cli_args_usage(cli_args->progname, cli_args->flags,
			       "too many arguments for command");
		ret = -EINVAL;
		goto err_out;
	}

	if (cmd->args_parse == NULL)
		goto done;

	ret = cmd->args_parse(argc, argv, cli_args);
	if (ret < 0) {
		goto err_out;
	}

done:
	*cmd_spec = cmd;
	ret = 0;
err_out:
	return ret;
}

static void
cli_args_free(const struct cli_cmd_spec *cmd,
	      struct cli_args *cli_args)
{
	if ((cmd != NULL) && (cmd->args_free != NULL))
		cmd->args_free(cli_args);
	if (cli_args->type == CLI_TYPE_AZURE) {
		free(cli_args->az.sub_name);
		free(cli_args->az.sub_id);
		free(cli_args->az.ps_file);
		free(cli_args->az.pem_file);
	} else if (cli_args->type == CLI_TYPE_S3) {
		free(cli_args->s3.key_id);
		free(cli_args->s3.secret);
	}
	free(cli_args->progname);
}

static int
cli_args_parse(int argc,
	       char * const *argv,
	       struct cli_args *cli_args,
	       const struct cli_cmd_spec **cmd_spec)
{
	int opt;
	int ret;
	extern char *optarg;
	extern int optind;
	char *pub_settings = NULL;
	char *s3_id = NULL;
	char *s3_secret = NULL;
	char *progname = strdup(argv[0]);
	if (progname == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	cli_args->insecure_http = false;

	while ((opt = getopt(argc, argv, "s:k:d:?i")) != -1) {
		uint32_t debug_level;
		char *sep;
		switch (opt) {
		case 's':
			pub_settings = strdup(optarg);
			if (pub_settings == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'k':
			s3_id = strdup(optarg);
			if (s3_id == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			sep = strchr(s3_id, ',');
			if ((sep == NULL) || (strlen(sep) <= 1)) {
				ret = -EINVAL;
				goto err_out;
			}
			s3_secret = strdup(sep + 1);
			if (s3_secret == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			*sep = 0;
			break;
		case 'd':
			debug_level = (uint32_t)strtol(optarg, NULL, 10);
			dbg_level_set(debug_level);
			break;
		case 'i':
			cli_args->insecure_http = true;
			break;
		default: /* '?' */
			cli_args_usage(progname, CLI_FL_BIN_ARG, NULL);
			ret = -EINVAL;
			goto err_out;
			break;
		}
	}
	if (((pub_settings == NULL) && (s3_id == NULL))
	 || ((pub_settings != NULL) && (s3_id != NULL))) {
		cli_args_usage(argv[0], CLI_FL_BIN_ARG,
			       "Either an Azure PublishSettings file, or "
			       "Amazon S3 key-duo is required");
		ret = -EINVAL;
		goto err_out;
	}

	if (pub_settings != NULL) {
		cli_args->type = CLI_TYPE_AZURE;
		cli_args->az.ps_file = pub_settings;
	} else {
		assert(s3_id != NULL);
		cli_args->type = CLI_TYPE_S3;
		cli_args->s3.key_id = s3_id;
		cli_args->s3.secret = s3_secret;
	}
	cli_args->progname = progname;

	if (argc - optind == 0) {
		/* no cmd string, elasto> prompt */
		*cmd_spec = NULL;
		cli_args->flags = CLI_FL_PROMPT;
		return 0;
	}

	cli_args->flags = CLI_FL_BIN_ARG;
	ret = cli_cmd_parse(argc - optind, &argv[optind],
			    cli_args, cmd_spec);
	if (ret < 0) {
		goto err_out;
	}


	return 0;
err_out:
	free(pub_settings);
	free(s3_id);
	free(s3_secret);
	free(progname);

	return ret;
}

static void
cli_cmd_line_completion(const char *line,
			struct linenoiseCompletions *lcs)
{
	struct cli_cmd_spec *cmd;

	for (cmd = cli_cmd_specs; cmd->id != CLI_CMD_NONE; cmd++) {
		if (!strncmp(cmd->name, line, strlen(line)))
			linenoiseAddCompletion(lcs, cmd->name);
	}
}

#define ARGS_MAX 20
static int
cli_cmd_tokenize(char *line,
		 char **argv,
		 int *_argc)
{
	int argc = *_argc;
	char space = ' ';
	char *end_char = NULL;
	char *str_start = NULL;
	char *c;

	for (c = line; (*c != '\0') && (argc < ARGS_MAX); c++) {
		if ((end_char == NULL) && (*c == ' ')) {
			continue;
		} else if ((end_char == NULL) && (*c == '\"')) {
			str_start = c + 1;
			end_char = c;
		} else if (end_char == NULL) {
			/* non-space */
			str_start = c;
			end_char = &space;
		} else if ((end_char != NULL) && (*c == *end_char)) {
			/* overwrite token for str terminator */
			*c = '\0';
			if (strlen(str_start) == 0) {
				fprintf(stderr, "ignoring empty argument %d\n",
					argc);
			} else {
				/* got a full word */
				argv[argc++] = str_start;
			}
			str_start = NULL;
			end_char = NULL;
		}
	}
	if ((end_char != NULL) && (*end_char == ' ')) {
		/* still processing space-separated token */
		argv[argc++] = str_start;
	} else if ((end_char != NULL) && (*end_char == '\"')) {
		fprintf(stderr, "no matching quote for string: %s\n",
			str_start);
		return -EINVAL;
	}

	*_argc = argc;
	return 0;
}

static int
cli_cmd_line_run(struct cli_args *cli_args,
		 char *line)
{
	int ret;
	int argc = 0;
	char *argv[ARGS_MAX];
	const struct cli_cmd_spec *cmd;

	/* add to history before tokenising */
	linenoiseHistoryAdd(line);
	linenoiseHistorySave(".elasto_history");

	ret = cli_cmd_tokenize(line, argv, &argc);
	if (ret < 0) {
		return ret;
	}
	ret = cli_cmd_parse(argc, argv,
			    cli_args, &cmd);
	if (ret < 0) {
		return ret;
	}
	ret = cmd->handle(cli_args);
	if (ret < 0) {
		return ret;
	}
	if (cmd->args_free != NULL)
		cmd->args_free(cli_args);

	return 0;
}


static int
cli_cmd_line_start(struct cli_args *cli_args)
{
	char *line;

	linenoiseSetCompletionCallback(cli_cmd_line_completion);
	linenoiseHistoryLoad(".elasto_history");
	while((line = linenoise("elasto> ")) != NULL) {
		if (line[0] != '\0') {
			cli_cmd_line_run(cli_args, line);
			/* ignore errors */
		}
		free(line);
	}
	return 0;
}

int
main(int argc, char * const *argv)
{
	struct cli_args cli_args;
	const struct cli_cmd_spec *cmd;
	int ret;
	apr_status_t rv;

	memset(&cli_args, 0, sizeof(cli_args));

	ret = cli_args_parse(argc, argv, &cli_args, &cmd);
	if (ret < 0) {
		goto err_out;
	}

	rv = apr_initialize();
	if (rv != APR_SUCCESS) {
		ret = -APR_TO_OS_ERROR(rv);
		goto err_args_free;
	}

	ret = elasto_conn_subsys_init();
	if (ret < 0) {
		goto err_apr_deinit;
	}

	if (cli_args.type == CLI_TYPE_AZURE) {
		ret = azure_ssl_pubset_process(cli_args.az.ps_file,
					       &cli_args.az.pem_file,
					       &cli_args.az.sub_id,
					       &cli_args.az.sub_name);
		if (ret < 0) {
			goto err_global_clean;
		}
	}

	if (cmd == NULL) {
		ret = cli_cmd_line_start(&cli_args);
	} else {
		ret = cmd->handle(&cli_args);
	}
	if (ret < 0) {
		goto err_global_clean;
	}

	ret = 0;
err_global_clean:
	elasto_conn_subsys_deinit();
err_apr_deinit:
	apr_terminate();
err_args_free:
	cli_args_free(cmd, &cli_args);
err_out:
	return ret;
}
