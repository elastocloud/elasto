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
#include <sys/types.h>
#include <pwd.h>

#include "ccan/list/list.h"
#include "lib/file/file_api.h"
#include "lib/dbg.h"
#include "lib/util.h"
#include "third_party/linenoise/linenoise.h"
#include "cli_common.h"

/*
 * cli_args needs to be a global for the linenoise hint callback, otherwise
 * passed as a function parameter.
 */
static struct cli_args cli_args;
static struct list_head cli_cmds = LIST_HEAD_INIT(cli_cmds);

void
cli_cmd_register(struct cli_cmd_spec *spec)
{
	list_add_tail(&cli_cmds, &spec->list);
}

void
cli_cmd_unregister(struct cli_cmd_spec *spec)
{
	list_del(&spec->list);
}

#define CLI_HANDLE_RET_EXIT 1000
int
cli_exit_handle(struct cli_args *cli_args)
{
	return CLI_HANDLE_RET_EXIT;
}

int
cli_help_handle(struct cli_args *cli_args)
{
	cli_args_usage(cli_args->progname, cli_args->flags, NULL);
	return 0;
}

static struct cli_cmd_spec help_spec = {
	.name = "help",
	.handle = &cli_help_handle,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
};

static struct cli_cmd_spec exit_spec = {
	.name = "exit",
	.handle = &cli_exit_handle,
	/* alias for quit, never display */
	.feature_flags = 0,
};

static struct cli_cmd_spec quit_spec = {
	.name = "quit",
	.handle = &cli_exit_handle,
	.feature_flags = CLI_FL_PROMPT | CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
};

__attribute__((constructor))
static void
cli_cmd_builtins_register(void)
{
	cli_cmd_register(&help_spec);
	cli_cmd_register(&exit_spec);
	cli_cmd_register(&quit_spec);
}

__attribute__((destructor))
static void
cli_cmd_builtins_unregister(void)
{
	cli_cmd_unregister(&help_spec);
	cli_cmd_unregister(&exit_spec);
	cli_cmd_unregister(&quit_spec);
}

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
"-K access_key:		Azure storage account access key\n"
"-k iam_creds:		Amazon IAM credentials file\n"
"-d log_level:		Log debug messages (default: 0)\n"
"-i			Insecure, use HTTP where possible "
"(default: HTTPS only)\n"
"-h history:		CLI history file (default: ~/.elasto_history)\n"
"-u URI:\t		REST Server URI (default: derived from credentials)"
"\n\n",
			progname);
	}

	fprintf(stderr, "Commands:\n");
	list_for_each(&cli_cmds, cmd, list) {
		/*
		 * Filter listing based on whether run from elasto> prompt or as
		 * binary arg, and whether Azure or S3 credentials were provided.
		 * Show only applicable commands.
		 */
		if ((cmd->feature_flags & flags & CLI_FL_BIN_ARG)
		 || (cmd->feature_flags & flags & CLI_FL_PROMPT)) {
			if ((cmd->feature_flags
				| CLI_FL_S3 | CLI_FL_AZ | CLI_FL_AFS) == 0) {
				continue;
			}
			if (cmd->feature_flags & flags & CLI_FL_AZ) {
				fprintf(stderr, "\t%s\t%s\n", cmd->name,
					(cmd->az_help ? cmd->az_help : ""));
			}
			if (cmd->feature_flags & flags & CLI_FL_AFS) {
				fprintf(stderr, "\t%s\t%s\n", cmd->name,
					(cmd->afs_help ? cmd->afs_help : ""));
			}
			if (cmd->feature_flags & flags & CLI_FL_S3) {
				fprintf(stderr, "\t%s\t%s\n", cmd->name,
					(cmd->s3_help ? cmd->s3_help : ""));
			}
		}
	}
}

static const struct cli_cmd_spec *
cli_cmd_lookup(const char *name)
{
	struct cli_cmd_spec *cmd;

	list_for_each(&cli_cmds, cmd, list) {
		if (strcmp(cmd->name, name) == 0)
			return cmd;
	}
	return NULL;
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

/**
 * Parse REST URI in the form proto://server
 */
struct cli_uri_mapping {
	char *uri_long;
	char *uri_short;
	enum elasto_ftype type;
} cli_uri_mapping[] = {
	{"azure_bb://", "abb://", ELASTO_FILE_ABB},
	{"azure_pb://", "apb://", ELASTO_FILE_APB},
	{"azure_fs://", "afs://", ELASTO_FILE_AFS},
	{"amazon_s3://", "s3://", ELASTO_FILE_S3},
};

static int
cli_uri_parse(const char *uri,
	      enum elasto_ftype *type)
{
	int i;

	if (type == NULL) {
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(cli_uri_mapping); i++) {
		if ((strcmp(uri, cli_uri_mapping[i].uri_long) == 0)
		 || (strcmp(uri, cli_uri_mapping[i].uri_short) == 0)) {
			*type = cli_uri_mapping[i].type;
			return 0;
		}
	}

	dbg(0, "invalid URI string: %s\n", uri);
	return -EINVAL;
}

static int
cli_auth_args_validate(enum elasto_ftype type,
		       char *az_ps_file,
		       char *az_access_key,
		       char *s3_creds_file)
{
	switch (type) {
	case ELASTO_FILE_ABB:
	case ELASTO_FILE_APB:
	case ELASTO_FILE_AFS:
		if (((az_ps_file == NULL) && (az_access_key == NULL))
		 || ((az_ps_file != NULL) && (az_access_key != NULL))) {
			dbg(0, "either a PublishSettings file or an access key "
			       "is required for Azure access\n");
			return -EINVAL;
		}
		if (s3_creds_file != NULL) {
			dbg(0, "S3 credentials incorrectly provided for "
			       "Azure access\n");
			return -EINVAL;
		}
		break;
	case ELASTO_FILE_S3:
		if (s3_creds_file == NULL) {
			dbg(0, "S3 credentials required for Amazon access\n");
			return -EINVAL;
		}
		if ((az_ps_file != NULL) || (az_access_key != NULL)) {
			dbg(0, "Azure credentials incorrectly provided for "
			    "Amazon S3 access\n");
			return -EINVAL;
		}
		break;
	default:
		dbg(0, "invalid cli type: %d\n", type);
		return -EINVAL;
	}

	return 0;
}

static void
cli_args_free(struct cli_args *cli_args)
{
	if ((cli_args->auth.type == ELASTO_FILE_ABB)
	 || (cli_args->auth.type == ELASTO_FILE_APB)
	 || (cli_args->auth.type == ELASTO_FILE_AFS)) {
		free(cli_args->auth.az.ps_path);
		free(cli_args->auth.az.access_key);
	} else if (cli_args->auth.type == ELASTO_FILE_S3) {
		free(cli_args->auth.s3.creds_path);
	}
	free(cli_args->history_file);
	free(cli_args->cwd);
	free(cli_args->progname);
}

static int
cli_args_parse(int argc,
	       char * const *argv,
	       struct cli_args *cli_args,
	       int *opt_idx)
{
	int opt;
	int ret;
	extern char *optarg;
	extern int optind;
	char *cwd = NULL;
	char *az_ps_file = NULL;
	char *az_access_key = NULL;
	char *s3_creds_file = NULL;
	char *history_file = NULL;
	char *uri = NULL;
	char *progname = strdup(argv[0]);
	if (progname == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	cwd = strdup("/");
	if (cwd == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	cli_args->auth.insecure_http = false;
	/* show help for all backends by default */
	cli_args->flags = CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3;

	while ((opt = getopt(argc, argv, "s:K:k:d:?ih:u:")) != -1) {
		uint32_t debug_level;
		switch (opt) {
		case 's':
			az_ps_file = strdup(optarg);
			if (az_ps_file == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'K':
			az_access_key = strdup(optarg);
			if (az_access_key == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'k':
			s3_creds_file = strdup(optarg);
			if (s3_creds_file == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'd':
			debug_level = (uint32_t)strtol(optarg, NULL, 10);
			dbg_level_set(debug_level);
			break;
		case 'i':
			cli_args->auth.insecure_http = true;
			break;
		case 'h':
			history_file = strdup(optarg);
			if (history_file == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		case 'u':
			uri = strdup(optarg);
			if (uri == NULL) {
				ret = -ENOMEM;
				goto err_out;
			}
			break;
		default: /* '?' */
			cli_args_usage(progname,
				       CLI_FL_BIN_ARG
				       | CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
				       NULL);
			ret = -EINVAL;
			goto err_out;
			break;
		}
	}

	if (uri != NULL) {
		/* parse only provider portion of the URI. TODO parse host */
		ret = cli_uri_parse(uri, &cli_args->auth.type);
		if (ret < 0) {
			goto err_out;
		}
	} else if ((az_ps_file != NULL) || (az_access_key != NULL)) {
		/* publish settings argument - assume Azure Bock Blob service */
		cli_args->auth.type = ELASTO_FILE_ABB;
	} else if (s3_creds_file != NULL) {
		/* iam creds argument - assume Amazon S3 service */
		cli_args->auth.type = ELASTO_FILE_S3;
	} else {
		cli_args_usage(argv[0], CLI_FL_BIN_ARG
					| CLI_FL_AZ | CLI_FL_AFS | CLI_FL_S3,
			       "Either an Azure PublishSettings file, access "
			       "key, or Amazon S3 key file is required");
		ret = -EINVAL;
		goto err_out;
	}

	ret = cli_auth_args_validate(cli_args->auth.type, az_ps_file,
				     az_access_key, s3_creds_file);
	if (ret < 0) {
		goto err_out;
	}

	if ((cli_args->auth.type == ELASTO_FILE_ABB)
	 || (cli_args->auth.type == ELASTO_FILE_APB)) {
		cli_args->auth.az.ps_path = az_ps_file;
		cli_args->auth.az.access_key = az_access_key;
		/* don't show S3 or AFS usage strings */
		cli_args->flags &= ~(CLI_FL_S3 | CLI_FL_AFS);
	} else if (cli_args->auth.type == ELASTO_FILE_AFS) {
		cli_args->auth.az.ps_path = az_ps_file;
		cli_args->auth.az.access_key = az_access_key;
		/* don't show S3 or Azure Blob usage strings */
		cli_args->flags &= ~(CLI_FL_S3 | CLI_FL_AZ);
	} else if (cli_args->auth.type == ELASTO_FILE_S3) {
		cli_args->auth.s3.creds_path = s3_creds_file;
		/* don't show Azure usage strings */
		cli_args->flags &= ~(CLI_FL_AZ | CLI_FL_AFS);
	} else {
		assert(false);
	}

	if (history_file == NULL) {
		/* default ~/.elasto_history */
		struct passwd *pw = getpwuid(getuid());
		if (pw == NULL || pw->pw_dir == NULL) {
			ret = -EINVAL;
			goto err_out;
		}
		ret = asprintf(&history_file, "%s/.elasto_history", pw->pw_dir);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
	}
	cli_args->history_file = history_file;
	cli_args->cwd = cwd;
	cli_args->progname = progname;

	if (argc - optind == 0) {
		/* no cmd string, elasto> prompt */
		cli_args->flags |= CLI_FL_PROMPT;
	} else {
		cli_args->flags |= CLI_FL_BIN_ARG;
	}
	*opt_idx = optind;

	return 0;
err_out:
	free(az_ps_file);
	free(az_access_key);
	free(s3_creds_file);
	free(history_file);
	free(cwd);
	free(progname);

	return ret;
}

static void
cli_cmd_line_completion(const char *line,
			struct linenoiseCompletions *lcs)
{
	struct cli_cmd_spec *cmd;

	list_for_each(&cli_cmds, cmd, list) {
		if (!strncmp(cmd->name, line, strlen(line))) {
			linenoiseAddCompletion(lcs, cmd->name);
		}
	}
}

static char *
cli_cmd_line_hint(const char *line,
		  int *color,
		  int *bold)
{
	struct cli_cmd_spec *cmd;
	char *s;

	if (line == NULL) {
	       return NULL;
	}
	for (;*line == ' '; line++);

	/* only show args hint if line matches "<cmd> " */
	s = strchr(line, ' ');
	if ((s == NULL) || (s == line) || (*(s + 1) != '\0')) {
		return NULL;
	}
	assert(s > line);

	*color = -1;
	*bold = 1;
	list_for_each(&cli_cmds, cmd, list) {
		if (strncmp(cmd->name, line, s - line)) {
			continue;
		}
		switch (cmd->feature_flags & cli_args.flags & ~CLI_FL_PROMPT) {
		case CLI_FL_AZ:
			return cmd->az_help;
		case CLI_FL_AFS:
			return cmd->afs_help;
		case CLI_FL_S3:
			return cmd->s3_help;
		default:
			/* multiple or none relevant */
			return NULL;
		}
	}
	return NULL;
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
cli_cmd_parse_run(int argc,
		  char * const *argv,
		  struct cli_args *cli_args)
{
	int ret;
	const struct cli_cmd_spec *cmd;

	ret = cli_cmd_parse(argc, argv,
			    cli_args, &cmd);
	if (ret < 0) {
		goto err_out;
	}
	ret = cmd->handle(cli_args);
	if (ret < 0) {
		goto err_cmd_args_free;
	}
err_cmd_args_free:
	if (cmd->args_free != NULL)
		cmd->args_free(cli_args);
err_out:
	return ret;
}

static int
cli_cmd_line_run(struct cli_args *cli_args,
		 char *line)
{
	int ret;
	int argc = 0;
	char *argv[ARGS_MAX];
	mode_t old_mask;

	/* add to history before tokenising */
	linenoiseHistoryAdd(line);
	/* history should only be visible to user */
	old_mask = umask(S_IRGRP | S_IWGRP | S_IXGRP
			| S_IROTH | S_IWOTH | S_IXOTH);
	linenoiseHistorySave(cli_args->history_file);
	umask(old_mask);

	ret = cli_cmd_tokenize(line, argv, &argc);
	if (ret < 0) {
		return ret;
	}

	return cli_cmd_parse_run(argc, argv, cli_args);
}

static int
cli_cmd_line_start(struct cli_args *cli_args)
{
	int ret = 0;

	linenoiseSetCompletionCallback(cli_cmd_line_completion);
	linenoiseSetHintsCallback(cli_cmd_line_hint);
	linenoiseHistoryLoad(cli_args->history_file);
	while (ret != CLI_HANDLE_RET_EXIT) {
		char *line = linenoise("elasto> ");
		if (line == NULL) {
			break;
		} else if (line[0] != '\0') {
			ret = cli_cmd_line_run(cli_args, line);
		}
		free(line);
	}
	return 0;
}

int
main(int argc, char * const *argv)
{
	int opt_idx = 0;
	int ret;

	cli_cmd_builtins_register();

	memset(&cli_args, 0, sizeof(cli_args));

	ret = cli_args_parse(argc, argv, &cli_args, &opt_idx);
	if (ret < 0) {
		goto err_out;
	}

	ret = elasto_subsystem_init();
	if (ret < 0) {
		goto err_args_free;
	}

	if (cli_args.flags & CLI_FL_PROMPT) {
		ret = cli_cmd_line_start(&cli_args);
	} else {
		/* process remaining arguments as a command invocation */
		assert(cli_args.flags & CLI_FL_BIN_ARG);
		assert(opt_idx < argc);
		ret = cli_cmd_parse_run(argc - opt_idx, &argv[opt_idx],
					&cli_args);
	}
	if (ret < 0) {
		goto err_args_free;
	}

	ret = 0;
err_args_free:
	cli_args_free(&cli_args);
err_out:
	cli_cmd_builtins_unregister();
	return ret;
}
