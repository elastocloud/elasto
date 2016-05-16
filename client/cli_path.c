/*
 * Copyright (C) SUSE LINUX GmbH 2016, all rights reserved.
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
#include <linux/limits.h>

#include "ccan/list/list.h"
#include "lib/file/file_api.h"
#include "lib/op.h"
#include "lib/conn.h"
#include "lib/dbg.h"
#include "lib/util.h"
#include "cli_common.h"

struct cli_path_ent {
	struct list_node list;
	char *cmpnt;
};

static int
cli_path_ent_add(char *cmpnt,
		 struct list_head *pents,
		 int *num_pents)
{
	struct cli_path_ent *pent;

	pent = malloc(sizeof(*pent));
	if (pent == NULL) {
		return -ENOMEM;
	}

	pent->cmpnt = strdup(cmpnt);
	if (pent->cmpnt == NULL) {
		free(pent);
		return -ENOMEM;
	}

	list_add_tail(pents, &pent->list);
	(*num_pents)++;
	return 0;
}

static void
cli_path_ent_del(struct cli_path_ent *pent,
		 int *num_pents)
{
	if (pent == NULL) {
		return;
	}
	free(pent->cmpnt);
	list_del(&pent->list);
	free(pent);
	(*num_pents)--;
}

static int
cli_path_ents_parse(const char *path,
		    struct list_head *pents,
		    int *num_pents)
{
	int ret;
	char *pdup;
	char *save_ptr;
	char *tok;

	pdup = strdup(path);
	if (pdup == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	tok = strtok_r(pdup, "/", &save_ptr);
	while (tok != NULL) {
		struct cli_path_ent *pent;
		if (strcmp("..", tok) == 0) {
			/* drop the last component */
			if (*num_pents == 0) {
				dbg(0, "can't go past path root at %s\n", tok);
				ret = -EINVAL;
				goto err_pdup_free;
			}
			pent = list_tail(pents, struct cli_path_ent, list);
			assert(pent != NULL);
			cli_path_ent_del(pent, num_pents);
		} else if (strcmp(".", tok) == 0) {
			/* ignore */
		} else {
			/* new entry */
			ret = cli_path_ent_add(tok, pents, num_pents);
			if (ret < 0) {
				goto err_pdup_free;
			}
		}

		tok = strtok_r(NULL, "/", &save_ptr);
	}

	ret = 0;
err_pdup_free:
	free(pdup);
	/* caller frees any pents remaining */
err_out:
	return ret;
}

static int
cli_path_ents_render_free(struct list_head *pents,
			  int *num_pents,
			  char **_abs_path_rendered)
{
	int ret;
	char *abs_path;
	int rslv_remain;
	int rslv_off;
	struct cli_path_ent *pent;
	struct cli_path_ent *pentn;

	if (*num_pents == 0) {
		abs_path = strdup("/");
		if (abs_path == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto done;
	}

	rslv_remain = PATH_MAX - 1;
	rslv_off = 0;
	abs_path = malloc(PATH_MAX);
	if (abs_path == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	abs_path[0] = '/';
	rslv_remain--;
	rslv_off++;
	list_for_each_safe(pents, pent, pentn, list) {
		int len;

		len = strlen(pent->cmpnt);
		assert(len > 0);

		/* need room for component + separator */
		if (len >= rslv_remain) {
			ret = -EINVAL;
			goto err_abs_free;
		}

		memcpy(&abs_path[rslv_off], pent->cmpnt, len);
		rslv_off += len;
		rslv_remain -= len;
		abs_path[rslv_off] = '/';
		rslv_off++;
		rslv_remain--;

		cli_path_ent_del(pent, num_pents);
	}

	/* overwrite last separator with terminator */
	assert(rslv_off > 0);
	abs_path[rslv_off - 1] = '\0';

done:
	assert(*num_pents == 0);
	*_abs_path_rendered = abs_path;
	return 0;

err_abs_free:
	free(abs_path);
err_out:
	return ret;
}

int
cli_path_realize(const char *real_cwd,
		 const char *usr_path,
		 char **_real_abs_path)
{
	int ret;
	int cwd_len;
	int usr_len;
	char *abs_path = NULL;
	struct list_head path_ents;
	int num_pents;
	struct cli_path_ent *pent;
	struct cli_path_ent *pentn;

	if (real_cwd == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	cwd_len = strlen(real_cwd);
	if ((cwd_len == 0) || (real_cwd[0] != '/')) {
		ret = -EINVAL;
		goto err_out;
	}

	if ((usr_path == NULL) || (strlen(usr_path) == 0)) {
		abs_path = strdup(real_cwd);
		if (abs_path == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		goto done;
	}

	usr_len = strlen(usr_path);
	if ((usr_len >= PATH_MAX) || (cwd_len + usr_len >= PATH_MAX)) {
		ret = -EINVAL;
		goto err_out;
	}

	list_head_init(&path_ents);
	num_pents = 0;
	if (usr_path[0] != '/') {
		/* usr path is relative, handle cwd */
		ret = cli_path_ents_parse(real_cwd, &path_ents, &num_pents);
		if (ret < 0) {
			goto err_pents_free;
		}
	}

	ret = cli_path_ents_parse(usr_path, &path_ents, &num_pents);
	if (ret < 0) {
		goto err_pents_free;
	}

	ret = cli_path_ents_render_free(&path_ents, &num_pents, &abs_path);
	if (ret < 0) {
		goto err_pents_free;
	}

done:
	*_real_abs_path = abs_path;
	return 0;

err_pents_free:
	list_for_each_safe(&path_ents, pent, pentn, list) {
		cli_path_ent_del(pent, &num_pents);
	}
err_out:
	return ret;
}
