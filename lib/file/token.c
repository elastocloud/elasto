/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#include <inttypes.h>
#include <sys/stat.h>

#include "ccan/list/list.h"
#include "lib/exml.h"
#include "lib/op.h"
#include "lib/conn.h"
#include "lib/azure_ssl.h"
#include "lib/util.h"
#include "lib/dbg.h"
#include "token.h"

int
elasto_ftoken_add(uint64_t key,
		  const char *val,
		  struct elasto_ftoken_list **_toks)
{
	int ret;
	struct elasto_kv *kv;
	struct elasto_ftoken_list *toks;
	bool new_alloced = false;

	if (_toks == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (*_toks != NULL) {
		/* appending to an existing list */
		toks = *_toks;
	} else {
		toks = malloc(sizeof(*toks));
		if (toks == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		list_head_init(&toks->kvs);
		toks->num_kvs = 0;
		new_alloced = true;
	}

	kv = malloc(sizeof(*kv));
	if (kv == NULL) {
		ret = -ENOMEM;
		goto err_toks_free;
	}
	kv->key = key;
	kv->val = strdup(val);
	if (kv->val == NULL) {
		ret = -ENOMEM;
		goto err_kv_free;
	}

	list_add_tail(&toks->kvs, &kv->list);
	toks->num_kvs++;
	if (new_alloced) {
		*_toks = toks;
	}

	return 0;

err_kv_free:
	free(kv);
err_toks_free:
	if (new_alloced) {
		free(toks);
	}
err_out:
	return ret;
}

int
elasto_ftoken_find(struct elasto_ftoken_list *toks,
		   uint64_t key,
		   const char **_val)
{
	struct elasto_kv *kv;

	if (_val == NULL) {
		return -EINVAL;
	}

	if (toks == NULL) {
		return -ENOENT;
	}

	list_for_each(&toks->kvs, kv, list) {
		if (kv->key == key) {
			*_val = kv->val;
			return 0;
		}
	}

	return -ENOENT;
}

void
elasto_ftoken_list_free(struct elasto_ftoken_list *toks)
{
	struct elasto_kv *kv;
	struct elasto_kv *kv_n;

	if (toks == NULL) {
		return;
	}

	list_for_each_safe(&toks->kvs, kv, kv_n, list) {
		free(kv->val);
		free(kv);
	}
	free(toks);
}
