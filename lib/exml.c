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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <search.h>
#include <inttypes.h>

#include <expat.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "exml.h"

enum xml_val_type {
	XML_VAL_STR,
	XML_VAL_I32,
	XML_VAL_I64,
	XML_VAL_U64,
	XML_VAL_BOOL,
	XML_VAL_B64,
	XML_VAL_CALLBACK,
	XML_VAL_PATH_CB,
};

struct xml_finder {
	struct list_node list;
	char *search_path;
	char *found_el_path;
	bool path_wildcard;
	char *search_attr;
	bool required;
	enum xml_val_type type;
	uint32_t handled;
	union {
		char **str;
		int32_t *i32;
		int64_t *i64;
		uint64_t *u64;
		bool *bl;
		char **b64_decode;
		struct {
			exml_want_cb_t fn;
			void *data;
		} cb;
	} ret_val;
	bool *_present;
};

struct xml_el {
	char *path;
	int leaf_index;
	int max_leaf_index;
};

/*
 * finders have the following state during parsing:
 * not found: path not encountered, on the finders list.
 * found await val: path encountered, awaiting value callback on
 *		    finders_val_wait list.
 * found: path encountered, value callback handled if needed. On the
 *	  founders list.
 */
struct xml_doc {
	XML_Parser parser;
	const char *buf;
	uint64_t buf_len;
	int num_finders;
	struct list_head finders;
	struct list_head finders_val_wait;
	struct list_head founders;
	bool parsing;
	char *el_path;
	int parse_ret;
	void *root_el;
};

static void
exml_el_free(const void *_el)
{
	struct xml_el *el = (struct xml_el *)_el;

	free(el->path);
	free(el);
}

static void
exml_el_print(const void *_el, const VISIT which, const int depth)
{
	struct xml_el *el = *(struct xml_el **)_el;

	switch (which) {
	case preorder:
		break;
	case postorder:
		dbg(6, "branch depth: %d: %s\n", depth, el->path);
		break;
	case endorder:
		break;
	case leaf:
		dbg(6, "leaf depth: %d: %s\n", depth, el->path);
		break;
	}
}

/*
 * Compare two tree elements.
 http://en.wikipedia.org/wiki/Binary_tree#Encoding_general_trees_as_binary_trees
 */
static int
exml_el_cmp(const void *a, const void *b)
{
	int ret;
	struct xml_el *el_a = (struct xml_el *)a;
	struct xml_el *el_b = (struct xml_el *)b;
	char *path_a;
	char *path_b;
	char *ta;
	char *tb;
	char *sa;
	char *sb;

	dbg(4, "comparing \"%s with \"%s\"\n", el_a->path, el_b->path);
	path_a = strdup(el_a->path);
	assert(path_a != NULL);
	path_b = strdup(el_b->path);
	assert(path_b != NULL);

	/* find path divergence */
	for (ta = strtok_r(path_a, "/", &sa), tb = strtok_r(path_b, "/", &sb);
	     ((ta != NULL) && (tb != NULL)) && (strcmp(ta, tb) == 0);
	     ta = strtok_r(NULL, "/", &sa), tb = strtok_r(NULL, "/", &sb)) {
		dbg(6, "match with component %s\n", ta);
	}

	if ((ta == NULL) && (tb == NULL)) {
		dbg(4, "\"%s\" and \"%s\" are identical\n",
		    el_a->path, el_b->path);
		ret = 0;
		goto out;
	} else if ((ta == NULL) && (tb != NULL)) {
		dbg(4, "\"%s\" is a parent of \"%s\"\n",
		    el_a->path, el_b->path);
		ret = 1;
		goto out;
	} else if ((tb == NULL) && (ta != NULL)) {
		dbg(4, "\"%s\" is nested under \"%s\"\n",
		    el_a->path, el_b->path);
		ret = -1;
		goto out;
	}

	dbg(4, "paths diverge at %s and %s\n", ta, tb);
	ret = strcmp(ta, tb);
out:
	free(path_a);
	free(path_b);
	return ret;
}

/*
 * Add a new element to the xdoc tree, and assign a leaf index based on how
 * many existing elements are found under the same path.
 */
static int
exml_el_encounter(struct xml_doc *xdoc,
		  const char *path,
		  char **path_with_leaf_index)
{
	int ret;
	struct xml_el *el;
	struct xml_el *el_new;
	void *_el_new;
	char *term;
	size_t index_buflen;

	el = malloc(sizeof(*el));
	if (el == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(el, 0, sizeof(*el));

	/* need to accommodate for the added leaf index suffix */
	index_buflen = sizeof("[99999]");
	el->path = malloc(strlen(path) + index_buflen);
	if (el->path == NULL) {
		ret = -ENOMEM;
		goto err_el_free;
	}
	strcpy(el->path, path);
	assert(strlen(el->path) >= 1);
	term = el->path + strlen(el->path) - 1;
	assert(*term == '/');

	/* no leaf index suffix for the root node */
	if (strlen(el->path) != 1) {
		/* search for first leaf index, may find existing */
		strcpy(term, "[0]/");
	}

	_el_new = tsearch((void *)el, &xdoc->root_el, exml_el_cmp);
	if (_el_new == NULL) {
		dbg(0, "failed to add new tree element\n");
		ret = -EFAULT;
		goto err_path_free;
	}
	el_new = *(struct xml_el **)_el_new;
	if (el_new != el) {
		/* existing elements return the first index */
		assert(el_new->leaf_index == 0);
		el->leaf_index = ++el_new->max_leaf_index;
		dbg(4, "collision at [0], new index suffix [%d]\n",
		    el->leaf_index);
		ret = snprintf(term, index_buflen, "[%d]/", el->leaf_index);
		if ((ret < 0) || (ret >= index_buflen)) {
			dbg(0, "failed to append index suffix\n");
			ret = -EINVAL;
			goto err_path_free;
		}
		_el_new = tsearch((void *)el, &xdoc->root_el, exml_el_cmp);
		el_new = *(struct xml_el **)_el_new;
		assert(el_new == el);
	}
	dbg(4, "added tree node: %s\n", el->path);

	*path_with_leaf_index = strdup(el->path);
	if (*path_with_leaf_index == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	return 0;

err_path_free:
	free(el->path);
err_el_free:
	free(el);
err_out:
	return ret;
}

int
exml_slurp(const char *buf,
	  uint64_t buf_len,
	  struct xml_doc **xdoc_out)
{
	int ret;
	struct xml_doc *xdoc;

	dbg(10, "slurping %" PRIu64 " bytes data: %*s\n",
	    buf_len, (int)buf_len, (const char *)buf);

	xdoc = malloc(sizeof(*xdoc));
	if (xdoc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(xdoc, 0, sizeof(*xdoc));
	list_head_init(&xdoc->finders);
	list_head_init(&xdoc->finders_val_wait);
	list_head_init(&xdoc->founders);

	xdoc->parser = XML_ParserCreate(NULL);
	if (xdoc->parser == NULL) {
		ret = -ENOMEM;
		goto err_doc_free;
	}
	xdoc->buf = buf;
	xdoc->buf_len = buf_len;
	ret = exml_el_encounter(xdoc, "/", &xdoc->el_path);
	if (ret < 0) {
		goto err_parser_free;
	}

	*xdoc_out = xdoc;

	return 0;
err_parser_free:
	XML_ParserFree(xdoc->parser);
err_doc_free:
	free(xdoc);
err_out:
	dbg(0, "failed to slurp xml\n");
	return ret;
}

/* free a stashed value */
static void
exml_finder_val_free(struct xml_finder *finder)
{
	if (finder->type == XML_VAL_STR) {
		free(*finder->ret_val.str);
		*finder->ret_val.str = NULL;
	} else if (finder->type == XML_VAL_B64) {
		free(*finder->ret_val.b64_decode);
		*finder->ret_val.b64_decode = NULL;
	}
}

/*
 * stash the obtained finder value in the type specific destination.
 * free the value buffer on success.
 */
static int
exml_finder_val_stash(struct xml_doc *xdoc,
		     char *got,
		     struct xml_finder *finder)
{
	char *sval_end;
	int ret;

	switch (finder->type) {
	case XML_VAL_STR:
		*finder->ret_val.str = got;
		got = NULL;
		break;
	case XML_VAL_I32:
		*finder->ret_val.i32 = strtol(got, &sval_end, 10);
		if (sval_end == got) {
			dbg(0, "non-numeric at %s: %s\n",
			    xdoc->el_path, got);
			return -EINVAL;
		}
		break;
	case XML_VAL_I64:
		*finder->ret_val.i64 = strtoll(got, &sval_end, 10);
		if (sval_end == got) {
			dbg(0, "non-numeric at %s: %s\n",
			    xdoc->el_path, got);
			return -EINVAL;
		}
		break;
	case XML_VAL_U64:
		*finder->ret_val.u64 = strtoull(got, &sval_end, 10);
		if (sval_end == got) {
			dbg(0, "non-numeric at %s: %s\n",
			    xdoc->el_path, got);
			return -EINVAL;
		}
		break;
	case XML_VAL_BOOL:
		if (!strcmp(got, "false")) {
			*finder->ret_val.bl = false;
		} else if (!strcmp(got, "true")) {
			*finder->ret_val.bl = true;
		} else {
			dbg(0, "invalid bool str: %s\n", got);
			return -EINVAL;
		}
		break;
	case XML_VAL_B64:
		if (strlen(got) <= 0) {
			return -EINVAL;
		}
		*finder->ret_val.b64_decode = malloc(strlen(got) + 1);
		if (*finder->ret_val.b64_decode == NULL) {
			return -ENOMEM;
		}
		ret = base64_decode(got, *finder->ret_val.b64_decode);
		if (ret < 0) {
			dbg(0, "failed to decode b64\n");
			free(*finder->ret_val.b64_decode);
			return ret;
		}
		/* zero terminate */
		(*finder->ret_val.b64_decode)[ret] = '\0';
		break;
	case XML_VAL_CALLBACK:
		ret = finder->ret_val.cb.fn(xdoc, xdoc->el_path, got,
					    finder->ret_val.cb.data);
		if (ret < 0) {
			dbg(0, "xml callback failed\n");
			return ret;
		}
		break;
	default:
		dbg(0, "unhandled type %d for path %s\n",
		    finder->type, xdoc->el_path);
		return -EIO;
		break;
	}
	if (finder->_present != NULL) {
		*finder->_present = true;
	}
	free(got);
	return 0;
}

static void
exml_el_data_cb(void *priv_data,
		const char *content,
		int len)
{
	struct xml_doc *xdoc = priv_data;
	struct xml_finder *finder;
	struct xml_finder *finder_n;
	char *got;
	int ret;

	/* walk list in case there's more than one finder for this path */
	list_for_each_safe(&xdoc->finders_val_wait, finder, finder_n, list) {
		if (strcmp(finder->found_el_path, xdoc->el_path) != 0) {
			dbg(3, "ignoring unmatched finder awaiting value %s\n",
			    finder->found_el_path);
			continue;
		}
		if (len == 0) {
			/* we shouldn't have got a callback */
			dbg(0, "empty value at %s\n", xdoc->el_path);
		}
		got = strndup(content, len);
		if (got == NULL) {
			XML_StopParser(xdoc->parser, XML_FALSE);
			xdoc->parse_ret = -ENOMEM;
			return;
		}

		assert(finder->handled == 0);
		ret = exml_finder_val_stash(xdoc, got, finder);
		if (ret < 0) {
			XML_StopParser(xdoc->parser, XML_FALSE);
			xdoc->parse_ret = ret;
			return;
		}
		finder->handled++;
		list_del(&finder->list);
		list_add_tail(&xdoc->founders, &finder->list);
	}

}

static int
exml_el_attr_search(const char **atts,
		   char *search_attr,
		   char **_attr_val)
{
	const char *s;
	char *attr_val;
	/* no char handler, only interested in attr */
	for (s = *atts; s != NULL; s = *(++atts)) {
		if (strcmp(s, search_attr) != 0) {
			/* skip unwanted attr val */
			if (*(++atts) == NULL) {
				dbg(0, "attr key %s without val!", s);
				break;
			}
			continue;
		}
		/* found, next array entry is the attr value */
		s = *(++atts);
		if (s == NULL) {
			dbg(0, "attr key %s without val!", search_attr);
			break;
		}
		if (strlen(s) == 0) {
			dbg(1, "empty attribute value for %s\n", search_attr);
			continue;
		}
		attr_val = strdup(s);
		if (attr_val == NULL) {
			return -ENOMEM;
		}
		*_attr_val = attr_val;
		return 0;
	}
	dbg(2, "attr [%s] not found\n", search_attr);
	return -ENOENT;
}

static int
exml_el_finder_path_cmp(const char *search_path,
			const char *el_path,
			bool wildcard,
			bool *_matched)
{
	char *spath;
	char *epath;
	char *stok;
	char *etok;
	char *ss;
	char *es;

	dbg(3, "comparing search_path \"%s\" with el_path \"%s\"\n",
	    search_path, el_path);

	spath = strdup(search_path);
	assert(spath != NULL);
	epath = strdup(el_path);
	assert(epath != NULL);

	for (stok = strtok_r(spath, "/", &ss), etok = strtok_r(epath, "/", &es);
	     ((stok != NULL) && (etok != NULL));
	     stok = strtok_r(NULL, "/", &ss), etok = strtok_r(NULL, "/", &es)) {
		char *sep;
		int scmp;
		if (!strcmp(stok, etok)) {
			dbg(5, "%s: direct match\n", stok);
			continue;
		}
		if (wildcard && !strcmp(stok, "*")) {
			dbg(5, "%s<->%s: wildcard match\n", stok, etok);
			continue;
		}

		sep = strchr(stok, '[');
		if (sep != NULL) {
			dbg(5, "%s<->%s: index in non-matching search token\n",
			    stok, etok);
			*_matched = false;
			goto out;
		}

		sep = strchr(etok, '[');
		assert(sep != NULL);	/* element path must have index */
		*sep = '\0';
		scmp = strcmp(stok, etok);
		*sep = '[';
		/* no index, search just needs to match */
		if (scmp == 0) {
			dbg(5, "%s<->%s: match without index\n", stok, etok);
			continue;
		}
		dbg(5, "%s<->%s: no match\n", stok, etok);
		*_matched = false;
		goto out;
	}

	if ((stok == NULL) && (etok == NULL)) {
		dbg(3, "%s<->%s full match\n", search_path, el_path);
		*_matched = true;
	} else {
		dbg(5, "%s<->%s no match\n", search_path, el_path);
		*_matched = false;
	}
out:
	free(spath);
	free(epath);
	return 0;
}

static int
exml_el_path_found_handle(struct xml_doc *xdoc,
			  struct xml_finder *finder,
			  const char **atts)
{
	int ret;

	finder->found_el_path = strdup(xdoc->el_path);
	if (finder->found_el_path == NULL) {
		return -ENOMEM;
	}
	if (finder->type == XML_VAL_PATH_CB) {
		/* no character handler, callback at path */
		ret = finder->ret_val.cb.fn(xdoc, finder->found_el_path, NULL,
					    finder->ret_val.cb.data);
		if (ret < 0) {
			dbg(0, "xml path (%s) callback failed\n",
			    xdoc->el_path);
			return ret;
		}
		assert(finder->handled == 0);
		finder->handled++;
		if (finder->_present != NULL) {
			*finder->_present = true;
		}
		list_del(&finder->list);
		xdoc->num_finders--;
		list_add_tail(&xdoc->founders, &finder->list);
		/* cb must add another finder entry if still interested */
		return 0;
	} else if (finder->search_attr != NULL) {
		char *attr_val;
		ret = exml_el_attr_search(atts, finder->search_attr, &attr_val);
		if ((ret < 0) && (ret != -ENOENT)) {
			return ret;
		} else if (ret == -ENOENT) {
			return 0;	/* ignore */
		}

		assert(finder->handled == 0);
		ret = exml_finder_val_stash(xdoc, attr_val, finder);
		if (ret < 0) {
			return ret;
		}
		finder->handled++;
		list_del(&finder->list);
		xdoc->num_finders--;
		list_add_tail(&xdoc->founders, &finder->list);
		return 0;
	}

	/*
	 * enable data callback to stash value
	 */
	XML_SetCharacterDataHandler(xdoc->parser, exml_el_data_cb);
	list_del(&finder->list);
	xdoc->num_finders--;
	list_add_tail(&xdoc->finders_val_wait, &finder->list);
	return 0;
}

static int
exml_el_finders_search(struct xml_doc *xdoc,
		       const char *el_path,
		       const char **atts)
{
	struct xml_finder *finder;
	struct xml_finder *finder_n;

	list_for_each_safe(&xdoc->finders, finder, finder_n, list) {
		bool match;
		int ret;
		ret = exml_el_finder_path_cmp(finder->search_path, el_path,
					      finder->path_wildcard, &match);
		if (ret < 0) {
			dbg(0, "finder comparison failed\n");
			return ret;
		}

		if (!match) {
			continue;
		}

		/* move finder to finders_val_wait or founders list */
		ret = exml_el_path_found_handle(xdoc, finder, atts);
		if (ret < 0) {
			dbg(0, "found callback failed\n");
			return ret;
		}
	}
	return 0;
}

static void
exml_el_start_cb(void *priv_data,
		const char *elem,
		const char **atts)
{
	struct xml_doc *xdoc = priv_data;
	char *new_path;
	int ret;

	/* disable data cb here, as previous value may have been empty */
	if (!list_empty(&xdoc->finders_val_wait)) {
		dbg(2, "finders awaiting value at start cb\n");
	}
	XML_SetCharacterDataHandler(xdoc->parser, NULL);

	ret = asprintf(&new_path, "%s%s/", xdoc->el_path, elem);
	if (ret == -1) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -ENOMEM;
		return;
	}
	dbg(3, "el path changing from (%s) to (%s)\n", xdoc->el_path, new_path);

	free(xdoc->el_path);
	ret = exml_el_encounter(xdoc, new_path, &xdoc->el_path);
	free(new_path);
	if (ret < 0) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = ret;
		return;
	}

	ret = exml_el_finders_search(xdoc, xdoc->el_path, atts);
	if (ret < 0) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = ret;
		return;
	}
}

static void
exml_el_end_cb(void *priv_data,
	      const char *elem)
{
	struct xml_doc *xdoc = priv_data;
	int elem_len = strlen(elem);
	int path_len;
	char *tok;

	/* overwrite the last leaf index */
	tok = strrchr(xdoc->el_path, '[');
	assert(tok != NULL);
	*tok = '\0';
	path_len = strlen(xdoc->el_path);
	if ((elem_len >= path_len)
	 || (strncmp(&xdoc->el_path[path_len - elem_len], elem,
		     elem_len) != 0)) {
		dbg(0, "end element %s outside current element path %s\n",
		    elem, xdoc->el_path);
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -EINVAL;
		return;
	}
	xdoc->el_path[path_len - elem_len] = '\0';

	dbg(3, "el_path changed to (%s)\n", xdoc->el_path);
}

int
exml_finders_walk_free(struct xml_doc *xdoc,
		       bool check_required,
		       bool free_vals)
{
	struct xml_finder *finder;
	struct xml_finder *finder_n;

	list_for_each_safe(&xdoc->finders, finder, finder_n, list) {
		if (check_required && finder->required) {
			dbg(1, "required xpath (%s) not found\n",
			    finder->search_path);
			/* clean up on exml_free() */
			return -ENOENT;
		}
		list_del(&finder->list);
		xdoc->num_finders--;

		free(finder->search_path);
		free(finder->search_attr);
		free(finder);
	}
	list_for_each_safe(&xdoc->finders_val_wait, finder, finder_n, list) {
		if (check_required && finder->required) {
			dbg(1, "required xpath (%s) value not found\n",
			    finder->search_path);
			return -ENOENT;
		}
		list_del(&finder->list);
		free(finder->search_path);
		free(finder->search_attr);
		free(finder->found_el_path);
		free(finder);
	}
	list_for_each_safe(&xdoc->founders, finder, finder_n, list) {
		if (free_vals) {
			exml_finder_val_free(finder);
		}
		list_del(&finder->list);
		free(finder->search_path);
		free(finder->search_attr);
		free(finder->found_el_path);
		free(finder);
	}
	return 0;
}

/*
 * On failure, all xdoc state is cleaned up via exml_free(), aside from any
 * finders that were found and allocated under the value pointer. E.g. string
 * or base64 types.
 */
int
exml_parse(struct xml_doc *xdoc)
{
	int ret;
	enum XML_Status xret;

	if ((xdoc == NULL) || (xdoc->parser == NULL)) {
		return -EINVAL;
	}

	XML_SetElementHandler(xdoc->parser, exml_el_start_cb, exml_el_end_cb);
	XML_SetUserData(xdoc->parser, xdoc);

	xdoc->parsing = true;
	xret = XML_Parse(xdoc->parser, xdoc->buf, xdoc->buf_len, XML_TRUE);
	xdoc->parsing = false;
	if (xret != XML_STATUS_OK) {
		enum XML_Error xerr = XML_GetErrorCode(xdoc->parser);
		dbg(0, "bad parsing status: %s\n", XML_ErrorString(xerr));
		return -EIO;
	} else if (xdoc->parse_ret < 0) {
		dbg(0, "parsing failed: %s\n", strerror(-xdoc->parse_ret));
		return xdoc->parse_ret;
	}

	if (dbg_level_get() >= 6) {
		twalk(xdoc->root_el, exml_el_print);
	}
	tdestroy(xdoc->root_el, exml_el_free);
	xdoc->root_el = NULL;

	/* walk list of finders, return error if required is missing */
	ret = exml_finders_walk_free(xdoc, true, false);
	if (ret < 0) {
		return ret;
	}

	assert(list_empty(&xdoc->finders));
	assert(xdoc->num_finders == 0);

	return 0;
}

void
exml_free(struct xml_doc *xdoc)
{
	if (xdoc->parsing) {
		dbg(0, "attempt to free xdoc while parsing, leaking!\n");
		return;
	}
	/* finders exist if parsing failed, need to free with found values */
	exml_finders_walk_free(xdoc, false, true);

	free(xdoc->el_path);
	if (xdoc->root_el != NULL) {
		/* parsing failed, need to free element tree */
		tdestroy(xdoc->root_el, exml_el_free);
	}
	XML_ParserFree(xdoc->parser);
	free(xdoc);
}

/*
 * @xp_expr: xpath in the form of:
 *	/parent/child
 *	./relative/path - (current path with indexes is prepended)
 *	/parent/child[@attribute]
 *	/parent[index]/child[index][@attribute]
 * 	/ * /child - (minus the spaces around the *)
 */
static int
exml_xpath_parse(const char *xp_expr,
		 const char *cur_el_path,
		 char **_search_path,
		 bool *_path_wildcard,
		 char **_attr)
{
	int ret;
	char *search_path = NULL;
	bool path_wildcard = false;
	char *attr = NULL;
	char *s;
	bool relative_path = false;

	if ((xp_expr == NULL)
	 || (strlen(xp_expr) == 0)
	 || (xp_expr[strlen(xp_expr) - 1] == '/')) {
		dbg(0, "bad xp_expr: %s\n", (xp_expr ? xp_expr : "null"));
		ret = -EINVAL;
		goto err_out;
	}

	if (strncmp(xp_expr, "./", 2) == 0) {
		relative_path = true;
		xp_expr += 2;
	} else if (xp_expr[0] != '/') {
		dbg(0, "bad xp_expr: %s\n", xp_expr);
		ret = -EINVAL;
		goto err_out;
	}

	ret = asprintf(&search_path, "%s%s/",
		       (relative_path ? cur_el_path : ""), xp_expr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	s = strstr(search_path, "[@");
	if (s != NULL) {
		*(s++) = '/';
		*(s++) = '\0';	/* terminate path */
		attr = strdup(s);
		if (attr == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}

		/* expecting [@attribute]/ enclosure */
		s = strstr(attr, "]");
		if ((s == NULL) || strcmp(s, "]/")) {
			dbg(0, "invalid attribute component in %s\n",
			    search_path);
			ret = -EINVAL;
			goto err_attr_free;
		}
		*s = '\0';
	}

	s = strchr(search_path, '*');
	if (s != NULL) {
		path_wildcard = true;
		if ((*(s + 1) != '/') || (*(s - 1) != '/')) {
			dbg(0, "invalid wildcard use (%s). Must consume one "
			       "path component\n", search_path);
			ret = -EINVAL;
			goto err_attr_free;
		}
		s = strchr(s + 1, '*');
		if (s != NULL) {
			dbg(0, "invalid multi-wildcard in (%s)\n", search_path);
			ret = -EINVAL;
			goto err_attr_free;
		}
	}

	*_search_path = search_path;
	*_path_wildcard = path_wildcard;
	*_attr = attr;
	return 0;

err_attr_free:
	free(attr);
err_path_free:
	free(search_path);
err_out:
	return ret;
}

/*
 * allocate and initialise an xpath search struct for use in a subsequent
 * xml_parse() call.
 * @xp_expr: xpath in the form of /parent/child or ./relative/path
 * @required: trigger xml_parse() failure if the xpath is not present
 * @present: set true if found during xml_parse(), may be NULL
 * @_finder: initialised finder struct returned on success
 */
static int
exml_finder_init(struct xml_doc *xdoc,
		const char *xp_expr,
		bool required,
		enum xml_val_type type,
		bool *present,
		struct xml_finder **_finder)
{
	int ret;
	struct xml_finder *finder;

	finder = malloc(sizeof(*finder));
	if (finder == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(finder, 0, sizeof(*finder));

	ret = exml_xpath_parse(xp_expr, xdoc->el_path, &finder->search_path,
			       &finder->path_wildcard, &finder->search_attr);
	if (ret < 0) {
		goto err_finder_free;
	}
	dbg(4, "new finder for (%s) [@%s]\n",
	    finder->search_path,
	    finder->search_attr ? finder->search_attr : "NONE");

	finder->required = required;
	finder->type = type;
	if (present != NULL) {
		*present = false;
		finder->_present = present;
	}
	list_add(&xdoc->finders, &finder->list);
	xdoc->num_finders++;
	*_finder = finder;

	return 0;

err_finder_free:
	free(finder);
err_out:
	return ret;
}

int
exml_str_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     char **value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_STR,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.str = value;
	return 0;
}

int
exml_int32_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     int32_t *value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_I32,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.i32 = value;
	return 0;
}

int
exml_int64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     int64_t *value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_I64,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.i64 = value;
	return 0;
}

int
exml_uint64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     uint64_t *value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_U64,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.u64 = value;
	return 0;
}

int
exml_bool_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     bool *value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_BOOL,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.bl = value;
	return 0;
}

int
exml_base64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     char **value,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_B64,
			present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.b64_decode = value;
	return 0;
}

int
exml_val_cb_want(struct xml_doc *xdoc,
		 const char *xp_expr,
		 bool required,
		 exml_want_cb_t cb,
		 void *cb_data,
		 bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_CALLBACK,
			      present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.cb.fn = cb;
	finder->ret_val.cb.data = cb_data;
	return 0;
}

/*
 * callback on path find instead of value retrieval.
 */
int
exml_path_cb_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     exml_want_cb_t cb,
	     void *cb_data,
	     bool *present)
{
	int ret;
	struct xml_finder *finder;

	ret = exml_finder_init(xdoc, xp_expr, required, XML_VAL_PATH_CB,
			      present, &finder);
	if (ret < 0) {
		return ret;
	}
	finder->ret_val.cb.fn = cb;
	finder->ret_val.cb.data = cb_data;
	return 0;
}
