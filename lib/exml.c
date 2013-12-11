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

struct xml_doc {
	XML_Parser parser;
	const char *buf;
	uint64_t buf_len;
	int num_finders;
	struct list_head finders;
	struct xml_finder *last_found;
	bool parsing;
	char *cur_path;
	int parse_ret;
};

int
exml_slurp(const char *buf,
	  uint64_t buf_len,
	  struct xml_doc **xdoc_out)
{
	int ret;
	struct xml_doc *xdoc;

	dbg(10, "slurping data: %s\n", (const char *)buf);

	xdoc = malloc(sizeof(*xdoc));
	if (xdoc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(xdoc, 0, sizeof(*xdoc));
	list_head_init(&xdoc->finders);

	xdoc->parser = XML_ParserCreate(NULL);
	if (xdoc->parser == NULL) {
		ret = -ENOMEM;
		goto err_doc_free;
	}
	xdoc->buf = buf;
	xdoc->buf_len = buf_len;
	xdoc->cur_path = strdup("/");
	if (xdoc->cur_path == NULL) {
		ret = -ENOMEM;
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
			    xdoc->cur_path, got);
			return -EINVAL;
		}
		break;
	case XML_VAL_I64:
		*finder->ret_val.i64 = strtoll(got, &sval_end, 10);
		if (sval_end == got) {
			dbg(0, "non-numeric at %s: %s\n",
			    xdoc->cur_path, got);
			return -EINVAL;
		}
		break;
	case XML_VAL_U64:
		*finder->ret_val.u64 = strtoull(got, &sval_end, 10);
		if (sval_end == got) {
			dbg(0, "non-numeric at %s: %s\n",
			    xdoc->cur_path, got);
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
		ret = finder->ret_val.cb.fn(xdoc, xdoc->cur_path, got,
					    finder->ret_val.cb.data);
		if (ret < 0) {
			dbg(0, "xml callback failed\n");
			return ret;
		}
		break;
	default:
		dbg(0, "unhandled type %d for path %s\n",
		    finder->type, xdoc->cur_path);
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
	char *got;
	int ret;

	finder = xdoc->last_found;
	if (finder == NULL) {
		dbg(0, "data cb for non-found finder\n");
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -EFAULT;
		return;
	}

	if (len == 0) {
		/* we shouldn't have got a callback */
		dbg(0, "empty value at %s\n", xdoc->cur_path);
	}
	got = strndup(content, len);
	if (got == NULL) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -ENOMEM;
		return;
	}

	if (finder->handled > 0) {
		dbg(2, "finder at (%s) handled, overwriting value\n",
		    finder->search_path);
		exml_finder_val_free(finder);
	}

	ret = exml_finder_val_stash(xdoc, got, finder);
	if (ret < 0) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = ret;
		return;
	}
	finder->handled++;
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
			continue;
		}
		/* found, next array entry is the attrib value */
		s = *(++atts);
		if (s == NULL) {
			dbg(0, "NULL attribute value for %s\n", search_attr);
			return -EINVAL;
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

static struct xml_finder *
exml_el_finders_search(struct list_head *finders,
		      const char *path)
{
	struct xml_finder *finder;

	list_for_each(finders, finder, list) {
		if (strcmp(finder->search_path, path) == 0) {
			dbg(6, "xpath (%s) found\n", path);
			return finder;
		} else if (finder->path_wildcard) {
			char *s;
			const char *path_after;
			int len;
			s = strchr(finder->search_path, '*');
			assert(s != NULL);	/* already checked */
			len = s - finder->search_path;
			if ((len > 0)
			 && (strncmp(finder->search_path, path, len) != 0)) {
				continue; /* no match before wild */
			}
			/* don't consider matched part in post '*' match */
			path_after = path + len;

			len = strlen(path_after) - strlen(s + 1);
			if (len < 0) {
				continue;
			}
			if ((len > 0)
			 && (strcmp(path_after + len, s + 1) != 0)) {
				continue; /* no match after wild */
			}
			dbg(6, "wild xpath (%s) match with (%s)\n",
			    finder->search_path, path);
			return finder;
		}
	}
	dbg(4, "xpath (%s) not found\n", path);
	return NULL;
}

static void
exml_el_start_cb(void *priv_data,
		const char *elem,
		const char **atts)
{
	struct xml_doc *xdoc = priv_data;
	char *new_path;
	int ret;
	struct xml_finder *finder;

	/* disable data cb here, as previous value may have been empty */
	xdoc->last_found = NULL;
	XML_SetCharacterDataHandler(xdoc->parser, NULL);

	ret = asprintf(&new_path, "%s%s/", xdoc->cur_path, elem);
	if (ret == -1) {
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -ENOMEM;
		return;
	}

	dbg(4, "xpath changing from (%s) to (%s)\n", xdoc->cur_path, new_path);
	free(xdoc->cur_path);
	xdoc->cur_path = new_path;

	finder = exml_el_finders_search(&xdoc->finders, new_path);
	if (finder == NULL) {
		/* no interest in this path */
		return;
	}

	if (finder->type == XML_VAL_PATH_CB) {
		/* no character handler, callback at path */
		ret = finder->ret_val.cb.fn(xdoc, new_path, NULL,
					    finder->ret_val.cb.data);
		if (ret < 0) {
			dbg(0, "xml path (%s) callback failed\n", new_path);
			XML_StopParser(xdoc->parser, XML_FALSE);
			xdoc->parse_ret = -ENOMEM;
			return;
		}
		finder->handled++;
		if (finder->_present != NULL) {
			*finder->_present = true;	/* TODO increment int */
		}
		/* keep on the finder list */
		return;
	} else if (finder->search_attr != NULL) {
		char *attr_val;
		ret = exml_el_attr_search(atts, finder->search_attr, &attr_val);
		if ((ret < 0) && (ret != -EINVAL)) {
			XML_StopParser(xdoc->parser, XML_FALSE);
			xdoc->parse_ret = ret;
			return;
		} else if (ret == -ENOENT) {
			return;	/* ignore */
		}

		if (finder->handled > 0) {
			exml_finder_val_free(finder);
		}
		ret = exml_finder_val_stash(xdoc, attr_val, finder);
		if (ret < 0) {
			XML_StopParser(xdoc->parser, XML_FALSE);
			xdoc->parse_ret = ret;
			return;
		}
		finder->handled++;
		return;
	}

	/* enable data callback to stash value */
	xdoc->last_found = finder;
	XML_SetCharacterDataHandler(xdoc->parser, exml_el_data_cb);
}

static void
exml_el_end_cb(void *priv_data,
	      const char *elem)
{
	struct xml_doc *xdoc = priv_data;
	int elem_len = strlen(elem);
	int path_len = strlen(xdoc->cur_path);

	/* -1 for trailing slash */
	if ((elem_len >= path_len)
	 || (strncmp(&xdoc->cur_path[path_len - 1 - elem_len], elem,
		     elem_len) != 0)) {
		dbg(0, "end element %s outside current path %s\n",
		    elem, xdoc->cur_path);
		XML_StopParser(xdoc->parser, XML_FALSE);
		xdoc->parse_ret = -EINVAL;
		return;
	}

	xdoc->cur_path[path_len - 1 - elem_len] = '\0';

	dbg(4, "xpath changed to (%s)\n", xdoc->cur_path);
}

int
exml_parse(struct xml_doc *xdoc)
{
	enum XML_Status xret;
	struct xml_finder *finder;
	struct xml_finder *finder_n;

	if ((xdoc == NULL) || (xdoc->parser == NULL)) {
		return -EINVAL;
	}

	XML_SetElementHandler(xdoc->parser, exml_el_start_cb, exml_el_end_cb);
	XML_SetUserData(xdoc->parser, xdoc);

	xdoc->parsing = true;
	xret = XML_Parse(xdoc->parser, xdoc->buf, xdoc->buf_len, XML_TRUE);
	xdoc->parsing = false;
	if (xret != XML_STATUS_OK) {
		dbg(0, "bad parsing status\n");
		return -EIO;
	} else if (xdoc->parse_ret < 0) {
		dbg(0, "parsing failed: %s\n", strerror(-xdoc->parse_ret));
		return xdoc->parse_ret;
	}

	/* check for required finders that were not located */
	list_for_each_safe(&xdoc->finders, finder, finder_n, list) {
		if (finder->required && (finder->handled == 0)) {
			dbg(0, "xpath (%s) not found\n", finder->search_path);
			/* clean up on exml_free() */
			return -ENOENT;
		}
		list_del(&finder->list);
		xdoc->num_finders--;

		free(finder->search_path);
		free(finder->search_attr);
		free(finder);
	}
	assert(list_empty(&xdoc->finders));
	assert(xdoc->num_finders == 0);

	return 0;
}

void
exml_free(struct xml_doc *xdoc)
{
	struct xml_finder *finder;
	struct xml_finder *finder_n;

	if (xdoc->parsing) {
		dbg(0, "attempt to free xdoc while parsing, leaking!\n");
		return;
	}
	list_for_each_safe(&xdoc->finders, finder, finder_n, list) {
		if (finder->handled > 0) {
			/* failed parse after finding somthing, free stash */
			exml_finder_val_free(finder);
		}
		free(finder->search_path);
		free(finder->search_attr);
		free(finder);
	}
	free(xdoc->cur_path);
	XML_ParserFree(xdoc->parser);
	free(xdoc);
}

/*
 * @xp_expr: xpath in the form of /parent/child, ./relative/path,
 *	     /parent/child[@attribute]
 */
static int
exml_xpath_parse(const char *xp_expr,
		 const char *cur_path,
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
		       (relative_path ? cur_path : ""), xp_expr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* -2 to compensate for trailing slash added */
	if (search_path[strlen(search_path) - 2] == ']') {
		/* expecting [@attribute] component */
		s = strstr(search_path, "[@");
		if (s == NULL) {
			dbg(0, "invalid attribute component in %s\n",
			    search_path);
			ret = -EINVAL;
			goto err_path_free;
		}
		*(s++) = '/';
		*(s++) = '\0';	/* terminate path */

		attr = strdup(s);
		if (attr == NULL) {
			ret = -ENOMEM;
			goto err_path_free;
		}

		s = strchr(attr, ']');
		assert(s != NULL);	/* already seen */
		*s = '\0';
	}

	s = strchr(search_path, '*');
	if (s != NULL) {
		path_wildcard = true;
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

	ret = exml_xpath_parse(xp_expr, xdoc->cur_path, &finder->search_path,
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
	list_add_tail(&xdoc->finders, &finder->list);
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
exml_cb_want(struct xml_doc *xdoc,
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
