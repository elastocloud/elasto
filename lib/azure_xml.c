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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <apr-1/apr_xml.h>

#include "dbg.h"

int
azure_xml_slurp(apr_pool_t *pool,
		bool is_file,
		const uint8_t *buf,
		uint64_t buf_len,
		struct apr_xml_doc **xdoc_out)
{
	int ret;
	apr_status_t rv;
	struct apr_xml_parser *xparser;
	struct apr_xml_doc *xdoc;

	if (is_file) {
		apr_file_t *afd;
		rv = apr_file_open(&afd, (const char *)buf, APR_FOPEN_READ,
				   APR_OS_DEFAULT, pool);
		if (rv != APR_SUCCESS) {
			ret = -APR_TO_OS_ERROR(rv);
			goto err_out;
		}

		rv = apr_xml_parse_file(pool, &xparser, &xdoc, afd, 1024);
		apr_file_close(afd);
		if (rv != APR_SUCCESS) {
			ret = -APR_TO_OS_ERROR(rv);
			goto err_out;
		}
	} else {
		xparser = apr_xml_parser_create(pool);
		if (xparser == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}

		rv = apr_xml_parser_feed(xparser, (const char *)buf, buf_len);
		if (rv != APR_SUCCESS) {
			ret = -APR_TO_OS_ERROR(rv);
			goto err_out;
		}

		rv = apr_xml_parser_done(xparser, &xdoc);
		if (rv != APR_SUCCESS) {
			ret = -APR_TO_OS_ERROR(rv);
			goto err_out;
		}
	}

	*xdoc_out = xdoc;

	return 0;

err_out:
	dbg(0, "failed to slurp xml\n");
	return ret;
}

/* find element at the same level as @xel */
static int
azure_xml_elem_lev_find(struct apr_xml_elem *xel,
			const char *name,
			struct apr_xml_elem **xel_found_out)
{
	while ((xel != NULL) && (strcmp(xel->name, name) != 0)) {
		xel = xel->next;
	}

	if (xel == NULL) {
		return -ENOENT;
	}

	*xel_found_out = xel;
	return 0;
}

/*
 * Evaluate basic xpath expression:
 *	/grandparent/parent/child
 */
int
azure_xml_path_el_get(struct apr_xml_elem *xel_parent,
		      const char *xp_expr,
		      struct apr_xml_elem **xel_child_out)
{
	int ret;
	char *component;
	struct apr_xml_elem *xel;
	struct apr_xml_elem *xel_next;
	char *expr = strdup(xp_expr);

	if (expr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	component = strtok(expr, "/");
	xel_next = xel_parent;
	while ((component != NULL) && (xel_next != NULL)) {
		/* check for index */
		ret = azure_xml_elem_lev_find(xel_next, component, &xel);
		if (ret < 0) {
			dbg(4, "could not find %s xpath component of %s\n",
			    component, xp_expr);
			goto err_expr_free;
		}
		xel_next = xel->first_child;
		component = strtok(NULL, "/");
	}

	dbg(4, "found %s xpath\n", xp_expr);
	*xel_child_out = xel;

	ret = 0;
err_expr_free:
	free(expr);
err_out:
	return ret;
}

/* get value at corresponding xpath */
int
azure_xml_path_get(struct apr_xml_elem *xel_parent,
		   const char *xp_expr,
		   char **value)
{
	int ret;
	struct apr_xml_elem *xel;

	ret = azure_xml_path_el_get(xel_parent, xp_expr, &xel);
	if (ret < 0) {
		return ret;
	}

	if (xel->first_cdata.first == NULL) {
		/* no value */
		*value = NULL;
		return 0;
	}

	*value = strdup(xel->first_cdata.first->text);
	if (*value == NULL) {
		return -ENOMEM;
	}

	return 0;
}

int
azure_xml_attr_get(struct apr_xml_elem *xel,
		   const char *key,
		   char **value)
{
	struct apr_xml_attr *attr;

	attr = xel->attr;

	while ((attr != NULL) && (strcmp(key, attr->name) != 0)) {
		attr = attr->next;
	}

	if (attr == NULL) {
		dbg(4, "could not find attr with key %s\n", key);
		return -ENOENT;
	}

	*value = strdup(attr->value);
	if (*value == NULL) {
		return -ENOMEM;
	}

	return 0;
}
