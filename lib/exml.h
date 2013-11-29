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
#ifndef _AZURE_EXML_H_
#define _AZURE_EXML_H_

struct xml_doc;
struct xml_elem {
	struct xml_doc *xdoc;
	const char *path;
};

int
exml_slurp(const char *buf,
	  uint64_t buf_len,
	  struct xml_doc **xdoc_out);

int
exml_parse(struct xml_doc *xdoc);

int
exml_str_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     char **value,
	     bool *present);

int
exml_int32_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     int32_t *value,
	     bool *present);

int
exml_int64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     int64_t *value,
	     bool *present);

int
exml_uint64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     uint64_t *value,
	     bool *present);

int
exml_bool_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     bool *value,
	     bool *present);

int
exml_base64_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     char **value,
	     bool *present);

typedef int (*exml_want_cb_t)(struct xml_doc *xdoc,
			     const char *path,
			     const char *val,
			     void *cb_data);
int
exml_cb_want(struct xml_doc *xdoc,
	     const char *xp_expr,
	     bool required,
	     exml_want_cb_t cb,
	     void *cb_data,
	     bool *present);

void
exml_free(struct xml_doc *xdoc);

#endif /* _AZURE_EXML_H_ */
