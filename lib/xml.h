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
#ifndef _AZURE_XML_H_
#define _AZURE_XML_H_

int
xml_slurp(apr_pool_t *pool,
		bool is_file,
		const uint8_t *buf,
		uint64_t buf_len,
		struct apr_xml_doc **xdoc_out);

int
xml_path_get(struct apr_xml_elem *xel_parent,
		   const char *xp_expr,
		   char **value);

int
xml_path_i32_get(struct apr_xml_elem *xel_parent,
		       const char *xp_expr,
		       int32_t *value);

int
xml_path_i64_get(struct apr_xml_elem *xel_parent,
		       const char *xp_expr,
		       int64_t *value);

int
xml_path_u64_get(struct apr_xml_elem *xel_parent,
		       const char *xp_expr,
		       uint64_t *value);

int
xml_path_bool_get(struct apr_xml_elem *xel_parent,
			const char *xp_expr,
			bool *value);

int
xml_path_b64_get(struct apr_xml_elem *xel_parent,
		 const char *xp_expr,
		 char **_val,
		 int *_len);

int
xml_path_el_get(struct apr_xml_elem *xel_parent,
		      const char *xp_expr,
		      struct apr_xml_elem **xel_child_out);

int
xml_attr_get(struct apr_xml_elem *xel,
		   const char *key,
		   char **value);
#endif /* _AZURE_XML_H_ */
