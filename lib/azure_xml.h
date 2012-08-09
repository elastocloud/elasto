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
 *
 * Author: David Disseldorp <ddiss@suse.de>
 */
#ifndef _AZURE_XML_H_
#define _AZURE_XML_H_

int
azure_xml_slurp(bool is_file,
		const uint8_t *buf,
		uint64_t buf_len,
		xmlDoc **xp_doc,
		xmlXPathContext **xp_ctx);

int
azure_xml_get_path(xmlXPathContext *xp_ctx,
		   const char *xp_expr,
		   const char *xp_attr,
		   char **content);

void
azure_xml_subsys_init(void);

void
azure_xml_subsys_deinit(void);
#endif /* _AZURE_XML_H_ */
