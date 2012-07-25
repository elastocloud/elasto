/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
#ifndef _AZURE_XML_H_
#define _AZURE_XML_H_

int
azure_xml_slurp(const uint8_t *buf,
		uint64_t buf_len,
		xmlDoc **xp_doc,
		xmlXPathContext **xp_ctx);

int
azure_xml_get_path(xmlXPathContext *xp_ctx,
		   const char *xp_expr,
		   xmlChar **content);

#endif /* _AZURE_XML_H_ */
