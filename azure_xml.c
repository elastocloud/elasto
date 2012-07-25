/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
 *
 * Author: ddiss@suse.de
 */
#include <stdint.h>
#include <errno.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

int
azure_xml_slurp(const uint8_t *buf,
		uint64_t buf_len,
		xmlDoc **xp_doc,
		xmlXPathContext **xp_ctx)
{
	int ret;
	xmlDoc *xdoc;
	xmlXPathContext *xpath_ctx;

	xdoc = xmlParseMemory((char *)buf, buf_len);
	if (xdoc == NULL) {
		printf("unable to parse in-memory XML\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* Create xpath evaluation context */
	xpath_ctx = xmlXPathNewContext(xdoc);
	if (xpath_ctx == NULL) {
		printf("unable to create XPath context\n");
		ret = -ENOMEM;
		goto err_free_doc;
	}

	if (xmlXPathRegisterNs(xpath_ctx, (xmlChar *)"def",
			(xmlChar *)"http://schemas.microsoft.com/windowsazure") != 0) {
		printf("Unable to register NS: def\n");
		ret = -EINVAL;
		goto err_free_xpctx;
	}
	if (xmlXPathRegisterNs(xpath_ctx, (xmlChar *)"i",
			(xmlChar *)"http://www.w3.org/2001/XMLSchema-instance") != 0) {
		printf("Unable to register NS: i\n");
		ret = -EINVAL;
		goto err_free_xpctx;
	}

	*xp_doc = xdoc;
	*xp_ctx = xpath_ctx;

	return 0;

err_free_xpctx:
	xmlXPathFreeContext(xpath_ctx);
err_free_doc:
	xmlFreeDoc(xdoc);
err_out:
	return ret;
}

int
azure_xml_get_path(xmlXPathContext *xp_ctx,
		   const char *xp_expr,
		   xmlChar **content)
{
	int ret;
	xmlXPathObject *xp_obj;
	xmlChar *ctnt;

	/* Evaluate xpath expression */
	xp_obj = xmlXPathEval((const xmlChar *)xp_expr, xp_ctx);
	if (xp_obj == NULL) {
		printf("Unable to evaluate xpath expression \"%s\"\n",
		       xp_expr);
		return -ENOENT;
	}

	if (xp_obj->nodesetval == NULL) {
		printf("null nodesetval\n");
		ret = -ENOENT;
		goto err_xp_obj;
	}
	if (xp_obj->nodesetval->nodeNr == 0) {
		printf("empty nodesetval\n");
		ret = -ENOENT;
		goto err_xp_obj;
	}

	ctnt = xmlNodeGetContent(xp_obj->nodesetval->nodeTab[0]);
	if (ctnt == NULL) {
		ret = -ENOMEM;
		goto err_xp_obj;
	}

	*content = ctnt;
	ret = 0;
err_xp_obj:
	xmlXPathFreeObject(xp_obj);
	return ret;
}

int
azure_xml_subsys_init(void)
{
	xmlInitParser();
}

void
azure_xml_subsys_deinit(void)
{
	xmlCleanupParser();
}
