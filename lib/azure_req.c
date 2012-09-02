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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xmlwriter.h>

#include "ccan/list/list.h"
#include "base64.h"
#include "azure_xml.h"
#include "azure_req.h"

void
azure_op_data_destroy(struct azure_op_data **data)
{
	struct azure_op_data *adata = *data;
	if (adata == NULL)
		return;
	free(adata->buf);
	if (adata->type == AOP_DATA_FILE)
		close(adata->file.fd);
	free(adata);
	*data = NULL;
}

/*
 * allocate a file based data structure, opening the underlying file
 */
int
azure_op_data_file_new(char *path,
		       uint64_t file_len,
		       uint64_t base_off,
		       int open_flags,
		       mode_t create_mode,
		       struct azure_op_data **data)
{
	struct azure_op_data *adata;

	adata = malloc(sizeof(*adata));
	if (adata == NULL)
		return -ENOMEM;

	adata->type = AOP_DATA_FILE;
	if (open_flags | O_CREAT)
		adata->file.fd = open(path, open_flags, create_mode);
	else
		adata->file.fd = open(path, open_flags);

	if (adata->file.fd == -1) {
		free(adata);
		return -errno;
	}
	adata->buf = (uint8_t *)path;
	adata->len = file_len;
	adata->off = 0;
	adata->base_off = base_off;
	*data = adata;

	return 0;
}

/*
 * allocate an iov based data structure
 * if @buf_alloc is set then allocate @buf_len, ignoring @buf and @base_off
 */
int
azure_op_data_iov_new(uint8_t *buf,
		      uint64_t buf_len,
		      uint64_t base_off,
		      bool buf_alloc,
		      struct azure_op_data **data)
{
	struct azure_op_data *adata;

	adata = malloc(sizeof(*adata));
	if (adata == NULL)
		return -ENOMEM;

	adata->type = AOP_DATA_IOV;
	if (buf_alloc) {
		assert(buf_len > 0);
		adata->buf = malloc(buf_len);
		if (adata->buf == NULL) {
			free(adata);
			return -ENOMEM;
		}
		adata->base_off = 0;
	} else {
		adata->buf = buf;
		adata->base_off = base_off;
	}
	adata->len = buf_len;
	adata->off = 0;
	*data = adata;

	return 0;
}

static char *
gen_date_str(void)
{
	char buf[200];
	time_t now;
	struct tm utc_tm;
	size_t ret;

	time(&now);
	gmtime_r(&now, &utc_tm);
	/* Sun, 11 Oct 2009 21:49:13 GMT */
	ret = strftime(buf, sizeof(buf), "%a, %d %b %Y %T GMT", &utc_tm);
	if (ret == 0)
		return NULL;
	return strdup(buf);

}

static void
azure_req_acc_keys_get_free(struct azure_req_acc_keys_get *acc_keys_get_req)
{
	free(acc_keys_get_req->sub_id);
	free(acc_keys_get_req->service_name);
}
static void
azure_rsp_acc_keys_get_free(struct azure_rsp_acc_keys_get *acc_keys_get_rsp)
{
	free(acc_keys_get_rsp->primary);
	free(acc_keys_get_rsp->secondary);
}

static int
azure_op_acc_keys_get_fill_hdr(struct azure_op *op)
{
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2012-03-01");
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int
azure_op_acc_keys_get(const char *sub_id,
		      const char *service_name,
		      struct azure_op *op)
{
	int ret;
	struct azure_req_acc_keys_get *acc_keys_get_req;

	/* TODO input validation */

	op->opcode = AOP_ACC_KEYS_GET;
	acc_keys_get_req = &op->req.acc_keys_get;

	/* we may not need to keep these, as they're only used in the URL */
	acc_keys_get_req->sub_id = strdup(sub_id);
	if (acc_keys_get_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	acc_keys_get_req->service_name = strdup(service_name);
	if (acc_keys_get_req->service_name == NULL) {
		ret = -ENOMEM;
		goto err_free_sub;
	}
	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s/keys",
		       sub_id, service_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_svc;
	}

	ret = azure_op_acc_keys_get_fill_hdr(op);
	if (ret < 0) {
		goto err_free_url;
	}

	return 0;
err_free_url:
	free(op->url);
err_free_svc:
	free(acc_keys_get_req->service_name);
err_free_sub:
	free(acc_keys_get_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_acc_keys_get_process(struct azure_op *op)
{
	int ret;
	struct azure_rsp_acc_keys_get *acc_keys_get_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	assert(op->opcode == AOP_ACC_KEYS_GET);
	assert(op->rsp.data->type == AOP_DATA_IOV);

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(false, op->rsp.data->buf, op->rsp.data->off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	acc_keys_get_rsp = &op->rsp.acc_keys_get;

	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Primary",
		NULL, &acc_keys_get_rsp->primary);
	if (ret < 0) {
		goto err_xml_free;
	}
	ret = azure_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Secondary",
		NULL, &acc_keys_get_rsp->secondary);
	if (ret < 0) {
		free(acc_keys_get_rsp->primary);
		goto err_xml_free;
	}
	ret = 0;

err_xml_free:
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_acc_list_free(struct azure_req_acc_list *acc_list_req)
{
	free(acc_list_req->sub_id);
}

static void
azure_acc_free(struct azure_account **pacc)
{
	struct azure_account *acc = *pacc;

	free(acc->svc_name);
	free(acc->url);
	free(acc->affin_grp);
	free(acc->location);
	free(acc->desc);
	free(acc);
}

static void
azure_rsp_acc_list_free(struct azure_rsp_acc_list *acc_list_rsp)
{
	struct azure_account *acc;
	struct azure_account *acc_n;

	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(&acc);
	}
}

static int
azure_op_acc_list_fill_hdr(struct azure_op *op)
{
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2012-03-01");
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int
azure_op_acc_list(const char *sub_id,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_acc_list *acc_list_req;

	/* TODO input validation */

	op->opcode = AOP_ACC_LIST;
	acc_list_req = &op->req.acc_list;

	acc_list_req->sub_id = strdup(sub_id);
	if (acc_list_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_sub_free;
	}

	ret = azure_op_acc_list_fill_hdr(op);
	if (ret < 0) {
		goto err_url_free;
	}

	return 0;
err_url_free:
	free(op->url);
err_sub_free:
	free(acc_list_req->sub_id);
err_out:
	return ret;
}

static int
azure_rsp_acc_iter_process(xmlXPathContext *xp_ctx,
			   int iter,
			   struct azure_account **acc_ret)
{
	int ret;
	struct azure_account *acc;
	char *query;

	acc = malloc(sizeof(*acc));
	if (acc == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(acc, 0, sizeof(*acc));

	ret = asprintf(&query,
		       "//def:StorageServices/def:StorageService[%d]/"
		       "def:ServiceName", iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &acc->svc_name);
	free(query);
	if (ret < 0) {
		goto err_acc_free;
	}

	ret = asprintf(&query,
		       "//def:StorageServices/def:StorageService[%d]/def:Url",
		       iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &acc->url);
	free(query);
	if (ret < 0) {
		goto err_name_free;
	}


	ret = asprintf(&query,
		       "//def:StorageServices/def:StorageService[%d]/"
		       "def:StorageServiceProperties/def:Description", iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_url_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &acc->desc);
	free(query);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_url_free;
	}

	ret = asprintf(&query,
		       "//def:StorageServices/def:StorageService[%d]/"
		       "def:StorageServiceProperties/def:AffinityGroup", iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_desc_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &acc->affin_grp);
	free(query);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_desc_free;
	}

	ret = asprintf(&query,
		       "//def:StorageServices/def:StorageService[%d]/"
		       "def:StorageServiceProperties/def:Location", iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_affin_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &acc->location);
	free(query);
	if ((ret < 0) && (ret != -ENOENT)) {
		goto err_affin_free;
	}
	*acc_ret = acc;

	return 0;

err_affin_free:
	free(acc->affin_grp);
err_desc_free:
	free(acc->desc);
err_url_free:
	free(acc->url);
err_name_free:
	free(acc->svc_name);
err_acc_free:
	free(acc);
err_out:
	return ret;
}

static int
azure_rsp_acc_list_process(struct azure_op *op)
{
	int ret;
	struct azure_rsp_acc_list *acc_list_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;
	int i;
	struct azure_account *acc;
	struct azure_account *acc_n;

	assert(op->opcode == AOP_ACC_LIST);
	assert(op->rsp.data->type == AOP_DATA_IOV);

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(false, op->rsp.data->buf, op->rsp.data->off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	acc_list_rsp = &op->rsp.acc_list;

	list_head_init(&acc_list_rsp->accs);
	for (i = 1; i <= 5000; i++) {
		ret = azure_rsp_acc_iter_process(xp_ctx, i, &acc);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			goto err_accs_free;
		}
		list_add_tail(&acc_list_rsp->accs, &acc->list);
		acc_list_rsp->num_accs++;
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
	return 0;

err_accs_free:
	list_for_each_safe(&acc_list_rsp->accs, acc, acc_n, list) {
		azure_acc_free(&acc);
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static int
azure_op_acc_create_fill_hdr(struct azure_op *op)
{
	op->http_hdr = curl_slist_append(op->http_hdr,
					 "x-ms-version: 2012-03-01");
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}
	op->http_hdr = curl_slist_append(op->http_hdr,
			"Content-Type: application/xml; charset=utf-8");
	if (op->http_hdr == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static int
azure_op_acc_create_fill_body(struct azure_account *acc,
			      struct azure_op_data **req_data)
{
	int ret;
	xmlTextWriter *writer;
	xmlBuffer *xbuf;
	char *b64_label;

	xbuf = xmlBufferCreate();
	if (xbuf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	writer = xmlNewTextWriterMemory(xbuf, 0);
	if (writer == NULL) {
		ret = -ENOMEM;
		goto err_xbuf_free;
	}

	ret = xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	if (ret < 0) {
		ret = -EIO;
		goto err_writer_free;
	}

	ret = xmlTextWriterStartElement(writer,
					BAD_CAST "CreateStorageServiceInput");
	if (ret < 0) {
		ret = -EIO;
		goto err_writer_free;
	}

	ret = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns",
			BAD_CAST "http://schemas.microsoft.com/windowsazure");
	if (ret < 0) {
		ret = -EIO;
		goto err_writer_free;
	}

	ret = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ServiceName",
					      "%s", acc->svc_name);
	if (ret < 0) {
		ret = -EBADF;
		goto err_writer_free;
	}

	ret = base64_encode(acc->label, strlen(acc->label), &b64_label);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_writer_free;
	}
	ret = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Label",
					     "%s", b64_label);
	free(b64_label);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_writer_free;
	}

	if (acc->desc != NULL) {
		ret = xmlTextWriterWriteFormatElement(writer,
						      BAD_CAST "Description",
						      "%s", acc->desc);
		if (ret < 0) {
			ret = -EBADF;
			goto err_writer_free;
		}
	}
	if (acc->affin_grp != NULL) {
		ret = xmlTextWriterWriteFormatElement(writer,
						      BAD_CAST "AffinityGroup",
						      "%s", acc->affin_grp);
		if (ret < 0) {
			ret = -EBADF;
			goto err_writer_free;
		}
	}
	if (acc->location != NULL) {
		ret = xmlTextWriterWriteFormatElement(writer,
						      BAD_CAST "Location",
						      "%s", acc->location);
		if (ret < 0) {
			ret = -EBADF;
			goto err_writer_free;
		}
	}

	ret = xmlTextWriterEndElement(writer);
	if (ret < 0) {
		ret = -EBADF;
		goto err_writer_free;
	}

	ret = xmlTextWriterEndDocument(writer);
	if (ret < 0) {
		ret = -EBADF;
		goto err_writer_free;
	}

	ret = azure_op_data_iov_new(NULL, xmlBufferLength(xbuf), 0, true,
				    req_data);
	/* XXX could use xmlBufferDetach to avoid the memcpy? */
	if (ret < 0) {
		goto err_writer_free;
	}
	memcpy((*req_data)->buf, xmlBufferContent(xbuf), (*req_data)->len);

	ret = 0;
err_writer_free:
	xmlFreeTextWriter(writer);
err_xbuf_free:
	xmlBufferFree(xbuf);
err_out:
	return ret;
}

int
azure_op_acc_create(const char *sub_id,
		    const char *svc_name,
		    const char *label,
		    const char *desc,
		    const char *affin_grp,
		    const char *location,
		    struct azure_op *op)
{
	int ret;
	struct azure_req_acc_create *acc_create_req;

	if ((sub_id == NULL) || (svc_name == NULL) || (label == NULL)) {
		return -EINVAL;
	} else if ((affin_grp == NULL) && (location == NULL)) {
		return -EINVAL;
	}

	op->opcode = AOP_ACC_CREATE;
	acc_create_req = &op->req.acc_create;

	acc_create_req->sub_id = strdup(sub_id);
	if (acc_create_req->sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	acc_create_req->acc.svc_name = strdup(svc_name);
	if (acc_create_req->acc.svc_name == NULL) {
		ret = -ENOMEM;
		goto err_sub_free;
	}
	acc_create_req->acc.label = strdup(label);
	if (acc_create_req->acc.label == NULL) {
		ret = -ENOMEM;
		goto err_svc_name_free;
	}

	if (desc != NULL) {
		acc_create_req->acc.desc = strdup(desc);
		if (acc_create_req->acc.desc == NULL) {
			ret = -ENOMEM;
			goto err_label_free;
		}
	}
	if (affin_grp != NULL) {
		acc_create_req->acc.affin_grp = strdup(affin_grp);
		if (acc_create_req->acc.affin_grp == NULL) {
			ret = -ENOMEM;
			goto err_desc_free;
		}
	} else {
		assert(location != NULL);
		acc_create_req->acc.location = strdup(location);
		if (acc_create_req->acc.location == NULL) {
			ret = -ENOMEM;
			goto err_desc_free;
		}
	}

	op->method = REQ_METHOD_POST;
	ret = asprintf(&op->url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_loc_free;
	}

	ret = azure_op_acc_create_fill_hdr(op);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_acc_create_fill_body(&acc_create_req->acc,
					    &op->req.data);
	if (ret < 0) {
		goto err_url_free;
	}

	return 0;
err_url_free:
	free(op->url);
err_loc_free:
	free(acc_create_req->acc.location);
	free(acc_create_req->acc.affin_grp);
err_desc_free:
	free(acc_create_req->acc.desc);
err_label_free:
	free(acc_create_req->acc.label);
err_svc_name_free:
	free(acc_create_req->acc.svc_name);
err_sub_free:
	free(acc_create_req->sub_id);
err_out:
	return ret;
}

static void
azure_req_ctnr_list_free(struct azure_req_ctnr_list *ctnr_list_req)
{
	free(ctnr_list_req->account);
}
static void
azure_rsp_ctnr_list_free(struct azure_rsp_ctnr_list *ctnr_list_rsp)
{
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	if (ctnr_list_rsp->num_ctnrs <= 0)
		return;

	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
}

static int
azure_op_ctnr_list_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_ctnr_list(const char *account,
		    struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_list *ctnr_list_req;

	/* TODO input validation */

	op->opcode = AOP_CONTAINER_LIST;
	ctnr_list_req = &op->req.ctnr_list;

	ctnr_list_req->account = strdup(account);
	if (ctnr_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/?comp=list",
		       account);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = azure_op_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_ctnr_list_fill_hdr(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_buf_free:
	azure_op_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_acc_free:
	free(ctnr_list_req->account);
err_out:
	return ret;
}

static int
azure_rsp_ctnr_iter_process(xmlXPathContext *xp_ctx,
			    int iter,
			    struct azure_ctnr **ctnr)
{
	int ret;
	char *query;
	char *name;
	struct azure_ctnr *ictnr;

	ret = asprintf(&query, "//Containers/Container[%d]/Name",
		       iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &name);
	free(query);
	if (ret < 0) {
		goto err_out;	/* -ENOENT = all processed */
	}

	ictnr = malloc(sizeof(*ictnr));
	if (ictnr == NULL) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ictnr->name = name;
	*ctnr = ictnr;

	return 0;

err_name_free:
	free(name);
err_out:
	return ret;
}

static int
azure_rsp_ctnr_list_process(struct azure_op *op)
{
	int ret;
	int i;
	struct azure_rsp_ctnr_list *ctnr_list_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;
	struct azure_ctnr *ctnr;
	struct azure_ctnr *ctnr_n;

	assert(op->opcode == AOP_CONTAINER_LIST);
	assert(op->rsp.data->type == AOP_DATA_IOV);

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(false, op->rsp.data->buf, op->rsp.data->off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	ctnr_list_rsp = &op->rsp.ctnr_list;

	list_head_init(&ctnr_list_rsp->ctnrs);
	/*
	 * Returns up to 5000 records (maxresults default),
	 * start at 1 for W3C xpath standard
	 */
	for (i = 1; i <= 5000; i++) {
		ret = azure_rsp_ctnr_iter_process(xp_ctx, i, &ctnr);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			goto err_ctnrs_free;
		}
		list_add_tail(&ctnr_list_rsp->ctnrs, &ctnr->list);
		ctnr_list_rsp->num_ctnrs++;
	}

	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
	return 0;

err_ctnrs_free:
	list_for_each_safe(&ctnr_list_rsp->ctnrs, ctnr, ctnr_n, list) {
		free(ctnr->name);
		free(ctnr);
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_ctnr_create_free(struct azure_req_ctnr_create *ctnr_create_req)
{
	free(ctnr_create_req->account);
	free(ctnr_create_req->ctnr);
}

static int
azure_op_ctnr_create_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_ctnr_create(const char *account,
		     const char *ctnr,
		     struct azure_op *op)
{

	int ret;
	struct azure_req_ctnr_create *ctnr_create_req;

	/* TODO input validation */

	op->opcode = AOP_CONTAINER_CREATE;
	ctnr_create_req = &op->req.ctnr_create;

	ctnr_create_req->account = strdup(account);
	if (ctnr_create_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ctnr_create_req->ctnr = strdup(ctnr);
	if (ctnr_create_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s?restype=container",
		       account, ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	azure_op_ctnr_create_fill_hdr(op);
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_ctnr_free:
	free(ctnr_create_req->ctnr);
err_acc_free:
	free(ctnr_create_req->account);
err_out:
	return ret;
}

static void
azure_req_ctnr_del_free(struct azure_req_ctnr_del *ctnr_del_req)
{
	free(ctnr_del_req->account);
	free(ctnr_del_req->container);
}

static int
azure_op_ctnr_del_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					 "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_ctnr_del(const char *account,
		   const char *container,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_ctnr_del *ctnr_del_req;

	op->opcode = AOP_CONTAINER_DEL;
	ctnr_del_req = &op->req.ctnr_del;

	ctnr_del_req->account = strdup(account);
	if (ctnr_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ctnr_del_req->container = strdup(container);
	if (ctnr_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s?restype=container",
		       account, container);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	/* mandatory headers */
	ret = azure_op_ctnr_del_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_free_container:
	free(ctnr_del_req->container);
err_free_account:
	free(ctnr_del_req->account);
err_out:
	return ret;
}

static void
azure_req_blob_list_free(struct azure_req_blob_list *blob_list_req)
{
	free(blob_list_req->account);
	free(blob_list_req->ctnr);
}
static void
azure_rsp_blob_list_free(struct azure_rsp_blob_list *blob_list_rsp)
{
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	if (blob_list_rsp->num_blobs <= 0)
		return;

	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob);
	}
}

static int
azure_op_blob_list_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_blob_list(const char *account,
		   const char *ctnr,
		   struct azure_op *op)
{

	int ret;
	struct azure_req_blob_list *blob_list_req;

	/* TODO input validation */

	op->opcode = AOP_BLOB_LIST;
	blob_list_req = &op->req.blob_list;

	blob_list_req->account = strdup(account);
	if (blob_list_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	blob_list_req->ctnr = strdup(ctnr);
	if (blob_list_req->ctnr == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net"
		       "/%s?restype=container&comp=list",
		       account, ctnr);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = azure_op_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_blob_list_fill_hdr(op);
	if (ret < 0) {
		goto err_buf_free;
	}
	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;

err_buf_free:
	azure_op_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_ctnr_free:
	free(blob_list_req->ctnr);
err_acc_free:
	free(blob_list_req->account);
err_out:
	return ret;
}

/*
 * process a single blob list iteration at @iter, return -ENOENT if no such
 * iteration exists
 */
static int
azure_rsp_blob_iter_process(xmlXPathContext *xp_ctx,
			    int iter,
			    struct azure_blob **blob)
{
	int ret;
	char *query;
	char *name;
	char *len;
	char *type;
	struct azure_blob *iblob;

	ret = asprintf(&query, "//EnumerationResults/Blobs/Blob[%d]/Name",
		       iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &name);
	free(query);
	if (ret < 0) {
		goto err_out;	/* -ENOENT = all processed */
	}
	ret = asprintf(&query, "//EnumerationResults/Blobs/Blob[%d]"
			       "/Properties/Content-Length",
		       iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &len);
	free(query);
	if (ret < 0) {
		goto err_name_free;
	}
	ret = asprintf(&query, "//EnumerationResults/Blobs/Blob[%d]"
			       "/Properties/BlobType",
		       iter);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_len_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &type);
	free(query);
	if (ret < 0) {
		goto err_len_free;
	}

	iblob = malloc(sizeof(*iblob));
	if (iblob == NULL) {
		ret = -ENOMEM;
		goto err_type_free;
	}
	iblob->name = name;
	iblob->len = strtoll(len, &query, 10);
	if (query == len) {
		printf("unsupported blob length response\n");
		ret = -EINVAL;
		goto err_blob_free;
	}
	iblob->is_page = (strcmp(type, BLOB_TYPE_PAGE) == 0);
	*blob = iblob;
	free(len);
	free(type);

	return 0;

err_blob_free:
	free(blob);
err_type_free:
	free(type);
err_len_free:
	free(len);
err_name_free:
	free(name);
err_out:
	return ret;
}

static int
azure_rsp_blob_list_process(struct azure_op *op)
{
	int ret;
	int i;
	struct azure_rsp_blob_list *blob_list_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;
	struct azure_blob *blob;
	struct azure_blob *blob_n;

	assert(op->opcode == AOP_BLOB_LIST);
	assert(op->rsp.data->type == AOP_DATA_IOV);

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(false, op->rsp.data->buf, op->rsp.data->off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	blob_list_rsp = &op->rsp.blob_list;

	list_head_init(&blob_list_rsp->blobs);
	for (i = 1; i <= 5000; i++) {
		ret = azure_rsp_blob_iter_process(xp_ctx, i, &blob);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			goto err_blobs_free;
		}
		list_add_tail(&blob_list_rsp->blobs, &blob->list);
		blob_list_rsp->num_blobs++;
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
	return 0;

err_blobs_free:
	list_for_each_safe(&blob_list_rsp->blobs, blob, blob_n, list) {
		free(blob->name);
		free(blob);
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_blob_put_free(struct azure_req_blob_put *blob_put_req)
{
	free(blob_put_req->account);
	free(blob_put_req->container);
	free(blob_put_req->bname);
}

static int
azure_op_blob_put_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (strcmp(op->req.blob_put.type, BLOB_TYPE_PAGE) == 0) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						  "x-ms-blob-type: PageBlob");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		ret = asprintf(&hdr_str, "x-ms-blob-content-length: %lu",
			       op->req.blob_put.pg_len);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						  "x-ms-blob-type: BlockBlob");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @data_type is AOP_DATA_NONE, then @len corresponds to the page blob
 * length, @buf must be NULL.
 * For a block blob, @len bytes from @buf are put if @data_type is AOP_DATA_IOV,
 * or @len bytes from the file at path @buf if @data_type is AOP_DATA_FILE.
 */
int
azure_op_blob_put(const char *account,
		   const char *container,
		   const char *bname,
		   enum azure_op_data_type data_type,
		   uint8_t *buf,
		   uint64_t len,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_blob_put *bl_put_req;

	/* TODO input validation */
	if ((data_type == AOP_DATA_NONE)
	 && (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len)) {
		ret = -EINVAL;
		goto err_out;
	}

	op->opcode = AOP_BLOB_PUT;
	bl_put_req = &op->req.blob_put;

	bl_put_req->account = strdup(account);
	if (bl_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	bl_put_req->container = strdup(container);
	if (bl_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	bl_put_req->bname = strdup(bname);
	if (bl_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	if (data_type == AOP_DATA_NONE) {
		bl_put_req->type = BLOB_TYPE_PAGE;
		bl_put_req->pg_len = len;
		assert(buf == NULL);	/* block only */
	} else if (data_type == AOP_DATA_IOV) {
		bl_put_req->type = BLOB_TYPE_BLOCK;

		ret = azure_op_data_iov_new(buf, len, 0, false, &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}

	} else if (data_type == AOP_DATA_FILE) {
		bl_put_req->type = BLOB_TYPE_BLOCK;

		ret = azure_op_data_file_new((char *)buf, len, 0, O_RDONLY, 0,
					     &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	/* mandatory headers */
	ret = azure_op_blob_put_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data->buf = NULL;
		azure_op_data_destroy(&op->req.data);
	}
err_free_bname:
	free(bl_put_req->bname);
err_free_container:
	free(bl_put_req->container);
err_free_account:
	free(bl_put_req->account);
err_out:
	return ret;
}

static void
azure_req_blob_get_free(struct azure_req_blob_get *blob_get_req)
{
	free(blob_get_req->account);
	free(blob_get_req->container);
	free(blob_get_req->bname);
}

static int
azure_op_blob_get_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (op->req.blob_get.len > 0) {
		ret = asprintf(&hdr_str, "x-ms-range: bytes=%lu-%lu",
			       op->req.blob_get.off,
			       (op->req.blob_get.off + op->req.blob_get.len - 1));
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_out;
		}
		op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
		free(hdr_str);
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	if (strcmp(op->req.blob_get.type, BLOB_TYPE_PAGE) == 0) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-blob-type: PageBlob");
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-blob-type: BlockBlob");
	}
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * if @len is zero then ignore @off and retrieve entire blob
 */
int
azure_op_blob_get(const char *account,
		  const char *container,
		  const char *bname,
		  bool is_page,
		  enum azure_op_data_type data_type,
		  uint8_t *buf,
		  uint64_t off,
		  uint64_t len,
		  struct azure_op *op)
{
	int ret;
	struct azure_req_blob_get *get_req;

	/* check for correct alignment */
	if (is_page && (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (is_page && (((off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != off)) {
		ret = -EINVAL;
		goto err_out;
	}

	op->opcode = AOP_BLOB_GET;
	get_req = &op->req.blob_get;

	get_req->account = strdup(account);
	if (get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	get_req->container = strdup(container);
	if (get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_acc_free;
	}

	get_req->bname = strdup(bname);
	if (get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_ctnr_free;
	}

	if (is_page) {
		get_req->type = BLOB_TYPE_PAGE;
	} else {
		get_req->type = BLOB_TYPE_BLOCK;
	}
	if (len > 0) {
		/* retrieve a specific range */
		get_req->off = off;
		get_req->len = len;
	}

	switch (data_type) {
	case AOP_DATA_NONE:
		/* recv buffer allocated when data arrives */
		assert(buf == NULL);
		break;
	case AOP_DATA_IOV:
		/* caller request data is stuffed into this buffer */
		assert(buf != NULL);
		ret = azure_op_data_iov_new(buf, len, 0, false, &op->rsp.data);
		if (ret < 0) {
			goto err_bname_free;
		}
		break;
	case AOP_DATA_FILE:
		/* file name is stored in buf */
		assert(buf != NULL);
		ret = azure_op_data_file_new((char *)buf, len, 0,
					     O_CREAT | O_WRONLY,
					  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
					     &op->rsp.data);
		if (ret < 0) {
			goto err_bname_free;
		}
		break;
	default:
		assert(true);	/* unsupported */
		break;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	/* mandatory headers */
	ret = azure_op_blob_get_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->rsp.data != NULL) {
		op->rsp.data->buf = NULL;
		azure_op_data_destroy(&op->rsp.data);
	}
err_bname_free:
	free(get_req->bname);
err_ctnr_free:
	free(get_req->container);
err_acc_free:
	free(get_req->account);
err_out:
	return ret;
}

static void
azure_req_page_put_free(struct azure_req_page_put *pg_put_req)
{
	free(pg_put_req->account);
	free(pg_put_req->container);
	free(pg_put_req->bname);
}

static int
azure_op_page_put_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = asprintf(&hdr_str, "x-ms-range: bytes=%lu-%lu",
		       op->req.page_put.off,
		       (op->req.page_put.off + op->req.page_put.len - 1));
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (op->req.page_put.clear_data) {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-page-write: clear");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	} else {
		op->http_hdr = curl_slist_append(op->http_hdr,
						 "x-ms-page-write: update");
		if (op->http_hdr == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
	}

	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					 "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}
/*
 * update or clear @len bytes of page data at @off.
 * if @buf is null then clear the byte range, otherwise update.
 */
int
azure_op_page_put(const char *account,
		   const char *container,
		   const char *bname,
		   uint8_t *buf,
		   uint64_t off,
		   uint64_t len,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_page_put *pg_put_req;

	/* check for correct alignment */
	if (((len / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != len) {
		ret = -EINVAL;
		goto err_out;
	}
	if (((off / PBLOB_SECTOR_SZ) * PBLOB_SECTOR_SZ) != off) {
		ret = -EINVAL;
		goto err_out;
	}

	op->opcode = AOP_BLOB_PUT;
	pg_put_req = &op->req.page_put;

	pg_put_req->account = strdup(account);
	if (pg_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (container == NULL) {
		pg_put_req->container = NULL;
	} else {
		pg_put_req->container = strdup(container);
		if (pg_put_req->container == NULL) {
			ret = -ENOMEM;
			goto err_free_account;
		}
	}
	pg_put_req->bname = strdup(bname);
	if (pg_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	pg_put_req->off = off;
	pg_put_req->len = len;
	if (buf == NULL) {
		pg_put_req->clear_data = true;
	} else {
		pg_put_req->clear_data = false;
		ret = azure_op_data_iov_new(buf, len, 0, false, &op->req.data);
		if (ret < 0) {
			goto err_free_bname;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}

	/* mandatory headers */
	ret = azure_op_page_put_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_data_close:
	/* should not free data.buf given by the caller on error */
	if (op->req.data != NULL) {
		op->req.data->buf = NULL;
		azure_op_data_destroy(&op->req.data);
	}
err_free_bname:
	free(pg_put_req->bname);
err_free_container:
	free(pg_put_req->container);
err_free_account:
	free(pg_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_put_free(struct azure_req_block_put *blk_put_req)
{
	free(blk_put_req->account);
	free(blk_put_req->container);
	free(blk_put_req->bname);
	free(blk_put_req->blk_id);
}

static int
azure_op_block_put_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/*
 * @len bytes from @buf are put if @data_type is AOP_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is AOP_DATA_FILE.
 * Note: For a given blob, the length of the value specified for the blockid
 *	 parameter must be the same size for each block.
 */
int
azure_op_block_put(const char *account,
		   const char *container,
		   const char *bname,
		   const char *blk_id,
		   struct azure_op_data *data,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_block_put *blk_put_req;
	char *b64_blk_id;

	if ((data == NULL) || (data->type == AOP_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}
	if (strlen(blk_id) > 64) {
		/*
		 * Prior to encoding, the string must be less than or equal to
		 * 64 bytes in size.
		 */
		ret = -EINVAL;
		goto err_out;
	}
	if (data->len > BLOB_BLOCK_MAX) {
		ret = -EINVAL;
		goto err_out;
	}

	op->opcode = AOP_BLOCK_PUT;
	blk_put_req = &op->req.block_put;

	blk_put_req->account = strdup(account);
	if (blk_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	blk_put_req->container = strdup(container);
	if (blk_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_put_req->bname = strdup(bname);
	if (blk_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	blk_put_req->blk_id = strdup(blk_id);
	if (blk_put_req->blk_id == NULL) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	ret = base64_html_encode(blk_id, strlen(blk_id), &b64_blk_id);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_data_close;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net"
		       "/%s/%s?comp=block&blockid=%s",
		       account, container, bname, b64_blk_id);
	free(b64_blk_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_id_free;
	}

	ret = azure_op_block_put_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_data_close:
	op->req.data = NULL;
err_id_free:
	free(blk_put_req->blk_id);
err_bname_free:
	free(blk_put_req->bname);
err_container_free:
	free(blk_put_req->container);
err_account_free:
	free(blk_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_list_put_free(struct azure_req_block_list_put *blk_list_put_req)
{
	struct azure_block *blk;
	struct azure_block *blk_n;
	free(blk_list_put_req->account);
	free(blk_list_put_req->container);
	free(blk_list_put_req->bname);
	list_for_each_safe(blk_list_put_req->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
	free(blk_list_put_req->blks);
}

static int
azure_op_block_list_put_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

static int
azure_op_block_list_put_fill_body(struct list_head *blks,
				  struct azure_op_data **req_data)
{
	int ret;
	xmlTextWriter *writer;
	xmlBuffer *xbuf;
	struct azure_block *blk;

	xbuf = xmlBufferCreate();
	if (xbuf == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	writer = xmlNewTextWriterMemory(xbuf, 0);
	if (writer == NULL) {
		ret = -ENOMEM;
		goto err_xbuf_free;
	}

	ret = xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	if (ret < 0) {
		ret = -EIO;
		goto err_writer_free;
	}

	ret = xmlTextWriterStartElement(writer, BAD_CAST "BlockList");
	if (ret < 0) {
		ret = -EIO;
		goto err_writer_free;
	}

	list_for_each(blks, blk, list) {
		const char *state;
		char *b64_id;

		switch(blk->state) {
		case BLOCK_STATE_COMMITED:
			state = "Committed";
			break;
		case BLOCK_STATE_UNCOMMITED:
			state = "Uncommitted";
			break;
		case BLOCK_STATE_LATEST:
			state = "Latest";
			break;
		default:
			ret = -EINVAL;
			goto err_writer_free;
			break;
		}
		ret = base64_encode(blk->id, strlen(blk->id), &b64_id);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_writer_free;
		}
		ret = xmlTextWriterWriteFormatElement(writer, BAD_CAST state,
						     "%s", b64_id);
		free(b64_id);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_writer_free;
		}
	}

	ret = xmlTextWriterEndElement(writer);
	if (ret < 0) {
		ret = -EBADF;
		goto err_writer_free;
	}

	ret = xmlTextWriterEndDocument(writer);
	if (ret < 0) {
		ret = -EBADF;
		goto err_writer_free;
	}

	/* XXX valgrind complains in curl_read_cb if buffer len is unaligned */
	ret = azure_op_data_iov_new(NULL, xmlBufferLength(xbuf), 0, true,
				    req_data);
	/* XXX could use xmlBufferDetach to avoid the memcpy? */
	if (ret < 0) {
		goto err_writer_free;
	}
	memcpy((*req_data)->buf, xmlBufferContent(xbuf), (*req_data)->len);

	ret = 0;
err_writer_free:
	xmlFreeTextWriter(writer);
err_xbuf_free:
	xmlBufferFree(xbuf);
err_out:
	return ret;
}

/*
 * @blks is a list of blocks to commit, items in the list are not duped
 */
int
azure_op_block_list_put(const char *account,
			const char *container,
			const char *bname,
			struct list_head *blks,
			struct azure_op *op)
{
	int ret;
	struct azure_req_block_list_put *blk_list_put_req;

	op->opcode = AOP_BLOCK_LIST_PUT;
	blk_list_put_req = &op->req.block_list_put;

	blk_list_put_req->account = strdup(account);
	if (blk_list_put_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	blk_list_put_req->container = strdup(container);
	if (blk_list_put_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_list_put_req->bname = strdup(bname);
	if (blk_list_put_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net"
		       "/%s/%s?comp=blocklist",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	ret = azure_op_block_list_put_fill_hdr(op);
	if (ret < 0)
		goto err_url_free;

	ret = azure_op_block_list_put_fill_body(blks, &op->req.data);
	if (ret < 0)
		goto err_url_free;

	blk_list_put_req->blks = blks;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_url_free:
	free(op->url);
err_bname_free:
	free(blk_list_put_req->bname);
err_container_free:
	free(blk_list_put_req->container);
err_account_free:
	free(blk_list_put_req->account);
err_out:
	return ret;
}

static void
azure_req_block_list_get_free(struct azure_req_block_list_get *blk_list_get_req)
{
	free(blk_list_get_req->account);
	free(blk_list_get_req->container);
	free(blk_list_get_req->bname);
}
static void
azure_rsp_block_list_get_free(struct azure_rsp_block_list_get *blk_list_get_rsp)
{
	struct azure_block *blk;
	struct azure_block *blk_n;
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
}

static int
azure_op_block_list_get_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					  "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

/* request a list of all committed and uncommited blocks for @bname */
int
azure_op_block_list_get(const char *account,
			const char *container,
			const char *bname,
			struct azure_op *op)
{
	int ret;
	struct azure_req_block_list_get *blk_list_get_req;

	op->opcode = AOP_BLOCK_LIST_GET;
	blk_list_get_req = &op->req.block_list_get;

	blk_list_get_req->account = strdup(account);
	if (blk_list_get_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	blk_list_get_req->container = strdup(container);
	if (blk_list_get_req->container == NULL) {
		ret = -ENOMEM;
		goto err_account_free;
	}

	blk_list_get_req->bname = strdup(bname);
	if (blk_list_get_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_container_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net"
		       "/%s/%s?comp=blocklist&blocklisttype=all",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_bname_free;
	}

	/* Response does not include a content-length header, alloc buf here */
	ret = azure_op_data_iov_new(NULL, 1024 * 1024, 0, true, &op->rsp.data);
	if (ret < 0) {
		goto err_url_free;
	}

	ret = azure_op_block_list_get_fill_hdr(op);
	if (ret < 0)
		goto err_buf_free;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_buf_free:
	azure_op_data_destroy(&op->rsp.data);
err_url_free:
	free(op->url);
err_bname_free:
	free(blk_list_get_req->bname);
err_container_free:
	free(blk_list_get_req->container);
err_account_free:
	free(blk_list_get_req->account);
err_out:
	return ret;
}

/*
 * process a single block list get iteration at @iter, return -ENOENT if no
 * such iteration exists
 */
static int
azure_rsp_blk_iter_process(xmlXPathContext *xp_ctx,
			   enum azure_block_state state,
			   int iter,
			   struct azure_block **blk_ret)
{
	int ret;
	char *q_base;
	char *query;
	char *name;
	char *size;
	struct azure_block *blk;

	if (state == BLOCK_STATE_COMMITED) {
		ret = asprintf(&q_base,
			       "//BlockList/CommittedBlocks/Block[%d]", iter);
	} else if (state == BLOCK_STATE_UNCOMMITED) {
		ret = asprintf(&q_base,
			       "//BlockList/UncommittedBlocks/Block[%d]", iter);
	} else {
		assert(true);	/* invalid */
	}
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = asprintf(&query, "%s/Name", q_base);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_qbase_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &name);
	free(query);
	if (ret < 0) {
		goto err_qbase_free;	/* -ENOENT = all processed */
	}

	ret = asprintf(&query, "%s/Size", q_base);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = azure_xml_get_path(xp_ctx, query, NULL, &size);
	free(query);
	if (ret < 0) {
		goto err_name_free;
	}

	blk = malloc(sizeof(*blk));
	if (blk == NULL) {
		ret = -ENOMEM;
		goto err_size_free;
	}
	blk->state = state;
	blk->id = malloc(strlen(name));
	if (blk->id == NULL) {
		ret = -ENOMEM;
		goto err_blk_free;
	}
	ret = base64_decode(name, blk->id);
	if (ret < 0) {
		ret = -EIO;
		goto err_id_free;
	}
	/* zero terminate */
	blk->id[ret] = '\0';
	blk->len = strtoll(size, &query, 10);
	if (query == size) {
		printf("unsupported block size response\n");
		ret = -EINVAL;
		goto err_id_free;
	}
	*blk_ret = blk;
	free(size);
	free(name);
	free(q_base);

	return 0;

err_id_free:
	free(blk->id);
err_blk_free:
	free(blk);
err_size_free:
	free(size);
err_name_free:
	free(name);
err_qbase_free:
	free(q_base);
err_out:
	return ret;
}

static int
azure_rsp_block_list_get_process(struct azure_op *op)
{
	int ret;
	int i;
	struct azure_rsp_block_list_get *blk_list_get_rsp;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;
	struct azure_block *blk;
	struct azure_block *blk_n;

	assert(op->opcode == AOP_BLOCK_LIST_GET);
	assert(op->rsp.data->type == AOP_DATA_IOV);

	/* parse response */
	assert(op->rsp.data->base_off == 0);
	ret = azure_xml_slurp(false, op->rsp.data->buf, op->rsp.data->off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	blk_list_get_rsp = &op->rsp.block_list_get;

	list_head_init(&blk_list_get_rsp->blks);
	for (i = 1; i <= 5000; i++) {
		ret = azure_rsp_blk_iter_process(xp_ctx, BLOCK_STATE_COMMITED,
						 i, &blk);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			goto err_blks_free;
		}
		list_add_tail(&blk_list_get_rsp->blks, &blk->list);
		blk_list_get_rsp->num_blks++;
	}
	for (i = 1; i <= 5000; i++) {
		ret = azure_rsp_blk_iter_process(xp_ctx, BLOCK_STATE_UNCOMMITED,
						 i, &blk);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			goto err_blks_free;
		}
		list_add_tail(&blk_list_get_rsp->blks, &blk->list);
		blk_list_get_rsp->num_blks++;
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
	return 0;

err_blks_free:
	list_for_each_safe(&blk_list_get_rsp->blks, blk, blk_n, list) {
		free(blk->id);
		free(blk);
	}
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_blob_del_free(struct azure_req_blob_del *bl_del_req)
{
	free(bl_del_req->account);
	free(bl_del_req->container);
	free(bl_del_req->bname);
}

static int
azure_op_blob_del_fill_hdr(struct azure_op *op)
{
	int ret;
	char *hdr_str;
	char *date_str;

	date_str = gen_date_str();
	if (date_str == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = asprintf(&hdr_str, "x-ms-date: %s", date_str);
	free(date_str);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	op->http_hdr = curl_slist_append(op->http_hdr, hdr_str);
	free(hdr_str);
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* different to the version in management */
	op->http_hdr = curl_slist_append(op->http_hdr,
					 "x-ms-version: 2009-09-19");
	if (op->http_hdr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* common headers and signature added later */

	return 0;

err_out:
	/* the slist is leaked on failure here */
	return ret;
}

int
azure_op_blob_del(const char *account,
		   const char *container,
		   const char *bname,
		   struct azure_op *op)
{
	int ret;
	struct azure_req_blob_del *bl_del_req;

	op->opcode = AOP_BLOB_DEL;
	bl_del_req = &op->req.blob_del;

	bl_del_req->account = strdup(account);
	if (bl_del_req->account == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	bl_del_req->container = strdup(container);
	if (bl_del_req->container == NULL) {
		ret = -ENOMEM;
		goto err_free_account;
	}

	bl_del_req->bname = strdup(bname);
	if (bl_del_req->bname == NULL) {
		ret = -ENOMEM;
		goto err_free_container;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url,
		       "https://%s.blob.core.windows.net/%s/%s",
		       account, container, bname);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_bname;
	}

	/* mandatory headers */
	ret = azure_op_blob_del_fill_hdr(op);
	if (ret < 0)
		goto err_free_url;

	/* the connection layer must sign this request before sending */
	op->sign = true;

	return 0;
err_free_url:
	free(op->url);
err_free_bname:
	free(bl_del_req->bname);
err_free_container:
	free(bl_del_req->container);
err_free_account:
	free(bl_del_req->account);
err_out:
	return ret;
}

static void
azure_rsp_error_free(struct azure_rsp_error *err)
{
	free(err->msg);
	free(err->buf);
}

/*
 * Check whether @err_code represents an azure error response. Nothing opcode
 * specific yet.
 */
bool
azure_rsp_is_error(enum azure_opcode opcode, int err_code)
{
	if (err_code == 0) {
		return false;
	} else if ((err_code >= 200) && (err_code < 300)) {
		return false;
	}
	return true;
}

static int
azure_rsp_error_process(struct azure_op *op)
{
	int ret;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	if (op->rsp.err_code == 0) {
		return 0;
	}

	if (op->rsp.err.off == 0) {
		/* no error description XML attached */
		op->rsp.err.msg = strdup("no error description");
		if (op->rsp.err.msg == NULL) {
			return -ENOMEM;
		}
		return 0;
	}

	ret = azure_xml_slurp(false, op->rsp.err.buf, op->rsp.err.off,
			      &xp_doc, &xp_ctx);
	if (ret < 0) {
		goto err_out;
	}

	ret = azure_xml_get_path(xp_ctx, "/Error/Message", NULL,
				 &op->rsp.err.msg);
	if (ret == -ENOENT) {
		/* data attached, but no error description XML */
		op->rsp.err.msg = strdup("no error description");
		if (op->rsp.err.msg == NULL) {
			ret = -ENOMEM;
			goto err_xml_free;
		}
	} else if (ret < 0) {
		goto err_xml_free;
	}
	printf("got error msg: %s\n", op->rsp.err.msg);
	ret = 0;

err_xml_free:
	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);
err_out:
	return ret;
}

static void
azure_req_free(struct azure_op *op)
{
	azure_op_data_destroy(&op->req.data);

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		azure_req_acc_keys_get_free(&op->req.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		azure_req_acc_list_free(&op->req.acc_list);
		break;
	case AOP_CONTAINER_LIST:
		azure_req_ctnr_list_free(&op->req.ctnr_list);
		break;
	case AOP_CONTAINER_CREATE:
		azure_req_ctnr_create_free(&op->req.ctnr_create);
		break;
	case AOP_CONTAINER_DEL:
		azure_req_ctnr_del_free(&op->req.ctnr_del);
		break;
	case AOP_BLOB_LIST:
		azure_req_blob_list_free(&op->req.blob_list);
		break;
	case AOP_BLOB_PUT:
		azure_req_blob_put_free(&op->req.blob_put);
		break;
	case AOP_BLOB_GET:
		azure_req_blob_get_free(&op->req.blob_get);
		break;
	case AOP_PAGE_PUT:
		azure_req_page_put_free(&op->req.page_put);
		break;
	case AOP_BLOCK_PUT:
		azure_req_block_put_free(&op->req.block_put);
		break;
	case AOP_BLOCK_LIST_PUT:
		azure_req_block_list_put_free(&op->req.block_list_put);
		break;
	case AOP_BLOCK_LIST_GET:
		azure_req_block_list_get_free(&op->req.block_list_get);
		break;
	case AOP_BLOB_DEL:
		azure_req_blob_del_free(&op->req.blob_del);
		break;
	default:
		assert(true);
		break;
	};
}

static void
azure_rsp_free(struct azure_op *op)
{
	azure_op_data_destroy(&op->rsp.data);

	if (op->rsp.is_error) {
		/* error response only, no aop data */
		azure_rsp_error_free(&op->rsp.err);
		return;
	}

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		azure_rsp_acc_keys_get_free(&op->rsp.acc_keys_get);
		break;
	case AOP_ACC_LIST:
		azure_rsp_acc_list_free(&op->rsp.acc_list);
		break;
	case AOP_CONTAINER_LIST:
		azure_rsp_ctnr_list_free(&op->rsp.ctnr_list);
		break;
	case AOP_BLOB_LIST:
		azure_rsp_blob_list_free(&op->rsp.blob_list);
		break;
	case AOP_BLOCK_LIST_GET:
		azure_rsp_block_list_get_free(&op->rsp.block_list_get);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
		/* nothing to do */
		break;
	default:
		assert(true);
		break;
	};
}

/* Free and zero op data */
void
azure_op_free(struct azure_op *op)
{
	/* CURLOPT_HTTPHEADER must be cleared before doing this */
	curl_slist_free_all(op->http_hdr);
	free(op->sig_src);
	free(op->url);
	azure_req_free(op);
	azure_rsp_free(op);
	memset(op, 0, sizeof(*op));
}

/*
 * unmarshall response data
 */
int
azure_rsp_process(struct azure_op *op)
{
	int ret;

	if (op->rsp.is_error) {
		/* set by conn layer, error response only */
		return azure_rsp_error_process(op);
	}

	switch (op->opcode) {
	case AOP_ACC_KEYS_GET:
		ret = azure_rsp_acc_keys_get_process(op);
		break;
	case AOP_ACC_LIST:
		ret = azure_rsp_acc_list_process(op);
		break;
	case AOP_CONTAINER_LIST:
		ret = azure_rsp_ctnr_list_process(op);
		break;
	case AOP_BLOB_LIST:
		ret = azure_rsp_blob_list_process(op);
		break;
	case AOP_BLOCK_LIST_GET:
		ret = azure_rsp_block_list_get_process(op);
		break;
	case AOP_CONTAINER_CREATE:
	case AOP_CONTAINER_DEL:
	case AOP_BLOB_PUT:
	case AOP_BLOB_GET:
	case AOP_PAGE_PUT:
	case AOP_BLOCK_PUT:
	case AOP_BLOCK_LIST_PUT:
	case AOP_BLOB_DEL:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(true);
		break;
	};

	return ret;
}
