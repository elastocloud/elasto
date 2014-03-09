/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2013, all rights reserved.
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
#include <inttypes.h>

#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "util.h"
#include "exml.h"
#include "data_api.h"
#include "op.h"
#include "sign.h"
#include "s3_req.h"

/*
 * primary Elasto-Backend Op structure for S3 requests
 */
struct s3_ebo {
	enum s3_opcode opcode;
	struct s3_req req;
	struct s3_rsp rsp;
	struct op op;
};

static int
s3_req_sign(const char *acc,
	    const uint8_t *key,
	    int key_len,
	    struct op *op)
{
	int ret;
	char *sig_str;
	char *hdr_str;
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);

	if (key == NULL) {
		return -EINVAL;
	}

	ret = sign_gen_s3(ebo->req.generic.bkt_name, key, key_len,
			  op, &op->sig_src, &sig_str);
	if (ret < 0) {
		dbg(0, "S3 signing failed: %s\n",
		    strerror(-ret));
		return ret;
	}
	ret = asprintf(&hdr_str, "AWS %s:%s",
		       acc, sig_str);
	free(sig_str);
	if (ret < 0) {
		return -ENOMEM;
	}

	ret = op_req_hdr_add(op, "Authorization", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static void
s3_req_free(struct op *op);
static void
s3_rsp_free(struct op *op);
static int
s3_rsp_process(struct op *op);

static void
s3_ebo_free(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);

	free(ebo);
}

static int
s3_ebo_init(enum s3_opcode opcode,
	    struct s3_ebo **_ebo)
{
	struct s3_ebo *ebo;

	ebo = malloc(sizeof(*ebo));
	if (ebo == NULL) {
		return -ENOMEM;
	}
	memset(ebo, 0, sizeof(*ebo));
	ebo->opcode = opcode;
	op_init(opcode, &ebo->op);

	ebo->op.req_sign = s3_req_sign;	/* all S3 reqs are signed */
	ebo->op.req_free = s3_req_free;
	ebo->op.rsp_free = s3_rsp_free;
	ebo->op.rsp_process = s3_rsp_process;
	ebo->op.ebo_free = s3_ebo_free;
	*_ebo = ebo;
	return 0;
}

static int
s3_req_fill_hdr_common(struct op *op)
{
	int ret;
	size_t sz;
	char hdr_buf[100];
	time_t t;
	struct tm tm_gmt;

	time(&t);
	gmtime_r(&t, &tm_gmt);
	sz = strftime(hdr_buf, ARRAY_SIZE(hdr_buf),
		      "%a, %d %b %Y %T %z", &tm_gmt);
	if (sz == 0) {
		return -E2BIG;
	}

	ret = op_req_hdr_add(op, "Date", hdr_buf);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

static void
s3_req_svc_list_free(struct s3_req_svc_list *svc_list)
{
	/* nothing to do */
}

static void
s3_bkt_free(struct s3_bucket **pbkt)
{
	struct s3_bucket *bkt = *pbkt;

	free(bkt->name);
	free(bkt->create_date);
	free(bkt);
}

static void
s3_rsp_svc_list_free(struct s3_rsp_svc_list *svc_list_rsp)
{
	struct s3_bucket *bkt;
	struct s3_bucket *bkt_n;

	free(svc_list_rsp->id);
	free(svc_list_rsp->disp_name);
	if (svc_list_rsp->num_bkts <= 0) {
		return;
	}
	list_for_each_safe(&svc_list_rsp->bkts, bkt, bkt_n, list) {
		s3_bkt_free(&bkt);
	}
}

int
s3_req_svc_list(struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;

	ret = s3_ebo_init(S3OP_SVC_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	/* no arguments */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host, "s3.amazonaws.com");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}
	ret = asprintf(&op->url_path, "/");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
s3_rsp_bkt_iter_process(struct xml_doc *xdoc,
			const char *path,
			const char *val,
			void *cb_data)
{
	struct s3_rsp_svc_list *svc_list_rsp
					= (struct s3_rsp_svc_list *)cb_data;
	int ret;
	struct s3_bucket *bkt;

	bkt = malloc(sizeof(*bkt));
	if (bkt == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(bkt, 0, sizeof(*bkt));

	ret = exml_str_want(xdoc, "./Name", true, &bkt->name, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	ret = exml_str_want(xdoc, "./CreationDate", true, &bkt->create_date, NULL);
	if (ret < 0) {
		goto err_blk_free;
	}

	list_add_tail(&svc_list_rsp->bkts, &bkt->list);
	svc_list_rsp->num_bkts++;

	return 0;

err_blk_free:
	free(bkt);
err_out:
	return ret;
}

static int
s3_rsp_svc_list_process(struct op *op,
			struct s3_rsp_svc_list *svc_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct s3_bucket *bkt;
	struct s3_bucket *bkt_n;

	assert(op->opcode == S3OP_SVC_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_str_want(xdoc, "/ListAllMyBucketsResult/Owner/ID", false,
			    &svc_list_rsp->id, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_str_want(xdoc, "/ListAllMyBucketsResult/Owner/DisplayName", false,
			    &svc_list_rsp->disp_name, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	list_head_init(&svc_list_rsp->bkts);

	ret = exml_path_cb_want(xdoc, "/ListAllMyBucketsResult/Buckets/Bucket", false,
				s3_rsp_bkt_iter_process, svc_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_bkts_free;
	}

	exml_free(xdoc);
	return 0;

err_bkts_free:
	list_for_each_safe(&svc_list_rsp->bkts, bkt, bkt_n, list) {
		s3_bkt_free(&bkt);
	}
	free(svc_list_rsp->disp_name);
	free(svc_list_rsp->id);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
s3_req_bkt_list_free(struct s3_req_bkt_list *bkt_list)
{
	free(bkt_list->bkt_name);
}

static void
s3_obj_free(struct s3_object **pobj)
{
	struct s3_object *obj = *pobj;

	free(obj->key);
	free(obj->last_mod);
	free(obj->store_class);
	free(obj);
}

static void
s3_rsp_bkt_list_free(struct s3_rsp_bkt_list *bkt_list_rsp)
{
	struct s3_object *obj;
	struct s3_object *obj_n;

	if (bkt_list_rsp->num_objs <= 0)
		return;
	list_for_each_safe(&bkt_list_rsp->objs, obj, obj_n, list) {
		s3_obj_free(&obj);
	}
}

int
s3_req_bkt_list(const char *bkt_name,
		   struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_bkt_list *bkt_list_req;

	ret = s3_ebo_init(S3OP_BKT_LIST, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	bkt_list_req = &ebo->req.bkt_list;

	bkt_list_req->bkt_name = strdup(bkt_name);
	if (bkt_list_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = asprintf(&op->url_path, "/");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_name_free:
	free(bkt_list_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
s3_rsp_obj_iter_process(struct xml_doc *xdoc,
			const char *path,
			const char *val,
			void *cb_data)
{
	struct s3_rsp_bkt_list *bkt_list_rsp
				= (struct s3_rsp_bkt_list *)cb_data;
	int ret;
	struct s3_object *obj;

	obj = malloc(sizeof(*obj));
	if (obj == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(obj, 0, sizeof(*obj));

	ret = exml_str_want(xdoc, "./Key", true, &obj->key, NULL);
	if (ret < 0) {
		goto err_obj_free;
	}

	ret = exml_str_want(xdoc, "./LastModified", true, &obj->last_mod, NULL);
	if (ret < 0) {
		goto err_obj_free;
	}

	ret = exml_uint64_want(xdoc, "./Size", true, &obj->size, NULL);
	if (ret < 0) {
		goto err_obj_free;
	}

	ret = exml_str_want(xdoc, "./StorageClass", true, &obj->store_class, NULL);
	if (ret < 0) {
		goto err_obj_free;
	}

	list_add_tail(&bkt_list_rsp->objs, &obj->list);
	bkt_list_rsp->num_objs++;

	return 0;

err_obj_free:
	free(obj);
err_out:
	return ret;
}

static int
s3_rsp_bkt_list_process(struct op *op,
			struct s3_rsp_bkt_list *bkt_list_rsp)
{
	int ret;
	struct xml_doc *xdoc;
	struct s3_object *obj;
	struct s3_object *obj_n;

	assert(op->opcode == S3OP_BKT_LIST);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	ret = exml_bool_want(xdoc, "/ListBucketResult/IsTruncated", true,
			     &bkt_list_rsp->truncated, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	list_head_init(&bkt_list_rsp->objs);

	ret = exml_path_cb_want(xdoc, "/ListBucketResult/Contents", false,
				s3_rsp_obj_iter_process, bkt_list_rsp, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_objs_free;
	}

	exml_free(xdoc);
	return 0;

err_objs_free:
	list_for_each_safe(&bkt_list_rsp->objs, obj, obj_n, list) {
		s3_obj_free(&obj);
	}
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
s3_req_bkt_create_free(struct s3_req_bkt_create *bkt_create)
{
	free(bkt_create->bkt_name);
	free(bkt_create->location);
}

static int
s3_op_bkt_create_fill_body(const char *location,
			   struct elasto_data **req_data_out)
{
	int ret;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	if (location == NULL) {
		dbg(2, "bucket location not specified, using S3 default\n");
		return 0;
	}

	/* 2k buf, should be strlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, 0, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	xml_data = (char *)req_data->iov.buf;
	ret = snprintf(xml_data, buf_remain,
		       "<CreateBucketConfiguration "
			  "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
				"<LocationConstraint>%s</LocationConstraint>"
		       "</CreateBucketConfiguration>",
		       location);
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending bucket creation req data: %s\n",
	    (char *)req_data->iov.buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_free(req_data);
err_out:
	return ret;
}

int
s3_req_bkt_create(const char *bkt_name,
		     const char *location,
		     struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_bkt_create *bkt_create_req;

	ret = s3_ebo_init(S3OP_BKT_CREATE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	bkt_create_req = &ebo->req.bkt_create;

	bkt_create_req->bkt_name = strdup(bkt_name);
	if (bkt_create_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	if (location != NULL) {
		bkt_create_req->location = strdup(location);
		if (bkt_create_req->location == NULL) {
			ret = -ENOMEM;
			goto err_bkt_free;
		}
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_loc_free;
	}

	ret = asprintf(&op->url_path, "/");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = s3_op_bkt_create_fill_body(location, &op->req.data);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_loc_free:
	free(bkt_create_req->location);
err_bkt_free:
	free(bkt_create_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_bkt_del_free(struct s3_req_bkt_del *bkt_del)
{
	free(bkt_del->bkt_name);
}

int
s3_req_bkt_del(const char *bkt_name,
		  struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_bkt_del *bkt_del_req;

	ret = s3_ebo_init(S3OP_BKT_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	bkt_del_req = &ebo->req.bkt_del;

	bkt_del_req->bkt_name = strdup(bkt_name);
	if (bkt_del_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_name_free;
	}
	ret = asprintf(&op->url_path, "/");
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_name_free:
	free(bkt_del_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_obj_put_free(struct s3_req_obj_put *obj_put)
{
	free(obj_put->bkt_name);
	free(obj_put->obj_name);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 */
int
s3_req_obj_put(const char *bkt_name,
		  const char *obj_name,
		  struct elasto_data *data,
		  struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_obj_put *obj_put_req;

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = s3_ebo_init(S3OP_OBJ_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	obj_put_req = &ebo->req.obj_put;

	obj_put_req->bkt_name = strdup(bkt_name);
	if (obj_put_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	obj_put_req->obj_name = strdup(obj_name);
	if (obj_put_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}
	ret = asprintf(&op->url_path, "/%s", obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_data_close:
	op->req.data = NULL;
	free(obj_put_req->obj_name);
err_bkt_free:
	free(obj_put_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_obj_get_free(struct s3_req_obj_get *obj_get)
{
	free(obj_get->bkt_name);
	free(obj_get->obj_name);
}

/*
 * @len bytes from @buf are put if @data_type is ELASTO_DATA_IOV, or @len bytes
 * fom the file at path @buf if @data_type is ELASTO_DATA_FILE.
 */
int
s3_req_obj_get(const char *bkt_name,
		  const char *obj_name,
		  struct elasto_data *data,
		  struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_obj_get *obj_get_req;

	if ((data == NULL) || (data->type == ELASTO_DATA_NONE)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = s3_ebo_init(S3OP_OBJ_GET, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	obj_get_req = &ebo->req.obj_get;

	obj_get_req->bkt_name = strdup(bkt_name);
	if (obj_get_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	obj_get_req->obj_name = strdup(obj_name);
	if (obj_get_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	if (data == NULL) {
		dbg(3, "no recv buffer, allocating on arrival\n");
	}
	op->rsp.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_GET;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_data_close;
	}
	ret = asprintf(&op->url_path, "/%s", obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_data_close:
	op->req.data = NULL;
	free(obj_get_req->obj_name);
err_bkt_free:
	free(obj_get_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_obj_del_free(struct s3_req_obj_del *obj_del)
{
	free(obj_del->bkt_name);
	free(obj_del->obj_name);
}

int
s3_req_obj_del(const char *bkt_name,
		  const char *obj_name,
		  struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_obj_del *obj_del_req;

	ret = s3_ebo_init(S3OP_OBJ_DEL, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	obj_del_req = &ebo->req.obj_del;

	obj_del_req->bkt_name = strdup(bkt_name);
	if (obj_del_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	obj_del_req->obj_name = strdup(obj_name);
	if (obj_del_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}
	ret = asprintf(&op->url_path, "/%s", obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_obj_free:
	free(obj_del_req->obj_name);
err_bkt_free:
	free(obj_del_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_obj_cp_free(struct s3_req_obj_cp *obj_cp)
{
	free(obj_cp->src.bkt_name);
	free(obj_cp->src.obj_name);
	free(obj_cp->dst.bkt_name);
	free(obj_cp->dst.obj_name);
}

static int
s3_req_obj_cp_hdr_fill(struct s3_req_obj_cp *obj_cp_req,
		       struct op *op)
{
	int ret;
	char *hdr_str;

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_out;
	}

	ret = asprintf(&hdr_str, "/%s/%s",
		       obj_cp_req->src.bkt_name,
		       obj_cp_req->src.obj_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}
	ret = op_req_hdr_add(op, "x-amz-copy-source", hdr_str);
	free(hdr_str);
	if (ret < 0) {
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

int
s3_req_obj_cp(const char *src_bkt,
		 const char *src_obj,
		 const char *dst_bkt,
		 const char *dst_obj,
		 struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_obj_cp *obj_cp_req;

	ret = s3_ebo_init(S3OP_OBJ_CP, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	obj_cp_req = &ebo->req.obj_cp;

	obj_cp_req->src.bkt_name = strdup(src_bkt);
	if (obj_cp_req->src.bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	obj_cp_req->src.obj_name = strdup(src_obj);
	if (obj_cp_req->src.obj_name == NULL) {
		ret = -ENOMEM;
		goto err_src_bkt_free;
	}

	obj_cp_req->dst.bkt_name = strdup(dst_bkt);
	if (obj_cp_req->dst.bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_src_obj_free;
	}

	obj_cp_req->dst.obj_name = strdup(dst_obj);
	if (obj_cp_req->dst.obj_name == NULL) {
		ret = -ENOMEM;
		goto err_dst_bkt_free;
	}

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", dst_bkt);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_dst_obj_free;
	}
	ret = asprintf(&op->url_path, "/%s", dst_obj);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_obj_cp_hdr_fill(obj_cp_req, op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_dst_obj_free:
	free(obj_cp_req->dst.obj_name);
err_dst_bkt_free:
	free(obj_cp_req->dst.bkt_name);
err_src_obj_free:
	free(obj_cp_req->src.obj_name);
err_src_bkt_free:
	free(obj_cp_req->src.bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_mp_start_free(struct s3_req_mp_start *mp_start_req)
{
	free(mp_start_req->bkt_name);
	free(mp_start_req->obj_name);
}

static void
s3_rsp_mp_start_free(struct s3_rsp_mp_start *mp_start_rsp)
{
	free(mp_start_rsp->upload_id);
}

int
s3_req_mp_start(const char *bkt,
		   const char *obj,
		   struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_mp_start *mp_start_req;

	ret = s3_ebo_init(S3OP_MULTIPART_START, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	mp_start_req = &ebo->req.mp_start;

	mp_start_req->bkt_name = strdup(bkt);
	if (mp_start_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	mp_start_req->obj_name = strdup(obj);
	if (mp_start_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	op->method = REQ_METHOD_POST;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}
	ret = asprintf(&op->url_path, "/%s?uploads",
		       obj);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_obj_free:
	free(mp_start_req->obj_name);
err_bkt_free:
	free(mp_start_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
s3_rsp_mp_start_process(struct op *op,
			struct s3_rsp_mp_start *mp_start_rsp)
{
	int ret;
	struct xml_doc *xdoc;

	assert(op->opcode == S3OP_MULTIPART_START);
	assert(op->rsp.data->type == ELASTO_DATA_IOV);

	assert(op->rsp.data->base_off == 0);
	ret = exml_slurp((const char *)op->rsp.data->iov.buf,
			 op->rsp.data->off, &xdoc);
	if (ret < 0) {
		goto err_out;
	}

	/* FIXME element should be mandatory? */
	ret = exml_str_want(xdoc, "/InitiateMultipartUploadResult/UploadId", false,
			    &mp_start_rsp->upload_id, NULL);
	if (ret < 0) {
		goto err_xdoc_free;
	}

	ret = exml_parse(xdoc);
	if (ret < 0) {
		goto err_rsp_free;
	}

	exml_free(xdoc);
	return 0;

err_rsp_free:
	s3_rsp_mp_start_free(mp_start_rsp);
err_xdoc_free:
	exml_free(xdoc);
err_out:
	return ret;
}

static void
s3_part_free(struct s3_part **_part)
{
	struct s3_part *part = *_part;
	free(part->etag);
	free(part);
}

static void
s3_req_mp_done_free(struct s3_req_mp_done *mp_done_req)
{
	struct s3_part *part;
	struct s3_part *part_n;

	free(mp_done_req->bkt_name);
	free(mp_done_req->obj_name);
	free(mp_done_req->upload_id);
	if (mp_done_req->parts == NULL) {
		return;
	}
	list_for_each_safe(mp_done_req->parts, part, part_n, list) {
		s3_part_free(&part);
	}
}

static int
s3_op_mp_done_fill_body(struct list_head *parts,
			struct elasto_data **req_data_out)
{
	int ret;
	struct s3_part *part;
	char *xml_data;
	int buf_remain;
	struct elasto_data *req_data;

	/* 2k buf, should be listlen calculated */
	buf_remain = 2048;
	ret = elasto_data_iov_new(NULL, buf_remain, 0, true, &req_data);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_out;
	}

	xml_data = (char *)req_data->iov.buf;
	ret = snprintf(xml_data, buf_remain,
		       "<CompleteMultipartUpload>");
	if ((ret < 0) || (ret >= buf_remain)) {
		/* truncated or error */
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	list_for_each(parts, part, list) {
		ret = snprintf(xml_data, buf_remain,
			       "<Part>"
					"<PartNumber>%u</PartNumber>"
					"<ETag>%s</ETag>"
			       "</Part>",
			       (unsigned int)part->pnum,
			       part->etag);
		if ((ret < 0) || (ret >= buf_remain)) {
			ret = -E2BIG;
			goto err_buf_free;
		}

		xml_data += ret;
		buf_remain -= ret;
	}

	ret = snprintf(xml_data, buf_remain,
		       "</CompleteMultipartUpload>");
	if ((ret < 0) || (ret >= buf_remain)) {
		ret = -E2BIG;
		goto err_buf_free;
	}

	xml_data += ret;
	buf_remain -= ret;

	/* truncate buffer to what was written */
	req_data->len = req_data->len - buf_remain;

	dbg(4, "sending multipart upload complete req data: %s\n",
	    (char *)req_data->iov.buf);
	*req_data_out = req_data;

	return 0;
err_buf_free:
	elasto_data_free(req_data);
err_out:
	return ret;
}

int
s3_req_mp_done(const char *bkt,
	       const char *obj,
	       const char *upload_id,
	       struct list_head *parts,
	       struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_mp_done *mp_done_req;

	ret = s3_ebo_init(S3OP_MULTIPART_DONE, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	mp_done_req = &ebo->req.mp_done;

	mp_done_req->bkt_name = strdup(bkt);
	if (mp_done_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	mp_done_req->obj_name = strdup(obj);
	if (mp_done_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	mp_done_req->upload_id = strdup(upload_id);
	if (mp_done_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	op->method = REQ_METHOD_POST;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_upload_free;
	}
	ret = asprintf(&op->url_path, "/%s?uploadId=%s",
		       obj, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	ret = s3_op_mp_done_fill_body(parts, &op->req.data);
	if (ret < 0) {
		goto err_hdr_free;
	}
	/* XXX should copy list */
	mp_done_req->parts = parts;

	*_op = op;
	return 0;

err_hdr_free:
	op_hdrs_free(&op->req.hdrs);
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_upload_free:
	free(mp_done_req->upload_id);
err_obj_free:
	free(mp_done_req->obj_name);
err_bkt_free:
	free(mp_done_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_mp_abort_free(struct s3_req_mp_abort *mp_abort_req)
{
	free(mp_abort_req->bkt_name);
	free(mp_abort_req->obj_name);
	free(mp_abort_req->upload_id);
}

int
s3_req_mp_abort(const char *bkt,
		const char *obj,
		const char *upload_id,
		struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_mp_abort *mp_abort_req;

	ret = s3_ebo_init(S3OP_MULTIPART_ABORT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	mp_abort_req = &ebo->req.mp_abort;

	mp_abort_req->bkt_name = strdup(bkt);
	if (mp_abort_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	mp_abort_req->obj_name = strdup(obj);
	if (mp_abort_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	mp_abort_req->upload_id = strdup(upload_id);
	if (mp_abort_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	op->method = REQ_METHOD_DELETE;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_obj_free;
	}
	ret = asprintf(&op->url_path, "/%s?uploadId=%s", obj, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;

err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_obj_free:
	free(mp_abort_req->obj_name);
err_bkt_free:
	free(mp_abort_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static void
s3_req_part_put_free(struct s3_req_part_put *part_put_req)
{
	free(part_put_req->bkt_name);
	free(part_put_req->obj_name);
	free(part_put_req->upload_id);
}

static void
s3_rsp_part_put_free(struct s3_rsp_part_put *part_put_rsp)
{
	free(part_put_rsp->etag);
}

int
s3_req_part_put(const char *bkt,
		const char *obj,
		const char *upload_id,
		uint32_t pnum,
		struct elasto_data *data,
		struct op **_op)
{
	int ret;
	struct s3_ebo *ebo;
	struct op *op;
	struct s3_req_part_put *part_put_req;

	ret = s3_ebo_init(S3OP_PART_PUT, &ebo);
	if (ret < 0) {
		goto err_out;
	}
	op = &ebo->op;
	part_put_req = &ebo->req.part_put;

	part_put_req->bkt_name = strdup(bkt);
	if (part_put_req->bkt_name == NULL) {
		ret = -ENOMEM;
		goto err_ebo_free;
	}

	part_put_req->obj_name = strdup(obj);
	if (part_put_req->obj_name == NULL) {
		ret = -ENOMEM;
		goto err_bkt_free;
	}

	part_put_req->upload_id = strdup(upload_id);
	if (part_put_req->upload_id == NULL) {
		ret = -ENOMEM;
		goto err_obj_free;
	}

	part_put_req->pnum = pnum;

	op->req.data = data;
	/* TODO add a foreign flag so @req.data is not freed with @op */

	op->method = REQ_METHOD_PUT;
	ret = asprintf(&op->url_host, "%s.s3.amazonaws.com", bkt);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uploadid_free;
	}
	ret = asprintf(&op->url_path, "/%s?partNumber=%u&uploadId=%s",
		       obj, (unsigned int)pnum, upload_id);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_uhost_free;
	}

	ret = s3_req_fill_hdr_common(op);
	if (ret < 0) {
		goto err_upath_free;
	}

	*_op = op;
	return 0;
err_upath_free:
	free(op->url_path);
err_uhost_free:
	free(op->url_host);
err_uploadid_free:
	free(part_put_req->upload_id);
err_obj_free:
	free(part_put_req->obj_name);
err_bkt_free:
	free(part_put_req->bkt_name);
err_ebo_free:
	free(ebo);
err_out:
	return ret;
}

static int
s3_rsp_part_put_process(struct op *op,
			struct s3_rsp_part_put *part_put_rsp)
{
	int ret;

	assert(op->opcode == S3OP_PART_PUT);
	ret = op_hdr_val_lookup(&op->rsp.hdrs, "ETag",
				&part_put_rsp->etag);
	if (ret < 0) {
		dbg(0, "no etag in response header\n");
		goto err_out;
	}

	ret = 0;
err_out:
	return ret;
}

static void
s3_req_free(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);

	switch (op->opcode) {
	case S3OP_SVC_LIST:
		s3_req_svc_list_free(&ebo->req.svc_list);
		break;
	case S3OP_BKT_LIST:
		s3_req_bkt_list_free(&ebo->req.bkt_list);
		break;
	case S3OP_BKT_CREATE:
		s3_req_bkt_create_free(&ebo->req.bkt_create);
		break;
	case S3OP_BKT_DEL:
		s3_req_bkt_del_free(&ebo->req.bkt_del);
		break;
	case S3OP_OBJ_PUT:
		s3_req_obj_put_free(&ebo->req.obj_put);
		break;
	case S3OP_OBJ_GET:
		s3_req_obj_get_free(&ebo->req.obj_get);
		break;
	case S3OP_OBJ_DEL:
		s3_req_obj_del_free(&ebo->req.obj_del);
		break;
	case S3OP_OBJ_CP:
		s3_req_obj_cp_free(&ebo->req.obj_cp);
		break;
	case S3OP_MULTIPART_START:
		s3_req_mp_start_free(&ebo->req.mp_start);
		break;
	case S3OP_MULTIPART_DONE:
		s3_req_mp_done_free(&ebo->req.mp_done);
		break;
	case S3OP_MULTIPART_ABORT:
		s3_req_mp_abort_free(&ebo->req.mp_abort);
		break;
	case S3OP_PART_PUT:
		s3_req_part_put_free(&ebo->req.part_put);
		break;
	default:
		assert(false);
		break;
	};
}

static void
s3_rsp_free(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);

	switch (op->opcode) {
	case S3OP_SVC_LIST:
		s3_rsp_svc_list_free(&ebo->rsp.svc_list);
		break;
	case S3OP_BKT_LIST:
		s3_rsp_bkt_list_free(&ebo->rsp.bkt_list);
		break;
	case S3OP_MULTIPART_START:
		s3_rsp_mp_start_free(&ebo->rsp.mp_start);
		break;
	case S3OP_PART_PUT:
		s3_rsp_part_put_free(&ebo->rsp.part_put);
		break;
	case S3OP_BKT_CREATE:
	case S3OP_BKT_DEL:
	case S3OP_OBJ_PUT:
	case S3OP_OBJ_GET:
	case S3OP_OBJ_DEL:
	case S3OP_OBJ_CP:
	case S3OP_MULTIPART_DONE:
	case S3OP_MULTIPART_ABORT:
		/* nothing to do */
		break;
	default:
		assert(false);
		break;
	};
}

/*
 * unmarshall response data
 */
int
s3_rsp_process(struct op *op)
{
	int ret;
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);

	ret = op_hdr_val_lookup(&op->rsp.hdrs, "x-amz-request-id",
				&op->rsp.req_id);
	if (ret < 0) {
		dbg(0, "no req_id in %d response\n", op->opcode);
	} else {
		dbg(4, "req_id in %d response: %s\n",
		    op->opcode, op->rsp.req_id);
	}

	switch (op->opcode) {
	case S3OP_SVC_LIST:
		ret = s3_rsp_svc_list_process(op, &ebo->rsp.svc_list);
		break;
	case S3OP_BKT_LIST:
		ret = s3_rsp_bkt_list_process(op, &ebo->rsp.bkt_list);
		break;
	case S3OP_MULTIPART_START:
		ret = s3_rsp_mp_start_process(op, &ebo->rsp.mp_start);
		break;
	case S3OP_PART_PUT:
		ret = s3_rsp_part_put_process(op, &ebo->rsp.part_put);
		break;
	case S3OP_BKT_CREATE:
	case S3OP_BKT_DEL:
	case S3OP_OBJ_PUT:
	case S3OP_OBJ_GET:
	case S3OP_OBJ_DEL:
	case S3OP_OBJ_CP:
	case S3OP_MULTIPART_DONE:
	case S3OP_MULTIPART_ABORT:
		/* nothing to do */
		ret = 0;
		break;
	default:
		assert(false);
		break;
	};

	return ret;
}

struct s3_rsp_svc_list *
s3_rsp_svc_list(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);
	return &ebo->rsp.svc_list;
}

struct s3_rsp_bkt_list *
s3_rsp_bkt_list(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);
	return &ebo->rsp.bkt_list;
}

struct s3_rsp_mp_start *
s3_rsp_mp_start(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);
	return &ebo->rsp.mp_start;
}

struct s3_rsp_part_put *
s3_rsp_part_put(struct op *op)
{
	struct s3_ebo *ebo = container_of(op, struct s3_ebo, op);
	return &ebo->rsp.part_put;
}
