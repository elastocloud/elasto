/*
 * Copyright (C) SUSE LINUX GmbH 2015-2016, all rights reserved.
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
#ifndef _S3_PATH_H_
#define _S3_PATH_H_

enum s3_path_type {
	S3_PATH_ROOT = 1,
	S3_PATH_BKT,
	S3_PATH_OBJ,
};

/* default host. bkt is normally added as prefix for bkt and obj operations */
#define S3_PATH_HOST_DEFAULT "s3.amazonaws.com"

/**
 * @type: entity that path refers to
 * @host_is_custom: @host is a custom hostname. This affects how URL paths are
 *		    generated - the bkt prefix should not be used.
 * @host: server hostname
 * @port: server port
 * @bkt: s3 bucket name
 * @obj: s3 object name
 */
struct s3_path {
	enum s3_path_type type;
	bool host_is_custom;
	char *host;
	uint16_t port;
	char *bkt;
	char *obj;
};

int
s3_path_parse(const char *custom_host,
	      uint16_t port,
	      const char *path,
	      bool insecure_http,
	      struct s3_path *s3_path);

void
s3_path_free(struct s3_path *s3_path);

int
s3_path_dup(const struct s3_path *path_orig,
	    struct s3_path *path_dup);

#define S3_PATH_IS_SVC(path) \
	((path != NULL) && (path->type == S3_PATH_ROOT))

#define S3_PATH_IS_BKT(path) \
	((path != NULL) && (path->type == S3_PATH_BKT))

#define S3_PATH_IS_OBJ(path) \
	((path != NULL) && (path->type == S3_PATH_OBJ))

#endif /* _S3_PATH_H_ */
