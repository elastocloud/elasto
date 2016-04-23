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
#ifndef _AZURE_BLOB_PATH_H_
#define _AZURE_BLOB_PATH_H_

enum az_blob_path_type {
	AZ_BLOB_PATH_ROOT = 1,
	AZ_BLOB_PATH_ACC,
	AZ_BLOB_PATH_CTNR,
	AZ_BLOB_PATH_BLOB,
};

/**
 * Azure Blob Service path representation
 *
 * The Azure Blob Service provides nesting at two levels: accounts can
 * carry one or more containers, which in turn can carry one or more
 * blobs.
 *
 * @type: value to indicate which path fields are set/NULL
 * @acc: Storage account name
 * @ctnr: Container name
 * @blob: Blob name, used for page and block blobs.
 */
struct az_blob_path {
	enum az_blob_path_type type;
	char *acc;
	char *ctnr;
	char *blob;
};

#define AZ_BLOB_PATH_IS_ACC(path) \
	((path != NULL) && (path->type == AZ_BLOB_PATH_ACC))

#define AZ_BLOB_PATH_IS_CTNR(path) \
	((path != NULL) && (path->type == AZ_BLOB_PATH_CTNR))

#define AZ_BLOB_PATH_IS_BLOB(path) \
	((path != NULL) && (path->type == AZ_BLOB_PATH_BLOB))

int
az_blob_path_parse(const char *path_str,
		   struct az_blob_path *az_blob_path);

void
az_blob_path_free(struct az_blob_path *az_blob_path);

int
az_blob_path_dup(const struct az_blob_path *path_orig,
		 struct az_blob_path *path_dup);

#endif /* ifdef _AZURE_BLOB_PATH_H_ */
