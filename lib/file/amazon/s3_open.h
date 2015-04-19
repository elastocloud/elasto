/*
 * Copyright (C) SUSE LINUX GmbH 2015, all rights reserved.
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
#ifndef _S3_OPEN_H_
#define _S3_OPEN_H_

int
s3_fpath_parse(const char *path,
	       struct elasto_fh_s3_path *s3_path);

void
s3_fpath_free(struct elasto_fh_s3_path *s3_path);

int
s3_fopen(void *mod_priv,
	 struct elasto_conn *conn,
	 const char *path,
	 uint64_t flags,
	 struct elasto_ftoken_list *toks);

int
s3_fclose(void *mod_priv,
	  struct elasto_conn *conn);

#endif /* _S3_OPEN_H_ */
