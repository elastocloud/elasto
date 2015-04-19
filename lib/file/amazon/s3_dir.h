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
#ifndef _S3_DIR_H_
#define _S3_DIR_H_

int
s3_fmkdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path);

int
s3_frmdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path);

int
s3_freaddir(void *mod_priv,
	     struct elasto_conn *conn,
	     void *cli_priv,
	     int (*dent_cb)(struct elasto_dent *,
			      void *));

#endif /* _S3_DIR_H_ */
