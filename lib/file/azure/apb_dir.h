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
#ifndef _APB_DIR_H_
#define _APB_DIR_H_

int
apb_fmkdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path);

int
apb_frmdir(void *mod_priv,
	   struct elasto_conn *conn,
	   const char *path);

int
apb_freaddir(void *mod_priv,
	     struct elasto_conn *conn,
	     void *cli_priv,
	     int (*dent_cb)(struct elasto_dent *,
			      void *));

#endif /* _APB_DIR_H_ */
