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
 */
#ifndef _AZURE_SSL_H_
#define _AZURE_SSL_H_

int
azure_ssl_pubset_process(const char *ps_file,
			 char **pem_file,
			 char **sub_id,
			 char **sub_name);
int
azure_ssl_pubset_cleanup(const char *pem_file);

#endif /* ifdef _AZURE_SSL_H_ */
