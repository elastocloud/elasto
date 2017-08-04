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
s3_fopen(struct event_base *ev_base,
	 void *mod_priv,
	 const char *host,
	 uint16_t port,
	 const char *path,
	 uint64_t flags,
	 struct elasto_ftoken_list *open_toks);

int
s3_fclose(void *mod_priv);

#endif /* _S3_OPEN_H_ */
