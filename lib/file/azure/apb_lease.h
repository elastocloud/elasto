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
#ifndef _APB_LEASE_H_
#define _APB_LEASE_H_

int
apb_flease_acquire(void *mod_priv,
		   struct elasto_conn *conn,
		   int32_t duration,
		   void **_flease_h);

int
apb_flease_break(void *mod_priv,
		 struct elasto_conn *conn,
		 void **_flease_h);

int
apb_flease_release(void *mod_priv,
		   struct elasto_conn *conn,
		   void **_flease_h);

void
apb_flease_free(void *mod_priv,
		void **_flease_h);

#endif /* _APB_LEASE_H_ */
