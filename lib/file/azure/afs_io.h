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
#ifndef _AFS_IO_H_
#define _AFS_IO_H_

/* page blob operations */
int
afs_fwrite(void *mod_priv,
	   uint64_t dest_off,
	   uint64_t dest_len,
	   struct elasto_data *src_data);

int
afs_fread(void *mod_priv,
	  uint64_t src_off,
	  uint64_t src_len,
	  struct elasto_data *dest_data);

int
afs_ftruncate(void *mod_priv,
	      uint64_t len);

int
afs_fallocate(void *mod_priv,
	      uint32_t mode,
	      uint64_t dest_off,
	      uint64_t dest_len);

int
afs_fsplice(void *src_mod_priv,
	    uint64_t src_off,
	    void *dest_mod_priv,
	    uint64_t dest_off,
	    uint64_t len);

#endif /* _AFS_IO_H_ */
