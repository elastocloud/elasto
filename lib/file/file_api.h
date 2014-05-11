/*
 * Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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
#ifndef _ELASTO_FILE_H_
#define _ELASTO_FILE_H_

struct elasto_fh {
	void *priv;
};

enum elasto_ftype {
	ELASTO_FILE_AZURE = 1,
};

struct elasto_fauth {
	enum elasto_ftype type;
	union {
		struct {
			char *ps_path;
		} az;
	};
	bool insecure_http;
};

int
elasto_fmkdir(const struct elasto_fauth *auth,
	      const char *path);

int
elasto_frmdir(const struct elasto_fauth *auth,
	      const char *path);

enum elasto_fopen_flags {
	ELASTO_FOPEN_CREATE	= 0x0001,
	ELASTO_FOPEN_EXCL	= 0x0002,
};

int
elasto_fopen(const struct elasto_fauth *auth,
	     const char *path,
	     uint64_t flags,
	     struct elasto_fh **_fh);

int
elasto_fwrite(struct elasto_fh *fh,
	      uint64_t dest_off,
	      uint64_t dest_len,
	      struct elasto_data *src);

int
elasto_fread(struct elasto_fh *fh,
	     uint64_t src_off,
	     uint64_t src_len,
	     struct elasto_data *dest);

int
elasto_ftruncate(struct elasto_fh *fh,
		 uint64_t len);

int
elasto_fclose(struct elasto_fh *fh);

int
elasto_flease_acquire(struct elasto_fh *fh,
		      int32_t duration);

int
elasto_flease_break(struct elasto_fh *fh);

int
elasto_flease_release(struct elasto_fh *fh);

enum elasto_flease_status {
	ELASTO_FLEASE_UNKNOWN = 0,
	ELASTO_FLEASE_LOCKED,
	ELASTO_FLEASE_UNLOCKED,
};

/**
 * @size: total size, in bytes
 * @blksize: blocksize for file system I/O
 * @lease_status: whether locked or unlocked
 */
struct elasto_fstat {
	uint64_t size;
	uint64_t blksize;
	enum elasto_flease_status lease_status;
};

int
elasto_fstat(struct elasto_fh *fh,
	     struct elasto_fstat *fstat);

int
elasto_fdebug(int level);

#endif /* _ELASTO_FILE_H_ */
