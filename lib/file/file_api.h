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

#ifdef  __cplusplus
extern "C" {
#endif

struct elasto_fh;

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

enum elasto_falloc_flags {
	ELASTO_FALLOC_PUNCH_HOLE	= 0x0001,
};

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

enum elasto_fstatfs_cap_flags {
	ELASTO_FSTATFS_CAP_SPARSE	= 0x0001,
	ELASTO_FSTATFS_CAP_WRITE_RANGE	= 0x0002,
	ELASTO_FSTATFS_CAP_LEASES	= 0x0004,
};

enum elasto_fstatfs_prop_flags {
	ELASTO_FSTATFS_PROP_READ_ONLY	= 0x0001,
};

struct elasto_fstatfs_region {
	char *region;
	char *location;
};

/**
 * @iosize_min: minimum unit of file system I/O
 * @iosize_min: optimal unit of file system I/O
 * @cap_flags: FS capabilities
 * @prop_flags: FS properties
 * @num_regions: number of entries in the regions array
 * @regions: array of datacenter locations for the backend
 */
struct elasto_fstatfs {
	uint64_t iosize_min;
	uint64_t iosize_optimal;
	uint64_t cap_flags;
	uint64_t prop_flags;
	uint64_t num_regions;
	const struct elasto_fstatfs_region *regions;
};

int
elasto_fstatfs(struct elasto_fh *fh,
	       struct elasto_fstatfs *fstatfs);

int
elasto_fdebug(int level);

#ifdef  __cplusplus
}
#endif

#endif /* _ELASTO_FILE_H_ */
