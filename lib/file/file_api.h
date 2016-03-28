/*
 * Copyright (C) SUSE LINUX GmbH 2013-2016, all rights reserved.
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
	ELASTO_FILE_AZURE = 1,	/* Alias for APB */
	ELASTO_FILE_APB = 1,	/* Azure page blob store */
	ELASTO_FILE_S3,		/* S3 object store */
	ELASTO_FILE_ABB,	/* Azure block blob store */
	ELASTO_FILE_AFS,	/* Azure file service */
};

struct elasto_fauth {
	enum elasto_ftype type;
	union {
		struct {
			char *ps_path;
			char *access_key;
		} az;
		struct {
			char *creds_path;
		} s3;
	};
	bool insecure_http;
};

/* wrapper for fopen(CREATE|EXCL|DIR) + fclose() */
int
elasto_fmkdir(const struct elasto_fauth *auth,
	      const char *path);

/* wrapper for fopen(DIR) + funlink_close() */
int
elasto_frmdir(const struct elasto_fauth *auth,
	      const char *path);

struct elasto_ftoken_list;

int
elasto_ftoken_add(uint64_t key,
		  const char *val,
		  struct elasto_ftoken_list **_toks);

void
elasto_ftoken_list_free(struct elasto_ftoken_list *toks);

enum elasto_fopen_flags {
	ELASTO_FOPEN_CREATE	= 0x0001,
	ELASTO_FOPEN_EXCL	= 0x0002,
	ELASTO_FOPEN_DIRECTORY	= 0x0004,

	ELASTO_FOPEN_FLAGS_MASK	= 0x0007
};

/**
 * Miscellaneous open parameters
 *
 * @ELASTO_FOPEN_TOK_CREATE_AT_LOCATION specifies a location constraint for a
 * newly created directory, where applicable (e.g. Azure Account).
 */
enum elasto_fopen_token_key {
	ELASTO_FOPEN_TOK_CREATE_AT_LOCATION	= 1,
};

/**
 * Open return values
 *
 * @ELASTO_FOPEN_RET_EXISTED:	existing file/dir was successfully opened
 * @ELASTO_FOPEN_RET_CREATED:	file/dir was successfully created and opened
 */
enum elasto_fopen_success_ret {
	/* -errno on failure */
	ELASTO_FOPEN_RET_EXISTED	= 0,
	ELASTO_FOPEN_RET_CREATED	= 1,
};

/**
 * open and possibly create a file or directory
 *
 * @auth:	Cloud backend authentication information
 * @path:	Path to open
 * @flags:	@elasto_fopen_flags mask
 * @open_toks:	custom open tokens
 * @fh:		handle returned on success
 *
 * @returns:	-errno on error, enum elasto_fopen_success_ret on success
 */
int
elasto_fopen(const struct elasto_fauth *auth,
	     const char *path,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks,
	     struct elasto_fh **_fh);

int
elasto_fwrite(struct elasto_fh *fh,
	      uint64_t dest_off,
	      uint64_t dest_len,
	      uint8_t *out_buf);

int
elasto_fwrite_cb(struct elasto_fh *fh,
		 uint64_t dest_off,
		 uint64_t dest_len,
		 void *cb_priv,
		 int (*out_cb)(uint64_t stream_off,
			       uint64_t need,
			       uint8_t **_out_buf,
			       uint64_t *buf_len,
			       void *priv));

int
elasto_fread(struct elasto_fh *fh,
	     uint64_t src_off,
	     uint64_t src_len,
	     uint8_t *in_buf);

int
elasto_fread_cb(struct elasto_fh *fh,
		uint64_t src_off,
		uint64_t src_len,
		void *cb_priv,
		int (*in_cb)(uint64_t stream_off,
			     uint64_t got,
			     uint8_t *in_buf,
			     uint64_t buf_len,
			     void *priv));

enum elasto_falloc_flags {
	ELASTO_FALLOC_PUNCH_HOLE	= 0x0001,

	ELASTO_FALLOC_ALL_MASK		= 0x0001,
};

int
elasto_fallocate(struct elasto_fh *fh,
		 uint32_t mode,
		 uint64_t dest_off,
		 uint64_t dest_len);

int
elasto_ftruncate(struct elasto_fh *fh,
		 uint64_t len);

int
elasto_fsplice(struct elasto_fh *src_fh,
	       uint64_t src_off,
	       struct elasto_fh *dest_fh,
	       uint64_t dest_off,
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

enum elasto_fstat_field {
	ELASTO_FSTAT_FIELD_TYPE		= 0x0001,
	ELASTO_FSTAT_FIELD_SIZE		= 0x0002,
	ELASTO_FSTAT_FIELD_BSIZE	= 0x0004,
	ELASTO_FSTAT_FIELD_LEASE	= 0x0008,

	ELASTO_FSTAT_FIELD_ALL_MASK	= 0x000F,
};

enum elasto_fstat_ent_type {
	ELASTO_FSTAT_ENT_FILE	=	0x0001,
	ELASTO_FSTAT_ENT_DIR	=	0x0002,
	ELASTO_FSTAT_ENT_ROOT	=	0x0004,
};

/**
 * @ent_type: type of entry
 * @size: total size, in bytes
 * @blksize: blocksize for file system I/O
 * @lease_status: whether locked or unlocked
 */
struct elasto_fstat {
	uint64_t field_mask;
	uint64_t ent_type;
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

struct elasto_dent {
	char *name;
	struct elasto_fstat fstat;
};

int
elasto_freaddir(struct elasto_fh *fh,
		void *priv,
		int (*dent_cb)(struct elasto_dent *,
			       void *));

int
elasto_funlink_close(struct elasto_fh *fh);

/**
 * @file_size: total size of the file in bytes
 * @off: offset of this allocated range in bytes
 * @len: length of this allocated range in bytes
 */
struct elasto_frange {
	uint64_t file_size;
	uint64_t off;
	uint64_t len;
};

/**
 * For a sparse file, check which regions are allocated
 * @fh: a valid Elasto file handle
 * @off: the first offset to start checking for allocated ranges
 * @len: the amount of bytes to check for allocated ranges, from @off
 * @flags: reserved for future use
 * @cb_priv: private data available in @range_cb
 * @range_cb: function to call for each range. May be invoked for adjacent
 *	      ranges - multiple invocations don't imply the presence of holes.
 */
int
elasto_flist_ranges(struct elasto_fh *fh,
		    uint64_t off,
		    uint64_t len,
		    uint64_t flags,	/* reserved */
		    void *cb_priv,
		    int (*range_cb)(struct elasto_frange *range,
				    void *priv));

int
elasto_fdebug(int level);

#ifdef  __cplusplus
}
#endif

#endif /* _ELASTO_FILE_H_ */
