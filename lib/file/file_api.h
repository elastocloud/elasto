/*
 * Copyright (C) SUSE LINUX GmbH 2013-2018, all rights reserved.
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
	ELASTO_FILE_LOCAL,	/* test back-end: local FS I/O */
};

/**
 * @type:	Cloud provider service identifier (see struct @elasto_ftype)
 * @ps_path:	Azure PublishSettings file path
 * @access_key:	Azure account access key
 * @creds_path:	S3 IAM credentials path. IAM is a CSV file in format:
 *			User Name,Access Key Id,Secret Access Key
 *			"johndoe",0123456789abcdef0123,qwerty.../QWERTY...==
 */
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

/*
 * DEPRECATED: doesn't support expicit server host.
 * use fopen[_host](CREATE|EXCL|DIR) + fclose() instead.
 */
int
elasto_fmkdir(const struct elasto_fauth *auth,
	      const char *path);

/*
 * DEPRECATED: doesn't support expicit server host.
 * Use fopen[_host](DIR) + funlink_close() instead.
 */
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
 * open and possibly create a file or directory. Unlike @elasto_fopen_host, this
 * connects to the default public cloud endpoint, using https on port 443, or
 * http on port 80 if @insecure_http is set.
 *
 * @auth:	Cloud backend authentication information
 * @path:	Path to open
 * @flags:	@elasto_fopen_flags mask
 * @open_toks:	custom open tokens
 * @_fh:	Elasto file/dir handle returned on success
 *
 * @returns:	-errno on error, enum elasto_fopen_success_ret on success
 */
int
elasto_fopen(const struct elasto_fauth *auth,
	     const char *path,
	     uint64_t flags,
	     struct elasto_ftoken_list *open_toks,
	     struct elasto_fh **_fh);

/**
 * open and possibly create a file or directory. Unlike @elasto_fopen, this
 * connects to a specific host (and port), rather than the default public cloud
 * endpoint.
 *
 * @auth:	Cloud backend authentication information
 * @host:	custom host to connect to.
 * @port:	port to connect to. If zero, port 443 or 80 will be used,
 *		depending on whether or not @insecure_http is set.
 * @path:	Path to open
 * @flags:	@elasto_fopen_flags mask
 * @open_toks:	custom open tokens
 * @_fh:	Elasto file/dir handle returned on success
 *
 * @returns:	-errno on error, enum elasto_fopen_success_ret on success
 */
int
elasto_fopen_host(const struct elasto_fauth *auth,
		  const char *host,
		  uint16_t port,
		  const char *path,
		  uint64_t flags,
		  struct elasto_ftoken_list *open_toks,
		  struct elasto_fh **_fh);

/**
 * Write @dest_len bytes from @out_bytes to an open file at offset @dest_off.
 * I/O is not in any way atomic, and will collide with any concurrent writers.
 *
 * NOTE: Azure Block Blobs and S3 Objects don't support writes at arbitrary
 * offsets, so need to be written all in one go from @dest_off=0. Page Blobs and
 * Azure Files *can* be written to at arbitrary offsets.
 *
 * @fh:		Elasto file handle
 * @dest_off:	File offset to write at
 * @dest_len:	Number of bytes to write
 * @out_buf:	Buffer containing write buffer
 *
 * @returns:	-errno on error
 */
int
elasto_fwrite(struct elasto_fh *fh,
	      uint64_t dest_off,
	      uint64_t dest_len,
	      uint8_t *out_buf);

/**
 * Write @dest_len bytes to an open file at offset @dest_off. Write data is
 * obtained from the caller via the @out_cb callback.
 * I/O is not in any way atomic, and will collide with any concurrent writers.
 *
 * NOTE: see @elasto_fwrite note regarding non-zero @dest_off.
 *
 * @fh:		Elasto file handle
 * @dest_off:	File offset to write at
 * @dest_len:	Number of bytes to write
 * @cb_priv:	Private pointer to pass to the @out_cb callback
 * @out_priv:	Callback to obtain write data from the caller
 *
 * @returns:	-errno on error
 */
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

/**
 * Read @src_len bytes from an open file at offset @src_off and store the result
 * in @in_buf.
 * I/O is not in any way atomic, and will collide with any concurrent writers.
 *
 * @fh:		Elasto file handle
 * @src_off:	File offset to read at
 * @src_len:	Number of bytes to read
 * @in_buf:	Buffer to use to store the read result
 *
 * @returns:	-errno on error
 */
int
elasto_fread(struct elasto_fh *fh,
	     uint64_t src_off,
	     uint64_t src_len,
	     uint8_t *in_buf);

/**
 * Read @src_len bytes from an open file at offset @src_off. Read data is
 * provided to the caller via the @in_cb callback.
 * I/O is not in any way atomic, and will collide with any concurrent writers.
 *
 * @fh:		Elasto file handle
 * @src_off:	File offset to read at
 * @src_len:	Number of bytes to read
 * @cb_priv:	Private pointer to pass to the @in_cb callback
 * @in_priv:	Callback to provide read data to the caller
 *
 * @returns:	-errno on error
 */
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

/**
 * Discard (hole punch) a given file range.
 *
 * @fh:		Elasto file handle
 * @mode:	Currently only ELASTO_FALLOC_PUNCH_HOLE is supported
 * @dest_off:	Offset to act upon
 * @dest_len:	Length to discard
 *
 * @returns:	-errno on error
 */
int
elasto_fallocate(struct elasto_fh *fh,
		 uint32_t mode,
		 uint64_t dest_off,
		 uint64_t dest_len);

/**
 * truncate a file to length @len.
 *
 * @fh:		Elasto file handle
 * @len:	New length to take
 *
 * @returns:	-errno on error
 */
int
elasto_ftruncate(struct elasto_fh *fh,
		 uint64_t len);

/**
 * Copy data from source to destination.
 *
 * @src_fh:	Source Elasto file handle
 * @src_off:	Source file offset
 * @dest_fh:	Destination Elasto file handle
 * @dest_off:	Destination file offset
 * @len:	Length to copy in bytes
 *
 * @returns:	-errno on error
 */
int
elasto_fsplice(struct elasto_fh *src_fh,
	       uint64_t src_off,
	       struct elasto_fh *dest_fh,
	       uint64_t dest_off,
	       uint64_t len);

/**
 * Close an Elasto handle. This currently releases any leases / locks
 * associated with the handle, but do not rely on this behaviour (see
 * elasto_flease_*).
 *
 * @fh:		Elasto file/dir handle
 *
 * @returns:	-errno on error
 */
int
elasto_fclose(struct elasto_fh *fh);

/**
 * Acquire a lock on an open Elasto handle (EXPERIMENTAL).
 * The lock state is *currently* stored with the open handle, and will be
 * released on close.
 *
 * @fh:		Elasto handle
 * @duration:	Duration to retain lock
 *
 * @returns:	-errno on error
 */
int
elasto_flease_acquire(struct elasto_fh *fh,
		      int32_t duration);

/**
 * Break a lock on an open Elasto handle (EXPERIMENTAL).
 *
 * @fh:		Elasto handle
 *
 * @returns:	-errno on error
 */
int
elasto_flease_break(struct elasto_fh *fh);

/**
 * Release a lock on an open Elasto handle (EXPERIMENTAL).
 *
 * @fh:		Elasto handle
 *
 * @returns:	-errno on error
 */
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
	ELASTO_FSTAT_FIELD_CONTENT_TYPE	= 0x0010,

	ELASTO_FSTAT_FIELD_ALL_MASK	= 0x001F,
};

enum elasto_fstat_ent_type {
	ELASTO_FSTAT_ENT_FILE	=	0x0001,
	ELASTO_FSTAT_ENT_DIR	=	0x0002,
	ELASTO_FSTAT_ENT_ROOT	=	0x0004,
};

/**
 * @field_mask: indicates which fields from struct elasto_fstat are valid
 * @ent_type: type of entry
 * @size: total size, in bytes
 * @blksize: blocksize for file system I/O
 * @lease_status: whether locked or unlocked
 * @content_type: content-type / MIME type
 */
struct elasto_fstat {
	uint64_t field_mask;
	uint64_t ent_type;
	uint64_t size;
	uint64_t blksize;
	enum elasto_flease_status lease_status;
	char content_type[256];
};

/**
 * Obtain details about a given file or directory.
 *
 * @fh:		Valid Elasto file/dir handle
 * @fstat:	File/dir details (see corresponding struct @elasto_fstat)
 */
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

/**
 * Obtain details about a given cloud backend (filesystem).
 *
 * @fh:		Valid Elasto directory handle
 * @fstatfs:	Filesystem details (see corresponding struct @elasto_fstatfs)
 */
int
elasto_fstatfs(struct elasto_fh *fh,
	       struct elasto_fstatfs *fstatfs);

struct elasto_dent {
	char *name;
	struct elasto_fstat fstat;
};

/**
 * Iterate files/dirs within a given directory.
 *
 * @fh:		Valid Elasto directory handle
 * @priv:	Private pointer passed to @dent_cb
 * @dent_cb:	Callback for each file/dir within the directory
 */
int
elasto_freaddir(struct elasto_fh *fh,
		void *priv,
		int (*dent_cb)(struct elasto_dent *,
			       void *));

/**
 * Remove a file or directory and close handle.
 *
 * @fh: open file or directory handle
 */
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
 * For a sparse file, check which regions are allocated.
 *
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

/**
 * Enable @stderr debug output.
 *
 * @level:	Debug level verbosity. Higher = more verbose.
 */
int
elasto_fdebug(int level);

#ifdef  __cplusplus
}
#endif

#endif /* _ELASTO_FILE_H_ */
