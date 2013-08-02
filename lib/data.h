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
#ifndef _ELASTO_DATA_H_
#define _ELASTO_DATA_H_

enum elasto_data_type {
	ELASTO_DATA_NONE = 0,
	ELASTO_DATA_IOV,
	ELASTO_DATA_FILE,
};

/*
 * @base_off is the base offset into the input/output
 * buffer. i.e. @iov.base_off + @off = read/write offset
 */
struct elasto_data {
	enum elasto_data_type type;
	uint64_t len;
	uint64_t off;
	uint64_t base_off;
	union {
		struct {
			/* @buf is allocated io buffer of size @len */
			uint8_t *buf;
		} iov;
		struct {
			/* file is @len bytes in size */
			char *path;
			int fd;
		} file;
	};
};

void
elasto_data_free(struct elasto_data *data);

int
elasto_data_file_new(char *path,
		     uint64_t file_len,
		     uint64_t base_off,
		     int open_flags,
		     mode_t create_mode,
		     struct elasto_data **_data);

int
elasto_data_iov_new(uint8_t *buf,
		    uint64_t buf_len,
		    uint64_t base_off,
		    bool buf_alloc,
		    struct elasto_data **_data);

int
elasto_data_iov_grow(struct elasto_data *data,
		     uint64_t grow_by);

#endif /* _ELASTO_DATA_H_ */
