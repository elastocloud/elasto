/*
 * Copyright (C) SUSE LINUX GmbH 2013-2015, all rights reserved.
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

#ifdef  __cplusplus
extern "C" {
#endif

enum elasto_data_type {
	ELASTO_DATA_NONE = 0,
	ELASTO_DATA_IOV,
	ELASTO_DATA_CB,
};

struct elasto_data {
	enum elasto_data_type type;
	uint64_t len;
	uint64_t off;
	union {
		struct {
			/* @buf is an io buffer of size @len */
			uint8_t *buf;
			bool foreign_buf;
		} iov;
		struct {
			void *priv;
			int (*out_cb)(uint64_t stream_off,
				      uint64_t need,
				      uint8_t **_out_buf,
				      uint64_t *buf_len,
				      void *priv);
			int (*in_cb)(uint64_t stream_off,
				     uint64_t got,
				     uint8_t *in_buf,
				     uint64_t buf_len,
				     void *priv);
		} cb;
	};
};

void
elasto_data_free(struct elasto_data *data);

/**
 * elasto_data_iov_new - initialise an buffer based data struct
 *
 * @buf:	Foreign buffer, or NULL if @buf_alloc is set.
 * @buf_len:	Length of foreign buffer, or allocation length.
 * @buf_alloc:	Set if buffer should be allocated and freed with @_data.
 * @_data:	Data struct allocated and returned on success.
 * @return:	0 on success, -errno on failure.
 */
int
elasto_data_iov_new(uint8_t *buf,
		    uint64_t buf_len,
		    bool buf_alloc,
		    struct elasto_data **_data);

int
elasto_data_iov_grow(struct elasto_data *data,
		     uint64_t grow_by);

/**
 * elasto_data_cb_new - initialise a callback data struct
 *
 * @out_len:	Amount of data to send.
 * @out_cb:	Called when a request needs data to send. Following callback,
 *		@out_buf is owned by the caller, and will be freed after use.
 *		TODO: should add an @out_free callback?
 * @in_len:	Amount of data to retrieve.
 * @in_cb:	Called when a response has non-error data to write. @stream_off
 *		is the total number of bytes into the response data. @in_buf is
 * 		subsequently owned by the callee, and should be freed after use.
 * @cb_priv:	Opaque blob that should be passed to the out/in_cb functions.
 * @_data:	Data struct allocated and returned on success.
 * @return:	0 on success, -errno on failure.
 */
int
elasto_data_cb_new(uint64_t out_len,
		   int (*out_cb)(uint64_t stream_off,
				 uint64_t need,
				 uint8_t **_out_buf,
				 uint64_t *buf_len,
				 void *priv),
		   uint64_t in_len,
		   int (*in_cb)(uint64_t stream_off,
				uint64_t got,
				uint8_t *in_buf,
				uint64_t buf_len,
				void *priv),
		   void *cb_priv,
		   struct elasto_data **_data);

#ifdef  __cplusplus
}
#endif

#endif /* _ELASTO_DATA_H_ */
