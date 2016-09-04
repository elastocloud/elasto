/*
 * Copyright (C) SUSE LINUX GmbH 2012-2016, all rights reserved.
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
#ifndef _SIGN_H_
#define _SIGN_H_

int
sign_gen_lite_azure(const char *account,
		    const uint8_t *key,
		    int key_len,
		    struct op *op,
		    char **sig_src,
		    char **sig_str);

int
sign_gen_shared_azure(const char *account,
		      const uint8_t *key,
		      int key_len,
		      struct op *op,
		      char **sig_src,
		      char **sig_str);

int
sign_gen_s3(const char *bkt_name,
	    const uint8_t *secret,
	    int secret_len,
	    struct op *op,
	    char **sig_src,
	    char **sig_str);

void
sign_init(void);

void
sign_deinit(void);

#endif /* _SIGN_H_ */
