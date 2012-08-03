/*
 * Copyright (C) SUSE LINUX Products GmbH 2012, all rights reserved.
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
 *
 * Author: David Disseldorp <ddiss@suse.de>
 */
#ifndef _AZURE_SIGN_H_
#define _AZURE_SIGN_H_

int
azure_sign_gen_lite(const char *account,
		    const uint8_t *key,
		    int key_len,
		    struct azure_req *req,
		    char **sig_src,
		    char **sig_str);

void
azure_sign_init(void);

void
azure_sign_deinit(void);

#endif /* _AZURE_SIGN_H_ */
