/*
 * Copyright (C) SUSE LINUX Products GmbH 2012-2014, all rights reserved.
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
#ifndef _AZURE_REQ_H_
#define _AZURE_REQ_H_

#define REQ_HOST_AZURE_MGMT "management.core.windows.net"

int
az_req_sign(const char *acc,
	    const uint8_t *key,
	    int key_len,
	    struct op *op);

int
az_req_common_hdr_fill(struct op *op,
		       bool mgmt);

#endif /* ifdef _AZURE_REQ_H_ */
