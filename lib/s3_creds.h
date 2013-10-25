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
#ifndef _S3_CREDS_H_
#define _S3_CREDS_H_

int
s3_creds_csv_process(const char *creds_file,
		     char **_user_name,
		     char **_access_key_id,
		     char **_secret_access_key);

#endif /* ifdef _S3_CREDS_H_ */
