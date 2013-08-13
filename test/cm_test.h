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
#ifndef _CM_TEST_H_
#define _CM_TEST_H_

struct cm_unity_state {
	char *pub_settings;
	char *s3_id;
	char *s3_secret;
	bool insecure_http;
	char *acc;
	char *ctnr;
};

struct cm_unity_state *
cm_unity_state_get(void);

int
cm_sign_s3_run(void);

int
cm_sign_azure_run(void);

int
cm_data_run(void);

#endif /* _CM_TEST_H_ */
