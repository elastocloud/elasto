/*
 * Copyright (C) SUSE LINUX 2012, all rights reserved
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
