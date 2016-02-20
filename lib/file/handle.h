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
#ifndef _HANDLE_H_
#define _HANDLE_H_

#define ELASTO_FH_MAGIC "ElastoF"
#define ELASTO_FH_POISON "PoisonF"

struct elasto_fh_mod_ops {
	void (*fh_free)(void *mod_priv);
	int (*open)(void *mod_priv,
		    const char *path,
		    uint64_t flags,
		    struct elasto_ftoken_list *open_toks);
	int (*close)(void *mod_priv);
	int (*write)(void *mod_priv,
		     uint64_t dest_off,
		     uint64_t dest_len,
		     struct elasto_data *src_data);
	int (*read)(void *mod_priv,
		    uint64_t src_off,
		    uint64_t src_len,
		    struct elasto_data *dest_data);
	int (*allocate)(void *mod_priv,
			uint32_t mode,
			uint64_t dest_off,
			uint64_t dest_len);
	int (*truncate)(void *mod_priv,
			uint64_t len);
	int (*splice)(void *src_mod_priv,
		      uint64_t src_off,
		      void *dest_mod_priv,
		      uint64_t dest_off,
		      uint64_t len);
	int (*stat)(void *mod_priv,
		    struct elasto_fstat *fstat);
	int (*statfs)(void *mod_priv,
		      struct elasto_fstatfs *fstatfs);
	int (*lease_acquire)(void *mod_priv,
			     int32_t duration,
			     void **_flease_h);
	int (*lease_break)(void *mod_priv,
			   void **_flease_h);
	int (*lease_release)(void *mod_priv,
			     void **_flease_h);
	void (*lease_free)(void *mod_priv,
			   void **_flease_h);
	int (*readdir)(void *mod_priv,
		       void *cli_priv,
		       int (*dent_cb)(struct elasto_dent *,
				      void *));
	int (*unlink)(void *mod_priv);
	int (*list_ranges)(void *mod_priv,
			   uint64_t off,
			   uint64_t len,
			   uint64_t flags,
			   void *cb_priv,
			   int (*range_cb)(struct elasto_frange *,
					   void *));
};

/* fh init calls this entry point for the corresponding module */
#define ELASTO_FILE_MOD_INIT_FN "elasto_file_mod_fh_init"
/* Elasto file module internal API version */
#define ELASTO_FILE_MOD_VERS_SYM "elasto_file_mod_version"
#define ELASTO_FILE_MOD_VERS_VAL 2ULL

/*
 * @magic: magic to verify handle on use
 * @type: module identifier
 * @mod_dl_h: module dlopen handle
 * @mod_priv: private module data returned on module init
 * @ops: module functions
 * @lease_h: opaque lease handle, returned on acquisition
 * @lease_state: last known lease state
 */
struct elasto_fh {
	char magic[8];
	enum elasto_ftype type;
	char *open_path;
	uint64_t open_flags;
	void *mod_dl_h;
	void *mod_priv;
	struct elasto_fh_mod_ops ops;
	void *flease_h;
	enum {
		ELASTO_FH_LEASE_NONE = 0,
		ELASTO_FH_LEASE_ACQUIRED,
	} lease_state;
};

int
elasto_fh_init(const struct elasto_fauth *auth,
	       const char *open_path,
	       uint64_t open_flags,
	       struct elasto_fh **_fh);

void
elasto_fh_free(struct elasto_fh *fh);

int
elasto_fh_validate(struct elasto_fh *fh);

#endif /* _HANDLE_H_ */
