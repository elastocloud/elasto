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
#ifndef _HANDLE_H_
#define _HANDLE_H_

#define ELASTO_FH_MAGIC "ElastoF"

struct elasto_fh_mod_ops {
	void (*fh_free)(void *mod_priv);
	int (*open)(void *mod_priv,
		    struct elasto_conn *conn,
		    const char *path,
		    uint64_t flags);
	int (*close)(void *mod_priv,
		     struct elasto_conn *conn);
	int (*write)(void *mod_priv,
		     struct elasto_conn *conn,
		     uint64_t dest_off,
		     uint64_t dest_len,
		     struct elasto_data *src_data);
	int (*read)(void *mod_priv,
		    struct elasto_conn *conn,
		    uint64_t src_off,
		    uint64_t src_len,
		    struct elasto_data *dest_data);
	int (*allocate)(void *mod_priv,
			struct elasto_conn *conn,
			uint32_t mode,
			uint64_t dest_off,
			uint64_t dest_len);
	int (*truncate)(void *mod_priv,
			struct elasto_conn *conn,
			uint64_t len);
	int (*stat)(void *mod_priv,
		    struct elasto_conn *conn,
		    struct elasto_fstat *fstat);
	int (*lease_acquire)(void *mod_priv,
			     struct elasto_conn *conn,
			     int32_t duration,
			     void **_flease_h);
	int (*lease_break)(void *mod_priv,
			   struct elasto_conn *conn,
			   void **_flease_h);
	int (*lease_release)(void *mod_priv,
			     struct elasto_conn *conn,
			     void **_flease_h);
	int (*mkdir)(void *mod_priv,
		     struct elasto_conn *conn,
		     const char *path);
	int (*rmdir)(void *mod_priv,
		     struct elasto_conn *conn,
		     const char *path);
};

/* fh init calls this entry point for the corresponding module */
#define ELASTO_FILE_MOD_INIT_FN "elasto_file_mod_fh_init"

/*
 * @magic: magic to verify handle on use
 * @conn: Elasto connection initialised by open op
 * @type: module identifier
 * @mod_dl_h: module dlopen handle
 * @mod_priv: private module data returned on module init
 * @ops: module functions
 * @lid: opaque lease ID, returned on acquisition
 * @lease_state: last known lease state
 */
struct elasto_fh {
	char magic[8];
	struct elasto_conn *conn;
	enum elasto_ftype type;
	void *mod_dl_h;
	void *mod_priv;
	struct elasto_fh_mod_ops ops;
	/* FIXME: make lid an iovec style blob */
	void *lid;
	enum {
		ELASTO_FH_LEASE_NONE = 0,
		ELASTO_FH_LEASE_ACQUIRED,
	} lease_state;
};

int
elasto_fh_init(const struct elasto_fauth *auth,
	       struct elasto_fh **_fh);

void
elasto_fh_free(struct elasto_fh *fh);

int
elasto_fh_validate(struct elasto_fh *fh);

#endif /* _HANDLE_H_ */
