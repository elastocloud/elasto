/*
 * Copyright 2016, David Disseldorp
 *
 * Based on tcmu-runner/consumer.c, and tcmu-runner/glfs.c which carries:
 * Copyright 2015, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <endian.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <poll.h>

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <scsi/scsi.h>
#define _BITS_UIO_H
#include <linux/target_core_user.h>
#include <libtcmu.h>
#include "scsi_defs.h"
#include "lib/file/file_api.h"

/*
 * Debug API implementation
 */
void dbgp(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

void errp(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
}

struct tcmu_device *tcmu_dev_array[128];
size_t dev_array_len = 0;

struct elasto_state {
	char *path;
	struct elasto_fauth *auth;
	struct elasto_fh *efh;

	int block_size;
	long long num_lbas;

	/*
	 * Current tcmu helper API reports WCE=1, but doesn't
	 * implement inquiry VPD 0xb2, so clients will not know UNMAP
	 * or WRITE_SAME are supported. TODO: fix this
	 */
};

#define min(a,b) ({ \
  __typeof__ (a) _a = (a); \
  __typeof__ (b) _b = (b); \
  (void) (&_a == &_b); \
  _a < _b ? _a : _b; \
})

static int
tcmu_elasto_fwritev_misaligned(struct elasto_state *estate,
			       struct iovec *iovec,
			       size_t iov_cnt,
			       uint64_t off,
			       uint64_t len)
{
	uint8_t *tmp_buf;
	size_t copied = 0;
	int ret;

	tmp_buf = malloc(len);
	if (tmp_buf == NULL) {
		return -ENOMEM;
	}

#if 0
	/* XXX similar to tcmu_memcpy_from_iovec, but doesn't change iovecs */
	while (len && iov_cnt) {
		size_t to_copy = min(iovec->iov_len, len);

		if (to_copy) {
			memcpy(iovec->iov_base, src + copied, to_copy);

			len -= to_copy;
			copied += to_copy;
			iovec->iov_base += to_copy;
			iovec->iov_len -= to_copy;
		}

		iovec++;
		iov_cnt--;
	}
#endif

	/* XXX this removes the copied length from the iovec[s] */
	copied = tcmu_memcpy_from_iovec(tmp_buf, len, iovec, iov_cnt);
	if (copied != len) {
		errp("failed to copy %lu bytes from iovec\n", len);
		free(tmp_buf);
		return -EBADF;
	}

	ret = elasto_fwrite(estate->efh, off, len, tmp_buf);
	free(tmp_buf);
	if (ret < 0) {
		errp("Could not write: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static int
tcmu_elasto_fwritev(struct elasto_state *estate,
		    struct iovec *iovec,
		    size_t iov_cnt,
		    uint64_t off,
		    uint64_t len)
{
	int ret;
	uint64_t remaining = len;

	while (remaining != 0) {
		uint64_t to_copy;

		to_copy = min(remaining, iovec->iov_len);
		if (to_copy % estate->block_size) {
			assert((remaining % estate->block_size) == 0);
			errp("write iovec not block aligned (%lu) falling back "
			     "to memcpy of %lu\n", iovec->iov_len, remaining);
			return tcmu_elasto_fwritev_misaligned(estate, iovec,
						iov_cnt, off, remaining);
		}

		ret = elasto_fwrite(estate->efh, off, to_copy, iovec->iov_base);
		if (ret < 0) {
			errp("Could not write: %s\n", strerror(-ret));
			return ret;
		}

		remaining -= to_copy;
		off += to_copy;
		iovec++;
		iov_cnt--;
		assert(iov_cnt >= 0);
	}

	return 0;
}

static int
tcmu_elasto_freadv_misaligned(struct elasto_state *estate,
			      struct iovec *iovec,
			      size_t iov_cnt,
			      uint64_t off,
			      uint64_t len)
{
	uint8_t *tmp_buf;
	size_t copied;
	int ret;

	tmp_buf = malloc(len);
	if (tmp_buf == NULL) {
		return -ENOMEM;
	}

	ret = elasto_fread(estate->efh, off, len, tmp_buf);
	if (ret < 0) {
		free(tmp_buf);
		errp("Could not read: %s\n", strerror(-ret));
		return ret;
	}

	/* XXX this removes the copied length from the iovec[s] */
	copied = tcmu_memcpy_into_iovec(iovec, iov_cnt, tmp_buf, len);
	free(tmp_buf);
	if (copied != len) {
		errp("failed to copy %lu bytes into iovec\n", len);
		return -EBADF;
	}

	return 0;
}

static int
tcmu_elasto_freadv(struct elasto_state *estate,
		   struct iovec *iovec,
		   size_t iov_cnt,
		   uint64_t off,
		   uint64_t len)
{
	int ret;
	uint64_t remaining = len;

	while (remaining != 0) {
		uint64_t to_copy;

		to_copy = min(remaining, iovec->iov_len);
		if (to_copy % estate->block_size) {
			assert((remaining % estate->block_size) == 0);
			errp("read iovec not block aligned (%lu) falling back "
			     "to memcpy of %lu\n", iovec->iov_len, remaining);
			return tcmu_elasto_freadv_misaligned(estate, iovec,
						iov_cnt, off, remaining);
		}

		ret = elasto_fread(estate->efh, off, to_copy, iovec->iov_base);
		if (ret < 0) {
			errp("read(off=%lu,len=%lu) failed: %s\n", off, to_copy, strerror(-ret));
			return ret;
		}

		remaining -= to_copy;
		off += to_copy;
		iovec++;
		iov_cnt--;
		assert(iov_cnt >= 0);
	}

	return 0;
}

#define TCMU_ELASTO_HND "elasto/"
static int
tcmu_elasto_cfg_parse(const char *cfgstring,
		      struct elasto_fauth **_auth,
		      char **_path)
{
	int ret;
	struct elasto_fauth *auth;
	const char *uri;
	const char *path_cfg;
	char *path;
	char *access_key;
	size_t len;

	auth = malloc(sizeof(*auth));
	if (auth == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(auth, 0, sizeof(*auth));

	/* must start with tcmu handler name (subtype) + '/' */
	if (strncmp(cfgstring, TCMU_ELASTO_HND, sizeof(TCMU_ELASTO_HND) - 1)) {
		errp("unexpected handler name: %s\n", cfgstring);
		ret = -EINVAL;
		goto err_auth_free;
	}

	/* next is the Azure Page Blob URI */
	uri = cfgstring + sizeof(TCMU_ELASTO_HND) - 1;
	if (strncmp(uri, "apb://", sizeof("apb://") - 1)) {
		errp("Bad REST protocol URI: %s\n", cfgstring);
		ret = -EINVAL;
		goto err_auth_free;
	}
	auth->type = ELASTO_FILE_APB;

	/* path immediately follows URI, but keep one '/' as root prefix */
	path_cfg = uri + sizeof("apb:/") - 1;

	/* space separator between path and access key */
	access_key = strchr(path_cfg, ' ');
	if (access_key == NULL) {
		errp("No access key\n");
		ret = -EINVAL;
		goto err_auth_free;
	}

	if (access_key <= path_cfg)  {
		errp("Bad config");
		ret = -EINVAL;
		goto err_auth_free;
	}

	len = access_key - path_cfg;
	path = strndup(path_cfg, len);
	if (path == NULL) {
		ret = -ENOMEM;
		goto err_auth_free;
	}

	while (*access_key == ' ') {
		access_key++;
	}

	if (strlen(access_key) > 256)  {
		errp("access key too long");
		ret = -EINVAL;
		goto err_path_free;
	}

	auth->az.access_key = strdup(access_key);
	if (auth->az.access_key == NULL) {
		ret = -ENOMEM;
		goto err_path_free;
	}

	/* insecure_http is disabled */

	*_auth = auth;
	*_path = path;
	return 0;

err_path_free:
	free(path);
err_auth_free:
	free(auth);
err_out:
	return ret;
}

static void
tcmu_elasto_auth_free(struct elasto_fauth *auth)
{
	free(auth->az.access_key);
	free(auth);
}

static bool
tcmu_elasto_cfg_check(const char *cfgstring,
		      char **reason)
{
	int ret;
	struct elasto_fauth *auth;
	char *path;

	printf("faking good config\n");
	return true;

	ret = tcmu_elasto_cfg_parse(cfgstring, &auth, &path);
	if (ret < 0) {
		*reason = strdup(strerror(-ret));
		return false;
	}

	tcmu_elasto_auth_free(auth);
	free(path);

	return true;
}

static int tcmu_elasto_open(struct tcmu_device *dev)
{
	struct elasto_state *estate;
	struct elasto_fh *efh;
	int ret = 0;
	int close_ret = 0;
	char *config;
	long long size;

	estate = calloc(1, sizeof(*estate));
	if (estate == NULL) {
		return -ENOMEM;
	}

	tcmu_set_dev_private(dev, estate);

	estate->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (estate->block_size == -1) {
		errp("Could not get device block size\n");
		ret = -EIO;
		goto err_estate_free;
	}

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		errp("Could not get device size\n");
		ret = -EIO;
		goto err_estate_free;
	}

	estate->num_lbas = size / estate->block_size;

	config = tcmu_get_dev_cfgstring(dev);
	if (config == NULL) {
		errp("no configuration found in cfgstring\n");
		ret = -EINVAL;
		goto err_estate_free;
	}

	errp("parsing tcmu config: %s\n", config);

	ret = tcmu_elasto_cfg_parse(config, &estate->auth, &estate->path);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_estate_free;
	}

	ret = elasto_fopen(estate->auth, estate->path, ELASTO_FOPEN_CREATE,
			   NULL, &efh);
	if (ret < 0) {
		errp("failed to open elasto path: %s\n", estate->path);
		goto err_auth_free;
	}

	if (ret == ELASTO_FOPEN_RET_CREATED) {
		/* new file, truncate to size */
		ret = elasto_ftruncate(efh, size);
		if (ret < 0) {
			errp("failed to open elasto path: %s\n", estate->path);
			goto err_efh_close;
		}
	} else {
		struct elasto_fstat est;
		assert(ret == ELASTO_FOPEN_RET_EXISTED);

		ret = elasto_fstat(efh, &est);
		if (ret < 0) {
			errp("failed to stat elasto path: %s\n", estate->path);
			goto err_efh_close;
		}

		if (est.size != size) {
			ret = -EINVAL;
			errp("elasto file size %llu doesn't match tcmu device "
			     "size %llu\n", est.size, size);
			goto err_efh_close;
		}

		if (est.blksize != estate->block_size) {
			ret = -EINVAL;
			errp("elasto block size %llu doesn't match tcmu device "
			     "size %llu\n", est.blksize, estate->block_size);
			goto err_efh_close;
		}
	}
	estate->efh = efh;

	/* Add new device to our horrible fixed-length array */
	tcmu_dev_array[dev_array_len] = dev;
	dev_array_len++;

	return 0;

err_efh_close:
	close_ret = elasto_fclose(efh);
	if (close_ret < 0) {
		errp("failed to close elasto path");
	}
err_auth_free:
	tcmu_elasto_auth_free(estate->auth);
	free(estate->path);
err_estate_free:
	free(estate);
	return ret;
}

static void tcmu_elasto_close(struct tcmu_device *dev)
{
	int ret;
	struct elasto_state *estate = tcmu_get_dev_private(dev);

	ret = elasto_fclose(estate->efh);
	if (ret < 0) {
		errp("failed to close elasto path");
	}
	tcmu_elasto_auth_free(estate->auth);
	free(estate->path);
	free(estate);
}

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
int tcmu_elasto_cmd_handle(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	struct elasto_state *estate = tcmu_get_dev_private(dev);
	struct elasto_fh *efh;
	uint8_t cmd;
	int ret;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	uint8_t *tmpbuf;
	uint64_t offset = estate->block_size * tcmu_get_lba(cdb);
	uint32_t tl     = estate->block_size * tcmu_get_xfer_length(cdb);
	int do_verify = 0;
	uint32_t cmp_offset;

	efh = estate->efh;
	ret = length = 0;
	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16) {
			return tcmu_emulate_read_capacity_16(estate->num_lbas,
							     estate->block_size,
							     cdb, iovec,
							     iov_cnt, sense);
		} else {
			return TCMU_NOT_HANDLED;
		}
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case COMPARE_AND_WRITE:
		/* Blocks are transferred twice, first the set that
		 * we compare to the existing data, and second the set
		 * to write if the compare was successful.
		 */
		length = tl / 2;

		tmpbuf = malloc(length);
		if (tmpbuf == NULL) {
			result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
						    ASC_INTERNAL_TARGET_FAILURE,
						    NULL);
			break;
		}

		ret = elasto_fread(efh, offset, length, tmpbuf);
		if (ret < 0) {
			result = set_medium_error(sense);
			free(tmpbuf);
			break;
		}

		cmp_offset = tcmu_compare_with_iovec(tmpbuf, iovec, length);
		if (cmp_offset != -1) {
			result = tcmu_set_sense_data(sense, MISCOMPARE,
					ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
						     &cmp_offset);
			free(tmpbuf);
			break;
		}

		free(tmpbuf);

		tcmu_seek_in_iovec(iovec, length);
		goto write;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (cdb[1] & 0x2) {
			result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						     ASC_INVALID_FIELD_IN_CDB, NULL);
		}
		/* nothing to sync - no local cache */
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		do_verify = 1;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = tl;
write:
		ret = tcmu_elasto_fwritev(estate, iovec, iov_cnt, offset, length);
		if (ret < 0) {
			result = set_medium_error(sense);
			break;
		}

		/* XXX no write cache so no need to sync */

		if (!do_verify)
			break;

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
						    ASC_INTERNAL_TARGET_FAILURE,
						    NULL);
			break;
		}

		ret = elasto_fread(efh, offset, length, tmpbuf);
		if (ret < 0) {
			result = set_medium_error(sense);
			free(tmpbuf);
			break;
		}

		cmp_offset = tcmu_compare_with_iovec(tmpbuf, iovec, length);
		if (cmp_offset != -1) {
			result = tcmu_set_sense_data(sense, MISCOMPARE,
					    ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					    &cmp_offset);
		}
		free(tmpbuf);
		break;

	case WRITE_SAME:
	case WRITE_SAME_16:
		errp("WRITE_SAME called, but has vpd b2 been implemented?\n");
		result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB, NULL);
		break;
#if 0
		/* WRITE_SAME used to punch hole in file */
		if (cdb[1] & 0x08) {
			ret = elasto_fallocate(efh, ELASTO_FALLOC_PUNCH_HOLE,
					       offset, tl);
			if (ret != 0) {
				result = tcmu_set_sense_data(sense,
						HARDWARE_ERROR,
						ASC_INTERNAL_TARGET_FAILURE,
						NULL);
			}
			break;
		}
		/* glfs.c WRITE_SAME implementation looks incorrect */
		errp("unhandled write_same request");
		return TCMU_NOT_HANDLED;
		break;
#endif
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = tcmu_iovec_length(iovec, iov_cnt);
		ret = tcmu_elasto_freadv(estate, iovec, iov_cnt, offset, length);
		if (ret < 0) {
			result = set_medium_error(sense);
		}
		break;
	case UNMAP:
		/* TODO: implement UNMAP */
		result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB, NULL);
		break;
	default:
		result = TCMU_NOT_HANDLED;
		break;
	}

	dbgp("io done %p %x %d %u\n", cdb, cmd, result, length);

	if (result != SAM_STAT_GOOD) {
		errp("io error %p %x %x %d %d %llu\n",
		     cdb, result, cmd, ret, length, (unsigned long long)offset);
	}

	return result;
}

static const char tcmu_elasto_cfg_desc[] =
	"Elasto config string is of the form:\n"
	"\"apb://<account>/<container>/<blob> <access key>\"\n"
	"where:\n"
	"  apb://      REST protocol URI (Azure Page Blob)\n"
	"  account     Microsoft Azure account name\n"
	"  container   Container within the Azure account\n"
	"  blob        Page blob name\n"
	"  access key  Azure account access key";

struct tcmulib_handler elasto_handler = {
	.name = "Elasto handler",
	.subtype = "elasto",
	.cfg_desc = tcmu_elasto_cfg_desc,

	.check_config = tcmu_elasto_cfg_check,

	.added = tcmu_elasto_open,
	.removed = tcmu_elasto_close,
};

int main(int argc, char **argv)
{
	struct tcmulib_context *tcmulib_ctx;
	struct pollfd pollfds[16];
	int i;
	int ret;

	elasto_fdebug(1);

	/* If any TCMU devices that exist that match subtype,
	   handler->added() will now be called from within
	   tcmulib_initialize(). */
	tcmulib_ctx = tcmulib_initialize(&elasto_handler, 1, errp);
	if (tcmulib_ctx <= 0) {
		errp("tcmulib_initialize failed with %p\n", tcmulib_ctx);
		exit(1);
	}

	while (1) {
		pollfds[0].fd = tcmulib_get_master_fd(tcmulib_ctx);
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		for (i = 0; i < dev_array_len; i++) {
			pollfds[i+1].fd = tcmu_get_dev_fd(tcmu_dev_array[i]);
			pollfds[i+1].events = POLLIN;
			pollfds[i+1].revents = 0;
		}

		ret = poll(pollfds, dev_array_len+1, -1);

		if (ret <= 0) {
			errp("poll() returned %d, exiting\n", ret);
			exit(1);
		}

		if (pollfds[0].revents) {
			/* If any tcmu devices have been added or removed, the
			   added() and removed() handler callbacks will be called
			   from within this. */
			tcmulib_master_fd_ready(tcmulib_ctx);

			/* Since devices (may) have changed, re-poll() instead of
			   processing per-device fds. */
			continue;
		}

		for (i = 0; i < dev_array_len; i++) {
			if (pollfds[i+1].revents) {
				struct tcmulib_cmd *cmd;
				struct tcmu_device *dev = tcmu_dev_array[i];

				tcmulib_processing_start(dev);

				while ((cmd = tcmulib_get_next_command(dev)) != NULL) {
					ret = tcmu_elasto_cmd_handle(dev,
							     cmd->cdb,
							     cmd->iovec,
							     cmd->iov_cnt,
							     cmd->sense_buf);
					tcmulib_command_complete(dev, cmd, ret);
				}

				tcmulib_processing_complete(dev);
			}
		}
	}

	return 0;
}
