/*
 * Copyright (C) SUSE LINUX GmbH 2012-2017, all rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/queue.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <event2/event_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include "third_party/hostcheck/libevent_https_client.h"
#include "ccan/list/list.h"
#include "dbg.h"
#include "base64.h"
#include "data.h"
#include "op.h"
#include "sign.h"
#include "util.h"
#include "conn.h"

/* convert base64 encoded key to binary and store in @econn */
int
elasto_conn_sign_setkey(struct elasto_conn *econn,
			const char *account,
			const char *key_b64)
{
	int ret;

	/* signing keys for S3 are set on econn initialisation */
	assert(econn->type == CONN_TYPE_AZURE);

	if (econn->sign.key_len > 0) {
		free(econn->sign.key);
		free(econn->sign.account);
		econn->sign.key_len = 0;
	}
	econn->sign.key = malloc(strlen(key_b64));
	if (econn->sign.key == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	econn->sign.account = strdup(account);
	if (econn->sign.account == NULL) {
		ret = -ENOMEM;
		goto err_key_free;
	}

	ret = base64_decode(key_b64, econn->sign.key);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_acc_free;
	}
	econn->sign.key_len = ret;
	dbg(1, "set account %s signing key: %s\n", account, key_b64);

	return 0;

err_acc_free:
	free(econn->sign.account);
err_key_free:
	free(econn->sign.key);
	econn->sign.key_len = 0;
err_out:
	return ret;
}

/*
 * @cb_nbytes is the number of bytes provided by this callback, clen is the
 * number of bytes expected across all callbacks, but may not be known.
 */
static int
ev_write_alloc_err(struct op *op,
		   uint64_t cb_nbytes)
{
	struct op_rsp_error *err = &op->rsp.err;

	if ((err->buf != NULL) && (cb_nbytes > (err->len - err->off))) {
		uint8_t *buf;
		dbg(6, "extending error buffer by %" PRIu64 " bytes\n",
		    cb_nbytes);
		buf = realloc(err->buf, err->len + cb_nbytes);
		if (buf == NULL) {
			return -ENOMEM;
		}
		err->buf = buf;
		err->len += cb_nbytes;
	} else if (err->buf == NULL) {
		uint64_t sz = (op->rsp.clen_recvd ? op->rsp.clen : cb_nbytes);
		dbg(9, "allocating new %" PRIu64 " byte error buffer\n", sz);
		err->buf = malloc(sz);
		if (err->buf == NULL) {
			return -ENOMEM;
		}
		err->len = sz;
		err->off = 0;
	}
	return 0;
}

/*
 * @cb_nbytes is the number of bytes provided by this callback, clen is the
 * number of bytes expected across all callbacks, but may not be known.
 */
static int
ev_write_alloc_std(struct op *op,
		   uint64_t cb_nbytes)

{
	int ret;
	uint64_t rem;

	dbg(9, "allocating buffer for %" PRIu64 " bytes\n", cb_nbytes);
	if (op->rsp.data == NULL) {
		uint64_t sz = (op->rsp.clen_recvd ? op->rsp.clen : cb_nbytes);
		/* requester wants us to allocate a recv iov */
		/* TODO check clen isn't too huge */
		ret = elasto_data_iov_new(NULL, sz, true, &op->rsp.data);
		op->rsp.recv_cb_alloced = true;
		return ret;
	}

	switch (op->rsp.data->type) {
	case ELASTO_DATA_IOV:
		rem = (op->rsp.data->len - op->rsp.data->off);
		if (op->rsp.recv_cb_alloced == true) {
			if (op->rsp.clen_recvd) {
				dbg(0, "unexpected alloc call after clen\n");
			}
			if (cb_nbytes > rem) {
				dbg(2, "growing buf for callback\n");
				ret = elasto_data_iov_grow(op->rsp.data,
							     cb_nbytes - rem);
				if (ret < 0) {
					return ret;
				}
			}
			return 0;
		}
		/* external req buffer */
		if (op->rsp.clen_recvd && (op->rsp.clen > op->rsp.data->len)) {
				dbg(0, "preallocated rsp buf not large enough "
				       "- alloced=%" PRIu64 ", "
				       "received clen=%" PRIu64 "\n",
				       op->rsp.data->len, op->rsp.clen);
			return -E2BIG;
		}
		/* FIXME check for space on !op->rsp.clen_recvd */
		break;
	case ELASTO_DATA_CB:
		/*
		 * cb_in_buf allocation is handled in the write handler, as we
		 * don't need to do anything smart with the clen.
		 */
		break;
	default:
		assert(false);
		break;
	}

	return 0;
}

static int
ev_write_err(struct op *op,
	     struct evbuffer *ev_in_buf,
	     uint64_t num_bytes)
{
	int ret;

	dbg(8, "filling error buffer of len %" PRIu64 " at off %" PRIu64
	    " with %" PRIu64 " bytes\n",
	    op->rsp.err.len, op->rsp.err.off, num_bytes);
	if (op->rsp.err.off + num_bytes > op->rsp.err.len) {
		dbg(0, "fatal: error rsp buffer exceeded, "
		       "len %" PRIu64 " off %" PRIu64 " io_sz %" PRIu64 "\n",
		       op->rsp.err.len, op->rsp.err.off, num_bytes);
		return -E2BIG;
	}

	ret = evbuffer_remove(ev_in_buf,
			      (void *)(op->rsp.err.buf + op->rsp.err.off),
			      num_bytes);
	/* no tolerance for partial IO */
	if ((ret < 0) || (ret != num_bytes)) {
		dbg(0, "unable to remove %" PRIu64 " bytes from error buffer\n",
		    num_bytes);
		return -EIO;
	}

	op->rsp.err.off += num_bytes;

	return 0;
}

static int
ev_write_std(struct op *op,
	     struct evbuffer *ev_in_buf,
	     uint64_t num_bytes)
{
	int ret;
	uint64_t write_off = op->rsp.data->off;
	uint8_t *cb_in_buf;

	/* rsp buffer must have been allocated */
	assert(op->rsp.data != NULL);

	dbg(9, "writing %" PRIu64 " bytes data\n", num_bytes);

	switch (op->rsp.data->type) {
	case ELASTO_DATA_IOV:
		if (write_off + num_bytes > op->rsp.data->len) {
			dbg(0, "fatal: write buffer exceeded, "
			       "len %" PRIu64 " off %" PRIu64 " io_sz %" PRIu64
			       "\n", op->rsp.data->len, write_off, num_bytes);
			return -E2BIG;
		}
		ret = evbuffer_remove(ev_in_buf,
				      (void *)(op->rsp.data->iov.buf + write_off),
				      num_bytes);
		/* no tolerance for partial IO */
		if ((ret < 0) || (ret != num_bytes)) {
			dbg(0, "unable to remove %" PRIu64 " bytes from buffer\n",
			    num_bytes);
			return -EIO;
		}
		break;
	case ELASTO_DATA_CB:
		if (op->rsp.data->cb.in_cb == NULL) {
			dbg(0, "error: data received with NULL in_cb\n");
			return -EIO;
		}

		/* allocate a buffer to hold only this cb data */
		cb_in_buf = malloc(num_bytes);
		if (cb_in_buf == NULL) {
			return -ENOMEM;
		}
		ret = evbuffer_remove(ev_in_buf,
				      cb_in_buf,
				      num_bytes);
		/* no tolerance for partial IO */
		if ((ret < 0) || (ret != num_bytes)) {
			dbg(0, "unable to remove %" PRIu64 " bytes from "
			       "buffer for callback\n", num_bytes);
			free(cb_in_buf);
			return -EIO;
		}

		/* in_cb is responsible for freeing cb_in_buf on success */
		ret = op->rsp.data->cb.in_cb(write_off, num_bytes, cb_in_buf,
					     num_bytes, op->rsp.data->cb.priv);
		if (ret < 0) {
			dbg(0, "data in_cb returned an error (%d), ending "
			       "xfer\n", ret);
			free(cb_in_buf);
			return -EIO;
		}

		break;
	default:
		assert(false);
		break;
	}
	op->rsp.data->off += num_bytes;
	return 0;
}

struct conn_op {
	struct elasto_conn *econn_orig;
	bool econn_is_redirect;
	struct elasto_conn *econn;
	/* event to track a single http req/rsp exchange */
	struct evhttp_request *ev_http;
	struct op *op;
	/* used for tracking internal (conn layer) errors */
	int error_ret;
	/*
	 * event to track entire op req/rsp exchange. may cover multiple http
	 * req/rsp exchanges, depending on retries or redirects.
	 */
	struct event ev_xchng;
};

static void
conn_op_flag_error(struct conn_op *conn_op,
		   int error_ret)
{
	dbg(0, "flagging connection error %d for op 0x%x\n",
	    error_ret, conn_op->op->opcode);

	conn_op->error_ret = error_ret;
}

static void
conn_op_cancel(struct conn_op *conn_op)
{
	dbg(0, "cancelling outstanding op\n");
	evhttp_cancel_request(conn_op->ev_http);
	conn_op->ev_http = NULL;

	if (!conn_op->op->rsp.is_error) {
		conn_op->op->rsp.is_error = true;
		conn_op->op->rsp.err_code = HTTP_BADREQUEST;
	}
}

/* never called on an empty response */
static void
ev_write_cb(struct evhttp_request *ev_req,
	    void *data)
{
	struct conn_op *conn_op = (struct conn_op *)data;
	struct op *op = conn_op->op;
	size_t len;
	uint64_t num_bytes;
	int ret;
	struct evbuffer *ev_in_buf;

	assert(conn_op->ev_http == ev_req);
	ev_in_buf = evhttp_request_get_input_buffer(ev_req);
	if (ev_in_buf == NULL) {
		dbg(0, "invalid NULL input buffer in write callback!\n");
		conn_op_cancel(conn_op);
		return;
	}
	len = evbuffer_get_length(ev_in_buf);
	if (len <= 0) {
		dbg(0, "invalid input buffer len: %d\n", (int)len);
		conn_op_cancel(conn_op);
		return;
	}
	num_bytes = len;
	op->rsp.write_cbs++;
	dbg(9, "ev write cb %" PRIu64 "\n", op->rsp.write_cbs);
	/* alloc content buffer on the first callback, or if clen is unknown */
	if ((op->rsp.write_cbs == 1) || (op->rsp.clen_recvd == false)) {
		int ret_code;
		/*
		 * should already have the http response code.
		 * XXX what if the response code hasn't arrived yet?
		 */
		ret_code = evhttp_request_get_response_code(ev_req);
		op->rsp.err_code = ret_code;
		op->rsp.is_error = op_rsp_is_error(op->opcode, ret_code);

		if (op->rsp.is_error) {
			ret = ev_write_alloc_err(op, num_bytes);
		} else {
			ret = ev_write_alloc_std(op, num_bytes);
		}
		if (ret < 0) {
			dbg(0, "failed to allocate response buffer\n");
			conn_op_cancel(conn_op);
			return;
		}
	}

	if (op->rsp.is_error) {
		ret = ev_write_err(op, ev_in_buf, num_bytes);
	} else {
		ret = ev_write_std(op, ev_in_buf, num_bytes);
	}
	if (ret < 0) {
		conn_op_cancel(conn_op);
		return;
	}
	return;
}

static int
ev_hdr_cb(struct evhttp_request *ev_req,
	  void *data)
{
	int ret;
	struct conn_op *conn_op = (struct conn_op *)data;
	struct op *op = conn_op->op;
	struct evkeyvalq *ev_in_hdrs;
	struct evkeyval *ev_hdr;

	ev_in_hdrs = evhttp_request_get_input_headers(ev_req);
	if (ev_in_hdrs == NULL) {
		dbg(0, "header callback with NULL queue\n");
		goto err_disconnect;
	}

	if (op->rsp.num_hdrs > 0) {
		/* headers should only be processed once */
		dbg(0, "unexpected multiple header callbacks!\n");
		goto err_disconnect;
	}

	TAILQ_FOREACH(ev_hdr, ev_in_hdrs, next) {
		dbg(3, "received hdr: %s = %s\n", ev_hdr->key, ev_hdr->value);

		ret = op_rsp_hdr_add(op, ev_hdr->key, ev_hdr->value);
		if (ret < 0) {
			goto err_disconnect;
		}

		if (!strcmp(ev_hdr->key, "Content-Length")) {
			char *eptr;
			uint64_t len;

			errno = 0;
			len = strtoull(ev_hdr->value, &eptr, 10);
			if ((eptr == ev_hdr->value) || (errno != 0)) {
				goto err_disconnect;
			}

			if (op->rsp.write_cbs > 0) {
				dbg(0, "clen header received after data callback!\n");
				goto err_disconnect;
			}
			/* allocate recv buffer in write callback */
			op->rsp.clen_recvd = true;
			op->rsp.clen = len;
		}
	}

	/*
	 * Do NOT clear processed headers via evhttp_clear_headers() -
	 * otherwise libevent won't see the Transfer-Encoding=chunked header,
	 * and will call the chunk callback without stripping the chunk-size
	 * + CRLF prefix and suffix!
	 */

	return 0;

err_disconnect:
	/* ev_req is freed by libevent on callback error */
	conn_op->ev_http = NULL;
	/* TODO set op error? */
	return -1;	/* force disconnect */
}

static void
ev_err_cb(enum evhttp_request_error ev_req_error,
	  void *data)
{
	struct conn_op *conn_op = (struct conn_op *)data;
	struct op *op = conn_op->op;

	/* ev_req is freed by libevent on error callback */
	conn_op->ev_http = NULL;

	if (op->rsp.is_error == true) {
		dbg(0, "is_error already set in error cb, ignoring %d\n",
		    ev_req_error);
		return;
	}

	op->rsp.is_error = true;

	switch (ev_req_error) {
	case EVREQ_HTTP_TIMEOUT:
		dbg(0, "got client error: Request Time-out\n");
		op->rsp.err_code = 408;	/* TODO add to libevent */
		break;
	case EVREQ_HTTP_EOF:
		dbg(0, "got client error: EOF\n");
		op->rsp.err_code = HTTP_SERVUNAVAIL;
		break;
	case EVREQ_HTTP_INVALID_HEADER:
		dbg(0, "got client error: invalid header\n");
		op->rsp.err_code = HTTP_BADREQUEST;
		break;
	case EVREQ_HTTP_BUFFER_ERROR:
		dbg(0, "got client error: IO\n");
		op->rsp.err_code = HTTP_BADREQUEST;
		break;
	case EVREQ_HTTP_REQUEST_CANCEL:
		dbg(0, "got client error: cancelled\n");
		op->rsp.err_code = HTTP_BADREQUEST;
		break;
	case EVREQ_HTTP_DATA_TOO_LONG:
		dbg(0, "got client error: data too long\n");
		op->rsp.err_code = HTTP_ENTITYTOOLARGE;
		break;
	default:
		dbg(0, "got client error callback with unknown code: %d",
		    (int)ev_req_error);
		op->rsp.err_code = HTTP_BADREQUEST;
		break;
	}
}

static void
elasto_read_evbuffer_cleanup_cb(const void *data,
				size_t datalen,
				void *extra)
{
	uint8_t *out_buf = extra;
	dbg(4, "freeing read data %p following cleanup callback\n", out_buf);
	free(out_buf);
}

static int
elasto_conn_send_prepare_read_data(struct evhttp_request *ev_req,
				   struct elasto_data *req_data,
				   uint64_t *_content_len)
{
	int ret;
	struct evbuffer *ev_out_buf;
	uint64_t read_off;
	uint64_t num_bytes;
	uint64_t content_len = (req_data ? req_data->len : 0);

	if (content_len == 0) {
		/* NULL or empty request buffer */
		goto done;
	}

	if ((req_data->type != ELASTO_DATA_IOV)
	 && (req_data->type != ELASTO_DATA_CB)) {
		ret = -EINVAL;	/* unsupported */
		goto err_out;
	}

	ev_out_buf = evhttp_request_get_output_buffer(ev_req);
	if (ev_out_buf == NULL) {
		ret = -ENOENT;
		goto err_out;
	}

	read_off = req_data->off;
	num_bytes = req_data->len - req_data->off;

	if (req_data->type == ELASTO_DATA_IOV) {
		ret = evbuffer_add(ev_out_buf,
				   (void *)(req_data->iov.buf + read_off),
				   num_bytes);
		if (ret < 0) {
			dbg(0, "failed to add iov output buffer\n");
			ret = -EFAULT;
			goto err_out;
		}
	} else if (req_data->type == ELASTO_DATA_CB) {
		uint8_t *out_buf = NULL;
		uint64_t buf_len = 0;

		if (req_data->cb.out_cb == NULL) {
			dbg(0, "error: data to send, but out_cb is NULL\n");
			return -EIO;
		}

		/* cb must provide a buffer with enough data to satisfy req */
		ret = req_data->cb.out_cb(read_off, num_bytes, &out_buf,
					  &buf_len, req_data->cb.priv);
		if (ret < 0) {
			dbg(0, "data out_cb returned an error (%d), ending "
			       "xfer\n", ret);
			ret = -EIO;
			goto err_out;
		} else if (out_buf == NULL) {
			ret = -EINVAL;
			goto err_out;
		} else if (buf_len < num_bytes) {
			dbg(0, "out_cb didn't provide enough data: needed %"
			       PRIu64 " got %" PRIu64 "\n", num_bytes, buf_len);
			/* conn layer now owns buf, so must cleanup */
			free(out_buf);
			ret = -EINVAL;
			goto err_out;
		}
		/* avoid a memcpy, libevent calls cleanup when sent */
		ret = evbuffer_add_reference(ev_out_buf, (const void *)out_buf,
					     num_bytes,
					     elasto_read_evbuffer_cleanup_cb,
					     out_buf);
		if (ret < 0) {
			dbg(0, "failed to add iov output buffer reference\n");
			free(out_buf);
			ret = -EFAULT;
			goto err_out;
		}
		dbg(4, "added out_cb read data %p\n", out_buf);
	}
	req_data->off += num_bytes;

done:
	*_content_len = content_len;
	ret = 0;
err_out:
	return ret;
}

static int
elasto_conn_send_prepare(struct conn_op *conn_op,
			 struct evhttp_request **_ev_req,
			 enum evhttp_cmd_type *_ev_req_type,
			 char **_url);

static int
conn_op_reissue(struct conn_op *conn_op)
{
	int ret;
	enum evhttp_cmd_type ev_req_type;
	char *url;

	ret = elasto_conn_send_prepare(conn_op,
				       &conn_op->ev_http,
				       &ev_req_type, &url);
	if (ret < 0) {
		goto err_out;
	}

	ret = evhttp_make_request(conn_op->econn->ev_conn, conn_op->ev_http,
				  ev_req_type, url);
	free(url);
	if (ret < 0) {
		/* on failure, the request is freed */
		conn_op->ev_http = NULL;
		ret = -ENOMEM;
		goto err_preped_free;
	}

	return 0;

err_preped_free:
	/*
	 * XXX ev_http already freed?
	 * evhttp_request_free(conn_op->ev_http);
	 * conn_op->ev_http = NULL;
	 */
err_out:
	return ret;
}

static int
elasto_conn_ev_ssl_init(struct elasto_conn *econn,
			SSL_CTX **_ssl_ctx,
			SSL **_ssl)
{
	int ret;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	X509_STORE *store;

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (ssl_ctx == NULL) {
		ret = -EFAULT;
		goto err_out;
	}

	store = SSL_CTX_get_cert_store(ssl_ctx);
	X509_STORE_set_default_paths(store);

	/*
	 * OpenSSL doesn't (currently) do server certificate hostname
	 * verification, so we need to add a wrapper callback.
	 * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
	 * Use libevent https-client (which makes use of iSECPartners and cURL
	 * helpers) to do this.
	 */
	libevent_https_client_ssl_cert_verify_init(ssl_ctx, econn->hostname);

	if (econn->pem_file != NULL) {
		ret = SSL_CTX_use_certificate_chain_file(ssl_ctx,
							 econn->pem_file);
		if (ret != 1) {
			ret = -EINVAL;
			goto err_ctx_free;
		}

		ret = SSL_CTX_use_PrivateKey_file(ssl_ctx, econn->pem_file,
						  SSL_FILETYPE_PEM);
		if (ret != 1) {
			ret = -EINVAL;
			goto err_ctx_free;
		}
	}

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		ret = -EFAULT;
		goto err_ctx_free;
	}

	*_ssl_ctx = ssl_ctx;
	*_ssl = ssl;

	return 0;

err_ctx_free:
	SSL_CTX_free(ssl_ctx);
err_out:
	return ret;
}

static void
elasto_conn_ev_disconnect(struct elasto_conn *econn)
{
	if (econn->ev_conn == NULL) {
		return;
	}
	evhttp_connection_set_closecb(econn->ev_conn, NULL, NULL);
	evhttp_connection_free(econn->ev_conn);
	econn->ev_conn = NULL;
	/* FIXME ev_bev is freed with the ev connection???!!!! */
	// bufferevent_free(econn->ev_bev);
	econn->ev_bev = NULL;
	if (!econn->insecure_http) {
		SSL_CTX_free(econn->ssl_ctx);
	}
}

static void
ev_conn_close_cb(struct evhttp_connection *ev_conn,
		 void *data)
{
	struct elasto_conn *econn = (struct elasto_conn *)data;

	dbg(0, "Connection to %s closed\n", econn->hostname);
	elasto_conn_ev_disconnect(econn);
}

static int
elasto_conn_ev_connect(struct elasto_conn *econn)
{
	int ret;
	struct bufferevent *ev_bev;
	struct evhttp_connection *ev_conn;
	struct ssl_ctx_st *ssl_ctx;
	struct ssl_st *ssl;
	int port;

	if ((econn->hostname == NULL) || (econn->ev_base == NULL)) {
	       return -EINVAL;
	}

	if (econn->insecure_http) {
		port = 80;
		ev_bev = bufferevent_socket_new(econn->ev_base, -1,
						BEV_OPT_CLOSE_ON_FREE);
		if (ev_bev == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		dbg(1, "Using HTTP instead of HTTPS\n");
	} else {
		port = 443;
		ret = elasto_conn_ev_ssl_init(econn, &ssl_ctx, &ssl);
		if (ret < 0) {
			goto err_out;
		}

		/* set hostname for Server Name Indication (SNI) */
		SSL_set_tlsext_host_name(ssl, econn->hostname);

		ev_bev = bufferevent_openssl_socket_new(econn->ev_base,
						    -1, ssl,
						    BUFFEREVENT_SSL_CONNECTING,
						    (BEV_OPT_CLOSE_ON_FREE
						    | BEV_OPT_DEFER_CALLBACKS));
		if (ev_bev == NULL) {
			ret = -ENOMEM;
			goto err_ssl_free;
		}

		/* Needed to avoid EOF error on server disconnect */
		bufferevent_openssl_set_allow_dirty_shutdown(ev_bev, 1);
	}

	/* synchronously resolve hostname and connect */
	ev_conn = evhttp_connection_base_bufferevent_new(econn->ev_base,
							 NULL,
							 ev_bev,
							 econn->hostname,
							 port);
	if (ev_conn == NULL) {
		dbg(0, "failed to resolve/connect to %s:%d\n",
		    econn->hostname, port);
		ret = -EBADF;
		goto err_bev_free;
	}

	evhttp_connection_set_closecb(ev_conn, ev_conn_close_cb, econn);
	/* 30s timeout */
	evhttp_connection_set_timeout(ev_conn, 30);

	econn->ev_bev = ev_bev;
	econn->ssl_ctx = ssl_ctx;
	econn->ssl = ssl;
	econn->ev_conn = ev_conn;

	return 0;

err_bev_free:
	bufferevent_free(ev_bev);
err_ssl_free:
	if (!econn->insecure_http) {
		SSL_CTX_free(ssl_ctx);
	}
err_out:
	return ret;
}

/*
 * initialise a temporary redirect connection, using properties of the original,
 * aside from host and connection.
 */
static int
elasto_conn_redirect_open(struct elasto_conn *econn_orig,
			  const char *host_redirect,
			  struct elasto_conn **_econn_redirect)
{
	int ret;
	struct elasto_conn *econn_redirect;

	assert(_econn_redirect != NULL);
	if (econn_orig->type != CONN_TYPE_S3) {
		dbg(0, "only S3 connections support redirects\n");
		ret = -EINVAL;
		goto err_out;
	}

	econn_redirect = malloc(sizeof(*econn_redirect));
	if (econn_redirect == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/*
	 * use ev_base from original, to ensure consistent event loop
	 * TODO add refcount to elasto_conn and take an econn_orig ref here.
	 */
	memset(econn_redirect, 0, sizeof(*econn_redirect));
	econn_redirect->type = econn_orig->type;
	econn_redirect->insecure_http = econn_orig->insecure_http;
	econn_redirect->ev_base = econn_orig->ev_base;
	econn_redirect->sign.key = econn_orig->sign.key;
	econn_redirect->sign.key_len = econn_orig->sign.key_len;
	econn_redirect->sign.account = econn_orig->sign.account;

	econn_redirect->hostname = strdup(host_redirect);
	if (econn_redirect->hostname == NULL) {
		ret = -ENOMEM;
		goto err_conn_free;
	}

	/* ev_bev, ev_conn, ssl_ctx and ssl filled during connection */
	ret = elasto_conn_ev_connect(econn_redirect);
	if (ret < 0) {
		dbg(0, "failed to handle redirected connection to %s\n",
		    host_redirect);
		goto err_hostname_free;
	}

	dbg(3, "connected to %s for op redirect\n", host_redirect);
	*_econn_redirect = econn_redirect;
	return 0;

err_hostname_free:
	free(econn_redirect->hostname);
err_conn_free:
	free(econn_redirect);
err_out:
	return ret;
}

static void
elasto_conn_redirect_close(struct elasto_conn *econn_redirect)
{
	elasto_conn_ev_disconnect(econn_redirect);
	free(econn_redirect->hostname);
	free(econn_redirect);
}

static void
conn_op_completion(struct conn_op *conn_op)
{
	int ret;

	if (conn_op->ev_http != NULL) {
		/* ev_req is cancelled / freed on error */
		evhttp_request_free(conn_op->ev_http);
		conn_op->ev_http = NULL;
	}

	if (conn_op->econn_is_redirect) {
		elasto_conn_redirect_close(conn_op->econn);
		conn_op->econn_is_redirect = false;
	}
	conn_op->econn = NULL;

	ret = op_rsp_process(conn_op->op);
	if (ret == -EAGAIN) {
		/* response is a redirect, resend via new conn */
		ret = op_req_redirect(conn_op->op);
		if (ret < 0) {
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		/* use original connection as redirect copy source */
		ret = elasto_conn_redirect_open(conn_op->econn_orig,
						conn_op->op->url_host,
						&conn_op->econn);
		if (ret < 0) {
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		conn_op->econn_is_redirect = true;
		/* reissue without exiting the event loop */
		ret = conn_op_reissue(conn_op);
		if (ret < 0) {
			elasto_conn_redirect_close(conn_op->econn);
			conn_op->econn_is_redirect = false;
			conn_op->econn = NULL;
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		return;
	} else if (ret == -ECONNABORTED) {
		dbg(1, "disconnect on send - reconnecting for resend\n");
		conn_op->econn = conn_op->econn_orig;
		ret = elasto_conn_ev_connect(conn_op->econn);
		if (ret < 0) {
			dbg(0, "reconnect failed\n");
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		ret = op_req_retry(conn_op->op);
		if (ret < 0) {
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		/* reissue without exiting the event loop */
		ret = conn_op_reissue(conn_op);
		if (ret < 0) {
			conn_op_flag_error(conn_op, ret);
			goto err_ev_break;
		}
		return;
	} else if (ret < 0) {
		conn_op_flag_error(conn_op, ret);
		goto err_ev_break;
	}

err_ev_break:
	/* mark exchange as complete, allow completion callback to run */
	dbg(2, "completed op 0x%x (%p)\n", conn_op->op->opcode, conn_op->op);
	event_active(&conn_op->ev_xchng, 0, 0);
}

static void
ev_done_cb(struct evhttp_request *ev_req,
	   void *data)
{
	struct conn_op *conn_op = (struct conn_op *)data;
	struct op *op = conn_op->op;
	struct evbuffer *ev_in_buf;
	size_t len;

	/* FIXME ev_req always freed after done callback?? */
	conn_op->ev_http = NULL;

	if (ev_req == NULL) {
		dbg(0, "NULL request on completion, an error occurred!\n");
		/* op error already flagged in error callback */
		assert(op->rsp.is_error);
		goto completion;
	}

	if (op->rsp.write_cbs == 0) {
		/* write callback already sets this, otherwise still needed */
		op->rsp.err_code = evhttp_request_get_response_code(ev_req),
		op->rsp.is_error = op_rsp_is_error(op->opcode,
						   op->rsp.err_code);
	}

	dbg(3, "op 0x%x request done with: %d %s\n", op->opcode, op->rsp.err_code,
	    evhttp_request_get_response_code_line(ev_req));

	ev_in_buf = evhttp_request_get_input_buffer(ev_req);
	if (ev_in_buf == NULL) {
		dbg(0, "NULL input buffer in completion callback\n");
		goto completion;
	}
	len = evbuffer_get_length(ev_in_buf);
	if (len != 0) {
		dbg(0, "unexpected completion input buffer len: %d\n", (int)len);
		goto completion;
	}

completion:
	conn_op_completion(conn_op);
}

static int
elasto_conn_req_type_map(enum op_req_method method,
			 enum evhttp_cmd_type *_ev_req_type)
{
	int i;
	struct {
		enum op_req_method method;
		enum evhttp_cmd_type ev_req_type;
	} mapping[] = {
		{ REQ_METHOD_GET, EVHTTP_REQ_GET },
		{ REQ_METHOD_PUT, EVHTTP_REQ_PUT },
		{ REQ_METHOD_POST, EVHTTP_REQ_POST },
		{ REQ_METHOD_HEAD, EVHTTP_REQ_HEAD },
		{ REQ_METHOD_DELETE, EVHTTP_REQ_DELETE },
	};

	for (i = 0; i < ARRAY_SIZE(mapping); i++) {
		if (mapping[i].method == method) {
			*_ev_req_type = mapping[i].ev_req_type;
			return 0;
		}
	}

	dbg(0, "invalid request method: %d\n", method);
	return -EINVAL;
}

/* a bit ugly, the signature src string is stored in @op for debugging */
static int
elasto_conn_send_prepare(struct conn_op *conn_op,
			 struct evhttp_request **_ev_req,
			 enum evhttp_cmd_type *_ev_req_type,
			 char **_url)
{
	struct elasto_conn *econn = conn_op->econn;
	struct op *op = conn_op->op;
	int ret;
	struct op_hdr *hdr;
	char *url;
	struct evhttp_request *ev_req;
	enum evhttp_cmd_type ev_req_type;
	struct evkeyvalq *ev_out_hdrs;
	uint64_t content_len = 0;
	char *clen_str;

	ret = asprintf(&url, "http%s://%s%s",
		       (econn->insecure_http ? "" : "s"),
		       econn->hostname, op->url_path);
	if (ret < 0) {
		return -ENOMEM;
	}

	dbg(3, "preparing %s request for dispatch to: %s\n",
	    op_method_str(op->method), url);

	ev_req = evhttp_request_new(ev_done_cb, conn_op);
	if (ev_req == NULL) {
		ret = -ENOMEM;
		goto err_url_free;
	}

	evhttp_request_set_header_cb(ev_req, ev_hdr_cb);
	evhttp_request_set_chunked_cb(ev_req, ev_write_cb);
	/* on error, the error cb and then the completion cb will be called */
	evhttp_request_set_error_cb(ev_req, ev_err_cb);

	ret = elasto_conn_req_type_map(op->method, &ev_req_type);
	if (ret < 0) {
		goto err_ev_req_free;
	}

	if ((ev_req_type == EVHTTP_REQ_PUT)
	 || (ev_req_type == EVHTTP_REQ_POST)) {
		ret = elasto_conn_send_prepare_read_data(ev_req, op->req.data,
							 &content_len);
		if (ret < 0) {
			dbg(0, "failed to attach read data\n");
			goto err_ev_req_free;
		}
	}

	/* Content-Length needs to be present during signing */
	ret = asprintf(&clen_str, "%" PRIu64, content_len);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_ev_req_free;
	}
	ret = op_req_hdr_add(op, "Content-Length", clen_str);
	free(clen_str);
	if (ret < 0) {
		goto err_ev_req_free;
	}

	if (op->req_sign != NULL) {
		ret = op->req_sign(econn->sign.account, econn->sign.key,
				   econn->sign.key_len, op);
		if (ret < 0) {
			goto err_ev_req_free;
		}
	}

	ev_out_hdrs = evhttp_request_get_output_headers(ev_req);
	if (ev_out_hdrs == NULL) {
		ret = -ENOENT;
		goto err_ev_req_free;
	}

	ret = evhttp_add_header(ev_out_hdrs, "Host", op->url_host);
	if (ret < 0) {
		ret = -EINVAL;
		goto err_ev_req_free;
	}
	ret = evhttp_add_header(ev_out_hdrs, "Connection", "Keep-Alive");
	if (ret < 0) {
		ret = -EINVAL;
		goto err_ev_req_free;
	}
	list_for_each(&op->req.hdrs, hdr, list) {
		dbg(3, "packing header: %s = %s\n", hdr->key, hdr->val);
		ret = evhttp_add_header(ev_out_hdrs, hdr->key, hdr->val);
		if (ret < 0) {
			ret = -EINVAL;
			goto err_ev_req_free;
		}
	}

	*_ev_req = ev_req;
	*_ev_req_type = ev_req_type;
	*_url = url;

	return 0;

err_ev_req_free:
	evhttp_request_free(ev_req);
err_url_free:
	free(url);
	return ret;
}

/*
 * send http request @op to server connected at @econn.
 * @return: NULL on ENOMEM, or event to track entire req/rsp exchange for op.
 */
struct event *
elasto_conn_op_tx(struct elasto_conn *econn,
		  struct op *op,
		  void (*cb)(evutil_socket_t, short, void *),
		  void *cb_arg)
{
	int ret;
	enum evhttp_cmd_type ev_req_type;
	char *url;
	struct conn_op *conn_op;

	conn_op = malloc(sizeof(*conn_op));
	if (conn_op == NULL) {
		return NULL;
	}
	memset(conn_op, 0, sizeof(*conn_op));
	conn_op->econn_orig = econn;
	conn_op->econn = econn;
	conn_op->op = op;

	dbg(2, "sending op 0x%x (%p) on conn %p\n", op->opcode, op, econn);

	ret = event_assign(&conn_op->ev_xchng, econn->ev_base, -1, 0,
			   cb, cb_arg);
	assert(ret == 0);
	event_add(&conn_op->ev_xchng, NULL);

	if (strcmp(econn->hostname, op->url_host)) {
		dbg(0, "invalid connection for op 0x%x: %s != %s\n",
		    op->opcode, econn->hostname, op->url_host);
		conn_op_flag_error(conn_op, -EINVAL);
		goto err_out;
	}

	if (econn->insecure_http && op->url_https_only) {
		dbg(0, "invalid connection for op 0x%x: connection is HTTP, "
		       "but op requires HTTPS\n", op->opcode);
		conn_op_flag_error(conn_op, -EINVAL);
		goto err_out;
	}

	if (econn->ev_conn == NULL) {
		dbg(1, "disconnected - reconnect for send\n");
		ret = elasto_conn_ev_connect(econn);
		if (ret < 0) {
			dbg(0, "failed to connect on send\n");
			conn_op_flag_error(conn_op, ret);
			goto err_out;
		}
	}

	ret = elasto_conn_send_prepare(conn_op,
				       &conn_op->ev_http,
				       &ev_req_type, &url);
	if (ret < 0) {
		conn_op_flag_error(conn_op, ret);
		goto err_op_unassoc;
	}

	ret = evhttp_make_request(conn_op->econn->ev_conn, conn_op->ev_http,
				  ev_req_type, url);
	free(url);
	if (ret < 0) {
		/* on failure, the request is freed */
		conn_op->ev_http = NULL;
		conn_op_flag_error(conn_op, -ENOMEM);
		goto err_preped_free;
	}

	return &conn_op->ev_xchng;

err_preped_free:
	if (conn_op->ev_http != NULL) {
		evhttp_request_free(conn_op->ev_http);
		conn_op->ev_http = NULL;
	}
err_op_unassoc:
	if (conn_op->econn_is_redirect) {
		elasto_conn_redirect_close(conn_op->econn);
	}
err_out:
	return &conn_op->ev_xchng;
}

void
elasto_conn_op_free(struct event *ev_xmit)
{
	struct conn_op *conn_op;

	if (ev_xmit == NULL) {
		return;
	}

	conn_op = container_of(ev_xmit, struct conn_op, ev_xchng);
	free(conn_op);
}

int
elasto_conn_op_rx(struct event *ev_xmit)
{
	struct conn_op *conn_op;

	if (ev_xmit == NULL) {
		dbg(0, "elasto_conn_op_rx() called with NULL ev!\n");
		return -EINVAL;
	}

	conn_op = container_of(ev_xmit, struct conn_op, ev_xchng);
	return conn_op->error_ret;
}

static void
elasto_conn_op_txrx_cmpl(evutil_socket_t sock,
			 short flags,
			 void *priv)
{
	struct event_base *ev_base = priv;
	int ret;

	/* break the event loop */
	ret = event_base_loopbreak(ev_base);
	if (ret < 0) {
		dbg(0, "failed to break connection loop\n");
	}
}

int
elasto_conn_op_txrx(struct elasto_conn *econn,
		    struct op *op)
{
	struct event *ev_xmit;
	int ret;

	ev_xmit = elasto_conn_op_tx(econn, op, elasto_conn_op_txrx_cmpl,
				    econn->ev_base);
	if (ev_xmit == NULL) {
		return -ENOMEM;
	}

	ret = event_base_dispatch(econn->ev_base);
	if (ret < 0) {
		dbg(0, "event_base_dispatch() failed\n");
		elasto_conn_op_free(ev_xmit);
	}

	ret = elasto_conn_op_rx(ev_xmit);
	elasto_conn_op_free(ev_xmit);

	return ret;
}

static int
elasto_conn_init_common(bool insecure_http,
			const char *host,
			struct elasto_conn **_econn)
{
	int ret;
	struct elasto_conn *econn = malloc(sizeof(*econn));
	if (econn == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(econn, 0, sizeof(*econn));

	econn->ev_base = event_base_new();
	if (econn->ev_base == NULL) {
		ret = -ENOMEM;
		goto err_conn_free;
	}

	econn->insecure_http = insecure_http;
	econn->hostname = strdup(host);
	if (econn->hostname == NULL) {
		ret = -ENOMEM;
		goto err_base_free;
	}

	*_econn = econn;

	return 0;

err_base_free:
	event_base_free(econn->ev_base);
err_conn_free:
	free(econn);
err_out:
	return ret;
}

int
elasto_conn_init_az(const char *pem_file,
		    bool insecure_http,
		    const char *host,
		    struct elasto_conn **econn_out)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_common(insecure_http, host, &econn);
	if (ret < 0) {
		goto err_out;
	}
	econn->type = CONN_TYPE_AZURE;
	if (pem_file != NULL) {
		/* no pem_file with Access Key credentials */
		econn->pem_file = strdup(pem_file);
		if (econn->pem_file == NULL) {
			ret = -ENOMEM;
			goto err_conn_free;
		}
	}

	/* pem_file needs to be set for SSL before connect */
	ret = elasto_conn_ev_connect(econn);
	if (ret < 0) {
		dbg(0, "failed to connect to %s\n", host);
		goto err_conn_free;
	}

	*econn_out = econn;

	return 0;

err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

/* signing keys are set immediately for S3 */
int
elasto_conn_init_s3(const char *id,
		    const char *secret,
		    bool insecure_http,
		    const char *host,
		    struct elasto_conn **econn_out)
{
	struct elasto_conn *econn;
	int ret;

	ret = elasto_conn_init_common(insecure_http, host, &econn);
	if (ret < 0) {
		goto err_out;
	}
	econn->type = CONN_TYPE_S3;
	econn->sign.key = (uint8_t *)strdup(secret);
	if (econn->sign.key == NULL) {
		ret = -ENOMEM;
		goto err_conn_free;
	}
	econn->sign.key_len = strlen(secret);

	econn->sign.account = strdup(id);
	if (econn->sign.account == NULL) {
		ret = -ENOMEM;
		goto err_conn_free;
	}

	ret = elasto_conn_ev_connect(econn);
	if (ret < 0) {
		dbg(0, "failed to connect to %s\n", host);
		goto err_conn_free;
	}

	*econn_out = econn;

	return 0;

err_conn_free:
	elasto_conn_free(econn);
err_out:
	return ret;
}

void
elasto_conn_free(struct elasto_conn *econn)
{
	if (econn == NULL) {
		return;
	}
	elasto_conn_ev_disconnect(econn);
	event_base_free(econn->ev_base);
	if (econn->sign.key_len > 0) {
		free(econn->sign.key);
		free(econn->sign.account);
	}
	free(econn->pem_file);
	free(econn->hostname);
	free(econn);
}

static void
ev_log_cb(int severity, const char *msg)
{
	int mapped_level;

	switch (severity) {
	case EVENT_LOG_DEBUG:
		mapped_level = 5;
		break;
	case EVENT_LOG_MSG:
		mapped_level = 4;
		break;
	case EVENT_LOG_WARN:
		mapped_level = 1;
		break;
	case EVENT_LOG_ERR:
		mapped_level = 0;
		break;
	default:
		mapped_level = 0;
		break;
	}

	dbg(mapped_level, "%s\n", msg);
}

struct event_base *
elasto_conn_ev_base_get(struct elasto_conn *econn)
{
	return econn->ev_base;
}

int
elasto_conn_subsys_init(void)
{
	SSL_library_init();
	ERR_load_crypto_strings();	/* called by SSL_load_error_strings? */
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	sign_init();

	if (dbg_level_get() > 0) {
		event_enable_debug_logging(EVENT_DBG_ALL);
	}
	event_set_log_callback(ev_log_cb);

	return 0;
}

void
elasto_conn_subsys_deinit(void)
{
	sign_deinit();
	EVP_cleanup();
	ERR_free_strings();
}
