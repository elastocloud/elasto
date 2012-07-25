#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <assert.h>
#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "azure_ssl.h"

int
azure_ssl_xml_slurp(const uint8_t *buf,
		    uint64_t buf_len,
		    xmlDoc **xp_doc,
		    xmlXPathContext **xp_ctx)
{
	int ret;
	xmlDoc *xdoc;
	xmlXPathContext *xpath_ctx;
	char *ns;

	xdoc = xmlParseMemory(buf, buf_len);
	if (xdoc == NULL) {
		printf("unable to parse in-memory XML\n");
		ret = -EINVAL;
		goto err_out;
	}

	/* Create xpath evaluation context */
	xpath_ctx = xmlXPathNewContext(xdoc);
	if (xpath_ctx == NULL) {
		printf("unable to create XPath context\n");
		ret = -ENOMEM;
		goto err_free_doc;
	}

	if (xmlXPathRegisterNs(xpath_ctx, "def",
			"http://schemas.microsoft.com/windowsazure") != 0) {
		printf("Unable to register NS: def\n");
		ret = -EINVAL;
		goto err_free_xpctx;
	}
	if (xmlXPathRegisterNs(xpath_ctx, "i",
			"http://www.w3.org/2001/XMLSchema-instance") != 0) {
		printf("Unable to register NS: i\n");
		ret = -EINVAL;
		goto err_free_xpctx;
	}

	*xp_doc = xdoc;
	*xp_ctx = xpath_ctx;

	return 0;

err_free_xpctx:
	xmlXPathFreeContext(xpath_ctx);
err_free_doc:
	xmlFreeDoc(xdoc);
err_out:
	return ret;
}

int
azure_ssl_xml_get_path(xmlXPathContext *xp_ctx,
		       const char *xp_expr,
		       xmlChar **content)
{
	int ret;
	xmlXPathObject *xp_obj;
	xmlChar *ctnt;

	/* Evaluate xpath expression */
	xp_obj = xmlXPathEval(xp_expr, xp_ctx);
	if (xp_obj == NULL) {
		printf("Unable to evaluate xpath expression \"%s\"\n",
		       xp_expr);
		return -ENOENT;
	}

	if (xp_obj->nodesetval == NULL) {
		printf("null nodesetval\n");
		ret = -ENOENT;
		goto err_xp_obj;
	}
	if (xp_obj->nodesetval->nodeNr == 0) {
		printf("empty nodesetval\n");
		ret = -ENOENT;
		goto err_xp_obj;
	}

	ctnt = xmlNodeGetContent(xp_obj->nodesetval->nodeTab[0]);
	if (ctnt == NULL) {
		ret = -ENOMEM;
		goto err_xp_obj;
	}

	*content = ctnt;
	ret = 0;
err_xp_obj:
	xmlXPathFreeObject(xp_obj);
	return ret;
}

CURL *
azure_ssl_curl_init(const char *pem_file, const char *pem_pw)
{
	CURL *curl;
	struct curl_slist *chunk = NULL;

	curl = curl_easy_init();
	if (curl == NULL) {
		return NULL;
	}

	chunk = curl_slist_append(chunk, "x-ms-version: 2012-03-01");
	if (chunk == NULL) {
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLCERT, pem_file);
	curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLKEY, pem_file);
	if (pem_pw) {
		curl_easy_setopt(curl, CURLOPT_KEYPASSWD, pem_pw);
	}
	/* XXX chunk cannot be freed yet */

	return curl;
}

size_t
curl_write_cb(char *ptr,
	      size_t size,
	      size_t nmemb,
	      void *userdata)
{
	struct azure_req *req = (struct azure_req *)userdata;
	uint64_t num_bytes = (size * nmemb);

	if (req->iov.off + num_bytes > req->iov.buf_len) {
		printf("fatal: curl_write_cb buffer exceeded, "
		       "len %u off %u io_sz %u\n",
		       req->iov.buf_len, req->iov.off, num_bytes);
		return -1;
	}

	memcpy((void *)(req->iov.buf + req->iov.off), ptr, num_bytes);
	req->iov.off += num_bytes;
	return num_bytes;
}

int
azure_ssl_curl_req_setup(CURL *curl, struct azure_req *req)
{
	req->curl = curl;

	/* XXX we need to clear preset opts when reusing */
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
	curl_easy_setopt(curl, CURLOPT_URL, req->url);
	if (req->method == REQ_METHOD_GET) {
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	}

	return 0;	/* FIXME detect curl_easy_setopt errors */
}

char *
azure_ssl_mgmt_url_list_sas(const char *sub_id)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices",
		       sub_id);
	if (ret < 0)
		return NULL;
	return url;
}

char *
azure_ssl_mgmt_url_get_sa_props(const char *sub_id, const char *service_name)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s",
		       sub_id, service_name);
	if (ret < 0)
		return NULL;
	return url;
}

void
azure_ssl_mgmt_get_sa_keys_free(struct azure_mgmt_get_sa_keys *get_sa_keys)
{
	free(get_sa_keys->in.sub_id);
	free(get_sa_keys->in.service_name);
	xmlFree(get_sa_keys->out.primary);
	xmlFree(get_sa_keys->out.secondary);
}

int
azure_ssl_mgmt_get_sa_keys_req(const char *sub_id, const char *service_name,
			       struct azure_req *req)
{
	int ret;
	struct azure_mgmt_get_sa_keys *get_sa_keys;

	/* TODO input validation */

	req->op = AOP_MGMT_GET_SA_KEYS;
	get_sa_keys = &req->mgmt_get_sa_keys;

	/* we may not need to keep these, as they're only used in the URL */
	get_sa_keys->in.sub_id = strdup(sub_id);
	if (get_sa_keys->in.sub_id == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}
	get_sa_keys->in.service_name = strdup(service_name);
	if (get_sa_keys->in.service_name == NULL) {
		ret = -ENOMEM;
		goto err_free_sub;
	}
	req->method = REQ_METHOD_GET;
	ret = asprintf(&req->url, "https://management.core.windows.net/"
		       "%s/services/storageservices/%s/keys",
		       sub_id, service_name);
	if (ret < 0) {
		ret = -ENOMEM;
		goto err_free_svc;
	}

	/* allocate response buffer, TODO determine appropriate size */
	req->iov.buf_len = (1024 * 1024);
	req->iov.buf = malloc(req->iov.buf_len);
	if (req->iov.buf == NULL) {
		ret = -ENOMEM;
		goto err_free_url;
	}

	return 0;
err_free_url:
	free(req->url);
err_free_svc:
	free(get_sa_keys->in.service_name);
err_free_sub:
	free(get_sa_keys->in.sub_id);
err_out:
	return ret;

}

int
azure_ssl_mgmt_get_sa_keys_rsp(struct azure_req *req)
{
	int ret;
	struct azure_mgmt_get_sa_keys *get_sa_keys;
	xmlDoc *xp_doc;
	xmlXPathContext *xp_ctx;

	/* parse response */
	ret = azure_ssl_xml_slurp(req->iov.buf, req->iov.off, &xp_doc, &xp_ctx);
	if (ret < 0) {
		return ret;
	}

	assert(req->op == AOP_MGMT_GET_SA_KEYS);
	get_sa_keys = &req->mgmt_get_sa_keys;

	ret = azure_ssl_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Primary",
		&get_sa_keys->out.primary);
	if (ret = 0) {
		xmlXPathFreeContext(xp_ctx);
		xmlFreeDoc(xp_doc);
		return ret;
	}
	ret = azure_ssl_xml_get_path(xp_ctx,
		"//def:StorageService/def:StorageServiceKeys/def:Secondary",
		&get_sa_keys->out.secondary);

	xmlXPathFreeContext(xp_ctx);
	xmlFreeDoc(xp_doc);

	return ret;
}

char *
azure_ssl_mgmt_url_check_sa_availability(const char *sub_id, const char *service_name)
{
	char *url;
	int ret;
	ret = asprintf(&url, "https://management.core.windows.net/"
		       "%s/services/storageservices/operations/isavailable/%s",
		       sub_id, service_name);
	if (ret < 0)
		return NULL;
	return url;
}

/* does not free curl, allowing for reuse */
void
azure_ssl_req_free(struct azure_req *req)
{
	free(req->iov.buf);
	free(req->signature);
	free(req->url);
	switch (req->op) {
	case AOP_MGMT_GET_SA_KEYS:
		azure_ssl_mgmt_get_sa_keys_free(&req->mgmt_get_sa_keys);
	};
}

int main(void)
{
	CURLcode res;
	struct azure_req req;
	const char *pem_file = "privateKey.pem";
	const char *pem_pword = "disso";
	const char *subscriber_id = "9baf7f32-66ae-42ca-9ad7-220050765863";
	CURL *curl;
	int ret;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	xmlInitParser();

	memset(&req, 0, sizeof(req));

	curl = azure_ssl_curl_init(pem_file, pem_pword);
	if (curl == NULL) {
		ret = -EINVAL;
		goto err_global_clean;
	}

	ret = azure_ssl_mgmt_get_sa_keys_req(subscriber_id, "ddiss", &req);
	if (ret < 0) {
		goto err_easy_clean;
	}

	ret = azure_ssl_curl_req_setup(curl, &req);
	if (ret < 0) {
		goto err_req_free;
	}

	/* dispatch */
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		printf("curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		ret = -EBADF;
		goto err_req_free;
	}

	ret = azure_ssl_mgmt_get_sa_keys_rsp(&req);
	if (ret < 0) {
		goto err_req_free;
	}

	printf("primary key: %s\n"
	       "secondary key: %s\n",
	       req.mgmt_get_sa_keys.out.primary,
	       req.mgmt_get_sa_keys.out.secondary);

	ret = 0;
err_req_free:
	azure_ssl_req_free(&req);
err_easy_clean:
	curl_easy_cleanup(curl);
err_global_clean:
	xmlCleanupParser();
	curl_global_cleanup();

	return ret;
}
