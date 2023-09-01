/*
 * Modsecurity wrapper for haproxy
 *
 * This file contains the wrapper which sends data in ModSecurity
 * and returns the verdict.
 *
 * Copyright 2016 OZON, Thierry Fournier <thierry.fournier@ozon.io>
 * Copyright 2021 Beekeeper AG, Maximilian Falkenstein <maximilian.falkenstein@beekeeper.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>

#include <haproxy/intops.h>
#include <haproxy/sample-t.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules_set.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "modsec_wrapper.h"
#include "spoa.h"

static ModSecurity *modsec_server = NULL;
static RulesSet *rules = NULL;

int clamp(struct sample *data, int lower, int upper) {
	if (data->data.type != SMP_T_SINT)
		return 0;

	if (data->data.u.sint > upper)
		return upper;

	if (data->data.u.sint < lower)
		return lower;

	return (int)data->data.u.sint;
}

int compare(const char* str, unsigned int len, const char* cmp, unsigned int cmp_len) {
	if (len < cmp_len)
		return -1;
	return strncmp(str, cmp, cmp_len);
}

char* terminated(struct sample *data) {
	if (data->data.type == SMP_T_STR) {
		char *retval = malloc(sizeof(char) * (data->data.u.str.data + 1));
		memcpy(retval, data->data.u.str.area, data->data.u.str.data);
		retval[data->data.u.str.data] = 0;
		return retval;
	} else if (data->data.type == SMP_T_IPV4) {
		char *retval = malloc(INET_ADDRSTRLEN);
		if (!inet_ntop(AF_INET, &data->data.u.ipv4, retval, INET_ADDRSTRLEN)) {
			free (retval);
			return NULL;
		}
		return retval;
	} else if (data->data.type == SMP_T_IPV6) {
		char *retval = malloc(INET6_ADDRSTRLEN);
		if (!inet_ntop(AF_INET6, &data->data.u.ipv6, retval, INET6_ADDRSTRLEN)) {
			free (retval);
			return NULL;
		}
		return retval;
	} else {
		return NULL;
	}
}

/* This function send logs. For now, it do nothing. */
static void modsec_log(void *obj, const void *str)
{
}

/* This function frees all ModSecurity resources. */
void modsecurity_close() {
	if (rules) {
		msc_rules_cleanup(rules);
	}
	if (modsec_server) {
		msc_cleanup(modsec_server);
	}
}

/* This function load the ModSecurity file. It returns -1 if the
 * initialisation fails.
 */
int modsecurity_load(const char *file)
{
	char *msg;
	const char* error_msg;
	size_t msg_len;
	char host_name[60];

	/* Initialises modsecurity. */
	modsec_server = msc_init();
	if (modsec_server == NULL) {
		LOG(&null_worker, "ModSecurity initialisation failed.\n");
		return -1;
	}

	/* Set log callback (to do nothing). */
	msc_set_log_cb(modsec_server, modsec_log);

	/* Set name for our process. */
	gethostname(host_name, 60);
	msg_len = snprintf(NULL, 0, "spoa-modsec-%s", host_name);
	msg = malloc(sizeof(char) * msg_len + 1);
	snprintf(msg, msg_len + 1, "spoa-modsec-%s", host_name);
	msc_set_connector_info(modsec_server, msg);
	free(msg);

	/* Load rules. */
	rules = msc_create_rules_set();
	int rc = msc_rules_add_file(rules, file, &error_msg);
	LOG(&null_worker, "ModSecurity loaded %i rules", rc);
	if (rc < 1) {
		LOG(&null_worker, "ModSecurity load configuration failed: %s\n", error_msg);
		// Internally, error_msg, was strdup'd by ModSec
		free((char*)error_msg);
		return -1;
	}

	return 1;
}

int modsecurity_process(struct worker *worker, struct modsecurity_parameters *params)
{
	Transaction *transaction;
	int fail;
	char *name, *value;
	int ret;
	char *buf, *end;

	const char *path;
	uint64_t path_len;

	const char *qs;
	uint64_t qs_len;

	const char *body;
	uint64_t body_len;
	uint64_t body_exposed_len;

	uint64_t name_len;
	uint64_t value_len;

	char *uri = NULL;
	uint64_t uri_len;

	// Some strings are expected to be null-terminated by ModSec. We mark them here with the _z postfix
	char *meth_z = NULL;
	char *vers_z = NULL;
	char *uniqueid_z = NULL;
	char *src_ip_z = NULL;
	char *dst_ip_z = NULL;
	int src_port;
	int dst_port;

	int return_code = -1;

	const char *hostname = NULL;
	uint64_t hostname_len = 0;
	int hostname_allocated = 0;

	ModSecurityIntervention intervention = {};
	intervention.status = 200;

	/* Decode uniqueid. */
	/* Init processing */
	if (params->uniqueid.data.u.str.data > 0) {
		uniqueid_z = terminated(&params->uniqueid);
		transaction = msc_new_transaction_with_id(modsec_server, rules, uniqueid_z, NULL);
	} else {
		uniqueid_z = NULL;
		transaction = msc_new_transaction(modsec_server, rules, NULL);
	}

	/* Decode path. */
	path = params->path.data.u.str.area;
	path_len = params->path.data.u.str.data;

	/* Decode query string. */
	qs = params->query.data.u.str.area;
	qs_len = params->query.data.u.str.data;

	/* Decode header binary block. */
	buf = params->hdrs_bin.data.u.str.area;
	end = buf + params->hdrs_bin.data.u.str.data;

	src_ip_z = terminated(&params->src_ip);
	dst_ip_z = terminated(&params->dst_ip);
	src_port = clamp(&params->src_port, 1, 65535);
	dst_port = clamp(&params->dst_port, 1, 65535);

	msc_process_connection(transaction, src_ip_z, src_port, dst_ip_z, dst_port);
	fail = 1;

	/* Decode each header. */
	while (1) {
		/* Decode header name. */
		ret = decode_varint(&buf, end, &name_len);
		if (ret == -1)
			return -1;
		name = buf;
		buf += name_len;
		if (buf > end)
			return -1;

		/* Decode header value. */
		ret = decode_varint(&buf, end, &value_len);
		if (ret == -1)
			return -1;
		value = buf;
		buf += value_len;
		if (buf > end)
			return -1;

		/* Detect the end of the headers. */
		if (name_len == 0 && value_len == 0)
			break;

		if (msc_add_n_request_header(transaction, (unsigned char*)name, name_len, (unsigned char*)value, value_len) != 1) {
			errno = EINVAL;
			goto fail;
		}
		if (name_len == 4 && (strncmp(name, "Host", 4) == 0 || strncmp(name, "host", 4) == 0)) {
			hostname = value;
			hostname_len = value_len;
		}
	}

	/* Default hostname if we couldn't find the header */
	if (!hostname) {
		hostname = malloc(sizeof(char) * 8);
		hostname_len = 7;
		strncpy((char*)hostname, "unknown", 8);
		hostname_allocated = 1;
	}

	// XXX: AWSHACK
	// NLBs send an excessive amount of healthchecks that don't even have a host header set correctly, flooding our logs
	// To prevent this, lets skip those requests here
	// Requests have:
	// * /healthz as path
	// * A 10.0.0.0/8 IP as both source and host header
	if (compare(path, path_len, "/healthz", 8) == 0) {
		// Hint: src_ip_z is always IPv6. HAProxy internally converts to IPv6 so that you can use consistent helper
		// functions, but in this case, that means we can just string compare
		if (compare(hostname, hostname_len, "10.", 3) == 0 &&
		    compare(src_ip_z, 10, "::ffff:10.", 10) == 0) {
			fail = 0;
			goto fail;
		}
	}

	if (msc_intervention(transaction, &intervention) > 0) {
		goto intervention;
	}

	/* Decode body length. Note that the following control
	 * is just set for avoifing a gcc warning.
	 */
	body_exposed_len = (uint64_t)params->body_length.data.u.sint;
	if (body_exposed_len < 0)
		return -1;

	/* Decode body. */
	body = params->body.data.u.str.area + params->body.data.u.str.head;
	body_len = params->body.data.u.str.data;

	if (!msc_append_request_body(transaction, (unsigned char*)body, body_len)) {
		errno = EINVAL;
		goto fail;
	}
	if (msc_intervention(transaction, &intervention) > 0) {
		goto intervention;
	}

	/* Generate parsed_uri */
	uri_len = snprintf(NULL, 0, "http://%.*s%.*s?%.*s", (int)hostname_len, hostname, (int)path_len, path, (int)qs_len, qs);
	uri = malloc(sizeof(char) * (uri_len+1));
	snprintf(uri, uri_len+1, "http://%.*s%.*s?%.*s", (int)hostname_len, hostname, (int)path_len, path, (int)qs_len, qs);

	meth_z = terminated(&params->method);
	vers_z = terminated(&params->vers);

	if (!msc_process_uri(transaction, uri, meth_z, vers_z)) {
		errno = EINVAL;
		goto fail;
	}
	if (msc_intervention(transaction, &intervention) > 0) {
		goto intervention;
	}

	/*
	 *
	 * Process analysis.
	 *
	 */

	if (!msc_process_request_headers(transaction)) {
		errno = EINVAL;
		goto fail;
	}
	if (msc_intervention(transaction, &intervention) > 0) {
		goto intervention;
	}

	if (msc_process_request_body(transaction) < 1) {
		errno = EINVAL;
		goto fail;
	}
	if (msc_intervention(transaction, &intervention) > 0) {
		goto intervention;
	}

	/* End processing. */

intervention:
	fail = 0;
	if (intervention.log) {
		free(intervention.log);
	}
	if (intervention.url) {
		free(intervention.url);
	}
	if (intervention.disruptive > 0 || intervention.status != 200) {
		return_code = intervention.status;
	}

	msc_process_logging(transaction);

fail:
	free(uri);
	free(meth_z);
	free(vers_z);
	free(uniqueid_z);
	free(src_ip_z);
	free(dst_ip_z);
	if (hostname_allocated) {
		free((void*)hostname);
	}
	msc_transaction_cleanup(transaction);

	if (fail) {

		/* errno == ERANGE / ENOMEM / EINVAL */
		switch (errno) {
		case ERANGE: LOG(worker, "Invalid range");
		case ENOMEM: LOG(worker, "Out of memory error");
		case EINVAL: LOG(worker, "Invalid value");
		default:     LOG(worker, "Unknown error");
		}
	}

	return return_code;
}
