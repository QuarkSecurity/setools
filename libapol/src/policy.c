/**
 * @file
 *
 * Public interface for SELinux policies.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "policy-query-internal.h"

#include <apol/perm-map.h>
#include <apol/domain-trans-analysis.h>

#include <qpol/policy_extend.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void apol_handle_default_callback(void *varg __attribute__ ((unused)), apol_policy_t * p
					 __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	switch (level) {
	case APOL_MSG_INFO:
		{
			/* by default do not display these messages */
			return;
		}
	case APOL_MSG_WARN:
		{
			fprintf(stderr, "WARNING: ");
			break;
		}
	case APOL_MSG_ERR:
	default:
		{
			fprintf(stderr, "ERROR: ");
			break;
		}
	}
	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

static void qpol_handle_route_to_callback(void *varg, qpol_policy_t * policy, int level, const char *fmt, va_list ap)
{
	apol_policy_t *p = (apol_policy_t *) varg;
	if (p == NULL) {
		apol_handle_default_callback(NULL, NULL, level, fmt, ap);
	} else if (p->msg_callback != NULL) {
		p->msg_callback(p->msg_callback_arg, p, level, fmt, ap);
	}
}

apol_policy_t *apol_policy_create_from_policy_path(const apol_policy_path_t * path, const int options,
						   apol_callback_fn_t msg_callback, void *varg)
{
	apol_policy_t *policy;
	const char *primary_path;
	int policy_type;
	if (!path) {
		errno = EINVAL;
		return NULL;
	}

	if (!(policy = calloc(1, sizeof(apol_policy_t)))) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return NULL;	       /* errno set by calloc */
	}
	if (msg_callback != NULL) {
		policy->msg_callback = msg_callback;
	} else {
		policy->msg_callback = apol_handle_default_callback;
	}
	policy->msg_callback_arg = varg;
	primary_path = apol_policy_path_get_primary(path);
	if (options & APOL_POLICY_OPTION_NO_RULES) {
		policy_type = qpol_policy_open_from_file_no_rules(primary_path, &policy->p, qpol_handle_route_to_callback, policy);
	} else {
		policy_type = qpol_policy_open_from_file(primary_path, &policy->p, qpol_handle_route_to_callback, policy);
	}
	if (policy_type < 0) {
		ERR(policy, "Unable to open policy at %s.", primary_path);
		apol_policy_destroy(&policy);
		return NULL;	       /* qpol sets errno */
	}
	policy->policy_type = policy_type;

	if (apol_policy_path_get_type(path) == APOL_POLICY_PATH_TYPE_MODULAR) {
		if (!qpol_policy_has_capability(policy->p, QPOL_CAP_MODULES)) {
			ERR(policy, "%s is not a base policy.", primary_path);
			apol_policy_destroy(&policy);
			return NULL;
		}
		const apol_vector_t *modules = apol_policy_path_get_modules(path);
		size_t i;
		for (i = 0; i < apol_vector_get_size(modules); i++) {
			const char *module_path = apol_vector_get_element(modules, i);
			qpol_module_t *mod = NULL;
			if (qpol_module_create_from_file(module_path, &mod)) {
				ERR(policy, "Error loading module %s.", module_path);
				apol_policy_destroy(&policy);
				return NULL;
			}
			if (qpol_policy_append_module(policy->p, mod)) {
				apol_policy_destroy(&policy);
				qpol_module_destroy(&mod);
				return NULL;
			}
		}
		if (qpol_policy_rebuild(policy->p)) {
			apol_policy_destroy(&policy);
			return NULL;
		}
	}
	return policy;
}

int apol_policy_open(const char *path, apol_policy_t ** policy, apol_callback_fn_t msg_callback, void *varg)
{
	apol_policy_path_t *policy_path;
	if (!path || !policy) {
		errno = EINVAL;
		return -1;
	}
	*policy = NULL;
	if ((policy_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, path, NULL)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	*policy = apol_policy_create_from_policy_path(policy_path, 0, msg_callback, varg);
	apol_policy_path_destroy(&policy_path);
	if (*policy == NULL) {
		return -1;
	}
	return 0;
}

int apol_policy_open_no_rules(const char *path, apol_policy_t ** policy, apol_callback_fn_t msg_callback, void *varg)
{
	apol_policy_path_t *policy_path;
	if (!path || !policy) {
		errno = EINVAL;
		return -1;
	}
	*policy = NULL;
	if ((policy_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, path, NULL)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	*policy = apol_policy_create_from_policy_path(policy_path, APOL_POLICY_OPTION_NO_RULES, msg_callback, varg);
	apol_policy_path_destroy(&policy_path);
	if (*policy == NULL) {
		return -1;
	}
	return 0;
}

void apol_policy_destroy(apol_policy_t ** policy)
{
	if (policy != NULL && *policy != NULL) {
		qpol_policy_destroy(&((*policy)->p));
		permmap_destroy(&(*policy)->pmap);
		apol_domain_trans_table_destroy(&(*policy)->domain_trans_table);
		free(*policy);
		*policy = NULL;
	}
}

int apol_policy_get_policy_type(apol_policy_t * policy)
{
	if (policy == NULL) {
		errno = EINVAL;
		return -1;
	}
	return policy->policy_type;
}

qpol_policy_t *apol_policy_get_qpol(apol_policy_t * policy)
{
	if (policy == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return policy->p;
}

int apol_policy_is_mls(apol_policy_t * p)
{
	if (p == NULL) {
		return -1;
	}
	return qpol_policy_is_mls_enabled(p->p);
}

int apol_policy_is_binary(apol_policy_t * p)
{
	return (p->policy_type == QPOL_POLICY_KERNEL_BINARY);
}

int apol_policy_is_modular(apol_policy_t * p)
{
	return (p->policy_type == QPOL_POLICY_MODULE_BINARY);
}

int apol_policy_is_source(apol_policy_t * p)
{
	return (p->policy_type == QPOL_POLICY_KERNEL_SOURCE);
}

char *apol_policy_get_version_type_mls_str(apol_policy_t * p)
{
	unsigned int version;
	char *policy_type, *mls, buf[64];
	if (qpol_policy_get_policy_version(p->p, &version) < 0) {
		return NULL;
	}
	switch (p->policy_type) {
	case QPOL_POLICY_KERNEL_SOURCE:
		policy_type = "source";
		break;
	case QPOL_POLICY_KERNEL_BINARY:
		policy_type = "binary";
		break;
	case QPOL_POLICY_MODULE_BINARY:
		policy_type = "modular";
		break;
	default:
		policy_type = "unknown";
		break;
	}
	if (qpol_policy_is_mls_enabled(p->p)) {
		mls = "mls";
	} else {
		mls = "non-mls";
	}
	if (snprintf(buf, sizeof(buf), "v.%u (%s, %s)", version, policy_type, mls) == -1) {
		return NULL;
	}
	return strdup(buf);
}

void apol_handle_msg(apol_policy_t * p, int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (p == NULL) {
		apol_handle_default_callback(NULL, NULL, level, fmt, ap);
	} else if (p->msg_callback != NULL) {
		p->msg_callback(p->msg_callback_arg, p, level, fmt, ap);
	}
	va_end(ap);
}
