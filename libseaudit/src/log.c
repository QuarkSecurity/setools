/**
 *  @file log.c
 *  Implementation for the main libseaudit object, seaudit_log_t.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
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

#include "seaudit_internal.h"

#include <apol/util.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

seaudit_log_t *seaudit_log_create(seaudit_handle_fn_t fn, void *callback_arg)
{
	seaudit_log_t *log = NULL;
	int error;
	if ((log = calloc(1, sizeof(*log))) == NULL) {
		return NULL;
	}
	log->fn = fn;
	log->handle_arg = callback_arg;
	if ((log->messages = apol_vector_create()) == NULL ||
	    (log->malformed_msgs = apol_vector_create()) == NULL ||
	    (log->models = apol_vector_create()) == NULL ||
	    (log->types = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (log->classes = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (log->roles = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (log->users = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (log->perms = apol_bst_create(apol_str_strcmp)) == NULL ||
	    (log->hosts = apol_bst_create(apol_str_strcmp)) == NULL || (log->bools = apol_bst_create(apol_str_strcmp)) == NULL) {
		error = errno;
		seaudit_log_destroy(&log);
		errno = error;
		return NULL;
	}
	return log;
}

void seaudit_log_destroy(seaudit_log_t ** log)
{
	size_t i;
	if (log == NULL || *log == NULL) {
		return;
	}
	for (i = 0; i < apol_vector_get_size((*log)->models); i++) {
		seaudit_model_t *m = apol_vector_get_element((*log)->models, i);
		model_remove_log(m, *log);
	}
	apol_vector_destroy(&(*log)->messages, message_free);
	apol_vector_destroy(&(*log)->malformed_msgs, free);
	apol_vector_destroy(&(*log)->models, NULL);
	apol_bst_destroy(&(*log)->types, free);
	apol_bst_destroy(&(*log)->classes, free);
	apol_bst_destroy(&(*log)->roles, free);
	apol_bst_destroy(&(*log)->users, free);
	apol_bst_destroy(&(*log)->perms, free);
	apol_bst_destroy(&(*log)->hosts, free);
	apol_bst_destroy(&(*log)->bools, free);
	free(*log);
	*log = NULL;
}

/******************** protected functions below ********************/

int log_append_model(seaudit_log_t * log, seaudit_model_t * model)
{
	if (apol_vector_append(log->models, model) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	return 0;
}

void log_remove_model(seaudit_log_t * log, seaudit_model_t * model)
{
	size_t i;
	if (apol_vector_get_index(log->models, model, NULL, NULL, &i) == 0) {
		apol_vector_remove(log->models, i);
	}
}

apol_vector_t *log_get_messages(seaudit_log_t * log)
{
	return log->messages;
}

apol_vector_t *log_get_malformed_messages(seaudit_log_t * log)
{
	return log->malformed_msgs;
}

static void seaudit_handle_default_callback(void *arg __attribute__ ((unused)),
					    seaudit_log_t * log __attribute__ ((unused)),
					    int level, const char *fmt, va_list va_args)
{
	switch (level) {
	case SEAUDIT_MSG_INFO:{
			/* by default do not display these messages */
			return;
		}
	case SEAUDIT_MSG_WARN:{
			fprintf(stderr, "WARNING: ");
			break;
		}
	case SEAUDIT_MSG_ERR:
	default:{
			fprintf(stderr, "ERROR: ");
			break;
		}
	}
	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

void seaudit_handle_msg(seaudit_log_t * log, int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (log == NULL || log->fn == NULL) {
		seaudit_handle_default_callback(NULL, NULL, level, fmt, ap);
	} else {
		log->fn(log->handle_arg, log, level, fmt, ap);
	}
	va_end(ap);
}

#if 0
const char *audit_log_field_strs[] = { "msg_field",
	"exe_field",
	"path_field",
	"dev_field",
	"src_usr_field",
	"src_role_field",
	"src_type_field",
	"tgt_usr_field",
	"tgt_role_field",
	"tgt_type_field",
	"obj_class_field",
	"perm_field",
	"inode_field",
	"ipaddr_field",
	"audit_header_field",
	"pid_field",
	"src_sid_field",
	"tgt_sid_field",
	"comm_field",
	"netif_field",
	"key_field",
	"cap_field",
	"port_field",
	"lport_field",
	"fport_field",
	"dest_field",
	"source_field",
	"laddr_field",
	"faddr_field",
	"daddr_field",
	"saddr_field",
	"src_context",
	"tgt_context",
	"name_field",
	"other_field",
	"policy_usrs_field",
	"policy_roles_field",
	"policy_types_field",
	"policy_classes_field",
	"policy_rules_field",
	"policy_binary_field",
	"boolean_num_field",
	"boolean_bool_field",
	"boolean_value_field",
	"date_field",
	"host_field"
};

#endif
