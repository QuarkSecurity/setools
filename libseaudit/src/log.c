/**
 *  @file
 *  Implementation for the main libseaudit object, seaudit_log_t.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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
	if ((log->messages = apol_vector_create(message_free)) == NULL ||
	    (log->malformed_msgs = apol_vector_create(free)) == NULL ||
		(log->groups = apol_vector_create(log_group_free)) == NULL || 
	    (log->models = apol_vector_create(NULL)) == NULL ||
	    (log->types = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->classes = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->roles = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->users = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->perms = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->hosts = apol_bst_create(apol_str_strcmp, free)) == NULL
	    || (log->bools = apol_bst_create(apol_str_strcmp, free)) == NULL
	    || (log->managers = apol_bst_create(apol_str_strcmp, free)) == NULL) {
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
	apol_vector_destroy(&(*log)->groups);
	apol_vector_destroy(&(*log)->messages);
	apol_vector_destroy(&(*log)->malformed_msgs);
	apol_vector_destroy(&(*log)->models);
	apol_bst_destroy(&(*log)->types);
	apol_bst_destroy(&(*log)->classes);
	apol_bst_destroy(&(*log)->roles);
	apol_bst_destroy(&(*log)->users);
	apol_bst_destroy(&(*log)->perms);
	apol_bst_destroy(&(*log)->hosts);
	apol_bst_destroy(&(*log)->bools);
	apol_bst_destroy(&(*log)->managers);
	free(*log);
	*log = NULL;
}

void seaudit_log_clear(seaudit_log_t * log)
{
	if (log == NULL) {
		errno = EINVAL;
		return;
	}
	apol_vector_destroy(&log->groups);
	apol_vector_destroy(&log->messages);
	apol_vector_destroy(&log->malformed_msgs);
	apol_bst_destroy(&log->types);
	apol_bst_destroy(&log->classes);
	apol_bst_destroy(&log->roles);
	apol_bst_destroy(&log->users);
	apol_bst_destroy(&log->perms);
	apol_bst_destroy(&log->hosts);
	apol_bst_destroy(&log->bools);
	apol_bst_destroy(&log->managers);
	if ((log->messages = apol_vector_create(message_free)) == NULL ||
	    (log->malformed_msgs = apol_vector_create(free)) == NULL ||
		(log->groups = apol_vector_create(log_group_free)) == NULL ||
	    (log->types = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->classes = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->roles = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->users = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->perms = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (log->hosts = apol_bst_create(apol_str_strcmp, free)) == NULL
	    || (log->bools = apol_bst_create(apol_str_strcmp, free)) == NULL
	    || (log->managers = apol_bst_create(apol_str_strcmp, free)) == NULL) {
		/* hopefully will never get here... */
		return;
	}
	for (size_t i = 0; i < apol_vector_get_size(log->models); i++) {
		seaudit_model_t *m = apol_vector_get_element(log->models, i);
		model_notify_log_changed(m, log);
	}
}

apol_vector_t *seaudit_log_get_users(const seaudit_log_t * log)
{
	if (log == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return apol_bst_get_vector(log->users, 0);
}

apol_vector_t *seaudit_log_get_roles(const seaudit_log_t * log)
{
	if (log == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return apol_bst_get_vector(log->roles, 0);
}

apol_vector_t *seaudit_log_get_types(const seaudit_log_t * log)
{
	if (log == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return apol_bst_get_vector(log->types, 0);
}

apol_vector_t *seaudit_log_get_classes(const seaudit_log_t * log)
{
	if (log == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return apol_bst_get_vector(log->classes, 0);
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

int log_group_message(seaudit_log_t * log, seaudit_message_t * msg)
{
	size_t i, num_groups;
	unsigned int msg_serial;
	apol_vector_t * msg_group;

	if (msg->group) {
		// this message has already been added to a group
		return 0;	
	}

	if (message_get_serial(msg, &msg_serial) != 0) {
		return -1;
	}

	msg_group = NULL;
	num_groups = apol_vector_get_size(log->groups);
		
	// search through the group vector in reverse. 	if the group already exists, 
	// it's likely that we recently added it and it will be at the end of the vector
	for (i = num_groups - 1; i != (size_t)-1; i--)
	{
		unsigned int first_serial;
		apol_vector_t * group = apol_vector_get_element(log->groups, i);
		if (apol_vector_get_size(group) <= 0) {
			continue;
		}
		seaudit_message_t * first_msg = apol_vector_get_element(group, 0);

		if (message_get_serial(first_msg, &first_serial) != 0) {
			return -1;
		}
			
		if (msg_serial == first_serial) {
			msg_group = group;
			break;
		}
	}

	if (!msg_group)
	{
		// didn't find an existing group, create a new one
		msg_group = apol_vector_create(NULL);
		apol_vector_append(log->groups, msg_group);
	}
	
	msg->group = msg_group;
	apol_vector_append(msg_group, msg);

	return 0;
}

void log_group_free(void *g)
{
	size_t i, num_messages;

	if (g == NULL)
		return;

	apol_vector_t *group = (apol_vector_t *)g;
	
	num_messages = apol_vector_get_size(group);
	for (i = 0; i < num_messages; i++) {
		seaudit_message_t * msg = apol_vector_get_element(group, i);
		msg->group = NULL;
	}
	apol_vector_destroy(&group);
}

const apol_vector_t *log_get_messages(const seaudit_log_t * log)
{
	return log->messages;
}

const apol_vector_t *log_get_malformed_messages(const seaudit_log_t * log)
{
	return log->malformed_msgs;
}

static void seaudit_handle_default_callback(void *arg __attribute__ ((unused)),
					    const seaudit_log_t * log __attribute__ ((unused)),
					    int level, const char *fmt, va_list va_args)
{
	switch (level) {
	case SEAUDIT_MSG_INFO:
	{
		/* by default do not display these messages */
		return;
	}
	case SEAUDIT_MSG_WARN:
	{
		fprintf(stderr, "WARNING: ");
		break;
	}
	case SEAUDIT_MSG_ERR:
	default:
	{
		fprintf(stderr, "ERROR: ");
		break;
	}
	}
	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

void seaudit_handle_msg(const seaudit_log_t * log, int level, const char *fmt, ...)
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
