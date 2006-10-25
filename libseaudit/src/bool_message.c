/**
 *  @file bool_message.c
 *  Implementation of a single boolean change log message.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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
#include <stdlib.h>
#include <string.h>

seaudit_bool_message_t *bool_message_create(void)
{
	seaudit_bool_message_t *bool = calloc(1, sizeof(seaudit_bool_message_t));
	if (bool == NULL) {
		return NULL;
	}
	if ((bool->changes = apol_vector_create()) == NULL) {
		bool_message_free(bool);
		return NULL;
	}
	return bool;
}

int bool_change_append(seaudit_log_t *log, seaudit_bool_message_t *bool,
		       char *name, int value)
{
	char *s = strdup(name);
	seaudit_bool_change_t *bc = NULL;
	int error;
	if (s == NULL ||
	    apol_bst_insert_and_get(log->bools, (void **) &s, NULL, free) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	if ((bc = calloc(1, sizeof(*bc))) == NULL ||
	    apol_vector_append(bool->changes, bc) < 0) {
		error = errno;
		free(s);
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	bc->bool = s;
	bc->value = value;
	return 0;
}

static void seaudit_bool_change_free(void *elem)
{
	if (elem != NULL) {
		seaudit_bool_change_t *b = elem;
		free(b);
	}
}

void bool_message_free(seaudit_bool_message_t *bool)
{
	if (bool != NULL) {
		apol_vector_destroy(&bool->changes, seaudit_bool_change_free);
		free(bool);
	}
}
