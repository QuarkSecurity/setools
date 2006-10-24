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

seaudit_bool_message_t *bool_message_create(void)
{
	return calloc(1, sizeof(seaudit_bool_message_t));
}


static void seaudit_bool_change_free(void *elem)
{
	if (elem != NULL) {
		seaudit_bool_change_t *b = elem;
		free(b);
	}
}

void bool_message_free(seaudit_bool_message_t *msg)
{
	if (msg != NULL) {
		apol_vector_destroy(&msg->changes, seaudit_bool_change_free);
		free(msg);
	}
}
