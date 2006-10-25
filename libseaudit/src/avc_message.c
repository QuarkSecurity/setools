/**
 *  @file avc_message.c
 *  Implementation of a single avc log message.
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

#include <errno.h>
#include <stdlib.h>

seaudit_avc_message_t *avc_message_create(void)
{
	seaudit_avc_message_t *avc = calloc(1, sizeof(seaudit_avc_message_t));
	if (avc == NULL) {
		return NULL;
	}
	if ((avc->perms = apol_vector_create_with_capacity(1)) == NULL) {
		int error = errno;
		avc_message_free(avc);
		errno = error;
		return NULL;
	}
	return avc;
}

void avc_message_free(seaudit_avc_message_t *avc)
{
	if (avc != NULL) {
		free(avc->exe);
		free(avc->comm);
		free(avc->path);
		free(avc->dev);
		free(avc->netif);
		free(avc->laddr);
		free(avc->faddr);
		free(avc->saddr);
		free(avc->daddr);
		free(avc->name);
		free(avc->ipaddr);
		apol_vector_destroy(&avc->perms, NULL);
		free(avc);
	}
}
