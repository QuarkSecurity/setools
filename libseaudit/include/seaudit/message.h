/**
 *  @file message.h
 *  Public interface for a single seaudit log message.  Note that this
 *  is an abstract class.
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

#ifndef SEAUDIT_MESSAGE_H
#define SEAUDIT_MESSAGE_H

typedef struct seaudit_message seaudit_message_t;

typedef enum seaudit_message_type {
	SEAUDIT_MESSAGE_TYPE_INVALID = 0,
	SEAUDIT_MESSAGE_TYPE_AVC,
	SEAUDIT_MESSAGE_TYPE_BOOL,
	SEAUDIT_MESSAGE_TYPE_LOAD
} seaudit_message_type_e;

/**
 * Get a pointer to a message's specific data.  This returns a void
 * pointer; the caller must cast it to one of seaudit_avc_message_t,
 * seaudit_bool_message_t, or seaudit_load_message_t.  Use the
 * returned value from the second parameter to determine which type
 * this message really is.
 *
 * @param msg Message from which to get data.
 * @param type Reference to the message specific type.
 *
 * @return Pointer to message's specific type, or NULL upon error.
 */
extern void *seaudit_message_get_data(seaudit_message_t *msg, seaudit_message_type_e *type);

#endif
