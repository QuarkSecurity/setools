/**
 *  @file log.h
 *  Public interface for the main libseaudit object, seaudit_log_t.
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

#ifndef SEAUDIT_LOG_H
#define SEAUDIT_LOG_H

#include <stdarg.h>
#include <apol/vector.h>

typedef struct seaudit_log seaudit_log_t;
typedef void (*seaudit_handle_fn_t)(void *arg, seaudit_log_t *log, int level, const char *fmt, va_list va_args);

/**
 * Define the types of logs that this library can parse.
 */
typedef enum seaudit_log_type {
	SEAUDIT_LOG_TYPE_INVALID = 0,
	SEAUDIT_LOG_TYPE_SYSLOG,
	SEAUDIT_LOG_TYPE_AUDITD
} seaudit_log_type_e;

/**
 * Allocate and initialize a new seaudit log structure.  This
 * structure holds log messages from one or more files; call
 * seaudit_log_parse() to actually add messages to this log.
 *
 * @param fn Function to be called by the error handler.  If NULL
 * then write messages to standard error.
 * @param callback_arg Argument for the callback.
 *
 * @return A newly allocated and initialized difference structure or
 * NULL on error; if the call fails, errno will be set.
 * The caller is responsible for calling seaudit_log_destroy() to free
 * memory used by this structure.
 */
extern seaudit_log_t *seaudit_log_create(seaudit_handle_fn_t fn,
					 void *callback_arg);


/**
 * Free all memory used by an seaudit log structure and set it to
 * NULL.
 *
 * @param log Reference pointer to the log structure to destroy.  This
 * pointer will be set to NULL. (If already NULL, function is a
 * no-op.)
 */
extern void seaudit_log_destroy(seaudit_log_t **log);


/**
 * Get a vector of all messages from this seaudit log object.
 *
 * @param log Log object containing messages.
 *
 * @return Vector of seaudit_message_t pointers.  Do not free() or
 * otherwise modify this vector or its contents.
 */
extern apol_vector_t *seaudit_log_get_messages(seaudit_log_t *log);


/**
 * Get a vector of all malformed messages from this seaudit log
 * object.  These are SELinux messages that did not parse cleanly for
 * some reason.  They will be returned in the same order in which they
 * were read from the log file.
 *
 * @param log Log object containing malformed messages.
 *
 * @return Vector of strings.  Do not free() or otherwise modify this
 * vector or its contents.
 */
extern apol_vector_t *seaudit_log_get_malformed_messages(seaudit_log_t *log);

#endif
