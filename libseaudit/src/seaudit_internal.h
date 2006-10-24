/**
 *  @file seaudit_internal.h
 *  Protected interface seaudit library.
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

#ifndef SEAUDIT_SEAUDIT_INTERNAL_H
#define SEAUDIT_SEAUDIT_INTERNAL_H

#include <config.h>

#include <seaudit/avc_message.h>
#include <seaudit/bool_message.h>
#include <seaudit/load_message.h>
#include <seaudit/log.h>
#include <seaudit/message.h>

#include <apol/bst.h>
#include <apol/vector.h>

/*************** master seaudit log object (defined in log.c) ***************/

struct seaudit_log {
	apol_vector_t *messages;  /* vector of seaudit_message_t pointers */
	size_t num_allow_messages, num_deny_messages;
	size_t num_bool_messages, num_load_messages;
	apol_bst_t *types, *classes, *roles, *users;
	apol_bst_t *perms, *hosts, *bools;
	seaudit_log_type_e logtype;
	seaudit_handle_fn_t fn;
	void *handle_arg;
        /** non-zero if tzset() has been called */
        int tz_initialized;
        /** non-zero if the parser is in the middle of a line */
        int next_line;
};

/*************** messages (defined in message.c) ***************/

struct seaudit_message {
	/** when this message was generated */
	struct tm *date_stamp;
	/** pointer into log->host for the hostname that generated
	 * this message, or NULL if none found */
	char *host;
	/** type of message this really is */
	seaudit_message_type_e type;
	/** fake polymorphism by having a union of possible subclasses */
	union {
		seaudit_avc_message_t *avc;
		seaudit_bool_message_t *bool;
		seaudit_load_message_t *load;
	} data;
};

/**
 * Allocate a new seaudit message, append the message to the log, and
 * return the message.
 *
 * @param log Log to which append the message.
 * @param type Message type for the newly constructed message.
 *
 * @return A newly allocated message.  The caller must not free the
 * value.
 */
seaudit_message_t *message_create(seaudit_log_t *log, seaudit_message_type_e type);

/**
 * Deallocate all space associated with a message, recursing into the
 * message's data field.
 *
 * @param msg If not NULL, message to free.
 */
void message_free(void *msg);


/*************** avc messages (defined in avc_message.c) ***************/

typedef enum seaudit_avc_message_class {
	SEAUDIT_AVC_DATA_INVALID = 0,
	SEAUDIT_AVC_DATA_MALFORMED,
	SEAUDIT_AVC_DATA_IPC,
	SEAUDIT_AVC_DATA_CAP,  /* capability */
	SEAUDIT_AVC_DATA_FS,
	SEAUDIT_AVC_DATA_NET,
} seaudit_avc_message_class_e;

typedef enum seaudit_avc_message_type {
	SEAUDIT_AVC_UNKNOWN = 0,
	SEAUDIT_AVC_DENIED,
	SEAUDIT_AVC_GRANTED
} seaudit_avc_message_type_e;

/**
 * Definition of an avc message.  Note that unless stated otherwise,
 * character pointers are into the message's log's respective BST.
 */
struct seaudit_avc_message {
	seaudit_avc_message_type_e msg;
	seaudit_avc_message_class_e avc_type;
	/** executable and path - free() this */
	char *exe;
	/** command - free() this */
	char *comm;
	/** path of the OBJECT - free() this */
	char *path;
	/** device for the object - free() this */
	char *dev;
	/** network interface - free() this */
	char *netif;
	/** free() this */
	char *laddr;
	/** free() this */
	char *faddr;
	/** source address - free() this */
	char *saddr;
	/** destination address - free() this */
	char *daddr;
	/** free() this */
	char *name;
	/** free() this */
	char *ipaddr;
	/** source context's user */
	char *suser;
	/** source context's role */
	char *srole;
	/** source context's type */
	char *stype;
	/** target context's user */
	char *tuser;
	/** target context's role */
	char *trole;
	/** target context's type */
	char *ttype;
	/** target class */
	char *tclass;
	/** audit header timestamp (seconds) */
	time_t tm_stmp_sec;
	/** audit header timestamp (nanoseconds) */
	long tm_stmp_nano;
	/** audit header serial number */
	unsigned int serial;
	/** pointers into log->perms BST (hence char *) */
	apol_vector_t *perms;
	/** key for an IPC call */
	int key;
	int is_key;
	/** process capability (corresponds with class 'capability') */
	int capability;
	int is_capability;
	/** inode of the object */
	unsigned long inode;
	int is_inode;
	/** source port */
	int source;
	/** destination port */
	int dest;
	int lport;
	int fport;
	int port;
	/** source sid */
	unsigned int src_sid;
	int is_src_sid;
	/** target sid */
	unsigned int tgt_sid;
	int is_tgt_sid;
	/** process ID of the subject */
	unsigned int pid;
	int is_pid;
};

/**
 * Allocate and return a new seaudit AVC message.
 *
 * @return A newly allocated AVC message.  The caller must not call
 * avc_message_free() upon the returned value afterwards.
 */
seaudit_avc_message_t *avc_message_create(void);

/**
 * Deallocate all space associated with an AVC message.
 *
 * @param msg If not NULL, message to free.
 */
void avc_message_free(seaudit_avc_message_t *msg);


/*************** bool messages (defined in bool_message.c) ***************/

typedef struct seaudit_bool_change {
	/** pointer into log's bools BST */
	char *bool;
	/** new value for the boolean */
	int value;
} seaudit_bool_change_t;

struct seaudit_bool_message {
	/** vector of seaudit_bool_change_t pointers; vector owns objects. */
	apol_vector_t *changes;
};

/**
 * Allocate and return a new seaudit boolean change message.
 *
 * @return A newly allocated boolean change message.  The caller must
 * not call bool_message_free() upon the returned value afterwards.
 */
seaudit_bool_message_t *bool_message_create(void);

/**
 * Deallocate all space associated with a boolean change message.
 *
 * @param msg If not NULL, message to free.
 */
void bool_message_free(seaudit_bool_message_t *msg);


/*************** load messages (defined in load_message.c) ***************/

struct seaudit_load_message {
	unsigned int users;   /* number of users */
	unsigned int roles;   /* number of roles */
	unsigned int types;   /* number of types */
	unsigned int classes; /* number of classes */
	unsigned int rules;   /* number of rules */
	unsigned int bools;   /* number of bools */
	char *binary;         /* path for binary that was loaded */
};

/**
 * Allocate and return a new seaudit policy load message.
 *
 * @return A newly allocated policy load message.  The caller must
 * not call load_message_free() upon the returned value afterwards.
 */
seaudit_load_message_t *load_message_create(void);

/**
 * Deallocate all space associated with a policy load message.
 *
 * @param msg If not NULL, message to free.
 */
void load_message_free(seaudit_load_message_t *msg);


/*************** error handling code (defined in log.c) ***************/

#define SEAUDIT_MSG_ERR  1
#define SEAUDIT_MSG_WARN 2
#define SEAUDIT_MSG_INFO 3

/**
 * Write a message to the callback stored within a seaudit_log_t
 * handler.  If the msg_callback field is empty then suppress the
 * message.
 *
 * @param log Error reporting handler.  If NULL then write message to
 * stderr.
 * @param level Severity of message, one of SEAUDIT_MSG_ERR,
 * SEAUDIT_MSG_WARN, or SEAUDIT_MSG_INFO.
 * @param fmt Format string to print, using syntax of printf(3).
 */
__attribute__ ((format(printf, 3, 4)))
extern void seaudit_handle_msg(seaudit_log_t *log, int level, const char *fmt, ...);

#undef ERR
#undef WARN
#undef INFO

#define ERR(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_ERR, format, __VA_ARGS__)
#define WARN(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_WARN, format, __VA_ARGS__)
#define INFO(handle, format, ...) seaudit_handle_msg(handle, SEAUDIT_MSG_INFO, format, __VA_ARGS__)

#endif
