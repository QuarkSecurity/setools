/**
 *  @file model.h
 *  Public interface to a seaudit_model_t.  This represents a subset
 *  of log messages from one or more seaudit_log_t, where the subset
 *  is defined by a finite set of seaudit_filters and sorted by some
 *  criterion.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2006 Tresys Technology, LLC
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

#ifndef SEAUDIT_MODEL_H
#define SEAUDIT_MODEL_H

#include "log.h"
#include "message.h"

typedef struct seaudit_model seaudit_model_t;

/**
 * Create a seaudit_model based upon the messages from some particular
 * seaudit_log.  The model will be initialized with all of the
 * messages from that log.
 *
 * @param log Log to model.
 *
 * @return An initialized model, or NULL upon error.  The caller must
 * call seaudit_model_destroy() afterwards.
 */
extern seaudit_model_t *seaudit_model_create(seaudit_log_t *log);

/**
 * Destroy the referenced seadit_model_t object.
 *
 * @param model Model to destroy.  The pointer will be set to NULL
 * afterwards.  (If pointer is already NULL then do nothing.)
 */
extern void seaudit_model_destroy(seaudit_model_t **model);

/**
 * Return a sorted list of messages associated with this model.  This
 * will cause the model to recalculate, as necessary, all messages
 * according to its filters and then sort them.
 *
 * @param log Log to which report error messages.
 * @param model Model containing messages.
 *
 * @return Vector of seaudit_message_t, pre-filtered and pre-sorted,
 * or NULL upon error.
 */
extern apol_vector_t *seaudit_model_get_messages(seaudit_log_t *log, seaudit_model_t *model);

/**
 * Return a sorted list of malformed messages associated with this
 * model.  This is the union of all malformed messages from the
 * model's logs.
 *
 * @param log Log to which report error messages.
 * @param model Model containing malformed messages.
 *
 * @return Vector of strings, or NULL upon error.  Treat the contents
 * of the vector as const char *.
 */
extern apol_vector_t *seaudit_model_get_malformed_messages(seaudit_log_t *log, seaudit_model_t *model);

#if 0
#include "multifilter.h"
#include "sort.h"

typedef struct filter_info {
	int orig_indx;
	bool_t filtered;
} filter_info_t;

typedef struct audit_log_view {
	audit_log_t *my_log; /* reference to the log */
	int *fltr_msgs;      /* filtered and sorted messages */
	int num_fltr_msgs;   /* num of filtered and sorted messages */
	int fltr_msgs_sz;    /* size of filtered messages array */
	struct sort_action_node *sort_actions;     /* sort functions */
	struct sort_action_node *last_sort_action;
	seaudit_multifilter_t *multifilter;
} audit_log_view_t;

#endif

#endif
