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

#include "filter.h"
#include "log.h"
#include "message.h"
#include "sort.h"

#include <stdlib.h>

typedef struct seaudit_model seaudit_model_t;

/**
 * Create a seaudit_model based upon the messages from some particular
 * seaudit_log_t.  The model will be initialized with the default
 * filter (i.e., accept all of the messages from the log).
 *
 * @param log Log to model.  If NULL then do not watch any log files.
 *
 * @return An initialized model, or NULL upon error.  The caller must
 * call seaudit_model_destroy() afterwards.
 */
extern seaudit_model_t *seaudit_model_create(seaudit_log_t * log);

/**
 * Destroy the referenced seadit_model_t object.
 *
 * @param model Model to destroy.  The pointer will be set to NULL
 * afterwards.  (If pointer is already NULL then do nothing.)
 */
extern void seaudit_model_destroy(seaudit_model_t ** model);

/**
 * Have the given model start watching the given log file, in addition
 * to any other log files the model was watching.
 *
 * @param model Model to modify.
 * @param log Additional log file to watch.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_model_append_log(seaudit_model_t * model, seaudit_log_t * log);

/**
 * Append a filter to a model.  The next time the model's messages are
 * retrieved only those messages that match this filter will be
 * returned.  Multiple filters may be applied to a model.  Upon
 * success, the model takes ownership of the filter.
 *
 * @param model Model to modify.
 * @param filter Additional filter to be applied.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_model_append_filter(seaudit_model_t * model, seaudit_filter_t * filter);

/**
 * Set a model to accept a message if all filters are met (default
 * behavior) or if any filter is met.
 *
 * @param model Model to modify.
 * @param match Matching behavior if model has multiple filters.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_model_set_filter_match(seaudit_model_t * model, seaudit_filter_match_e match);

/**
 * Get the current filter match value for a model.
 *
 * @param model Model containing filter match value.
 *
 * @return One of SEAUDIT_FILTER_MATCH_ALL or SEAUDIT_FILTER_MATCH_ANY.
 */
extern seaudit_filter_match_e seaudit_model_get_filter_match(seaudit_model_t * model);

/**
 * Append a sort criterion to a model.  The next time the model's
 * messages are retrieved they will be sorted by this criterion.  If
 * the model already has sort criteria, they will have a higher
 * priority than this new criterion.  Upon success, the model takes
 * ownership of the sort object
 *
 * @param model Model to modify.
 * @param sort Additional sort criterion.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_model_append_sort(seaudit_model_t * model, seaudit_sort_t * sort);

/**
 * Remove all sort criteria from this model.  The next time the
 * model's messages are retrieved they will be in the same order as
 * provided by the model's logs.
 *
 * @param model Model to modify.
 */
extern int seaudit_model_remove_all_sort(seaudit_model_t * model);

/**
 * Return a sorted list of messages associated with this model.  This
 * will cause the model to recalculate, as necessary, all messages
 * according to its filters and then sort them.
 *
 * @param log Log to which report error messages.
 * @param model Model containing messages.
 *
 * @return A newly allocated vector of seaudit_message_t, pre-filtered
 * and pre-sorted, or NULL upon error.  The caller is responsible for
 * calling apol_vector_destroy() upon this value, passing NULL as the
 * second parameter.
 */
extern apol_vector_t *seaudit_model_get_messages(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return a sorted list of malformed messages associated with this
 * model.  This is the union of all malformed messages from the
 * model's logs.  This will cause the model to recalculate, as
 * necessary, all messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model containing malformed messages.
 *
 * @return A newly allocated vector of strings, or NULL upon error.
 * Treat the contents of the vector as const char *.  The caller is
 * responsible for calling apol_vector_destroy() upon this value,
 * passing NULL as the second parameter.
 */
extern apol_vector_t *seaudit_model_get_malformed_messages(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of avc allow messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of allow messages in the model.  This could be zero.
 */
extern size_t seaudit_model_get_num_allows(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of avc deny messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of deny messages in the model.  This could be zero.
 */
extern size_t seaudit_model_get_num_denies(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of boolean change messages currently within the
 * model.  This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of boolean messages in the model.  This could be
 * zero.
 */
extern size_t seaudit_model_get_num_bools(seaudit_log_t * log, seaudit_model_t * model);

/**
 * Return the number of load messages currently within the model.
 * This will cause the model to recalculate, as necessary, all
 * messages according to its filters.
 *
 * @param log Log to which report error messages.
 * @param model Model to get statistics.
 *
 * @return Number of load messages in the model.  This could be zero.
 */
extern size_t seaudit_model_get_num_loads(seaudit_log_t * log, seaudit_model_t * model);

#endif
