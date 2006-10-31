/**
 *  @file filter.h
 *  Public interface to a seaudit_filter_t.  A filter is used to
 *  modify the list of messages returned from a seaudit_model_t.
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

#ifndef SEAUDIT_FILTER_H
#define SEAUDIT_FILTER_H

#include <apol/vector.h>

typedef struct seaudit_filter seaudit_filter_t;

/**
 * By default, all criteria of a filter must be met for a message to
 * be accepted.  This behavior can be changed such that a message is
 * accepted if any of the criteria pass.
 */
typedef enum seaudit_filter_match
{
	SEAUDIT_FILTER_MATCH_ALL = 0,
	SEAUDIT_FILTER_MATCH_ANY
} seaudit_filter_match_e;

/**
 * Create a new filter object.  The default matching behavior is to
 * reject all messages.
 *
 * @return A newly allocated filter.  The caller is responsible for
 * calling seaudit_filter_destroy() afterwards.
 */
extern seaudit_filter_t *seaudit_filter_create(void);

/**
 * Destroy the referenced seaudit_filter_t object.
 *
 * @param filter Filter object to destroy.  The pointer will be set to
 * NULL afterwards.  (If pointer is already NULL then do nothing.)
 */
extern void seaudit_filter_destroy(seaudit_filter_t ** filter);

/**
 * Set a filter to accept a message if all criteria are met (default
 * behavior) or if any criterion is met.
 *
 * @param filter Filter to modify.
 * @param match Matching behavior if filter has multiple criteria.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_match(seaudit_filter_t * filter, seaudit_filter_match_e match);

/**
 * Get the current match value for a filter.
 *
 * @param filter Filter containing match value.
 *
 * @return One of SEAUDIT_FILTER_MATCH_ALL or SEAUDIT_FILTER_MATCH_ANY.
 */
extern seaudit_filter_match_e seaudit_filter_get_match(seaudit_filter_t * filter);

/**
 * Set the name of this filter, overwriting any previous name.
 *
 * @param filter Filter to modify.
 * @param name New name for this filter.  This function will duplicate
 * the string.  If this is NULL then clear the existing name.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_name(seaudit_filter_t * filter, const char *name);

/**
 * Get the name of this filter.
 *
 * @param filter Filter from which to get name.
 *
 * @return Name of the filter, or NULL if no name has been set.  Do
 * not free() or otherwise modify this string.
 */
extern char *seaudit_filter_get_name(seaudit_filter_t * filter);

/**
 * Set the description of this filter, overwriting any previous
 * description.
 *
 * @param filter Filter to modify.
 * @param desc New description for this filter.  This function will
 * duplicate the string.  If this is NULL then clear the existing
 * description.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_description(seaudit_filter_t * filter, const char *desc);

/**
 * Get the description of this filter.
 *
 * @param filter Filter from which to get description.
 *
 * @return Description of the filter, or NULL if no description has
 * been set.  Do not free() or otherwise modify this string.
 */
extern char *seaudit_filter_get_description(seaudit_filter_t * filter);

/**
 * Set the list of source users.  A message is accepted if its source
 * user is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_source_user(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source users for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_source_user(seaudit_filter_t * filter);

/**
 * Set the list of source roles.  A message is accepted if its source
 * role is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_source_role(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source roles for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_source_role(seaudit_filter_t * filter);

/**
 * Set the list of source types.  A message is accepted if its source
 * type is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_source_type(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of source types for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_source_type(seaudit_filter_t * filter);

/**
 * Set the list of target users.  A message is accepted if its target
 * user is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_target_user(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target users for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_target_user(seaudit_filter_t * filter);

/**
 * Set the list of target roles.  A message is accepted if its target
 * role is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_target_role(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target roles for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_target_role(seaudit_filter_t * filter);

/**
 * Set the list of target types.  A message is accepted if its target
 * type is within this list.  Upon success the filter takes ownership
 * of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_target_type(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target types for a filter.  This will be
 * a vector of strings.  Treat the vector and its contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_target_type(seaudit_filter_t * filter);

/**
 * Set the list of target object classes.  A message is accepted if
 * its target class is within this list.  Upon success the filter
 * takes ownership of the vector and the strings within.
 *
 * @param filter Filter to modify.
 * @param v Vector of allocated strings, or NULL to clear current
 * settings.
 *
 * @return 0 on success, < 0 on error.
 */
extern int seaudit_filter_set_target_class(seaudit_filter_t * filter, apol_vector_t * v);

/**
 * Return the current list of target object classes for a filter.
 * This will be a vector of strings.  Treat the vector and its
 * contents as const.
 *
 * @param filter Filter to get values.
 *
 * @return Vector of strings, or NULL if no value has been set.
 */
extern apol_vector_t *seaudit_filter_get_target_class(seaudit_filter_t * filter);

#if 0

#include <apol/util.h>
#include <apol/vector.h>
#include "filter_criteria.h"

#define FILTER_FILE_FORMAT_VERSION "1.3"

typedef struct seaudit_filter
{
	seaudit_criteria_t *class_criteria;
	seaudit_criteria_t *exe_criteria;
	seaudit_criteria_t *comm_criteria;
	seaudit_criteria_t *msg_criteria;
	seaudit_criteria_t *path_criteria;
	seaudit_criteria_t *netif_criteria;
	seaudit_criteria_t *ipaddr_criteria;
	seaudit_criteria_t *ports_criteria;
	seaudit_criteria_t *host_criteria;
	seaudit_criteria_t *date_time_criteria;
	enum seaudit_filter_match_t match;
	char *name;
	char *desc;
} seaudit_filter_t;

int seaudit_filter_save_to_file(seaudit_filter_t * filter, const char *filename);
void seaudit_filter_append_to_file(seaudit_filter_t * filter, FILE * file, int tabs);
apol_vector_t *seaudit_filter_get_list(seaudit_filter_t * filter);

#endif

#endif
