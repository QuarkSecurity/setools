/**
 *  @file model.h
 *  Public interface to a seaudit_model_t.  This represents a subset
 *  of log messages from a seaudit_model_t, where the subset is
 *  defined by a finite set of seaudit_filters and sorted by some
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

audit_log_view_t* audit_log_view_create(void);
void audit_log_view_destroy(audit_log_view_t* view);
void audit_log_view_set_log(audit_log_view_t *view, audit_log_t *log);
void audit_log_view_purge_fltr_msgs(audit_log_view_t *view);
int audit_log_view_do_filter(audit_log_view_t *log, int **deleted, int *num_deleted);
void audit_log_view_set_multifilter(audit_log_view_t *view, seaudit_multifilter_t *multifilter);

#endif
