/**
 *  @file audit_filter.h
 *  Public interface to audit_filter_t.  This is an abstract class that
 *  defines a filter, used to select messages for an audit_model_t.
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

#ifndef SEAUDIT_AUDIT_FILTER_H
#define SEAUDIT_AUDIT_FILTER_H

#include <time.h>
#include "log.h"

struct seaudit_criteria;
/* callback type for printing criteria */
typedef void (*seaudit_criteria_print_t) (struct seaudit_criteria * criteria, FILE * stream, int tabs);
/* callback type for criteria */
typedef bool_t(*seaudit_criteria_action_t) (msg_t * msg, struct seaudit_criteria * criteria, audit_log_t * log);
/* callback type for criteria cleanup */
typedef void (*seaudit_criteria_destroy_t) (struct seaudit_criteria * criteria);

/*
 * generic criteria structure */
typedef struct seaudit_criteria
{
	unsigned int msg_types;	       /* message types for the criteria */
	seaudit_criteria_action_t criteria_act;	/* function to perform the criteria matching */
	seaudit_criteria_print_t print;
	seaudit_criteria_destroy_t destroy;	/* function to free the criteria type */
	void *data;		       /* data for the criteria ie. date_criteria_t */
	bool_t dirty;
} seaudit_criteria_t;

#define FILTER_CRITERIA_DT_OPTION_BEFORE 0
#define FILTER_CRITERIA_DT_OPTION_AFTER 1
#define FILTER_CRITERIA_DT_OPTION_BETWEEN 2

/* create a criteria */
seaudit_criteria_t *class_criteria_create(char **classes, int num_classes);
seaudit_criteria_t *exe_criteria_create(const char *exe);
seaudit_criteria_t *host_criteria_create(const char *host);
seaudit_criteria_t *path_criteria_create(const char *path);
seaudit_criteria_t *comm_criteria_create(const char *comm);
seaudit_criteria_t *netif_criteria_create(const char *netif);
seaudit_criteria_t *ipaddr_criteria_create(const char *ipaddr);	/* a generic match-any IP criteria */
seaudit_criteria_t *ports_criteria_create(int port);	/* a generic match-any port criteria */
seaudit_criteria_t *date_time_criteria_create(struct tm *start, struct tm *end, int option);
seaudit_criteria_t *msg_criteria_create(int msg);

apol_vector_t *strs_criteria_get_strs(seaudit_criteria_t * criteria);
#define class_criteria_get_strs(criteria) strs_criteria_get_strs(criteria)

const char *glob_criteria_get_str(seaudit_criteria_t * criteria);
#define exe_criteria_get_str(criteria) glob_criteria_get_str(criteria)
#define path_criteria_get_str(criteria) glob_criteria_get_str(criteria)
#define ipaddr_criteria_get_str(criteria) glob_criteria_get_str(criteria)
#define host_criteria_get_str(criteria) glob_criteria_get_str(criteria)
#define comm_criteria_get_str(criteria) glob_criteria_get_str(criteria)

const char *netif_criteria_get_str(seaudit_criteria_t * criteria);
int ports_criteria_get_val(seaudit_criteria_t * criteria);
void seaudit_criteria_print(seaudit_criteria_t * criteria, FILE * stream, int tabs);
const struct tm *date_time_criteria_get_date(seaudit_criteria_t * criteria, bool_t start);
int date_time_criteria_get_option(seaudit_criteria_t * criteria);
int msg_criteria_get_val(seaudit_criteria_t * criteria);

/* destroy a criteria */
void seaudit_criteria_destroy(seaudit_criteria_t * ftr);

#endif
