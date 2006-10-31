/**
 *  @file filter.c
 *  Implementation of seaudit filters.
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

#include "seaudit_internal.h"

#include <apol/util.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/uri.h>

struct seaudit_filter
{
	seaudit_filter_match_e match;
	char *name;
	char *desc;
	/** model that is watching this filter */
	seaudit_model_t *model;
	/** vector of strings, for source users */
	apol_vector_t *src_users;
	/** vector of strings, for source roles */
	apol_vector_t *src_roles;
	/** vector of strings, for source types */
	apol_vector_t *src_types;
	/** vector of strings, for target users */
	apol_vector_t *tgt_users;
	/** vector of strings, for target roles */
	apol_vector_t *tgt_roles;
	/** vector of strings, for target types */
	apol_vector_t *tgt_types;
	/** vector of strings, for target object classes */
	apol_vector_t *tgt_classes;
};

seaudit_filter_t *seaudit_filter_create(void)
{
	seaudit_filter_t *s = calloc(1, sizeof(*s));
	return s;
}

void seaudit_filter_destroy(seaudit_filter_t ** filter)
{
	if (filter != NULL && *filter != NULL) {
		free((*filter)->name);
		free((*filter)->desc);
		apol_vector_destroy(&(*filter)->src_users, free);
		apol_vector_destroy(&(*filter)->src_roles, free);
		apol_vector_destroy(&(*filter)->src_types, free);
		apol_vector_destroy(&(*filter)->tgt_users, free);
		apol_vector_destroy(&(*filter)->tgt_roles, free);
		apol_vector_destroy(&(*filter)->tgt_types, free);
		apol_vector_destroy(&(*filter)->tgt_classes, free);
		free(*filter);
		*filter = NULL;
	}
}

int seaudit_filter_set_match(seaudit_filter_t * filter, seaudit_filter_match_e match)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->match = match;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

seaudit_filter_match_e seaudit_filter_get_match(seaudit_filter_t * filter)
{
	return filter->match;
}

int seaudit_filter_set_name(seaudit_filter_t * filter, const char *name)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	free(filter->name);
	filter->name = NULL;
	if (name != NULL && (filter->name = strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_filter_get_name(seaudit_filter_t * filter)
{
	return filter->name;
}

int seaudit_filter_set_description(seaudit_filter_t * filter, const char *desc)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	free(filter->desc);
	filter->desc = NULL;
	if (desc != NULL && (filter->desc = strdup(desc)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_filter_get_description(seaudit_filter_t * filter)
{
	return filter->desc;
}

/**
 * Helper function to set a criterion's vector.
 */
static int filter_set_vector(seaudit_filter_t * filter, apol_vector_t ** tgt, apol_vector_t * v)
{
	apol_vector_destroy(tgt, free);
	*tgt = v;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

int seaudit_filter_set_source_user(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_users, v);
}

apol_vector_t *seaudit_filter_get_source_user(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_users;
}

int seaudit_filter_set_source_role(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_roles, v);
}

apol_vector_t *seaudit_filter_get_source_role(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_roles;
}

int seaudit_filter_set_source_type(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->src_types, v);
}

apol_vector_t *seaudit_filter_get_source_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->src_types;
}

int seaudit_filter_set_target_user(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_users, v);
}

apol_vector_t *seaudit_filter_get_target_user(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_users;
}

int seaudit_filter_set_target_role(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_roles, v);
}

apol_vector_t *seaudit_filter_get_target_role(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_roles;
}

int seaudit_filter_set_target_type(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_types, v);
}

apol_vector_t *seaudit_filter_get_target_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_types;
}

int seaudit_filter_set_target_class(seaudit_filter_t * filter, apol_vector_t * v)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_vector(filter, &filter->tgt_classes, v);
}

apol_vector_t *seaudit_filter_get_target_class(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->tgt_classes;
}

/*************** filter criteria below (all are private) ***************/

static int filter_src_user_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_users != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->suser != NULL;
}

static int filter_src_user_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_users, msg->data.avc->suser, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_src_role_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_roles != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->srole != NULL;
}

static int filter_src_role_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_roles, msg->data.avc->srole, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_src_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_types != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->stype != NULL;
}

static int filter_src_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_types, msg->data.avc->stype, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_user_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_users != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tuser != NULL;
}

static int filter_tgt_user_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_users, msg->data.avc->tuser, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_role_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_roles != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->trole != NULL;
}

static int filter_tgt_role_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_roles, msg->data.avc->trole, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_types != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->ttype != NULL;
}

static int filter_tgt_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_types, msg->data.avc->ttype, apol_str_strcmp, NULL, &i) == 0;
}

static int filter_tgt_class_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->tgt_classes != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tclass != NULL;
}

static int filter_tgt_class_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->tgt_classes, msg->data.avc->tclass, apol_str_strcmp, NULL, &i) == 0;
}

typedef int (filter_support_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);
typedef int (filter_accept_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);

struct filter_criteria_t
{
	filter_support_func *support;
	filter_accept_func *accept;
};

/**
 * Filter criteria are actually implemented as entries within this
 * function pointer tabel.  During filter_is_accepted() each element
 * of this table is retrieved; if the support functions returns
 * non-zero then the accept function is called.  To add new filter
 * criteria, implement their support and accept functions and then
 * append new entries to this table.
 */
const static struct filter_criteria_t filter_criteria[] = {
	{filter_src_user_support, filter_src_user_accept},
	{filter_src_role_support, filter_src_role_accept},
	{filter_src_type_support, filter_src_type_accept},
	{filter_tgt_user_support, filter_tgt_user_accept},
	{filter_tgt_role_support, filter_tgt_role_accept},
	{filter_tgt_type_support, filter_tgt_type_accept},
	{filter_tgt_class_support, filter_tgt_class_accept}
};

/******************** protected functions below ********************/

void filter_set_model(seaudit_filter_t * filter, seaudit_model_t * model)
{
	filter->model = model;
}

int filter_is_accepted(seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	int criteria_passed = 0, acceptval;
	size_t i;
	for (i = 0; i < sizeof(filter_criteria) / sizeof(filter_criteria[0]); i++) {
		if (filter_criteria[i].support(filter, msg)) {
			acceptval = filter_criteria[i].accept(filter, msg);
			if (acceptval) {
				criteria_passed++;
				if (filter->match == SEAUDIT_FILTER_MATCH_ANY) {
					return 1;
				}
			}
			if (filter->match == SEAUDIT_FILTER_MATCH_ALL && !acceptval) {
				return 0;
			}
		}
	}
	if (filter->match == SEAUDIT_FILTER_MATCH_ANY) {
		/* if got here, then no criteria were met */
		return 0;
	}
	/* if got here, then all criteria were met or none were attempted */
	if (criteria_passed) {
		return 1;
	}
	return 0;
}

#if 0

apol_vector_t *seaudit_filter_get_list(seaudit_filter_t * filter)
{
	apol_vector_t *criterias;

	if (!(criterias = apol_vector_create())) {
		return NULL;
	}
	apol_vector_append(criterias, (void *)filter->exe_criteria);
	apol_vector_append(criterias, (void *)filter->comm_criteria);
	apol_vector_append(criterias, (void *)filter->msg_criteria);
	apol_vector_append(criterias, (void *)filter->path_criteria);
	apol_vector_append(criterias, (void *)filter->netif_criteria);
	apol_vector_append(criterias, (void *)filter->ipaddr_criteria);
	apol_vector_append(criterias, (void *)filter->ports_criteria);
	apol_vector_append(criterias, (void *)filter->host_criteria);
	apol_vector_append(criterias, (void *)filter->date_time_criteria);
	return criterias;
}

int seaudit_filter_save_to_file(seaudit_filter_t * filter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";

	if (!filter || !filename)
		return -1;
	file = fopen(filename, "w");
	if (!file)
		return -1;
	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\">\n", FILTER_FILE_FORMAT_VERSION);
	seaudit_filter_append_to_file(filter, file, 1);
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}

void seaudit_filter_append_to_file(seaudit_filter_t * filter, FILE * file, int tabs)
{
	seaudit_criteria_t *criteria;
	apol_vector_t *criteria_vector;
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;

	if (!filter || !file)
		return;

	str_xml = xmlCharStrdup(filter->name);
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "<filter name=\"%s\" match=\"%s\">\n", escaped, filter->match == SEAUDIT_FILTER_MATCH_ALL ? "all" : "any");
	free(escaped);
	free(str_xml);

	if (filter->desc) {
		str_xml = xmlCharStrdup(filter->desc);
		escaped = xmlURIEscapeStr(str_xml, NULL);
		for (i = 0; i < tabs + 1; i++)
			fprintf(file, "\t");
		fprintf(file, "<desc>%s</desc>\n", escaped);
		free(escaped);
		free(str_xml);
	}
	criteria_vector = (apol_vector_t *) seaudit_filter_get_list(filter);
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		criteria = apol_vector_get_element(criteria_vector, i);
		if (criteria)
			seaudit_criteria_print(criteria, file, tabs + 2);
	}
	apol_vector_destroy(&criteria_vector, 0);
	fprintf(file, "\t</filter>\n");
}

#endif
