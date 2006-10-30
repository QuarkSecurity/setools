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

/******************** protected functions below ********************/

void filter_set_model(seaudit_filter_t * filter, seaudit_model_t * model)
{
	filter->model = model;
}

int filter_is_accepted(seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return -1;		       /* FIX ME */
}

#if 0

bool_t seaudit_filter_does_message_match(seaudit_filter_t * filter, msg_t * message, audit_log_t * log)
{
	seaudit_criteria_t *criteria = NULL;
	bool_t match = TRUE;
	apol_vector_t *criteria_vector;
	int i;

	if (filter == NULL || message == NULL || log == NULL)
		return FALSE;

	criteria_vector = (apol_vector_t *) seaudit_filter_get_list(filter);
	if (criteria_vector == NULL) {
		return FALSE;
	}
	for (i = 0; i < apol_vector_get_size(criteria_vector); i++) {
		criteria = apol_vector_get_element(criteria_vector, i);
		if (!criteria)
			continue;
		if (message->msg_type & criteria->msg_types) {
			if (!criteria->criteria_act(message, criteria, log)) {
				match = FALSE;
				if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
					return FALSE;
			} else {
				if (filter->match == SEAUDIT_FILTER_MATCH_ANY)
					return TRUE;
			}
		} else {
			match = FALSE;
			if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
				return FALSE;
		}
	}
	if (filter->match == SEAUDIT_FILTER_MATCH_ANY)
		match = FALSE;
	if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
		match = TRUE;
	apol_vector_destroy(&criteria_vector, 0);
	return match;
}

apol_vector_t *seaudit_filter_get_list(seaudit_filter_t * filter)
{
	apol_vector_t *criterias;

	if (!(criterias = apol_vector_create())) {
		return NULL;
	}
	apol_vector_append(criterias, (void *)filter->src_type_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_type_criteria);
	apol_vector_append(criterias, (void *)filter->src_role_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_role_criteria);
	apol_vector_append(criterias, (void *)filter->src_user_criteria);
	apol_vector_append(criterias, (void *)filter->tgt_user_criteria);
	apol_vector_append(criterias, (void *)filter->class_criteria);
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
