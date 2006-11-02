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
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/uri.h>

#define FILTER_FILE_FORMAT_VERSION "1.3"

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
	/** criteria for executable, glob expression */
	char *exe;
	/** criteria for host, glob expression */
	char *host;
	/** criteria for path, glob expression */
	char *path;
	/** criteria for command, glob expression */
	char *comm;
	/** criteria for IP address, glob expression */
	char *ipaddr;
	/** criteria for port (exact match) */
	int port;
	/** criteria for netif, exact match */
	char *netif;
	/** criteria for AVC message type */
	seaudit_avc_message_type_e avc_msg_type;
	struct tm *start, *end;
	seaudit_filter_date_match_e date_match;
};

seaudit_filter_t *seaudit_filter_create(void)
{
	seaudit_filter_t *s = calloc(1, sizeof(*s));
	return s;
}

apol_vector_t *seaudit_filter_create_from_file(const char *filename)
{
	return NULL;
#if 0				       /* FIX ME! */
	seaudit_multifilter_parser_data_t parse_data;
	xmlSAXHandler handler;

	if (filename == NULL) {
		errno = EINVAL;
		return NULL;
	}
	memset(&handler, 0, sizeof(xmlSAXHandler));
	handler.startElement = my_parse_startElement;
	handler.endElement = my_parse_endElement;
	handler.characters = my_parse_characters;
	memset(&parse_data, 0, sizeof(seaudit_multifilter_parser_data_t));
	parse_data.multifilter = seaudit_multifilter_create();
	err = xmlSAXUserParseFile(&handler, &parse_data, filename);
	seaudit_multifilter_parser_data_free(&parse_data);
	if (err || parse_data.invalid_names == TRUE) {
		seaudit_multifilter_destroy(parse_data.multifilter);
		*is_multi = FALSE;
		*multifilter = NULL;
		if (err)
			return err;
		else
			return 1;      /* invalid file */
	}

	*is_multi = parse_data.is_multi;
	*multifilter = parse_data.multifilter;

	return 0;
#endif
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
		free((*filter)->exe);
		free((*filter)->host);
		free((*filter)->path);
		free((*filter)->comm);
		free((*filter)->ipaddr);
		free((*filter)->netif);
		free((*filter)->start);
		free((*filter)->end);
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
 * Helper function to set a criterion's vector, by duping the vector
 * and its strings.
 */
static int filter_set_vector(seaudit_filter_t * filter, apol_vector_t ** tgt, apol_vector_t * v)
{
	int retval = 0;
	size_t i;
	char *s, *t;
	apol_vector_destroy(tgt, free);
	if (v != NULL) {
		if ((*tgt = apol_vector_create_with_capacity(apol_vector_get_size(v))) == NULL) {
			retval = -1;
		} else {
			for (i = 0; i < apol_vector_get_size(v); i++) {
				s = apol_vector_get_element(v, i);
				if ((t = strdup(s)) == NULL || apol_vector_append(*tgt, t) < 0) {
					free(t);
					retval = -1;
					break;
				}
			}
		}
	}
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return retval;
}

/**
 * Helper function to set a criterion string.
 */
static int filter_set_string(seaudit_filter_t * filter, char **dest, const char *src)
{
	int retval = 0;
	free(*dest);
	*dest = NULL;
	if (src != NULL && (*dest = strdup(src)) == NULL) {
		retval = -1;
	}
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return retval;
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

int seaudit_filter_set_executable(seaudit_filter_t * filter, const char *exe)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->exe, exe);
}

char *seaudit_filter_get_executable(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->exe;
}

int seaudit_filter_set_host(seaudit_filter_t * filter, const char *host)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->host, host);
}

char *seaudit_filter_get_host(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->host;
}

int seaudit_filter_set_path(seaudit_filter_t * filter, const char *path)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->path, path);
}

char *seaudit_filter_get_path(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->path;
}

int seaudit_filter_set_command(seaudit_filter_t * filter, const char *command)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->comm, command);
}

char *seaudit_filter_get_command(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->comm;
}

int seaudit_filter_set_ipaddress(seaudit_filter_t * filter, const char *ipaddr)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->ipaddr, ipaddr);
}

char *seaudit_filter_get_ipaddress(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->ipaddr;
}

int seaudit_filter_set_port(seaudit_filter_t * filter, const int port)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->port = port;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

int seaudit_filter_get_port(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return 0;
	}
	return filter->port;
}

int seaudit_filter_set_netif(seaudit_filter_t * filter, const char *netif)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	return filter_set_string(filter, &filter->netif, netif);
}

char *seaudit_filter_get_netif(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return filter->netif;
}

int seaudit_filter_set_message_type(seaudit_filter_t * filter, const seaudit_avc_message_type_e message_type)
{
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	filter->avc_msg_type = message_type;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return 0;
}

seaudit_avc_message_type_e seaudit_filter_get_message_type(seaudit_filter_t * filter)
{
	if (filter == NULL) {
		errno = EINVAL;
		return SEAUDIT_AVC_UNKNOWN;
	}
	return filter->avc_msg_type;
}

int seaudit_filter_set_date(seaudit_filter_t * filter, const struct tm *start, const struct tm *end,
			    seaudit_filter_date_match_e date_match)
{
	int retval = 0;
	if (filter == NULL) {
		errno = EINVAL;
		return -1;
	}
	free(filter->start);
	filter->start = NULL;
	free(filter->end);
	filter->end = NULL;
	if (start != NULL) {
		if ((filter->start = calloc(1, sizeof(*(filter->start)))) == NULL) {
			retval = -1;
		} else {
			memcpy(filter->start, start, sizeof(*start));
		}
		if ((filter->end = calloc(1, sizeof(*(filter->end)))) == NULL) {
			retval = -1;
		} else {
			if (end != NULL) {
				memcpy(filter->end, end, sizeof(*end));
			}
		}
	}
	filter->date_match = date_match;
	if (filter->model != NULL) {
		model_notify_filter_changed(filter->model, filter);
	}
	return retval;
}

void seaudit_filter_get_date(seaudit_filter_t * filter, struct tm **start, struct tm **end, seaudit_filter_date_match_e * match)
{
	if (start != NULL) {
		*start = NULL;
	}
	if (end != NULL) {
		*end = NULL;
	}
	if (match != NULL) {
		match = SEAUDIT_FILTER_DATE_MATCH_BEFORE;
	}
	if (filter == NULL || start == NULL || end == NULL || match == NULL) {
		errno = EINVAL;
		return;
	}
	*start = filter->start;
	*end = filter->end;
	*match = filter->date_match;
}

/*************** filter criteria below (all are private) ***************/

static void filter_string_vector_print(const char *criteria_name, apol_vector_t * v, FILE * f, int tabs)
{
	int i;
	size_t j;
	if (v == NULL) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (j = 0; j < apol_vector_get_size(v); j++) {
		xmlChar *s = xmlCharStrdup(apol_vector_get_element(v, j));
		xmlChar *escaped = xmlURIEscapeStr(s, NULL);
		for (i = 0; i < tabs + 1; i++) {
			fprintf(f, "\t");
		}
		fprintf(f, "<item>%s</item>\n", escaped);
		free(escaped);
		free(s);
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static void filter_string_print(const char *criteria_name, const char *s, FILE * f, int tabs)
{
	int i;
	xmlChar *t, *escaped;
	if (s == NULL) {
		return;
	}
	t = xmlCharStrdup(s);
	escaped = xmlURIEscapeStr(t, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"%s\">\n", criteria_name);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%s</item>\n", escaped);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
	free(escaped);
	free(t);
}

static int filter_src_user_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->src_users != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->suser != NULL;
}

static int filter_src_user_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	size_t i;
	return apol_vector_get_index(filter->src_users, msg->data.avc->suser, apol_str_strcmp, NULL, &i) == 0;
}

static void filter_src_user_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("src_user", filter->src_users, f, tabs);
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

static void filter_src_role_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("src_role", filter->src_roles, f, tabs);
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

static void filter_src_type_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("src_type", filter->src_types, f, tabs);
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

static void filter_tgt_user_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("tgt_user", filter->tgt_users, f, tabs);
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

static void filter_tgt_role_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("tgt_role", filter->tgt_roles, f, tabs);
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

static void filter_tgt_type_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("tgt_type", filter->tgt_types, f, tabs);
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

static void filter_tgt_class_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_vector_print("obj_class", filter->tgt_classes, f, tabs);
}

static int filter_exe_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->exe != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->exe != NULL;
}

static int filter_exe_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->exe, msg->data.avc->exe, 0) == 0;
}

static void filter_exe_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("exe", filter->exe, f, tabs);
}

static int filter_host_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->host != NULL && msg->host != NULL;
}

static int filter_host_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->host, msg->host, 0) == 0;
}

static void filter_host_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("host", filter->host, f, tabs);
}

static int filter_path_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->path != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->path != NULL;
}

static int filter_path_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->path, msg->data.avc->path, 0) == 0;
}

static void filter_path_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("path", filter->path, f, tabs);
}

static int filter_comm_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->comm != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->comm != NULL;
}

static int filter_comm_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return fnmatch(filter->comm, msg->data.avc->comm, 0) == 0;
}

static void filter_comm_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("comm", filter->comm, f, tabs);
}

static int filter_ipaddr_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->ipaddr != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->saddr != NULL
										   || msg->data.avc->daddr != NULL
										   || msg->data.avc->faddr != NULL
										   || msg->data.avc->laddr != NULL);
}

static int filter_ipaddr_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->saddr && fnmatch(filter->ipaddr, msg->data.avc->saddr, 0) == 0)
		return 1;
	if (msg->data.avc->daddr && fnmatch(filter->ipaddr, msg->data.avc->daddr, 0) == 0)
		return 1;
	if (msg->data.avc->faddr && fnmatch(filter->ipaddr, msg->data.avc->faddr, 0) == 0)
		return 1;
	if (msg->data.avc->laddr && fnmatch(filter->ipaddr, msg->data.avc->laddr, 0) == 0)
		return 1;
	return 0;
}

static void filter_ipaddr_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("ipaddr", filter->ipaddr, f, tabs);
}

static int filter_port_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->port != 0 && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && (msg->data.avc->port != 0 || msg->data.avc->source != 0
									      || msg->data.avc->dest != 0
									      || msg->data.avc->fport != 0
									      || msg->data.avc->lport != 0);
}

static int filter_port_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	if (msg->data.avc->port != 0 && filter->port == msg->data.avc->port) {
		return 1;
	}
	if (msg->data.avc->source != 0 && filter->port == msg->data.avc->source) {
		return 1;
	}
	if (msg->data.avc->dest != 0 && filter->port == msg->data.avc->dest) {
		return 1;
	}
	if (msg->data.avc->fport != 0 && filter->port == msg->data.avc->fport) {
		return 1;
	}
	if (msg->data.avc->lport != 0 && filter->port == msg->data.avc->lport) {
		return 1;
	}
	return 0;
}

static void filter_port_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	int i;
	if (filter->port == 0) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"port\">\n");
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%d</item>\n", filter->port);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static int filter_netif_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->netif != NULL && msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->netif != NULL;
}

static int filter_netif_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return strcmp(filter->netif, msg->data.avc->netif) == 0;
}

static void filter_netif_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	filter_string_print("netif", filter->netif, f, tabs);
}

static int filter_avc_msg_type_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->avc_msg_type != SEAUDIT_AVC_UNKNOWN && msg->type == SEAUDIT_MESSAGE_TYPE_AVC
		&& msg->data.avc->msg != SEAUDIT_AVC_UNKNOWN;
}

static int filter_avc_msg_type_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->avc_msg_type == msg->data.avc->msg;
}

static void filter_avc_msg_type_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	int i;
	if (filter->avc_msg_type == SEAUDIT_AVC_UNKNOWN) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"msg\">\n");
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%d</item>\n", filter->avc_msg_type);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

static int filter_date_support(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	return filter->start != NULL && msg->date_stamp != NULL;
}

/**
 * Given two dates compare them, checking to see if the dates passed
 * in have valid years and correcting if not before comparing.
 */
static int filter_date_comp(const struct tm *t1, const struct tm *t2)
{
	/* tm has year, month, day, hour, min, sec */
	/* if we should compare the years */
	int retval;
	if (t1->tm_year != 0 && t2->tm_year != 0 && (retval = t1->tm_year - t2->tm_year) != 0) {
		return retval;
	}
	if ((retval = t1->tm_mon - t2->tm_mon) != 0) {
		return retval;
	}
	if ((retval = t1->tm_mday - t2->tm_mday) != 0) {
		return retval;
	}
	if ((retval = t1->tm_hour - t2->tm_hour) != 0) {
		return retval;
	}
	if ((retval = t1->tm_min - t2->tm_min) != 0) {
		return retval;
	}
	if ((retval = t1->tm_sec - t2->tm_sec) != 0) {
		return retval;
	}
	return 0;
}

static int filter_date_accept(const seaudit_filter_t * filter, const seaudit_message_t * msg)
{
	int compval = filter_date_comp(filter->start, msg->date_stamp);
	if (filter->date_match == SEAUDIT_FILTER_DATE_MATCH_BEFORE) {
		return compval > 0;
	} else if (filter->date_match == SEAUDIT_FILTER_DATE_MATCH_AFTER) {
		return compval < 0;
	} else {
		if (compval > 0)
			return 0;
		compval = filter_date_comp(filter->end, msg->date_stamp);
		return compval < 0;
	}
}

static void filter_date_print(const seaudit_filter_t * filter, FILE * f, int tabs)
{
	int i;
	xmlChar *s, *escaped;
	if (filter->start == NULL) {
		return;
	}
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "<criteria type=\"date_time\">\n");
	s = xmlCharStrdup(asctime(filter->start));
	escaped = xmlURIEscapeStr(s, NULL);
	for (i = 0; i < tabs + 1; i++) {
		fprintf(f, "\t");
	}
	fprintf(f, "<item>%s</item>\n", escaped);
	free(s);
	free(escaped);
	s = xmlCharStrdup(asctime(filter->end));
	escaped = xmlURIEscapeStr(s, NULL);
	for (i = 0; i < tabs + 1; i++)
		fprintf(f, "\t");
	fprintf(f, "<item>%s</item>\n", escaped);
	free(s);
	free(escaped);
	for (i = 0; i < tabs + 1; i++)
		fprintf(f, "\t");
	fprintf(f, "<item>%d</item>\n", filter->date_match);
	for (i = 0; i < tabs; i++)
		fprintf(f, "\t");
	fprintf(f, "</criteria>\n");
}

typedef int (filter_support_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);
typedef int (filter_accept_func) (const seaudit_filter_t * filter, const seaudit_message_t * msg);
typedef void (filter_print_func) (const seaudit_filter_t * filter, FILE * f, int tabs);

struct filter_criteria_t
{
	filter_support_func *support;
	filter_accept_func *accept;
	filter_print_func *print;
};

/**
 * Filter criteria are actually implemented as entries within this
 * function pointer table.  During filter_is_accepted() each element
 * of this table is retrieved; if the support functions returns
 * non-zero then the accept function is called.  To add new filter
 * criteria, implement their support and accept functions and then
 * append new entries to this table.
 */
const static struct filter_criteria_t filter_criteria[] = {
	{filter_src_user_support, filter_src_user_accept, filter_src_user_print},
	{filter_src_role_support, filter_src_role_accept, filter_src_role_print},
	{filter_src_type_support, filter_src_type_accept, filter_src_type_print},
	{filter_tgt_user_support, filter_tgt_user_accept, filter_tgt_user_print},
	{filter_tgt_role_support, filter_tgt_role_accept, filter_tgt_role_print},
	{filter_tgt_type_support, filter_tgt_type_accept, filter_tgt_type_print},
	{filter_tgt_class_support, filter_tgt_class_accept, filter_tgt_class_print},
	{filter_exe_support, filter_exe_accept, filter_exe_print},
	{filter_host_support, filter_host_accept, filter_host_print},
	{filter_path_support, filter_path_accept, filter_path_print},
	{filter_comm_support, filter_comm_accept, filter_comm_print},
	{filter_ipaddr_support, filter_ipaddr_accept, filter_ipaddr_print},
	{filter_port_support, filter_port_accept, filter_port_print},
	{filter_netif_support, filter_netif_accept, filter_netif_print},
	{filter_avc_msg_type_support, filter_avc_msg_type_accept, filter_avc_msg_type_print},
	{filter_date_support, filter_date_accept, filter_date_print}
};

int seaudit_filter_save_to_file(seaudit_filter_t * filter, const char *filename)
{
	FILE *file;
	const char *XML_VER = "<?xml version=\"1.0\"?>\n";

	if (filter == NULL || filename == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((file = fopen(filename, "w")) == NULL) {
		return -1;
	}
	fprintf(file, XML_VER);
	fprintf(file, "<view xmlns=\"http://oss.tresys.com/projects/setools/seaudit-%s/\">\n", FILTER_FILE_FORMAT_VERSION);
	seaudit_filter_append_to_file(filter, file, 1);
	fprintf(file, "</view>\n");
	fclose(file);
	return 0;
}

void seaudit_filter_append_to_file(seaudit_filter_t * filter, FILE * file, int tabs)
{
	xmlChar *escaped;
	xmlChar *str_xml;
	int i;
	size_t j;

	if (filter == NULL || file == NULL) {
		errno = EINVAL;
		return;
	}

	if (filter->name == NULL) {
		str_xml = xmlCharStrdup("Unnamed");
	} else {
		str_xml = xmlCharStrdup(filter->name);
	}
	escaped = xmlURIEscapeStr(str_xml, NULL);
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "<filter name=\"%s\" match=\"%s\">\n", escaped, filter->match == SEAUDIT_FILTER_MATCH_ALL ? "all" : "any");
	free(escaped);
	free(str_xml);

	if (filter->desc != NULL) {
		str_xml = xmlCharStrdup(filter->desc);
		escaped = xmlURIEscapeStr(str_xml, NULL);
		for (i = 0; i < tabs + 1; i++)
			fprintf(file, "\t");
		fprintf(file, "<desc>%s</desc>\n", escaped);
		free(escaped);
		free(str_xml);
	}
	for (j = 0; j < sizeof(filter_criteria) / sizeof(filter_criteria[0]); j++) {
		filter_criteria[j].print(filter, file, tabs + 1);
	}
	for (i = 0; i < tabs; i++)
		fprintf(file, "\t");
	fprintf(file, "</filter>\n");
}

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
