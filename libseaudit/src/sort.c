/**
 *  @file model.c
 *  Implementation of seaudit sort routines.
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

#include "seaudit_internal.h"

#include <string.h>

typedef int (sort_comp_func) (seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b);

typedef int (sort_supported_func) (seaudit_sort_t * sort, const seaudit_message_t * m);

struct seaudit_sort
{
	sort_comp_func *comp;
	sort_supported_func *support;
	int direction;
};

void seaudit_sort_destroy(seaudit_sort_t ** sort)
{
	if (sort != NULL && *sort != NULL) {
		free(*sort);
		*sort = NULL;
	}
}

static int sort_host_comp(seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b)
{
	int val = strcmp(a->host, b->host);
	return (sort->direction >= 0 ? val : -1 * val);
}

static int sort_host_support(seaudit_sort_t * sort, const seaudit_message_t * msg)
{
	return msg->host != NULL;
}

seaudit_sort_t *seaudit_sort_by_host(int direction)
{
	seaudit_sort_t *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	s->comp = sort_host_comp;
	s->support = sort_host_support;
	s->direction = direction;
	return s;
}

/******************** protected functions below ********************/

int sort_is_supported(seaudit_sort_t * sort, const seaudit_message_t * msg)
{
	return sort->support(sort, msg);
}

int sort_comp(seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b)
{
	return sort->comp(sort, a, b);
}

#if 0

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static sort_action_node_t *current_list = NULL;
static int reverse_sort = 0;
static audit_log_t *audit_log = NULL;



static int msg_field_compare(const msg_t * a, const msg_t * b)
{
	/* if message types in auditlog.h are in alpha order then this function doesn't need to change */

	if (a->msg_type < b->msg_type)
		return -1;	       /* a=avc msg, b=load policy msg OR a=bool, b=avc|load */
	if (a->msg_type == b->msg_type) {
		if (a->msg_type != AVC_MSG)
			return 0;      /* a = b and not AVC */
		if (a->msg_data.avc_msg->msg < b->msg_data.avc_msg->msg)
			return -1;     /* a=denied, b=granted */
		if (a->msg_data.avc_msg->msg > b->msg_data.avc_msg->msg)
			return 1;      /* a=granted, b=denied */
		return 0;	       /* a->msg = b->msg */
	}
	return 1;		       /* a=load policy msg, b=avc|bool  msg OR a=avc, b=boolean */
}

static int perm_compare(const msg_t * a, const msg_t * b)
{
	if (a->msg_type < b->msg_type)
		return -1;
	if (apol_vector_get_size(msg_get_avc_data(a)->perms) > 0 && apol_vector_get_size(msg_get_avc_data(b)->perms) > 0) {
		return strcmp(apol_vector_get_element(msg_get_avc_data(a)->perms, 0),
			      apol_vector_get_element(msg_get_avc_data(b)->perms, 0));
	}
	/* If one of the messages does not contain permissions, then always return a NONMATCH value. */
	return 1;
}

static int date_compare(const msg_t * a, const msg_t * b)
{
	return date_time_compare(a->date_stamp, b->date_stamp);
}

/* given two dates compare them, checking to see if the dates passed in
 * have valid years and correcting if not before comparing */
int date_time_compare(struct tm *t1, struct tm *t2)
{
	/* tm has year, month, day, hour, min, sec */
	/* if we should compare the years */
	if (t1->tm_year != 0 && t2->tm_year != 0) {
		if (t1->tm_year > t2->tm_year)
			return 1;
		else if (t1->tm_year < t2->tm_year)
			return -1;
	}

	if (t1->tm_mon > t2->tm_mon)
		return 1;
	else if (t1->tm_mon < t2->tm_mon)
		return -1;

	if (t1->tm_mday > t2->tm_mday)
		return 1;
	else if (t1->tm_mday < t2->tm_mday)
		return -1;

	if (t1->tm_hour > t2->tm_hour)
		return 1;
	else if (t1->tm_hour < t2->tm_hour)
		return -1;

	if (t1->tm_min > t2->tm_min)
		return 1;
	else if (t1->tm_min < t2->tm_min)
		return -1;

	if (t1->tm_sec > t2->tm_sec)
		return 1;
	else if (t1->tm_sec < t2->tm_sec)
		return -1;

	return 0;
}

static int src_user_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->src_user;
	i_b = msg_get_avc_data(b)->src_user;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_user(audit_log, i_a);
	sb = audit_log_get_user(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int tgt_user_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->tgt_user;
	i_b = msg_get_avc_data(b)->tgt_user;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_user(audit_log, i_a);
	sb = audit_log_get_user(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int src_role_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->src_role;
	i_b = msg_get_avc_data(b)->src_role;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_role(audit_log, i_a);
	sb = audit_log_get_role(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int tgt_role_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->tgt_role;
	i_b = msg_get_avc_data(b)->tgt_role;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_role(audit_log, i_a);
	sb = audit_log_get_role(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int src_type_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->src_type;
	i_b = msg_get_avc_data(b)->src_type;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_type(audit_log, i_a);
	sb = audit_log_get_type(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int tgt_type_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->tgt_type;
	i_b = msg_get_avc_data(b)->tgt_type;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_type(audit_log, i_a);
	sb = audit_log_get_type(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int obj_class_compare(const msg_t * a, const msg_t * b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = msg_get_avc_data(a)->obj_class;
	i_b = msg_get_avc_data(b)->obj_class;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_obj(audit_log, i_a);
	sb = audit_log_get_obj(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int exe_compare(const msg_t * a, const msg_t * b)
{
	char *exe_a, *exe_b;
	int ret;
	exe_a = msg_get_avc_data(a)->exe;
	exe_b = msg_get_avc_data(b)->exe;

	if (!exe_a)
		return -1;
	if (!exe_b)
		return 1;

	ret = strcmp(exe_a, exe_b);
	if (ret == 0)
		return 0;
	else
		return ret;
}

static int comm_compare(const msg_t * a, const msg_t * b)
{
	char *comm_a, *comm_b;
	int ret;
	comm_a = msg_get_avc_data(a)->comm;
	comm_b = msg_get_avc_data(b)->comm;

	if (!comm_a)
		return -1;
	if (!comm_b)
		return 1;

	ret = strcmp(comm_a, comm_b);
	if (ret == 0)
		return 0;
	else
		return ret;
}

static int path_compare(const msg_t * a, const msg_t * b)
{
	char *sa, *sb;

	sa = msg_get_avc_data(a)->path;
	sb = msg_get_avc_data(b)->path;

	if (!sa)
		return -1;
	if (!sb)
		return 1;
	return strcmp(sa, sb);
}

static int dev_compare(const msg_t * a, const msg_t * b)
{
	char *sa, *sb;

	sa = msg_get_avc_data(a)->dev;
	sb = msg_get_avc_data(b)->dev;

	if (!sa)
		return -1;
	if (!sb)
		return 1;
	return strcmp(sa, sb);
}

static int inode_compare(const msg_t * a, const msg_t * b)
{
	if (msg_get_avc_data(a)->inode == msg_get_avc_data(b)->inode) {
		return 0;
	} else if (msg_get_avc_data(a)->inode < msg_get_avc_data(b)->inode) {
		return -1;
	} else {
		return 1;
	}
}

static int pid_compare(const msg_t * a, const msg_t * b)
{
	if (msg_get_avc_data(a)->pid == msg_get_avc_data(b)->pid) {
		return 0;
	} else if (msg_get_avc_data(a)->pid < msg_get_avc_data(b)->pid) {
		return -1;
	} else {
		return 1;
	}
}

static sort_action_node_t *sort_action_node_create(void)
{
	sort_action_node_t *cl;
	cl = (sort_action_node_t *) malloc(sizeof(sort_action_node_t));
	if (!cl) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	memset(cl, 0, sizeof(sort_action_node_t));
	return cl;
}

sort_action_node_t *msg_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG | BOOLEAN_MSG;
	node->sort = &msg_field_compare;
	return node;
}

sort_action_node_t *host_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG | BOOLEAN_MSG;
	node->sort = &host_field_compare;
	return node;
}

sort_action_node_t *perm_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &perm_compare;
	return node;
}

sort_action_node_t *date_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG | BOOLEAN_MSG;
	node->sort = &date_compare;
	return node;
}

sort_action_node_t *src_user_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_user_compare;
	return node;
}

sort_action_node_t *tgt_user_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_user_compare;
	return node;
}

sort_action_node_t *src_role_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_role_compare;
	return node;
}

sort_action_node_t *tgt_role_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_role_compare;
	return node;
}

sort_action_node_t *src_type_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &src_type_compare;
	return node;
}

sort_action_node_t *tgt_type_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &tgt_type_compare;
	return node;
}

sort_action_node_t *obj_class_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &obj_class_compare;
	return node;
}

sort_action_node_t *exe_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &exe_compare;
	return node;
}

sort_action_node_t *comm_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &comm_compare;
	return node;
}

sort_action_node_t *path_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &path_compare;
	return node;
}

sort_action_node_t *dev_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &dev_compare;
	return node;
}

sort_action_node_t *inode_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &inode_compare;
	return node;
}

sort_action_node_t *pid_sort_action_create(void)
{
	sort_action_node_t *node = sort_action_node_create();
	if (!node) {
		fprintf(stderr, "Out of memory!\n");
		return NULL;
	}
	node->msg_types = AVC_MSG;
	node->sort = &pid_compare;
	return node;
}

#endif
