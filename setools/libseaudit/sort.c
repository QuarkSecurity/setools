/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 */

#include "sort.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static sort_action_node_t *current_list = NULL;
static int reverse_sort = 0;
static audit_log_t *audit_log = NULL;

void sort_action_list_destroy(sort_action_node_t *cl)
{
	sort_action_node_t *cur, *next;

	cur = cl;
	while (cur) {
		next = cur->next;
		free(cur);
		cur = next;
	}
}

int audit_log_append_sort(audit_log_t *log, sort_action_node_t *node)
{
	if (!log->sort_actions) {
		log->sort_actions = node;
		log->last_sort_action = node;
		return 0;
	}
	log->last_sort_action->next = node;
	node->prev = log->last_sort_action->next;
	log->last_sort_action = node;
	return 0;
}

int audit_log_remove_sort(audit_log_t *log, sort_action_node_t *node)
{
	sort_action_node_t *cur;

	for (cur = log->sort_actions; cur; cur = cur->next) {
		if (cur == node) {
			if (cur == log->last_sort_action) {
				log->last_sort_action = cur->prev;
				cur->prev->next = NULL;
			} else if (cur == log->sort_actions) {
				if (cur->next) {
					log->sort_actions = cur->next;
					cur->next->prev = NULL;
				} else {
					log->sort_actions = NULL;
				}
			} else {
				cur->prev->next = cur->next;
				cur->next->prev = cur->prev;
			}
			return 0;
		}
	}
	return 1;
}

typedef struct sort_data {
	int offset;
	int msg_indx;
	msg_t *msg;
} sort_data_t;

/*
 * Sort an audit log returning the new positions of the items.
 */
int audit_log_sort(audit_log_t *log, int **new_order, int reverse)
{
	int i, rc, sort_len, len, indx;
	sort_data_t *sort_data;
	sort_action_node_t *cur;
	bool_t found;

	if (!log->fltr_msgs || !log->sort_actions)
		return -1;

	if (log->num_fltr_msgs == 1) {
		*new_order = NULL;
		return 0;
	}
	sort_data = (sort_data_t*)malloc(sizeof(sort_data_t) * log->num_fltr_msgs);
	if (!sort_data)
		return -1;
	memset(sort_data, 0, sizeof(sort_data_t) * log->num_fltr_msgs);

	/* We push the msgs of types that the sort actions don't support to the
	 * end of the list. This allows us to not sort them at all but leave
	 * them in the message list at the end for display.
	 */
	len = 0;
	sort_len = 0;
	for (i = 0; i < log->num_fltr_msgs; i++) {
		found = FALSE;
		for (cur = log->sort_actions; cur != NULL; cur = cur->next) {
			indx = log->fltr_msgs[i];
			if (!(log->msg_list[indx]->msg_type & cur->msg_types)) {
				len++;
				sort_data[log->num_fltr_msgs - len].offset = i;
				sort_data[log->num_fltr_msgs - len].msg_indx = indx;
				sort_data[log->num_fltr_msgs - len].msg = log->msg_list[indx];
				found = TRUE;
				break;
			}
		}
		if (!found) {
			sort_data[sort_len].offset = i;
			indx = log->fltr_msgs[i];
			sort_data[sort_len].msg_indx = indx;
			sort_data[sort_len].msg = log->msg_list[indx];
			sort_len++;
		}
	}
	if (sort_len == 0) {
		rc = 0;
		goto out;
	}

	current_list = log->sort_actions;
	reverse_sort = reverse;
	audit_log = log;
	qsort(sort_data, sort_len, sizeof(sort_data_t), &msg_compare);
	for (i = 0; i < log->num_fltr_msgs; i++) {
		log->fltr_msgs[i] = sort_data[i].msg_indx;
	}

	*new_order = (int*)malloc(sizeof(int) * log->num_fltr_msgs);
	if (!*new_order) {
		rc = -1;
		goto out;
	}

	for (i = 0; i < log->num_fltr_msgs; i++) {
		(*new_order)[i] = sort_data[i].offset;
	}	

	rc = 0;
out:
	free(sort_data);
	return rc;
}

int msg_compare(const void *a, const void *b)
{
	sort_action_node_t *cur;
	msg_t *msg_a, *msg_b;
	int ret = 0;
	assert(current_list);

	msg_a = ((sort_data_t*)a)->msg;
	msg_b = ((sort_data_t*)b)->msg;
	
	for (cur = current_list; cur != NULL; cur = cur->next) {
		ret = cur->sort(msg_a, msg_b);
		if (reverse_sort) {
			if (ret == 1)
				ret = -1;
			else if (ret == -1)
				ret = 1;
		}
		if (ret != 0)
			return ret;
	}
	return ret;
}

static int msg_field_compare(const msg_t *a, const msg_t *b)
{
	if (a->msg_type < b->msg_type)
		return -1; /* a=avc msg, b=load policy msg */
	if (a->msg_type == b->msg_type) {
		if (a->msg_type != AVC_MSG)
			return 0;  /* a = b */
		if (a->msg_data.avc_msg->msg < b->msg_data.avc_msg->msg)
			return -1; /* a=denied, b=granted */
		if (a->msg_data.avc_msg->msg > b->msg_data.avc_msg->msg)
			return 1;  /* a=granted, b=denied */
		return 0; /* a = b */
	}
	return 1; /* a=load policy msg, b=avc msg */
}

static int perm_compare(const msg_t *a, const msg_t *b)
{
	return strcmp(audit_log_get_perm(audit_log, msg_get_avc_data(a)->perms[0]), 
		      audit_log_get_perm(audit_log, msg_get_avc_data(b)->perms[0]));
}

static int date_compare(const msg_t *a, const msg_t *b)
{
	time_t at, bt;
	double diff;

	at = mktime(a->date_stamp);
	bt = mktime(b->date_stamp);

	diff = difftime(at, bt);

	if (diff < 0)
		return -1;
	else if (diff > 0)
		return 1;
	else
		return 0;

}

static int host_field_compare(const msg_t *a, const msg_t *b)
{
	int i_a, i_b;
	const char *sa, *sb;

	i_a = a->host;
	i_b = b->host;

	if (i_a < 0)
		return -1;
	if (i_b < 0)
		return 1;

	sa = audit_log_get_host(audit_log, i_a);
	sb = audit_log_get_host(audit_log, i_b);

	assert(sa && sb);

	return strcmp(sa, sb);
}

static int src_user_compare(const msg_t *a, const msg_t *b)
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

static int tgt_user_compare(const msg_t *a, const msg_t *b)
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

static int src_role_compare(const msg_t *a, const msg_t *b)
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

static int tgt_role_compare(const msg_t *a, const msg_t *b)
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

static int src_type_compare(const msg_t *a, const msg_t *b)
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

static int tgt_type_compare(const msg_t *a, const msg_t *b)
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

static int obj_class_compare(const msg_t *a, const msg_t *b)
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

static int exe_compare(const msg_t *a, const msg_t *b)
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

static int path_compare(const msg_t *a, const msg_t *b)
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

static int dev_compare(const msg_t *a, const msg_t *b)
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

static int inode_compare(const msg_t *a, const msg_t *b)
{
	if (msg_get_avc_data(a)->inode == msg_get_avc_data(b)->inode) {
		return 0;
	} else if (msg_get_avc_data(a)->inode < msg_get_avc_data(b)->inode) {
		return -1;
	} else {
		return 1;
	}
}

static int pid_compare(const msg_t *a, const msg_t *b)
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
	cl = (sort_action_node_t*)malloc(sizeof(sort_action_node_t));
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
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG;
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
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG;
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
	node->msg_types = AVC_MSG | LOAD_POLICY_MSG;
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
