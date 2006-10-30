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

#include <apol/util.h>

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

static seaudit_sort_t *sort_create(sort_comp_func * comp, sort_supported_func support, int direction)
{
	seaudit_sort_t *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		return NULL;
	}
	s->comp = comp;
	s->support = support;
	s->direction = direction;
	return s;
}

static int sort_message_type_comp(seaudit_sort_t * sort
				  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	if (a->type != b->type) {
		return a->type - b->type;
	}
	if (a->type == SEAUDIT_MESSAGE_TYPE_AVC) {
		return a->data.avc->msg - b->data.avc->msg;
	}
	return 0;
}

static int sort_message_type_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type != SEAUDIT_MESSAGE_TYPE_INVALID;
}

seaudit_sort_t *seaudit_sort_by_message_type(int direction)
{
	return sort_create(sort_message_type_comp, sort_message_type_support, direction);
}

/**
 * Given two dates compare them, checking to see if the dates passed
 * in have valid years and correcting if not before comparing.
 */
static int sort_date_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* tm has year, month, day, hour, min, sec */
	/* if we should compare the years */
	struct tm *t1 = a->date_stamp;
	struct tm *t2 = b->date_stamp;
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

static int sort_date_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->date_stamp != NULL;
}

seaudit_sort_t *seaudit_sort_by_date(int direction)
{
	return sort_create(sort_date_comp, sort_date_support, direction);
}

static int sort_host_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->host, b->host);
}

static int sort_host_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->host != NULL;
}

seaudit_sort_t *seaudit_sort_by_host(int direction)
{
	return sort_create(sort_host_comp, sort_host_support, direction);
}

static int sort_perm_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	size_t i;
	return apol_vector_compare(a->data.avc->perms, b->data.avc->perms, apol_str_strcmp, NULL, &i);
}

static int sort_perm_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC &&
		msg->data.avc->perms != NULL && apol_vector_get_size(msg->data.avc->perms) >= 1;
}

seaudit_sort_t *seaudit_sort_by_permission(int direction)
{
	return sort_create(sort_perm_comp, sort_perm_support, direction);
}

static int sort_source_user_comp(seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->suser, b->data.avc->suser);
}

static int sort_source_user_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->suser != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_user(int direction)
{
	return sort_create(sort_source_user_comp, sort_source_user_support, direction);
}

static int sort_source_role_comp(seaudit_sort_t * sort __attribute((unused)), const seaudit_message_t * a,
				 const seaudit_message_t * b)
{
	return strcmp(a->data.avc->srole, b->data.avc->srole);
}

static int sort_source_role_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->srole != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_role(int direction)
{
	return sort_create(sort_source_role_comp, sort_source_role_support, direction);
}

static int sort_source_type_comp(seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->stype, b->data.avc->stype);
}

static int sort_source_type_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->stype != NULL;
}

seaudit_sort_t *seaudit_sort_by_source_type(int direction)
{
	return sort_create(sort_source_type_comp, sort_source_type_support, direction);
}

static int sort_target_user_comp(seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tuser, b->data.avc->tuser);
}

static int sort_target_user_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tuser != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_user(int direction)
{
	return sort_create(sort_target_user_comp, sort_target_user_support, direction);
}

static int sort_target_role_comp(seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->trole, b->data.avc->trole);
}

static int sort_target_role_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->trole != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_role(int direction)
{
	return sort_create(sort_target_role_comp, sort_target_role_support, direction);
}

static int sort_target_type_comp(seaudit_sort_t * sort
				 __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->ttype, b->data.avc->ttype);
}

static int sort_target_type_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->ttype != NULL;
}

seaudit_sort_t *seaudit_sort_by_target_type(int direction)
{
	return sort_create(sort_target_type_comp, sort_target_type_support, direction);
}

static int sort_object_class_comp(seaudit_sort_t * sort
				  __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->tclass, b->data.avc->tclass);
}

static int sort_object_class_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->tclass != NULL;
}

seaudit_sort_t *seaudit_sort_by_object_class(int direction)
{
	return sort_create(sort_object_class_comp, sort_object_class_support, direction);
}

static int sort_executable_comp(seaudit_sort_t * sort
				__attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->exe, b->data.avc->exe);
}

static int sort_executable_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->exe != NULL;
}

seaudit_sort_t *seaudit_sort_by_executable(int direction)
{
	return sort_create(sort_executable_comp, sort_executable_support, direction);
}

static int sort_command_comp(seaudit_sort_t * sort
			     __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->comm, b->data.avc->comm);
}

static int sort_command_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->comm != NULL;
}

seaudit_sort_t *seaudit_sort_by_command(int direction)
{
	return sort_create(sort_command_comp, sort_command_support, direction);
}

static int sort_path_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->path, b->data.avc->path);
}

static int sort_path_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->path != NULL;
}

seaudit_sort_t *seaudit_sort_by_path(int direction)
{
	return sort_create(sort_path_comp, sort_path_support, direction);
}

static int sort_device_comp(seaudit_sort_t * sort
			    __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	return strcmp(a->data.avc->dev, b->data.avc->dev);
}

static int sort_device_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->dev != NULL;
}

seaudit_sort_t *seaudit_sort_by_device(int direction)
{
	return sort_create(sort_device_comp, sort_device_support, direction);
}

static int sort_inode_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* need this logic because inodes are unsigned, so subtraction
	 * could overflow */
	if (a->data.avc->inode < b->data.avc->inode) {
		return -1;
	}
	return a->data.avc->inode - b->data.avc->inode;
}

static int sort_inode_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->inode > 0;
}

seaudit_sort_t *seaudit_sort_by_inode(int direction)
{
	return sort_create(sort_inode_comp, sort_inode_support, direction);
}

static int sort_pid_comp(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * a, const seaudit_message_t * b)
{
	/* need this logic because pids are unsigned, so subtraction
	 * could overflow */
	if (a->data.avc->pid < b->data.avc->pid) {
		return -1;
	}
	return a->data.avc->pid - b->data.avc->pid;
}

static int sort_pid_support(seaudit_sort_t * sort __attribute__ ((unused)), const seaudit_message_t * msg)
{
	return msg->type == SEAUDIT_MESSAGE_TYPE_AVC && msg->data.avc->pid > 0;
}

seaudit_sort_t *seaudit_sort_by_pid(int direction)
{
	return sort_create(sort_pid_comp, sort_pid_support, direction);
}

/******************** protected functions below ********************/

int sort_is_supported(seaudit_sort_t * sort, const seaudit_message_t * msg)
{
	return sort->support(sort, msg);
}

int sort_comp(seaudit_sort_t * sort, const seaudit_message_t * a, const seaudit_message_t * b)
{
	int retval = sort->comp(sort, a, b);
	return (sort->direction >= 0 ? retval : -1 * retval);
}
