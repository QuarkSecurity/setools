/**
 *  @file sort.h
 *  Public interface to a seaudit_sort_t.  This represents an abstract
 *  object that specifies how to sort messages within a particular
 *  seaudit_model_t.  The caller obtains a sort object and appends it
 *  to a model via seaudit_model_append_search().
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

#ifndef SEAUDIT_SORT_H
#define SEAUDIT_SORT_H

typedef struct seaudit_sort seaudit_sort_t;

/**
 * Destroy the referenced seaudit_sort_t object.
 *
 * @param sort Sort object to destroy.  The pointer will be set to
 * NULL afterwards.  (If pointer is already NULL then do nothing.)
 */
extern void seaudit_sort_destroy(seaudit_sort_t ** sort);

/**
 * Instruct a model to sort messages by host name, alphabetically.
 *
 * @param direction Direction to sort.  Non-negative for ascending,
 * negative for descending.
 *
 * @return Sort object for this criterion, or NULL upon error.  The
 * caller is responsible for calling seaudit_sort_destroy()
 * afterwards.
 */
extern seaudit_sort_t *seaudit_sort_by_host(int direction);

#if 0
struct sort_action_node;
typedef int (*sort_action_t) (const msg_t * a, const msg_t * b);

typedef struct sort_action_node
{
	int msg_types;
	sort_action_t sort;
	struct sort_action_node *prev;
	struct sort_action_node *next;
} sort_action_node_t;

sort_action_node_t *msg_sort_action_create(void);
sort_action_node_t *host_sort_action_create(void);
sort_action_node_t *perm_sort_action_create(void);
sort_action_node_t *date_sort_action_create(void);
sort_action_node_t *src_user_sort_action_create(void);
sort_action_node_t *tgt_user_sort_action_create(void);
sort_action_node_t *src_role_sort_action_create(void);
sort_action_node_t *tgt_role_sort_action_create(void);
sort_action_node_t *src_type_sort_action_create(void);
sort_action_node_t *tgt_type_sort_action_create(void);
sort_action_node_t *obj_class_sort_action_create(void);
sort_action_node_t *exe_sort_action_create(void);
sort_action_node_t *comm_sort_action_create(void);
sort_action_node_t *path_sort_action_create(void);
sort_action_node_t *dev_sort_action_create(void);
sort_action_node_t *inode_sort_action_create(void);
sort_action_node_t *pid_sort_action_create(void);
#endif

#endif
