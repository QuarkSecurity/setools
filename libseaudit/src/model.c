/**
 *  @file model.c
 *  Implementation of seaudit_model_t.
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

struct seaudit_model {
	/** vector of seaudit_log_t pointers; this model will get
	 * messages from these logs */
	apol_vector_t *logs;
	/** vector of seaudit_message_t pointers; these point into
	 * messages from the watched logs */
	apol_vector_t *messages;
	/** vector of char * pointers; these point into malformed
	 * messages from the watched logs */
	apol_vector_t *malformed_messages;
	/** non-zero whenever this model needs to be recalculated */
	int dirty;
};

/**
 * Recalculate all of the messages associated with a particular model,
 * based upon that model's criteria.  If the model is marked as not
 * dirty then do nothing and return success.
 *
 * @param log Log to which report error messages.
 * @param model Model whose messages list to refresh.
 *
 * @return 0 on success, < 0 on error.
 */
static int model_refresh(seaudit_log_t *log, seaudit_model_t *model)
{
	size_t i, j;
	seaudit_log_t *l;
	apol_vector_t *v;
	seaudit_message_t *message;
	int error;

	if (!model->dirty) {
		return 0;
	}
	apol_vector_destroy(&model->messages, NULL);
	apol_vector_destroy(&model->malformed_messages, NULL);
	if ((model->messages = apol_vector_create()) == NULL ||
	    (model->malformed_messages = apol_vector_create()) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	for (i = 0; i < apol_vector_get_size(model->logs); i++) {
		l = apol_vector_get_element(model->logs, 1);
		v = seaudit_log_get_messages(l);
		for (j = 0; j < apol_vector_get_size(v); j++) {
			message = apol_vector_get_element(v, j);
			if (apol_vector_append(model->logs, message) < 0) {
				error = errno;
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
		}
		v = seaudit_log_get_malformed_messages(l);
		if (apol_vector_cat(model->malformed_messages, v) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}
        model->dirty = 0;
	return 0;
}

seaudit_model_t *seaudit_model_create(seaudit_log_t *log)
{
	seaudit_model_t *m = NULL;
	int error;
	if ((m = calloc(1, sizeof(*m))) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return NULL;
	}

	if ((m->logs = apol_vector_create_with_capacity(1)) == NULL ||
	    apol_vector_append(m->logs, log) < 0) {
		error = errno;
		seaudit_model_destroy(&m);
		ERR(log, "%s", strerror(error));
		errno = error;
		return NULL;
	}
        m->dirty = 1;
	return m;
}

void seaudit_model_destroy(seaudit_model_t **model)
{
	if (model == NULL || *model == NULL) {
		return;
	}
	apol_vector_destroy(&(*model)->logs, NULL);
	apol_vector_destroy(&(*model)->messages, NULL);
	free(*model);
	*model = NULL;
}

apol_vector_t *seaudit_model_get_messages(seaudit_log_t *log, seaudit_model_t *model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (model_refresh(log, model) < 0) {
		return NULL;
	}
	return log->messages;
}

apol_vector_t *seaudit_model_get_malformed_messages(seaudit_log_t *log, seaudit_model_t *model)
{
	if (log == NULL || model == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (model_refresh(log, model) < 0) {
		return NULL;
	}
	return model->malformed_messages;
}

#if 0

static void sort_kept_messages(int *kept, int num_kept, filter_info_t *info);


/* filter the log into the view */
int audit_log_view_do_filter(audit_log_view_t *view, int **deleted, int *num_deleted)
{
	filter_info_t *info;
	bool_t found, show;
	int i, j, msg_index, *kept, num_kept, *added, num_added;

	if (!view || !view->my_log)
		return -1;

	/* by default append everything that is not already filtered */
	if (!view->multifilter) {
		view->fltr_msgs = (int*)realloc(view->fltr_msgs, sizeof(int) * apol_vector_get_size(view->my_log->msg_list));
		for(i = 0; i < apol_vector_get_size(view->my_log->msg_list); i++) {
			found = FALSE;
			for (j = 0; j < view->num_fltr_msgs; j++)
				if (view->fltr_msgs[j] == i)
					found = TRUE;
			if (!found) {
				view->fltr_msgs[view->num_fltr_msgs] = i;
				view->num_fltr_msgs++;
			}
		}
		(*num_deleted) = 0;
		(*deleted) = NULL;
		return 0;
	}

	(*deleted) = (int*)malloc(sizeof(int)*view->num_fltr_msgs);
	if (!(*deleted)) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	(*num_deleted) = 0;
	kept = (int*)malloc(sizeof(int)*view->num_fltr_msgs);
	if (!kept) {
		free(*deleted);
		fprintf(stderr, "out of memory");
		return -1;
	}
	num_kept = 0;
	added = (int*)malloc(sizeof(int)*apol_vector_get_size(view->my_log->msg_list));
	if (!added) {
		free(*deleted); free(kept);
		fprintf(stderr, "out of memory");
		return -1;
	}
	num_added = 0;
	info = (filter_info_t*)malloc(sizeof(filter_info_t)*apol_vector_get_size(view->my_log->msg_list));
	if (!info) {
		free(*deleted); free(kept); free(added);
		fprintf(stderr, "out of memory");
		return -1;
	}
	memset(info, 0, sizeof(filter_info_t) * apol_vector_get_size(view->my_log->msg_list));
	for (i = 0; i < view->num_fltr_msgs; i++) {
		msg_index = view->fltr_msgs[i];
		info[msg_index].orig_indx = i;
		info[msg_index].filtered = TRUE;
	}
	/* filter log into view */
	audit_log_view_purge_fltr_msgs(view);
        seaudit_multifilter_make_dirty_filters(view->multifilter);
	for (i = 0; i < apol_vector_get_size(view->my_log->msg_list); i++) {
		msg_t *msg;
		msg = apol_vector_get_element(view->my_log->msg_list, i);
		show = seaudit_multifilter_should_message_show(view->multifilter, msg, view->my_log);
		if (show) {
			if (info[i].filtered == TRUE) {
				kept[num_kept] = i;
				num_kept++;
			} else {
				added[num_added] = i;
				num_added++;
			}
			view->num_fltr_msgs++;
		} else {
			if (info[i].filtered == TRUE) {
				(*deleted)[(*num_deleted)] = info[i].orig_indx;
				(*num_deleted)++;
			}
		}
	}

	sort_kept_messages(kept, num_kept, info);
	free(info);
	view->fltr_msgs = (int*)malloc(sizeof(int)*(num_kept+num_added));
	if (!view->fltr_msgs) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	memcpy(view->fltr_msgs, kept, sizeof(int) * num_kept);
	memcpy(&view->fltr_msgs[num_kept], added, sizeof(int) * (num_added));
	free(added); free(kept);
	return 0;
}

static void sort_kept_messages(int *kept, int num_kept, filter_info_t *info)
{
	int i, j, msg_a, msg_b, tmp;
	for (j = 0; j < num_kept; j++) {
		for (i = 0; i < num_kept-1-j; i++) {
			msg_a = kept[i];
			msg_b = kept[i+1];
			if (info[msg_a].orig_indx > info[msg_b].orig_indx) {
				tmp = kept[i];
				kept[i] = kept[i+1];
				kept[i+1] = tmp;
			}
		}
	}
	return;
}

#endif
