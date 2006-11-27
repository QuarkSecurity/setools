/**
 *  @file message_view.c
 *  Implementation of the view for a libseaudit model.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "message_view.h"

#include <errno.h>
#include <string.h>

struct message_view
{
	seaudit_model_t *model;
	toplevel_t *top;
	GtkWidget *w;
};

message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model)
{
	message_view_t *view;

	GtkWidget *tree_view;
	GtkTreeSelection *selection;

	if ((view = calloc(1, sizeof(*view))) == NULL) {
		int error = errno;
		toplevel_ERR(top, "%s", strerror(error));
		message_view_destroy(&view);
		errno = error;
		return NULL;
	}
	view->model = model;
	view->top = top;

	view->w = gtk_scrolled_window_new(NULL, NULL);
	tree_view = gtk_tree_view_new();
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_container_add(GTK_CONTAINER(view->w), tree_view);
	gtk_widget_show(tree_view);
	gtk_widget_show(view->w);

	/*
	 * g_signal_connect(G_OBJECT(tree_view), "row_activated", G_CALLBACK(message_view_on_select), view);
	 * g_signal_connect(G_OBJECT(tree_view), "button-press-event", G_CALLBACK(message_view_on_button_press), view);
	 * g_signal_connect(G_OBJECT(tree_view), "popup-menu", G_CALLBACK(message_view_on_popup_menu), view);
	 */
	/*
	 * seaudit_window_create_list(GTK_TREE_VIEW(tree_view), column_visibility);
	 * view = seaudit_filtered_view_create(log, GTK_TREE_VIEW(tree_view), view_name);
	 */
	return view;
}

void message_view_destroy(message_view_t ** view)
{
	if (view != NULL && *view != NULL) {
		seaudit_model_destroy(&(*view)->model);
		free(*view);
		*view = NULL;
	}
}

GtkWidget *message_view_get_view(message_view_t * view)
{
	return view->w;
}

#if 0

#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <string.h>

seaudit_filtered_view_t *seaudit_filtered_view_create(audit_log_t * log, GtkTreeView * tree_view, const char *view_name)
{
	seaudit_filtered_view_t *filtered_view;

	if (tree_view == NULL)
		return NULL;

	filtered_view = (seaudit_filtered_view_t *) malloc(sizeof(seaudit_filtered_view_t));
	if (filtered_view == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(filtered_view, 0, sizeof(seaudit_filtered_view_t));
	if ((filtered_view->multifilter_window = multifilter_window_create(filtered_view, view_name)) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view);
		return NULL;
	}
	if ((filtered_view->store = seaudit_log_view_store_create()) == NULL) {
		fprintf(stderr, "out of memory");
		free(filtered_view->multifilter_window);
		free(filtered_view);
		return NULL;
	}
	filtered_view->notebook_index = -1;
	filtered_view->tree_view = tree_view;
	filtered_view->name = g_string_new(view_name);
	seaudit_log_view_store_open_log(filtered_view->store, log);
	gtk_tree_view_set_model(tree_view, GTK_TREE_MODEL(filtered_view->store));

	return filtered_view;
}

void seaudit_filtered_view_destroy(seaudit_filtered_view_t * view)
{
	multifilter_window_destroy(view->multifilter_window);
	seaudit_log_view_store_close_log(view->store);
	g_string_free(view->name, TRUE);
}

void seaudit_filtered_view_display(seaudit_filtered_view_t * filtered_view, GtkWindow * parent)
{
	if (!filtered_view)
		return;
	multifilter_window_display(filtered_view->multifilter_window, parent);
}

void seaudit_filtered_view_set_log(seaudit_filtered_view_t * view, audit_log_t * log)
{
	if (view == NULL)
		return;
	seaudit_log_view_store_close_log(view->store);
	seaudit_log_view_store_open_log(view->store, log);
}

void seaudit_filtered_view_save_view(seaudit_filtered_view_t * filtered_view, gboolean saveas)
{
	if (!filtered_view)
		return;
	multifilter_window_save_multifilter(filtered_view->multifilter_window, saveas, FALSE);
}

void seaudit_filtered_view_set_multifilter_window(seaudit_filtered_view_t * filtered_view, multifilter_window_t * window)
{
	multifilter_window_destroy(filtered_view->multifilter_window);
	filtered_view->multifilter_window = window;
	g_string_assign(window->name, filtered_view->name->str);
	window->parent = filtered_view;
}

void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t * filtered_view, gint index)
{
	if (filtered_view == NULL)
		return;
	filtered_view->notebook_index = index;
}

void seaudit_filtered_view_do_filter(seaudit_filtered_view_t * view, gpointer user_data)
{
	if (!view)
		return;
	multifilter_window_apply_multifilter(view->multifilter_window);
}

#endif
