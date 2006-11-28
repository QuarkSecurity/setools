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
	/** toplevel of the view, currently a scrolled_window */
	GtkWidget *w;
	/** actual GTK+ widget that displays the rows and columns of
         * message data */
	GtkWidget *tree;
	GtkListStore *store;
};

typedef seaudit_sort_t *(*sort_generator_fn_t) (int direction);

struct view_column_record
{
	preference_field_e id;
	const char *name;
	const char *sample_text;
	sort_generator_fn_t sort;
};

static const struct view_column_record column_data[] = {
	{HOST_FIELD, "Hostname", "Hostname", seaudit_sort_by_host},
	{MESSAGE_FIELD, "Message", "Message", seaudit_sort_by_message_type},
	{DATE_FIELD, "Date", "Jan 01 00:00:00", seaudit_sort_by_date},
	{SUSER_FIELD, "Source\nUser", "Source", seaudit_sort_by_source_user},
	{SROLE_FIELD, "Source\nRole", "Source", seaudit_sort_by_source_role},
	{STYPE_FIELD, "Source\nType", "unlabeled_t", seaudit_sort_by_source_type},
	{TUSER_FIELD, "Target\nUser", "Target", seaudit_sort_by_target_user},
	{TROLE_FIELD, "Target\nRole", "Target", seaudit_sort_by_target_role},
	{TTYPE_FIELD, "Target\nType", "unlabeled_t", seaudit_sort_by_target_type},
	{OBJCLASS_FIELD, "Object\nClass", "Object", seaudit_sort_by_object_class},
	{PERM_FIELD, "Permission", "Permission", seaudit_sort_by_permission},
	{EXECUTABLE_FIELD, "Executable", "/usr/bin/cat", seaudit_sort_by_executable},
	{COMMAND_FIELD, "Command", "/usr/bin/cat", seaudit_sort_by_command},
	{PID_FIELD, "PID", "12345", seaudit_sort_by_pid},
	{INODE_FIELD, "Inode", "123456", seaudit_sort_by_inode},
	{PATH_FIELD, "Path", "/home/gburdell/foo", seaudit_sort_by_path},
	{OTHER_FIELD, "Other", "Lorem ipsum dolor sit amet", NULL}
};

static const size_t num_columns = sizeof(column_data) / sizeof(column_data[0]);

message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model)
{
	message_view_t *view;
	GtkTreeSelection *selection;
	GtkCellRenderer *renderer;
	size_t i;

	if ((view = calloc(1, sizeof(*view))) == NULL) {
		int error = errno;
		toplevel_ERR(top, "%s", strerror(error));
		message_view_destroy(&view);
		errno = error;
		return NULL;
	}
	view->model = model;
	view->top = top;
	view->store = gtk_list_store_new(OTHER_FIELD + 1,
					 /* hostname */
					 G_TYPE_STRING,
					 /* message */
					 G_TYPE_STRING,
					 /* date */
					 G_TYPE_STRING,
					 /* source user */
					 G_TYPE_STRING,
					 /* source role */
					 G_TYPE_STRING,
					 /* source type */
					 G_TYPE_STRING,
					 /* target user */
					 G_TYPE_STRING,
					 /* target role */
					 G_TYPE_STRING,
					 /* target type */
					 G_TYPE_STRING,
					 /* object class */
					 G_TYPE_STRING,
					 /* permission */
					 G_TYPE_STRING,
					 /* executable */
					 G_TYPE_STRING,
					 /* command */
					 G_TYPE_STRING,
					 /* pid */
					 G_TYPE_UINT,
					 /* inode */
					 G_TYPE_ULONG,
					 /* path */
					 G_TYPE_STRING,
					 /* other */
					 G_TYPE_STRING);
	view->w = gtk_scrolled_window_new(NULL, NULL);
	view->tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(view->store));
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view->tree));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_container_add(GTK_CONTAINER(view->w), view->tree);
	gtk_widget_show(view->tree);
	gtk_widget_show(view->w);

	renderer = gtk_cell_renderer_text_new();
	for (i = 0; i < num_columns; i++) {
		struct view_column_record r = column_data[i];
		PangoLayout *layout = gtk_widget_create_pango_layout(GTK_WIDGET(view->tree), r.sample_text);
		gint width;
		GtkTreeViewColumn *column;
		pango_layout_get_pixel_size(layout, &width, NULL);
		g_object_unref(G_OBJECT(layout));
		width += 12;
		column = gtk_tree_view_column_new_with_attributes(r.name, renderer, "text", r.id, NULL);
		gtk_tree_view_column_set_clickable(column, TRUE);
		gtk_tree_view_column_set_resizable(column, TRUE);
		if (r.sort != NULL) {
			gtk_tree_view_column_set_sort_column_id(column, r.id);
			/* FIX ME
			 * g_signal_connect_after(G_OBJECT(column), "clicked", G_CALLBACK(message_view_on_column_clicked), view);
			 */
		}
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_fixed_width(column, width);
		gtk_tree_view_append_column(GTK_TREE_VIEW(view->tree), column);
	}

	/*
	 * g_signal_connect(G_OBJECT(tree_view), "row_activated", G_CALLBACK(message_view_on_select), view);
	 * g_signal_connect(G_OBJECT(tree_view), "button-press-event", G_CALLBACK(message_view_on_button_press), view);
	 * g_signal_connect(G_OBJECT(tree_view), "popup-menu", G_CALLBACK(message_view_on_popup_menu), view);
	 */
	message_view_update_visible_columns(view);
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

/**
 * Given the name of a column, return its column record data.
 */
static const struct view_column_record *get_record(const char *name)
{
	size_t i;
	for (i = 0; i < num_columns; i++) {
		const struct view_column_record *r = column_data + i;
		if (strcmp(r->name, name) == 0) {
			return r;
		}
	}
	return NULL;
}

void message_view_update_visible_columns(message_view_t * view)
{
	GList *columns, *c;
	preferences_t *prefs = toplevel_get_prefs(view->top);
	columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(view->tree));
	c = columns;
	while (c != NULL) {
		GtkTreeViewColumn *vc = GTK_TREE_VIEW_COLUMN(c->data);
		const gchar *title = gtk_tree_view_column_get_title(vc);
		const struct view_column_record *r = get_record(title);
		if (preferences_is_column_visible(prefs, r->id)) {
			gtk_tree_view_column_set_visible(vc, TRUE);
		} else {
			gtk_tree_view_column_set_visible(vc, FALSE);
		}
		c = g_list_next(c);
	}
	g_list_free(columns);
}

#if 0

#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <string.h>

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
