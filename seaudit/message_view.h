/**
 *  @file message_view.h
 *  Declaration of a single tab within the main notebook, showing
 *  all messages within a libseaudit model.
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

#ifndef MESSAGE_VIEW_H
#define MESSAGE_VIEW_H

#include "toplevel.h"

#include <gtk/gtk.h>
#include <seaudit/model.h>

typedef struct message_view message_view_t;

/**
 * Allocate a new view for a particular model.
 *
 * @param top Handle to the controlling toplevel widget.
 * @param model libseaudit model to display.  The view takes ownership
 * of the model afterwards.
 *
 * @return A newly allocated view, or NULL upon error.  The caller is
 * responsible for calling message_view_destroy() afterwards.
 */
message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model);

/**
 * Destroy a view and free its memory.  This does nothing if the
 * pointer is set to NULL.
 *
 * @param view Reference to a toplevel object.  Afterwards the pointer
 * will be set to NULL.
 */
void message_view_destroy(message_view_t ** view);

/**
 * Get the message view's widget display.  This widget will be placed
 * in a container for the user to see.
 *
 * @param view View whose widget to obtain.
 *
 * @return View's widget.
 */
GtkWidget *message_view_get_view(message_view_t * view);

/**
 * Show/hide columns in a view based upon the user's current
 * preferences.
 *
 * @param view View's columns to update.
 */
void message_view_update_visible_columns(message_view_t * view);

#if 0

#include <gtk/gtk.h>
#include <glade/glade.h>
#include "multifilter_window.h"
#include "auditlogmodel.h"

typedef struct seaudit_filtered_view
{
	multifilter_window_t *multifilter_window;
	SEAuditLogViewStore *store;
	GtkTreeView *tree_view;
	gint notebook_index;
	GString *name;
} seaudit_filtered_view_t;

/*
 * Public member functions
 */
void seaudit_filtered_view_set_log(seaudit_filtered_view_t * view, audit_log_t * log);
void seaudit_filtered_view_display(seaudit_filtered_view_t * filters_view, GtkWindow * parent);
void seaudit_filtered_view_save_view(seaudit_filtered_view_t * filtered_view, gboolean saveas);
void seaudit_filtered_view_set_notebook_index(seaudit_filtered_view_t * filtered_view, gint index);
void seaudit_filtered_view_set_multifilter_window(seaudit_filtered_view_t * filtered_view, multifilter_window_t * window);
void seaudit_filtered_view_do_filter(seaudit_filtered_view_t * view, gpointer user_data);	/* this can be used as a callback from g_list_foreach() */
void seaudit_filtered_view_set_name(seaudit_filtered_view_t * filtered_view, const char *name);

#endif
#endif
