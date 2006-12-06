/**
 *  @file modify_view.h
 *  Dialog that allows the user to modify the current view.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef MODIFY_VIEW_H
#define MODIFY_VIEW_H

#include "toplevel.h"
#include "message_view.h"

/**
 * Display and run a dialog that allows the user to modify a view.
 *
 * @param top Toplevel containing message view.
 * @param view Message view to modify.
 */
void modify_view_run(toplevel_t * top, message_view_t * view);

#if 0

#include <gtk/gtk.h>
#include <glade/glade.h>

struct filter_window;
struct seaudit_filtered_view;

typedef struct multifilter_window
{
	GladeXML *xml;
	GtkWindow *window;
	GtkListStore *liststore;
	GtkTreeView *treeview;
	gint num_filter_windows;
	GList *filter_windows;
	GString *name;
	GString *match;
	GString *show;
	GString *filename;
	struct seaudit_filtered_view *parent;
} multifilter_window_t;

multifilter_window_t *multifilter_window_create(struct seaudit_filtered_view *parent, const gchar * view_name);
void multifilter_window_init(multifilter_window_t * window, struct seaudit_filtered_view *parent, const gchar * view_name);
void multifilter_window_display(multifilter_window_t * window, GtkWindow * parent);
void multifilter_window_hide(multifilter_window_t * window);
void multifilter_window_destroy(multifilter_window_t * window);
void multifilter_window_save_multifilter(multifilter_window_t * window, gboolean saveas, gboolean multifilter_is_parent_window);
int multifilter_window_load_multifilter(multifilter_window_t * window);
void multifilter_window_set_filter_name_in_list(multifilter_window_t * window, struct filter_window *filter_window);
void multifilter_window_apply_multifilter(multifilter_window_t * window);

#endif
#endif
