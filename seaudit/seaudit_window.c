/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date : January 22, 2004
 * Modified: don.patterson@tresys.com 10-2004
 */

#include "seaudit_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include "query_window.h"
#include <string.h>

static int seaudit_window_view_matches_tab_index(gconstpointer data, gconstpointer index);
static int seaudit_window_create_list(GtkTreeView * view, bool_t visibility[]);
static GtkTreeViewColumn *seaudit_window_create_column(GtkTreeView * view, const char *name,
						       GtkCellRenderer * renderer, int field, int max_width, bool_t visibility[]);
static void seaudit_window_on_log_column_clicked(GtkTreeViewColumn * column, gpointer user_data);
static void seaudit_window_close_view(GtkButton * button, seaudit_window_t * window);
static void seaudit_window_on_notebook_switch_page(GtkNotebook * notebook, GtkNotebookPage * page, guint pagenum,
						   seaudit_window_t * window);

extern seaudit_t *seaudit_app;

static void
seaudit_window_tree_view_onSelect_ViewEntireMsg(GtkTreeView * treeview,
						GtkTreePath * path, GtkTreeViewColumn * column, gpointer user_data)
{
	/* we passed the view as userdata when we connected the signal */
	seaudit_window_view_entire_message_in_textbox(NULL);
}

static void seaudit_window_popup_menu_on_view_msg(GtkWidget * menuitem, gpointer user_data)
{
	int idx = GPOINTER_TO_INT(user_data);

	seaudit_window_view_entire_message_in_textbox(&idx);
}

static void seaudit_window_popup_menu_on_query_policy(GtkWidget * menuitem, gpointer user_data)
{
	int idx = GPOINTER_TO_INT(user_data);

	query_window_create(&idx);
}

static void seaudit_window_popup_menu_on_export_selection(GtkWidget * menuitem, gpointer userdata)
{
	seaudit_on_export_selection_activated();
}

static void seaudit_window_popup_menu(GtkWidget * treeview, GdkEventButton * event, int *idx)
{
	GtkWidget *menu, *menuitem, *menuitem2, *menuitem3;
	gint data = *idx;

	menu = gtk_menu_new();
	if (menu == NULL) {
		fprintf(stderr, "Unable to create menu widget.\n");
		return;
	}
	menuitem = gtk_menu_item_new_with_label("View Entire Message");
	menuitem2 = gtk_menu_item_new_with_label("Query Policy using Message");
	menuitem3 = gtk_menu_item_new_with_label("Export Messages to File");
	if (menuitem == NULL || menuitem2 == NULL || menuitem3 == NULL) {
		fprintf(stderr, "Unable to create menuitem widgets.\n");
		return;
	}

	g_signal_connect(menuitem, "activate", (GCallback) seaudit_window_popup_menu_on_view_msg, GINT_TO_POINTER(data));
	g_signal_connect(menuitem2, "activate", (GCallback) seaudit_window_popup_menu_on_query_policy, GINT_TO_POINTER(data));
	g_signal_connect(menuitem3, "activate", (GCallback) seaudit_window_popup_menu_on_export_selection, NULL);

	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem2);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem3);

	gtk_widget_show_all(menu);

	/* Note: event can be NULL here when called from seaudit_window_onPopupMenu;
	 *  gdk_event_get_time() accepts a NULL argument */
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
		       (event != NULL) ? event->button : 0, gdk_event_get_time((GdkEvent *) event));
}

static gboolean seaudit_window_onButtonPressed(GtkWidget * treeview, GdkEventButton * event, gpointer userdata)
{
	GtkTreePath *path;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GList *glist = NULL;
	GtkTreeIter iter;
	int fltr_msg_idx;

	/* single click with the right mouse button? */
	if (event->type == GDK_BUTTON_PRESS && event->button == 3) {
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));

		/* Get tree path for row that was clicked */
		if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), event->x, event->y, &path, NULL, NULL, NULL)) {
			glist = gtk_tree_selection_get_selected_rows(selection, &model);
			if (glist == NULL) {
				gtk_tree_path_free(path);
				return FALSE;
			}
			if (gtk_tree_model_get_iter(model, &iter, path) == 0) {
				fprintf(stderr, "Could not get valid iterator for the selected path.\n");
				gtk_tree_path_free(path);
				g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
				g_list_free(glist);
				return FALSE;
			}
			fltr_msg_idx = seaudit_log_view_store_iter_to_idx((SEAuditLogViewStore *) model, &iter);

			seaudit_window_popup_menu(treeview, event, &fltr_msg_idx);
			g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
			g_list_free(glist);
			gtk_tree_path_free(path);
		}
		return TRUE;	       /* we handled this */
	} else if (event->type == GDK_BUTTON_PRESS && event->button == 1) {
		/* remember that we don't care about deselection, because you can't
		 * deselect rows so something will always be selected unless we reload */
		seaudit_view_entire_selection_update_sensitive(FALSE);
	}
	return FALSE;		       /* we did not handle this */
}

static gboolean seaudit_window_onPopupMenu(GtkWidget * treeview, gpointer userdata)
{
	seaudit_window_popup_menu(treeview, NULL, NULL);

	return TRUE;		       /* we handled this */
}

void seaudit_window_open_view(seaudit_window_t * window, audit_log_t * log, bool_t * column_visibility)
{
	multifilter_window_t *multifilter_window;
	seaudit_filtered_view_t *view;

	if (!window)
		return;
	multifilter_window = multifilter_window_create(NULL, NULL);
	if (multifilter_window_load_multifilter(multifilter_window) != 0) {
		multifilter_window_destroy(multifilter_window);
		return;
	}
	if (strcmp(multifilter_window->name->str, "") != 0)
		view = seaudit_window_add_new_view(window, log, column_visibility, multifilter_window->name->str);
	else
		view = seaudit_window_add_new_view(window, log, column_visibility, NULL);

	seaudit_filtered_view_set_multifilter_window(view, multifilter_window);
	seaudit_filtered_view_do_filter(view, NULL);
}

int seaudit_window_get_num_views(seaudit_window_t * window)
{
	if (!window)
		return -1;
	return gtk_notebook_get_n_pages(window->notebook);
}

void seaudit_window_save_current_view(seaudit_window_t * window, gboolean saveas)
{
	seaudit_filtered_view_t *view;

	if (!window)
		return;
	view = seaudit_window_get_current_view(window);
	g_assert(view);
	seaudit_filtered_view_save_view(view, saveas);
}

void seaudit_window_filter_views(seaudit_window_t * window)
{
	if (!window)
		return;
	g_list_foreach(window->views, (GFunc) seaudit_filtered_view_do_filter, NULL);
}

/*
 * Helper function for seaudit_window_t object
 */
static int seaudit_window_view_matches_tab_index(gconstpointer data, gconstpointer index)
{
	seaudit_filtered_view_t *view;
	if (!data) {
		return -1;
	}
	view = (seaudit_filtered_view_t *) data;
	if (view->notebook_index == GPOINTER_TO_INT(index))
		return 0;
	return 1;
}

/*
 * Gtk Callbacks registered by seaudit_window_t
 */
static void seaudit_window_on_log_column_clicked(GtkTreeViewColumn * column, gpointer user_data)
{
	GtkTreeSelection *selection;
	GList *selected_rows;
	GtkTreePath *path;
	GtkTreeModel *model;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(user_data));
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(user_data));
	selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
	if (selected_rows == NULL)
		return;
	path = selected_rows->data;
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(user_data), path, NULL, FALSE, 0.0, 0.0);
}

static void seaudit_window_on_notebook_switch_page(GtkNotebook * notebook, GtkNotebookPage * page, guint pagenum,
						   seaudit_window_t * window)
{
	seaudit_filtered_view_t *view;
	GtkTreeSelection *selection;

	seaudit_update_status_bar(seaudit_app);
	/* if the current page has a selected row then
	 * make sure the view entire message button is sensitive */
	if (!window)
		return;
	view = seaudit_window_get_current_view(window);
	if (view && view->tree_view) {
		selection = gtk_tree_view_get_selection(view->tree_view);
		assert(selection);
		if (gtk_tree_selection_count_selected_rows(selection) == 0)
			seaudit_view_entire_selection_update_sensitive(TRUE);
		else
			seaudit_view_entire_selection_update_sensitive(FALSE);
	}
}
