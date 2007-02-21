/**
 *  @file
 *  Routines for displaying the results after running poldiff.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "result_item.h"
#include "results.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>
#include <qpol/cond_query.h>

enum
{
	RESULTS_SUMMARY_COLUMN_LABEL = 0,
	RESULTS_SUMMARY_COLUMN_FORM,
	RESULTS_SUMMARY_COLUMN_ITEM,
	RESULTS_SUMMARY_COLUMN_NUM
};

#define NUM_RESULT_ITEMS 1

struct results
{
	toplevel_t *top;
	GladeXML *xml;
	GtkTreeStore *summary_tree;
	GtkTreeView *summary_view;
	GtkTextBuffer *main_buffer, *key_buffer;
	GtkTextView *view;
	GtkTextTag *policy_orig_tag, *policy_mod_tag;
	GtkLabel *stats;
	result_item_t *items[NUM_RESULT_ITEMS];
};

static const poldiff_form_e form_map[] = {
	POLDIFF_FORM_ADDED, POLDIFF_FORM_ADD_TYPE,
	POLDIFF_FORM_REMOVED, POLDIFF_FORM_REMOVE_TYPE,
	POLDIFF_FORM_MODIFIED
};

static void results_summary_on_change(GtkTreeSelection * selection, gpointer user_data);

static gboolean results_on_line_event(GtkTextTag * tag, GObject * event_object,
				      GdkEvent * event, const GtkTextIter * iter, gpointer user_data);
static gboolean results_on_text_view_motion(GtkWidget * widget, GdkEventMotion * event, gpointer user_data);
/**
 * Callback whenever the user double-clicks a row in the summary tree.
 */
static void results_summary_on_row_activate(GtkTreeView * tree_view, GtkTreePath * path, GtkTreeViewColumn * column,
					    gpointer user_data);

/**
 * Build a GTK tree store to hold the summary table of contents; then
 * add that (empty) tree to the tree view.
 */
static void results_create_summary(results_t * r)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;

	r->summary_tree = gtk_tree_store_new(RESULTS_SUMMARY_COLUMN_NUM, G_TYPE_STRING, G_TYPE_INT, G_TYPE_POINTER);
	r->summary_view = GTK_TREE_VIEW(glade_xml_get_widget(r->xml, "toplevel summary view"));
	assert(r->summary_view != NULL);
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_title(col, "Differences");
	gtk_tree_view_append_column(r->summary_view, col);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", RESULTS_SUMMARY_COLUMN_LABEL);
	gtk_tree_view_set_model(r->summary_view, GTK_TREE_MODEL(r->summary_tree));

	selection = gtk_tree_view_get_selection(r->summary_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
	g_signal_connect(G_OBJECT(selection), "changed", G_CALLBACK(results_summary_on_change), r);
	g_signal_connect(r->summary_view, "row-activated", G_CALLBACK(results_summary_on_row_activate), r);
}

results_t *results_create(toplevel_t * top)
{
	results_t *r;
	int i;
	GtkTextTagTable *tag_table;
	GtkTextAttributes *attr;
	GtkTextView *text_view;
	gint size;
	PangoTabArray *tabs;

	if ((r = calloc(1, sizeof(*r))) == NULL) {
		return NULL;
	}
	r->top = top;
	r->xml = glade_get_widget_tree(GTK_WIDGET(toplevel_get_window(r->top)));
	results_create_summary(r);

	tag_table = gtk_text_tag_table_new();
	r->main_buffer = gtk_text_buffer_new(tag_table);
	gtk_text_buffer_create_tag(r->main_buffer, "header", "style", PANGO_STYLE_ITALIC, "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "subheader",
				   "family", "monospace", "weight", PANGO_WEIGHT_BOLD, "underline", PANGO_UNDERLINE_SINGLE, NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "removed-header",
				   "family", "monospace", "foreground", "red", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "added-header",
				   "family", "monospace", "foreground", "dark green", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "modified-header",
				   "family", "monospace", "foreground", "dark blue", "weight", PANGO_WEIGHT_BOLD, NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "removed", "family", "monospace", "foreground", "red", NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "added", "family", "monospace", "foreground", "dark green", NULL);
	gtk_text_buffer_create_tag(r->main_buffer, "modified", "family", "monospace", "foreground", "dark blue", NULL);
	r->policy_orig_tag = gtk_text_buffer_create_tag(r->main_buffer, "line-pol_orig",
							"family", "monospace",
							"foreground", "blue", "underline", PANGO_UNDERLINE_SINGLE, NULL);
	g_signal_connect_after(G_OBJECT(r->policy_orig_tag), "event", G_CALLBACK(results_on_line_event), r);
	r->policy_mod_tag = gtk_text_buffer_create_tag(r->main_buffer, "line-pol_mod",
						       "family", "monospace",
						       "foreground", "blue", "underline", PANGO_UNDERLINE_SINGLE, NULL);
	g_signal_connect_after(G_OBJECT(r->policy_mod_tag), "event", G_CALLBACK(results_on_line_event), r);

	r->view = GTK_TEXT_VIEW(glade_xml_get_widget(r->xml, "toplevel results view"));
	assert(r->view != NULL);
	g_signal_connect(G_OBJECT(r->view), "motion-notify-event", G_CALLBACK(results_on_text_view_motion), r);
	attr = gtk_text_view_get_default_attributes(r->view);
	size = pango_font_description_get_size(attr->font);
	tabs = pango_tab_array_new_with_positions(4,
						  FALSE,
						  PANGO_TAB_LEFT, 3 * size,
						  PANGO_TAB_LEFT, 6 * size, PANGO_TAB_LEFT, 9 * size, PANGO_TAB_LEFT, 12 * size);
	gtk_text_view_set_tabs(r->view, tabs);
	gtk_text_view_set_buffer(r->view, r->main_buffer);

	r->key_buffer = gtk_text_buffer_new(tag_table);
	text_view = GTK_TEXT_VIEW(glade_xml_get_widget(r->xml, "toplevel key view"));
	assert(text_view != NULL);
	gtk_text_view_set_buffer(text_view, r->key_buffer);

	r->stats = GTK_LABEL((glade_xml_get_widget(r->xml, "toplevel stats label")));
	assert(r->stats != NULL);
	gtk_label_set_text(r->stats, "");

	result_item_t *(*result_item_constructors[NUM_RESULT_ITEMS]) (GtkTextTagTable *) = {
	result_item_create_classes};
	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		if ((r->items[i] = result_item_constructors[i] (tag_table)) == NULL) {
			results_destroy(&r);
			return NULL;
		}
	}
	return r;
}

void results_destroy(results_t ** r)
{
	if (r != NULL && *r != NULL) {
		int i;
		for (i = 0; i < NUM_RESULT_ITEMS; i++) {
			result_item_destroy(&((*r)->items[i]));
		}
		free(*r);
		*r = NULL;
	}
}

void results_open_policies(results_t * r, apol_policy_t * orig, apol_policy_t * mod)
{
	int i;
	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		result_item_policy_changed(r->items[i], orig, mod);
	}
}

void results_clear(results_t * r)
{
	gtk_tree_store_clear(r->summary_tree);
	gtk_text_view_set_buffer(r->view, r->main_buffer);
	util_text_buffer_clear(r->main_buffer);
	util_text_buffer_clear(r->key_buffer);
	gtk_label_set_text(r->stats, "");
}

/**
 * Update the summary tree and summary buffer to reflect the number of
 * items added/removed/modified.
 */
static void results_update_summary(results_t * r)
{
	GtkTreeIter topiter, childiter;
	GtkTextIter iter;
	size_t sum_diffs;
	int i, j, forms[5];
	GString *s = g_string_new("");
	poldiff_t *diff = toplevel_get_poldiff(r->top);
	assert(diff != NULL);

	gtk_tree_store_append(r->summary_tree, &topiter, NULL);
	gtk_tree_store_set(r->summary_tree, &topiter,
			   RESULTS_SUMMARY_COLUMN_LABEL, "Summary",
			   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_NONE, RESULTS_SUMMARY_COLUMN_ITEM, NULL, -1);
	gtk_text_buffer_get_start_iter(r->main_buffer, &iter);
	gtk_text_buffer_insert_with_tags_by_name(r->main_buffer, &iter, "Policy Difference Statistics\n\n", -1, "header", NULL);
	static const char *form_name_map[] = {
		"Added", "Added Type", "Removed", "Removed Type", "Modified"
	};

	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		if (result_item_is_supported(r->items[i])) {
			const char *label;
			gtk_tree_store_append(r->summary_tree, &topiter, NULL);
			result_item_get_forms(r->items[i], forms);
			label = result_item_get_label(r->items[i]);
			sum_diffs = 0;
			g_string_printf(s, "%s:\n", label);
			gtk_text_buffer_insert_with_tags_by_name(r->main_buffer, &iter, s->str, -1, "subheader", NULL);
			for (j = 0; j < 5; j++) {
				if (forms[j] > 0) {
					size_t num_diffs;
					num_diffs = result_item_get_num_differences(r->items[i], form_map[j]);
					sum_diffs += num_diffs;
					gtk_tree_store_append(r->summary_tree, &childiter, &topiter);
					g_string_printf(s, "%s %zd", form_name_map[j], num_diffs);
					gtk_tree_store_set(r->summary_tree, &childiter,
							   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
							   RESULTS_SUMMARY_COLUMN_FORM, form_map[j],
							   RESULTS_SUMMARY_COLUMN_ITEM, r->items[i], -1);
				}
			}
			g_string_printf(s, "%s %zd", label, sum_diffs);
			gtk_tree_store_set(r->summary_tree, &topiter,
					   RESULTS_SUMMARY_COLUMN_LABEL, s->str,
					   RESULTS_SUMMARY_COLUMN_FORM, POLDIFF_FORM_NONE,
					   RESULTS_SUMMARY_COLUMN_ITEM, r->items[i], -1);
		}
	}

	g_string_free(s, TRUE);
}

/**
 * Show the legend of the symbols used in results displays.
 */
static void results_populate_key_buffer(results_t * r)
{
	GString *string = g_string_new("");
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(r->key_buffer, &iter);

	g_string_printf(string, " Added(+):\n  Items added in\n  modified policy.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "added", NULL);
	g_string_printf(string, " Removed(-):\n  Items removed\n  from original\n   policy.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "removed", NULL);
	g_string_printf(string, " Modified(*):\n  Items modified\n  from original\n  policy to\n  modified policy.");
	gtk_text_buffer_insert_with_tags_by_name(r->key_buffer, &iter, string->str, -1, "modified", NULL);
	g_string_free(string, TRUE);
}

/**
 * Populate the status bar with summary info of our diff.
 */
static void results_update_stats(results_t * r)
{
	GString *string = g_string_new("");
	int i, j, forms[5];
	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		if (result_item_is_supported(r->items[i])) {
			const char *label;
			size_t sum_diffs = 0;
			result_item_get_forms(r->items[i], forms);
			label = result_item_get_label(r->items[i]);
			for (j = 0; j < 5; j++) {
				if (forms[j] > 0) {
					sum_diffs += result_item_get_num_differences(r->items[i], form_map[j]);
				}
			}
			g_string_append_printf(string, "%s: %zd", label, sum_diffs);
		}
	}
	gtk_label_set_text(r->stats, string->str);
	g_string_free(string, TRUE);
}

void results_update(results_t * r)
{
	int i, j, forms[5], was_diff_run = 0;
	poldiff_t *diff = toplevel_get_poldiff(r->top);

	results_clear(r);

	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		result_item_poldiff_run(r->items[i], diff, 0);
	}
	/* only show diff-relevant buffers if a diff was actually run */
	for (i = 0; i < NUM_RESULT_ITEMS; i++) {
		if (result_item_is_supported(r->items[i])) {
			result_item_get_forms(r->items[i], forms);
			for (j = 0; j < 5; j++) {
				if (forms[j] > 0) {
					was_diff_run = 1;
					break;
				}
			}
		}
	}
	if (was_diff_run) {
		results_update_summary(r);
		results_populate_key_buffer(r);
		results_update_stats(r);

		/* select the summary item */
		GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
		GtkTreeIter iter;
		gtk_tree_model_get_iter_first(GTK_TREE_MODEL(r->summary_tree), &iter);
		gtk_tree_selection_select_iter(selection, &iter);
	}
}

void results_switch_to_page(results_t * r)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
	GtkTreeIter iter;
	gboolean sens = FALSE;
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		int form;
		result_item_t *item;
		results_sort_e sort;
		results_sort_dir_e dir;
		gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
				   RESULTS_SUMMARY_COLUMN_ITEM, &item, -1);
		if (item != NULL && result_item_get_current_sort(item, &sort, &dir)) {
			sens = TRUE;
		}
	}
	toplevel_set_sort_menu_sensitivity(r->top, sens);
}

/**
 * Callback invoked when the user selects an entry from the summary
 * tree.
 */
static void results_summary_on_change(GtkTreeSelection * selection, gpointer user_data)
{
	results_t *r = (results_t *) user_data;
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		int form;
		result_item_t *item;
		results_sort_e sort;
		results_sort_dir_e dir;
		gboolean sens = FALSE;
		gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
				   RESULTS_SUMMARY_COLUMN_ITEM, &item, -1);
		if (item == NULL) {
			gtk_text_view_set_buffer(r->view, r->main_buffer);
		} else {
			if (result_item_get_current_sort(item, &sort, &dir)) {
				sens = TRUE;
				toplevel_set_sort_menu_selection(r->top, sort, dir);
			}
		}
		toplevel_set_sort_menu_sensitivity(r->top, sens);
#if 0
		results_record_select(r, item_record, form);
#endif
	}
}

static void results_summary_on_row_activate(GtkTreeView * tree_view, GtkTreePath * path, GtkTreeViewColumn * column
					    __attribute__ ((unused)), gpointer user_data __attribute__ ((unused)))
{
	gboolean expanded = gtk_tree_view_row_expanded(tree_view, path);
	if (!expanded) {
		gtk_tree_view_expand_row(tree_view, path, 1);
	} else {
		gtk_tree_view_collapse_row(tree_view, path);
	}
}

/**
 * Callback invoked when the user clicks on a line number tag.  This
 * will flip to the appropriate policy's source page and jump to that
 * line.
 */
static gboolean results_on_line_event(GtkTextTag * tag, GObject * event_object __attribute__ ((unused)),
				      GdkEvent * event, const GtkTextIter * iter, gpointer user_data)
{
	results_t *r = (results_t *) user_data;
	int offset;
	sediffx_policy_e which_pol = -1;
	unsigned long line;
	GtkTextIter *start, *end;
	if (event->type == GDK_BUTTON_PRESS) {
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);

		while (!gtk_text_iter_starts_word(start))
			gtk_text_iter_backward_char(start);
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);

		/* the line # in policy starts with 1, in the buffer it
		 * starts at 0 */
		line = atoi(gtk_text_iter_get_slice(start, end)) - 1;
		if (tag == r->policy_orig_tag) {
			which_pol = SEDIFFX_POLICY_ORIG;
		} else if (tag == r->policy_mod_tag) {
			which_pol = SEDIFFX_POLICY_MOD;
		} else {
			/* should never get here */
			assert(0);
		}
		toplevel_show_policy_line(r->top, which_pol, line);
		return TRUE;
	}
	return FALSE;
}

/**
 * Set the cursor to a hand when user scrolls over a line number in
 * when displaying te diff.
 */
static gboolean results_on_text_view_motion(GtkWidget * widget, GdkEventMotion * event, gpointer user_data __attribute__ ((unused)))
{
	GtkTextBuffer *buffer;
	GtkTextView *textview;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags, *tagp;
	gint x, ex, ey, y;
	int hovering = 0;

	textview = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(textview, GTK_TEXT_WINDOW_WIDGET, ex, ey, &x, &y);
	buffer = gtk_text_view_get_buffer(textview);
	gtk_text_view_get_iter_at_location(textview, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	for (tagp = tags; tagp != NULL; tagp = tagp->next) {
		if (strncmp(GTK_TEXT_TAG(tagp->data)->name, "line", 4) == 0) {
			hovering = TRUE;
			break;
		}
	}

	if (hovering) {
		cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);
	}
	g_slist_free(tags);
	return FALSE;
}

void results_sort(results_t * r, results_sort_e field, int direction)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(r->summary_view);
	GtkTreeIter iter;
	int form;
	result_item_t *item;
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter)) {
		return;
	}
	gtk_tree_model_get(GTK_TREE_MODEL(r->summary_tree), &iter, RESULTS_SUMMARY_COLUMN_FORM, &form,
			   RESULTS_SUMMARY_COLUMN_ITEM, &item, -1);
#if 0
	assert(item_record->bit_pos == (POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES));
	if (r->te_sort_field[form] != field || r->te_sort_direction[form] != direction || !r->te_buffered[form]) {
		r->te_sort_field[form] = field;
		r->te_sort_direction[form] = direction;
		r->te_buffered[form] = 0;
		results_select_rules(r, item_record, form);
	}
#endif
}

GtkTextView *results_get_text_view(results_t * r)
{
	return r->view;
}
