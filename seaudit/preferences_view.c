/**
 *  @file preferences_view.c
 *  Implementation of preferences editor.
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

#include <config.h>

#include "preferences_view.h"
#include <assert.h>

struct pref_toggle
{
	const char *widget_name;
	preference_field_e preference_field;
};

static const struct pref_toggle pref_toggle_map[] = {
	{"HostCheck", HOST_FIELD},
	{"MessageCheck", MESSAGE_FIELD},
	{"DateCheck", DATE_FIELD},
	{"SourceUserCheck", SUSER_FIELD},
	{"SourceRoleCheck", SROLE_FIELD},
	{"SourceTypeCheck", STYPE_FIELD},
	{"TargetUserCheck", TUSER_FIELD},
	{"TargetRoleCheck", TROLE_FIELD},
	{"TargetTypeCheck", TTYPE_FIELD},
	{"ObjectClassCheck", OBJCLASS_FIELD},
	{"PermissionCheck", PERM_FIELD},
	{"ExecutableCheck", EXECUTABLE_FIELD},
	{"CommandCheck", COMMAND_FIELD},
	{"PIDCheck", PID_FIELD},
	{"InodeCheck", INODE_FIELD},
	{"PathCheck", PATH_FIELD},
	{"OtherCheck", OTHER_FIELD}
};
static const size_t num_toggles = sizeof(pref_toggle_map) / sizeof(pref_toggle_map[0]);

int preferences_view_run(toplevel_t * top, GtkWindow * parent)
{
	GladeXML *xml = toplevel_get_glade_xml(top);
	preferences_t *prefs = toplevel_get_prefs(top);
	GtkWidget *dialog, *w;
	size_t i;
	gint response;

	dialog = glade_xml_get_widget(xml, "PreferencesWindow");
	gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);

	for (i = 0; i < num_toggles; i++) {
		int visible;
		w = glade_xml_get_widget(xml, pref_toggle_map[i].widget_name);
		assert(w != NULL);
		visible = preferences_is_column_visible(prefs, pref_toggle_map[i].preference_field);
		if (visible) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
		} else {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
		}
	}

	response = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_hide(dialog);
	if (response != GTK_RESPONSE_OK) {
		return 0;
	}
	for (i = 0; i < num_toggles; i++) {
		gboolean active;
		w = glade_xml_get_widget(xml, pref_toggle_map[i].widget_name);
		active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
		if (active) {
			preferences_set_column_visible(prefs, pref_toggle_map[i].preference_field, 1);
		} else {
			preferences_set_column_visible(prefs, pref_toggle_map[i].preference_field, 0);
		}
	}
	return 1;
}

#if 0

#include "preferences.h"
#include "utilgui.h"
#include "seaudit.h"
#include <glib/gprintf.h>
#include <string.h>

extern seaudit_t *seaudit_app;

/* static functions called only if preferences window is open */
static void on_preference_toggled(GtkToggleButton * toggle, gpointer user_data);
static void on_browse_policy_button_clicked(GtkWidget * widget, gpointer user_data);
static void on_browse_log_button_clicked(GtkWidget * widget, gpointer user_data);

static void change_log_update_interval(seaudit_conf_t * conf_file, int millisecs)
{
	assert(millisecs > 0);
	conf_file->real_time_interval = millisecs;
}

void on_prefer_window_ok_button_clicked(GtkWidget * widget, gpointer user_data)
{
	GtkWidget *prefer_window;
	GladeXML *xml = (GladeXML *) user_data;
	GtkEntry *log_entry, *pol_entry, *report_css, *report_config, *interval_lbl;
	seaudit_conf_t *seaudit_conf = NULL;
	const gchar *interval_str = NULL;
	int interval;

	prefer_window = glade_xml_get_widget(xml, "PreferWindow");
	g_assert(widget);
	log_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	g_assert(log_entry);
	pol_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	g_assert(pol_entry);
	report_css = GTK_ENTRY(glade_xml_get_widget(xml, "report-css-entry"));
	g_assert(report_css);
	report_config = GTK_ENTRY(glade_xml_get_widget(xml, "report-config-entry"));
	g_assert(report_config);
	interval_lbl = GTK_ENTRY(glade_xml_get_widget(xml, "interval_lbl"));
	g_assert(interval_lbl);

	seaudit_conf = &(seaudit_app->seaudit_conf);
	interval_str = gtk_entry_get_text(interval_lbl);
	if (!apol_str_is_only_white_space(interval_str)) {
		interval = atoi(interval_str);
		if (interval > 0)
			change_log_update_interval(seaudit_conf, interval);
		else {
			message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, "Update interval must be greater than 0!");
			return;
		}
	} else {
		message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, "Update interval cannot be empty!");
		return;
	}

	set_seaudit_conf_default_log(seaudit_conf, gtk_entry_get_text(log_entry));
	set_seaudit_conf_default_policy(seaudit_conf, gtk_entry_get_text(pol_entry));

	if (set_seaudit_conf_file_path(&(seaudit_conf->default_seaudit_report_config_file), gtk_entry_get_text(report_config)) != 0)
		return;
	if (set_seaudit_conf_file_path(&(seaudit_conf->default_seaudit_report_css_file), gtk_entry_get_text(report_css)) != 0)
		return;
	save_seaudit_conf_file(seaudit_conf);

	gtk_widget_destroy(prefer_window);
}

static void display_browse_dialog_for_entry_box(GtkEntry * entry, const char *file_path, const char *title)
{
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;
	GtkWidget *window;

	g_assert(entry);
	file_selector = gtk_file_selection_new(title);

	/* get the top level widget, which of this widget is the prefer window */
	window = GTK_WIDGET(entry);
	while (gtk_widget_get_parent(window))
		window = gtk_widget_get_parent(window);;
	assert(window);

	/* set the file selector window to be transient on the preference window, so that when it pops up it gets centered on it */
	gtk_window_set_transient_for(GTK_WINDOW(file_selector), GTK_WINDOW(window));
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (file_path != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), gtk_entry_get_text(entry));
	g_signal_connect(GTK_OBJECT(file_selector), "response", G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return;
		}
		filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector));
		if (g_file_test(filename, G_FILE_TEST_EXISTS) && !g_file_test(filename, G_FILE_TEST_IS_DIR))
			break;
		if (g_file_test(filename, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename);
	}
	gtk_entry_set_text(entry, filename);
	gtk_widget_destroy(file_selector);
}

static void on_browse_log_button_clicked(GtkWidget * widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	GtkEntry *entry;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	display_browse_dialog_for_entry_box(entry, seaudit_app->seaudit_conf.default_log_file, "Select Default Log");
}

static void on_browse_policy_button_clicked(GtkWidget * widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	GtkEntry *entry;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	display_browse_dialog_for_entry_box(entry, seaudit_app->seaudit_conf.default_policy_file, "Select Default Policy");
}

static void on_browse_report_css_button_clicked(GtkWidget * widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	GtkEntry *entry;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "report-css-entry"));
	display_browse_dialog_for_entry_box(entry,
					    seaudit_app->seaudit_conf.default_seaudit_report_css_file,
					    "Select HTML Report Style Sheet File");
}

static void on_browse_report_config_button_clicked(GtkWidget * widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML *) user_data;
	GtkEntry *entry;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "report-config-entry"));
	display_browse_dialog_for_entry_box(entry,
					    seaudit_app->seaudit_conf.default_seaudit_report_config_file,
					    "Select Report Configuration File");
}

void on_preferences_activate(GtkWidget * widget, GdkEvent * event, gpointer callback_data)
{
	GladeXML *xml;
	GtkWidget *button, *window;
	GtkEntry *entry;
	GtkToggleButton *toggle = NULL;
	GString *path;
	char *dir;
	GString *interval = g_string_new("");

	window = glade_xml_get_widget(xml, "PreferencesWindow");
	/* set this window to be transient on the main window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered on xml_new we have to hide and then show */
	gtk_window_set_transient_for(GTK_WINDOW(window), seaudit_app->window->window);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_window_present(GTK_WINDOW(window));

	/* make the window modal */
	gtk_window_set_modal(GTK_WINDOW(window), TRUE);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "interval_lbl"));
	g_assert(entry);
	g_string_printf(interval, "%d", seaudit_app->seaudit_conf.real_time_interval);
	assert(interval != NULL);
	gtk_entry_set_text(entry, interval->str);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_log_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_log_file);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_policy_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_policy_file);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "report-config-entry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_seaudit_report_config_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_seaudit_report_config_file);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "report-css-entry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_seaudit_report_css_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_seaudit_report_css_file);

	button = glade_xml_get_widget(xml, "BrowseLogButton");
	g_assert(widget);
	g_signal_connect(GTK_OBJECT(button), "clicked", G_CALLBACK(on_browse_log_button_clicked), (gpointer) xml);

	button = glade_xml_get_widget(xml, "BrowsePolicyButton");
	g_assert(widget);
	g_signal_connect(GTK_OBJECT(button), "clicked", G_CALLBACK(on_browse_policy_button_clicked), (gpointer) xml);

	button = glade_xml_get_widget(xml, "report-css-button");
	g_assert(widget);
	g_signal_connect(GTK_OBJECT(button), "clicked", G_CALLBACK(on_browse_report_css_button_clicked), (gpointer) xml);

	button = glade_xml_get_widget(xml, "report-config-button");
	g_assert(widget);
	g_signal_connect(GTK_OBJECT(button), "clicked", G_CALLBACK(on_browse_report_config_button_clicked), (gpointer) xml);

}

#endif
