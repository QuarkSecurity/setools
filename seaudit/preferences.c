/**
 *  @file preferences.c
 *  Implementation of the storage class seaudit_prefs_t.
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

#include "preferences.h"

#include <apol/util.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/** default frequency, in milliseconds, to poll log file for changes */
#define DEFAULT_LOG_UPDATE_INTERVAL 1000

/** maximum number of recent log files and recent policy files to remember */
#define MAX_RECENT_ENTRIES 5

/** name of the user's seaudit personal preferences file */
#define USER_SEAUDIT_CONF ".seaudit"

/** name of the system seaudit preference file */
#define SYSTEM_SEAUDIT_CONF "dot_seaudit"

struct visible_field
{
	const char *field;
	int visible;
};

static const struct visible_field default_visible_fields[] = {
	{"host_field", 1},
	{"date_field", 1},
	{"msg_field", 1},
	{"src_usr_field", 0},
	{"src_role_field", 0},
	{"src_type_field", 1},
	{"tgt_usr_field", 0},
	{"tgt_role_field", 0},
	{"tgt_type_field", 1},
	{"obj_class_field", 1},
	{"perm_field", 1},
	{"inode_field", 0},
	{"path_field", 0},
	{"exe_field", 1},
	{"comm_field", 1},
	{"pid_field", 0},
	{"other_field", 1}
};
static size_t num_visible_fields = sizeof(default_visible_fields) / sizeof(default_visible_fields[0]);

struct seaudit_prefs
{
	/** path to default system log file */
	char *log;
	/** path to default policy */
	char *policy;
	/** default path when writing reports */
	char *report;
	/** default path to the stylesheet, used during report writing */
	char *stylesheet;
	/** vector of paths (strings) to recently opened log files */
	apol_vector_t *recent_log_files;
	/** vector of paths (strings) to recently opened policy files */
	apol_vector_t *recent_policy_files;
	/** non-zero if seaudit should poll the log file for changes */
	int real_time_log;
	/** frequency, in milliesconds, to poll log file */
	int real_time_interval;
	struct visible_field *fields;
};

seaudit_prefs_t *seaudit_prefs_create(void)
{
	seaudit_prefs_t *prefs = NULL;
	FILE *file = NULL;
	char *path = NULL, *value;
	apol_vector_t *v = NULL;
	size_t i, j;
	int error = 0;

	if ((prefs = calloc(1, sizeof(*prefs))) == NULL ||
	    (prefs->recent_log_files = apol_vector_create()) == NULL ||
	    (prefs->recent_policy_files = apol_vector_create()) == NULL ||
	    (prefs->fields = calloc(num_visible_fields, sizeof(struct visible_field))) == NULL) {
		error = errno;
		goto cleanup;
	}
	prefs->real_time_interval = DEFAULT_LOG_UPDATE_INTERVAL;
	memcpy(prefs->fields, default_visible_fields, num_visible_fields * sizeof(struct visible_field));
	path = apol_file_find_user_config(USER_SEAUDIT_CONF);
	if (!path) {
		if ((path = apol_file_find_path(SYSTEM_SEAUDIT_CONF)) == NULL) {
			return prefs;
		}
	}
	if ((file = fopen(path, "r")) == NULL) {
		error = errno;
		goto cleanup;
	}
	prefs->log = apol_config_get_var("DEFAULT_LOG_FILE", file);
	prefs->policy = apol_config_get_var("DEFAULT_POLICY_FILE", file);
	prefs->report = apol_config_get_var("DEFAULT_REPORT_CONFIG_FILE", file);
	prefs->stylesheet = apol_config_get_var("DEFAULT_REPORT_CSS_FILE", file);
	if ((v = apol_config_split_var("RECENT_LOG_FILES", file)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_destroy(&prefs->recent_log_files, free);
	prefs->recent_log_files = v;
	if ((v = apol_config_split_var("RECENT_POLICY_FILES", file)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_destroy(&prefs->recent_policy_files, free);
	prefs->recent_policy_files = v;

	if ((v = apol_config_split_var("LOG_COLUMNS_HIDDEN", file)) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (j = 0; j < num_visible_fields; j++) {
		prefs->fields[j].visible = 1;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		char *s = apol_vector_get_element(v, i);
		for (j = 0; j < num_visible_fields; j++) {
			if (strcmp(s, prefs->fields[j].field) == 0) {
				prefs->fields[j].visible = 0;
				break;
			}
		}
	}
	apol_vector_destroy(&v, free);
	value = apol_config_get_var("REAL_TIME_LOG_MONITORING", file);
	if (value != NULL && value[0] != '0') {
		prefs->real_time_log = 1;
	}
	free(value);
	value = apol_config_get_var("REAL_TIME_LOG_UPDATE_INTERVAL", file);
	if (value != NULL) {
		prefs->real_time_interval = atoi(value);
	}
	free(value);
      cleanup:
	free(path);
	if (file != NULL) {
		fclose(file);
	}
	if (error != 0) {
		seaudit_prefs_destroy(&prefs);
		errno = error;
		return NULL;
	}
	return prefs;
}

void seaudit_prefs_destroy(seaudit_prefs_t ** prefs)
{
	if (prefs != NULL && *prefs != NULL) {
		free((*prefs)->log);
		free((*prefs)->policy);
		free((*prefs)->report);
		free((*prefs)->stylesheet);
		apol_vector_destroy(&(*prefs)->recent_log_files, free);
		apol_vector_destroy(&(*prefs)->recent_policy_files, free);
		free((*prefs)->fields);
		free(*prefs);
		*prefs = NULL;
	}
}

int seaudit_prefs_write_to_conf_file(seaudit_prefs_t * prefs)
{
	FILE *file = NULL;
	char *home, *conf_file = NULL, *value;
	apol_vector_t *hidden_fields = NULL;
	size_t i;
	int retval = 0, error = 0;

	/* we need to open ~/.seaudit */
	home = getenv("HOME");
	if (!home) {
		error = EBADRQC;
		goto cleanup;
	}
	if (asprintf(&conf_file, "%s/%s", home, USER_SEAUDIT_CONF) < 0) {
		error = errno;
		goto cleanup;
	}

	if ((file = fopen(conf_file, "w")) == NULL) {
		error = errno;
		goto cleanup;
	}

	fprintf(file, "# configuration file for seaudit - an audit log tool for Security Enhanced Linux.\n");
	fprintf(file, "# this file is auto-generated\n\n");

	if (prefs->log != NULL) {
		fprintf(file, "DEFAULT_LOG_FILE %s\n", prefs->log);
	}
	if (prefs->policy != NULL) {
		fprintf(file, "DEFAULT_POLICY_FILE %s\n", prefs->policy);
	}
	if (prefs->report != NULL) {
		fprintf(file, "DEFAULT_REPORT_CONFIG_FILE %s\n", prefs->report);
	}
	if (prefs->stylesheet != NULL) {
		fprintf(file, "DEFAULT_REPORT_CSS_FILE %s\n", prefs->stylesheet);
	}
	if ((value = apol_config_join_var(prefs->recent_log_files)) == NULL) {
		error = errno;
		goto cleanup;
	}
	fprintf(file, "RECENT_LOG_FILES %s\n", value);
	free(value);
	if ((value = apol_config_join_var(prefs->recent_policy_files)) == NULL) {
		error = errno;
		goto cleanup;
	}
	fprintf(file, "RECENT_POLICY_FILES %s\n", value);
	free(value);
	if ((hidden_fields = apol_vector_create()) == NULL) {
		error = errno;
		goto cleanup;
	}
	for (i = 0; i < num_visible_fields; i++) {
		if (!prefs->fields[i].visible && apol_vector_append(hidden_fields, (char *)prefs->fields[i].field) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	if ((value = apol_config_join_var(hidden_fields)) == NULL) {
		error = errno;
		goto cleanup;
	}
	fprintf(file, "LOG_COLUMNS_HIDDEN %s\n", value);
	free(value);
	fprintf(file, "REAL_TIME_LOG_MONITORING %d\n", prefs->real_time_log);
	fprintf(file, "REAL_TIME_LOG_UPDATE_INTERVAL %d\n", prefs->real_time_interval);
	retval = 0;
      cleanup:
	free(conf_file);
	apol_vector_destroy(&hidden_fields, NULL);
	if (file != NULL) {
		fclose(file);
	}
	errno = error;
	return retval;
}

int seaudit_prefs_set_log(seaudit_prefs_t * prefs, const char *log)
{
	free(prefs->log);
	if ((prefs->log = strdup(log)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_prefs_get_log(seaudit_prefs_t * prefs)
{
	return prefs->log;
}

int seaudit_prefs_set_policy(seaudit_prefs_t * prefs, const char *policy)
{
	free(prefs->policy);
	if ((prefs->policy = strdup(policy)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_prefs_get_policy(seaudit_prefs_t * prefs)
{
	return prefs->policy;
}

int seaudit_prefs_set_report(seaudit_prefs_t * prefs, const char *report)
{
	free(prefs->report);
	if ((prefs->report = strdup(report)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_prefs_get_report(seaudit_prefs_t * prefs)
{
	return prefs->report;
}

int seaudit_prefs_set_stylesheet(seaudit_prefs_t * prefs, const char *stylesheet)
{
	free(prefs->stylesheet);
	if ((prefs->stylesheet = strdup(stylesheet)) == NULL) {
		return -1;
	}
	return 0;
}

char *seaudit_prefs_get_stylesheet(seaudit_prefs_t * prefs)
{
	return prefs->stylesheet;
}

/**
 * Add an entry to a vector, discarding the oldest entry if the vector
 * size is too large.
 */
static int prefs_add_recent_vector(apol_vector_t * v, const char *entry)
{
	size_t i;
	char *s;
	if (apol_vector_get_index(v, (void *)entry, apol_str_strcmp, NULL, &i) == 0) {
		return 0;
	}
	if ((s = strdup(entry)) == NULL || apol_vector_append(v, s) < 0) {
		int error = errno;
		free(s);
		errno = error;
		return -1;
	}
	if (apol_vector_get_size(v) >= MAX_RECENT_ENTRIES) {
		s = apol_vector_get_element(v, 0);
		free(s);
		return apol_vector_remove(v, 0);
	}
	return 0;
}

int seaudit_prefs_add_recent_log(seaudit_prefs_t * prefs, const char *log)
{
	return prefs_add_recent_vector(prefs->recent_log_files, log);
}

int seaudit_prefs_add_recent_policy(seaudit_prefs_t * prefs, const char *policy)
{
	return prefs_add_recent_vector(prefs->recent_policy_files, policy);
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

void update_column_visibility(seaudit_filtered_view_t * view, gpointer user_data)
{
	GList *columns;
	GtkTreeViewColumn *col = NULL;

	columns = gtk_tree_view_get_columns(view->tree_view);
	while (columns != NULL) {
		col = GTK_TREE_VIEW_COLUMN(columns->data);
		gtk_tree_view_column_set_visible(col,
						 seaudit_app->seaudit_conf.
						 column_visibility[gtk_tree_view_column_get_sort_column_id(col)]);
		columns = g_list_next(columns);
	}
}

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

	/* set the updated visibility if needed */
	if (!seaudit_app->column_visibility_changed)
		return;
	g_list_foreach(seaudit_app->window->views, (GFunc) update_column_visibility, NULL);
	seaudit_app->column_visibility_changed = FALSE;
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

static void on_preference_toggled(GtkToggleButton * toggle, gpointer user_data)
{
	if (!strcmp("MessageCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_MSG_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;
	} else if (!strcmp("DateCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[DATE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("OtherCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_MISC_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceUserCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_USER_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceRoleCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_ROLE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceTypeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_TYPE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetUserCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_USER_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetRoleCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_ROLE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetTypeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_TYPE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("ObjectClassCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_OBJ_CLASS_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PermissionCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PERM_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("ExecutableCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_EXE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("CommandCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_COMM_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PIDCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PID_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("InodeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_INODE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PathCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PATH_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("HostCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[HOST_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("RealTimeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.real_time_log = gtk_toggle_button_get_active(toggle);
	}

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

	assert(interval);
	dir = apol_file_find("prefer_window.glade");
	if (!dir) {
		fprintf(stderr, "could not find prefer_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/prefer_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	window = glade_xml_get_widget(xml, "PreferWindow");
	g_assert(window);
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

	button = glade_xml_get_widget(xml, "OkButton");
	g_assert(button);
	g_signal_connect(GTK_OBJECT(button), "clicked", G_CALLBACK(on_prefer_window_ok_button_clicked), (gpointer) xml);

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

	glade_xml_signal_connect(xml, "on_preference_toggled", G_CALLBACK(on_preference_toggled));

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "MessageCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_MSG_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "DateCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[DATE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "OtherCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_MISC_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceUserCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_USER_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceRoleCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_ROLE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceTypeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_TYPE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetUserCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_USER_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetRoleCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_ROLE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetTypeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_TYPE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "ObjectClassCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_OBJ_CLASS_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PermissionCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PERM_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "ExecutableCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_EXE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "CommandCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_COMM_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PIDCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PID_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "InodeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_INODE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PathCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PATH_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "RealTimeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.real_time_log);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "HostCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[HOST_FIELD]);
	return;
}

#endif
