/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 */

#include "seaudit.h"
#include "parse.h"
#include "auditlog.h"
#include "auditlogmodel.h"
#include "query_window.h"
#include "filter_window.h"
#include "utilgui.h"
#include "preferences.h"
#include "seaudit_callback.h"
#include <libapol/policy-io.h>
#include <libapol/util.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

/* The following should be defined in the make environment */
#ifndef SEAUDIT_GUI_VERSION_STRING
	#define SEAUDIT_GUI_VERSION_STRING "UNKNOWN"
#endif
seaudit_t *seaudit_app = NULL;

/* command line options */
static struct option const opts[] =
{
	{"log", required_argument, NULL, 'l'},
	{"policy", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};
static void seaudit_set_real_time_log_button_state(bool_t state);
static int seaudit_read_policy_conf(const char *fname);
static void seaudit_print_version_info(void);
static void seaudit_print_usage_info(const char *program_name, bool_t brief);
static void seaudit_parse_command_line(int argc, char **argv, GString **policy_filename, GString **log_filename);
static void seaudit_update_title_bar(void *user_data);
static void seaudit_set_recent_logs_submenu(seaudit_conf_t *conf_file);
static void seaudit_set_recent_policys_submenu(seaudit_conf_t *conf_file);
static void seaudit_policy_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data);
static void seaudit_log_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data);
static gboolean seaudit_real_time_update_log(gpointer callback_data);
static void seaudit_exit_app(void);

/* seaudit object */
seaudit_t* seaudit_init(void)
{
	seaudit_t *seaudit;

	seaudit = (seaudit_t*)malloc(sizeof(seaudit_t));
	if (!seaudit) {
		fprintf(stderr, "memory error\n");
		return NULL;
	}
	memset(seaudit, 0, sizeof(seaudit_t));
	/* we load user configuration first so the window can be set up
	 * set up properly on create */
	load_seaudit_conf_file(&(seaudit->seaudit_conf));
	seaudit->window = seaudit_window_create(NULL, seaudit->seaudit_conf.column_visibility);
	seaudit->policy_file = g_string_new("");
	seaudit->audit_log_file = g_string_new("");
	return seaudit;
}

void seaudit_destroy(seaudit_t *seaudit_app)
{
	if (seaudit_app->cur_policy)
		close_policy(seaudit_app->cur_policy);
	seaudit_callbacks_free();
	if (seaudit_app->log_file_ptr)
		fclose(seaudit_app->log_file_ptr);
	free_seaudit_conf(&(seaudit_app->seaudit_conf));
	g_string_free(seaudit_app->policy_file, TRUE);
	g_string_free(seaudit_app->audit_log_file, TRUE);
	free(seaudit_app);
	seaudit_app = NULL;
}

void seaudit_update_status_bar(seaudit_t *seaudit)
{	
	char str[STR_SIZE];
	char *ver_str = NULL;
	int num_log_msgs, num_filtered_log_msgs;
	char old_time[TIME_SIZE], recent_time[TIME_SIZE];
	seaudit_filtered_view_t *view;

	if (!seaudit || !seaudit->window || !seaudit->window->xml)
		return;

	GtkLabel *v_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit->window->xml, "PolicyVersionLabel");
	GtkLabel *l_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit->window->xml, "LogNumLabel");
	GtkLabel *d_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit->window->xml, "LogDateLabel");

	if (seaudit->cur_policy == NULL) {
		ver_str = "Policy Version: No policy";
		gtk_label_set_text(v_status_bar, ver_str);
	} else {
               	if(is_binary_policy(seaudit->cur_policy))
                	snprintf(str, STR_SIZE, "Policy Version: %s (binary)", get_policy_version_name(seaudit->cur_policy->version));
               	else
                	snprintf(str, STR_SIZE, "Policy Version: %s (source)", get_policy_version_name(seaudit->cur_policy->version));
		gtk_label_set_text(v_status_bar, str);
	}

	if (seaudit->cur_log == NULL) {
		snprintf(str, STR_SIZE, "Log Messages: No log");
		gtk_label_set_text(l_status_bar, str);
		snprintf(str, STR_SIZE, "Dates: No log");
		gtk_label_set_text(d_status_bar, str);
	} else {
		view = seaudit_window_get_current_view(seaudit->window);
		if (view)
			num_filtered_log_msgs = view->store->log_view->num_fltr_msgs;
		else 
			num_filtered_log_msgs = 0;

		num_log_msgs = seaudit->cur_log->num_msgs;
		snprintf(str, STR_SIZE, "Log Messages: %d/%d", num_filtered_log_msgs, num_log_msgs);
		gtk_label_set_text(l_status_bar, str);
		if (num_log_msgs > 0) {
			strftime(old_time, TIME_SIZE, "%b %d %H:%M:%S" , 
				 seaudit->cur_log->msg_list[0]->date_stamp);
			strftime(recent_time, TIME_SIZE, "%b %d %H:%M:%S", 
				 seaudit->cur_log->msg_list[num_log_msgs-1]->date_stamp);
			snprintf(str, STR_SIZE, "Dates: %s - %s", old_time, recent_time);
			gtk_label_set_text(d_status_bar, str);
		} else {
			snprintf(str, STR_SIZE, "Dates: No messages");
			gtk_label_set_text(d_status_bar, str);
		}
	}
}

int seaudit_open_policy(seaudit_t *seaudit, const char *filename)
{
	unsigned int opts;
	FILE *file;
	policy_t *tmp_policy = NULL;
	int rt;
	const int SEAUDIT_STR_SZ = 128;
	GString *msg;
	GtkWidget *dialog;
	gint response;

	if (filename == NULL)
		return -1;

	show_wait_cursor(GTK_WIDGET(seaudit->window->window));
	if (seaudit->cur_policy != NULL) {
		dialog = gtk_message_dialog_new(seaudit->window->window,
						GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
						GTK_MESSAGE_WARNING,
						GTK_BUTTONS_YES_NO,
						"Opening a new policy will close all \"Query Policy\" windows\n"
						"Do you wish to continue anyway?");
		g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(get_dialog_response), &response);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if (response != GTK_RESPONSE_YES) {
			clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
			return 0;
		}
	}
	if (g_file_test(filename, G_FILE_TEST_IS_DIR)) {
		msg = g_string_new("Error opening file: File is a directory!\n");
		message_display(seaudit->window->window, GTK_MESSAGE_ERROR, msg->str);
		g_string_free(msg, TRUE);
		clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
		return -1;
	}
	
	file = fopen(filename, "r");
	if (!file) {
		msg = g_string_new("Error opening file: ");
		if (strlen(filename) > SEAUDIT_STR_SZ) {
			char *tmp = NULL;
			tmp = g_strndup(filename, SEAUDIT_STR_SZ);
			g_string_append(msg, tmp);
			g_string_append(msg, "...");
			g_free(tmp);
		} else {
			g_string_append(msg, filename);
		}
		g_string_append(msg, "!\n");
		g_string_append(msg, strerror(errno));
		message_display(seaudit->window->window, GTK_MESSAGE_ERROR, msg->str);
		g_string_free(msg, TRUE);
		clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
		return -1;
	} else 
		fclose(file);
	
	opts = POLOPT_AV_RULES | POLOPT_USERS | POLOPT_ROLES;
	
	rt = open_partial_policy(filename, opts, &tmp_policy);
	if (rt != 0) {
		if (tmp_policy)
			close_policy(tmp_policy);
		msg = g_string_new("");
		g_string_append(msg, "The specified file does not appear to be a valid\nSE Linux Policy\n\n");
		message_display(seaudit->window->window, GTK_MESSAGE_ERROR, msg->str);
		clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
		return -1;
	}
	if (seaudit->cur_policy)
		close_policy(seaudit->cur_policy);
	seaudit->cur_policy = tmp_policy;
	g_string_assign(seaudit->policy_file, filename);
	if (!is_binary_policy(seaudit_app->cur_policy)) {
		seaudit_read_policy_conf(filename);
	}
	policy_load_signal_emit();

	add_path_to_recent_policy_files(filename, &(seaudit->seaudit_conf));
	seaudit_set_recent_policys_submenu(&(seaudit->seaudit_conf));
	save_seaudit_conf_file(&(seaudit->seaudit_conf));
	clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
	return 0;
}

int seaudit_open_log_file(seaudit_t *seaudit, const char *filename)
{
	FILE *tmp_file;
	int rt, i;
	GString *msg = NULL;
	audit_log_t *new_log = NULL;

	if (filename == NULL)
		return -1;
	show_wait_cursor(GTK_WIDGET(seaudit->window->window));
    	tmp_file = fopen(filename, "r");
	if (!tmp_file) {
		msg = g_string_new("Error opening file ");
		g_string_append(msg, filename);
		g_string_append(msg, "!\n");
		g_string_append(msg, strerror(errno));
	   		message_display(seaudit->window->window, 
				GTK_MESSAGE_ERROR, 
				msg->str);		
		goto dont_load_log;
	}

	new_log = audit_log_create();
	rt = parse_audit(tmp_file, new_log);
	if (rt == PARSE_RET_MEMORY_ERROR) {
		message_display(seaudit->window->window, 
				GTK_MESSAGE_ERROR, 
				PARSE_MEMORY_ERROR_MSG);
		goto dont_load_log;
	}
	else if (rt == PARSE_RET_NO_SELINUX_ERROR) {
		message_display(seaudit->window->window, 
				GTK_MESSAGE_ERROR, 
				PARSE_NO_SELINUX_ERROR_MSG);
		goto dont_load_log;
	}
	else if (rt == PARSE_RET_INVALID_MSG_WARN) {
		message_display(seaudit->window->window, 
				GTK_MESSAGE_WARNING, 
				PARSE_INVALID_MSG_WARN_MSG);
		goto load_log;
	}
	else if (rt == PARSE_RET_SUCCESS)
		goto load_log;
	
 dont_load_log:
	if (new_log)
		audit_log_destroy(new_log);
	if (tmp_file)
		fclose(tmp_file);
	if (msg)
		g_string_free(msg, TRUE);
	clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
	return -1;

 load_log:
	audit_log_destroy(seaudit->cur_log);
	seaudit->cur_log = new_log;
	seaudit->log_file_ptr = tmp_file;
	
	for (i = 0; i < g_list_length(seaudit->window->views); i++)
		seaudit_filtered_view_set_log(g_list_nth_data(seaudit->window->views, i), new_log);

	g_string_assign(seaudit->audit_log_file, filename);
	add_path_to_recent_log_files(filename, &(seaudit->seaudit_conf));
	seaudit_set_recent_logs_submenu(&(seaudit->seaudit_conf));
	save_seaudit_conf_file(&(seaudit->seaudit_conf));
	log_load_signal_emit();
	clear_wait_cursor(GTK_WIDGET(seaudit->window->window));
	return 0;
}

/*
 * We don't want to do the heavy work of loading and displaying the log
 * and policy before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
typedef struct filename_data {
	GString *log_filename;
	GString *policy_filename;
} filename_data_t;

gboolean delayed_main(gpointer data)
{
	filename_data_t *filenames = (filename_data_t*)data;

	if (filenames->log_filename) {
		seaudit_open_log_file(seaudit_app, filenames->log_filename->str);
		g_string_free(filenames->log_filename, TRUE);
	}
	if (filenames->policy_filename) {
		seaudit_open_policy(seaudit_app, filenames->policy_filename->str);
		g_string_free(filenames->policy_filename, TRUE);
	}
	return FALSE;
}



int main(int argc, char **argv)
{
	filename_data_t filenames;
	char *policy_file = NULL;
        GString *msg = NULL;
        int rt;
        
	filenames.policy_filename = filenames.log_filename = NULL; 			
	seaudit_parse_command_line(argc, argv, &filenames.policy_filename, &filenames.log_filename);
	gtk_init(&argc, &argv);
	glade_init();

	seaudit_app = seaudit_init();
	if (!seaudit_app)
		exit(1);

	seaudit_set_recent_policys_submenu(&(seaudit_app->seaudit_conf));
	seaudit_set_recent_logs_submenu(&(seaudit_app->seaudit_conf));
	seaudit_set_real_time_log_button_state(seaudit_app->seaudit_conf.real_time_log);

	/* if no files were given on the command line then use the 
         * current user-saved default filenames */
	if (filenames.log_filename == NULL)
		if (seaudit_app->seaudit_conf.default_log_file)
			filenames.log_filename = g_string_new(seaudit_app->seaudit_conf.default_log_file);
	if (filenames.policy_filename == NULL) {
		if (seaudit_app->seaudit_conf.default_policy_file) {
			filenames.policy_filename = g_string_new(seaudit_app->seaudit_conf.default_policy_file);
		} else {
                        /* There was no default policy file specified at the command-line or
                         * in the users .seaudit file, so use the policy default logic from 
                         * libapol. With seaudit we prefer the source policy over binary. */
                        rt = find_default_policy_file((POL_TYPE_SOURCE | POL_TYPE_BINARY), &policy_file);
                        if (rt == GENERAL_ERROR) {
                        	exit(1);	
                        } else if (rt != FIND_DEFAULT_SUCCESS) {
                        	/* no policy to use, so warn the user and then start up without a default policy. */
                                msg = g_string_new("Could not find system default policy to open. Use the \
                                		    File menu to open a policy");
                                message_display(seaudit_app->window->window,
                                        GTK_MESSAGE_WARNING,
                                        msg->str);
                        } else if (policy_file) {
                        	filenames.policy_filename = g_string_new(policy_file);
                        	free(policy_file);
                        } 
               }	
	}

	seaudit_update_status_bar(seaudit_app);
	seaudit_update_title_bar(NULL);
	
	policy_load_callback_register((seaudit_callback_t)&seaudit_update_status_bar, seaudit_app);
	log_load_callback_register((seaudit_callback_t)&seaudit_update_status_bar, seaudit_app);
	policy_load_callback_register(&seaudit_update_title_bar, NULL);
	log_load_callback_register(&seaudit_update_title_bar, NULL);
	log_filtered_callback_register((seaudit_callback_t)&seaudit_update_status_bar, seaudit_app);
	/* finish loading later */
	g_idle_add(&delayed_main, &filenames);

	/* go */
	gtk_main();

	return 0;
}


/*
 * glade autoconnected callbacks for main window
 *
 */
void seaudit_on_TopWindow_destroy(GtkWidget *widget)
{
	seaudit_exit_app();
}

/*
 * glade autoconnected callbacks for menus
 *
 */
void seaudit_on_new_tab_clicked(GtkMenuItem *menu_item, gpointer user_data)
{
	seaudit_window_add_new_view(seaudit_app->window, seaudit_app->cur_log, seaudit_app->seaudit_conf.column_visibility,
				    NULL);

}

void seaudit_on_open_view_clicked(GtkMenuItem *menu_item, gpointer user_data)
{
	seaudit_window_open_view(seaudit_app->window, seaudit_app->cur_log, seaudit_app->seaudit_conf.column_visibility);
}

void seaudit_on_save_view_clicked(GtkMenuItem *menu_item, gpointer user_data)
{
	seaudit_window_save_current_view(seaudit_app->window, FALSE);
}

void seaudit_on_saveas_view_clicked(GtkMenuItem *menu_item, gpointer user_data)
{
	seaudit_window_save_current_view(seaudit_app->window, TRUE);
}

void seaudit_on_PolicyFileOpen_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	file_selector = gtk_file_selection_new("Open Policy");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_policy_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), seaudit_app->seaudit_conf.default_policy_file);

	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
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
	seaudit_open_policy(seaudit_app, filename);
	gtk_widget_destroy(file_selector);
	return;
}

void seaudit_on_LogFileOpen_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	file_selector = gtk_file_selection_new("Open Log");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_log_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), seaudit_app->seaudit_conf.default_log_file);

	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
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
	gtk_widget_destroy(file_selector);
	seaudit_open_log_file(seaudit_app, filename);
	return;
}

void seaudit_on_FileQuit_activate(GtkWidget *widget, gpointer user_data)
{
	seaudit_exit_app();
	return;
}

/*
 * glade autoconnected callbacks for Help menu
 */
void seaudit_on_about_seaudit_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *dialog;
	GString *str;
	
	str = g_string_new("");
	g_string_assign(str, "Audit Log Analysis Tool for Security \nEnhanced Linux");
        g_string_append(str, "\n\nCopyright (c) 2003-2004\nTresys Technology, LLC\nwww.tresys.com/selinux");
	g_string_append(str, "\n\nGUI version ");
	g_string_append(str, SEAUDIT_GUI_VERSION_STRING);
	g_string_append(str, "\nlibseaudit version ");
	g_string_append(str, libseaudit_get_version());
	g_string_append(str, "\nlibapol version ");
	g_string_append(str, libapol_get_version()); /* the libapol version */
	
	dialog = gtk_message_dialog_new(seaudit_app->window->window,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_CLOSE,
					str->str);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free(str, TRUE);
	return;
}

void seaudit_on_help_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *window;
	GtkWidget *scroll;
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	GString *string;
	char *help_text = NULL;
	int len, rt;
	char *dir;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	text_view = gtk_text_view_new();
	gtk_window_set_title(GTK_WINDOW(window), "seAudit Help");
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 300);
	gtk_container_add(GTK_CONTAINER(window), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));	
	dir = find_file("seaudit_help.txt");
	if (!dir) {
		string = g_string_new("");
		g_string_assign(string, "Can not find help file");
		message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	string = g_string_new(dir);
	free(dir);
	g_string_append(string, "/seaudit_help.txt");
	rt = read_file_to_buffer(string->str, &help_text, &len);
	g_string_free(string, TRUE);
	if (rt != 0) {
		if (help_text)
			free(help_text);
		return;
	}
	gtk_text_buffer_set_text(buffer, help_text, len);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_widget_show(text_view);
	gtk_widget_show(scroll);
	gtk_widget_show(window);
	return;
}

/*
 * glade autoconnected callbacks for the main toolbar
 */
void seaudit_on_filter_log_button_clicked(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	seaudit_filtered_view_t *view;

	if (seaudit_app->cur_log == NULL) {
		message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, "There is no audit log loaded.");
		return;
	}

	view = seaudit_window_get_current_view(seaudit_app->window);
	seaudit_filtered_view_display(view);	
	return;
}

void seaudit_on_top_window_query_button_clicked(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	query_window_create();
}


void seaudit_on_real_time_button_pressed(GtkButton *button, gpointer user_data)
{
	bool_t state = seaudit_app->real_time_state;
	seaudit_set_real_time_log_button_state(!state);
}

/*
 * Gtk callbacks registered by seaudit_t object
 */
static void seaudit_set_recent_logs_submenu(seaudit_conf_t *conf_file)
{
	GtkWidget *submenu, *submenu_item;
	GtkMenuItem *recent;
	int i;

	recent = GTK_MENU_ITEM(glade_xml_get_widget(seaudit_app->window->xml, "OpenRecentLog"));
	g_assert(recent);
	gtk_menu_item_remove_submenu(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < conf_file->num_recent_log_files; i++) {
		submenu_item = gtk_menu_item_new_with_label(conf_file->recent_log_files[i]);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(seaudit_log_file_open_from_recent_menu), 
				 conf_file->recent_log_files[i]);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
	return;
}

static void seaudit_set_recent_policys_submenu(seaudit_conf_t *conf_file)
{
	GtkWidget *submenu, *submenu_item;
	GtkMenuItem *recent;
	int i;

	recent = GTK_MENU_ITEM(glade_xml_get_widget(seaudit_app->window->xml, "OpenRecentPolicy"));
	g_assert(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < conf_file->num_recent_policy_files; i++) {
		submenu_item = gtk_menu_item_new_with_label(conf_file->recent_policy_files[i]);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(seaudit_policy_file_open_from_recent_menu), 
				 conf_file->recent_policy_files[i]);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
	return;
}

static void seaudit_policy_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data)
{
	const char *filename = (const char*)user_data;
	seaudit_open_policy(seaudit_app, filename);
}

static void seaudit_log_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data)
{
	const char *filename = (const char*)user_data;
	seaudit_open_log_file(seaudit_app, filename);
}

/*
 * Timeout function used to keep the log up to date, always
 * return TRUE so we get called repeatedly */
static gboolean seaudit_real_time_update_log(gpointer callback_data)
{
	int rt;
	#define MSG_SIZE 64 /* should be big enough */
	
	/* simply return if the log is not open */
	if (!seaudit_app->log_file_ptr)
		return TRUE;

	rt = parse_audit(seaudit_app->log_file_ptr, seaudit_app->cur_log);
	if (rt == PARSE_RET_NO_SELINUX_ERROR)
		return TRUE;
	seaudit_window_filter_views(seaudit_app->window);
	return TRUE;
}

/*
 * Helper functions for seaudit_t
 */
static void seaudit_set_real_time_log_button_state(bool_t state)
{
	GtkWidget *widget, *image, *text;

	widget = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeButton");
	g_assert(widget);
	text = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeLabel");
	g_assert(text);
	image = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeImage");
	g_assert(image);
			
	/* remove timeout function if exists */
	if (seaudit_app->timeout_key)
		gtk_timeout_remove(seaudit_app->timeout_key);

	if (!state) {
		gtk_image_set_from_stock(GTK_IMAGE(image), GTK_STOCK_STOP, GTK_ICON_SIZE_SMALL_TOOLBAR);
		gtk_label_set_text(GTK_LABEL(text), "Monitor off");
		/* make inactive */
		seaudit_app->timeout_key = 0;
		seaudit_app->real_time_state = state;
	} else {
		gtk_image_set_from_stock(GTK_IMAGE(image), GTK_STOCK_REFRESH, GTK_ICON_SIZE_SMALL_TOOLBAR);
		gtk_label_set_text(GTK_LABEL(text), "Monitor on");
		/* make active */
		seaudit_app->timeout_key = gtk_timeout_add(LOG_UPDATE_INTERVAL, 
							   &seaudit_real_time_update_log, NULL);
		seaudit_app->real_time_state = state;
	}
}

static int seaudit_read_policy_conf(const char *fname)
{
	char *buf = NULL;
	int len, rt;

	rt = read_file_to_buffer(fname, &buf, &len);
	if (rt != 0) {
		if (buf)
			free(buf);
		return -1;
	}
	
	seaudit_app->policy_text = gtk_text_buffer_new(NULL);
	gtk_text_buffer_set_text(seaudit_app->policy_text, buf, len);
	free(buf);
	return 0;
}

static void seaudit_print_version_info(void)
{
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   GUI version %s\n", SEAUDIT_GUI_VERSION_STRING);
	printf("   libapol version %s\n", libapol_get_version());
	printf("   libseaudit version %s\n\n", libseaudit_get_version());
}

static void seaudit_print_usage_info(const char *program_name, bool_t brief)
{
	printf("Usage:%s [options]\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n", program_name);
		return;
	}
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   -l FILE, --log FILE     open log file named FILE\n");
	printf("   -p FILE, --policy FILE  open policy file named FILE\n");
	printf("   -h, --help              display this help and exit\n");
	printf("   -v, --version           display version information\n\n");
	return;
}

static void seaudit_parse_command_line(int argc, char **argv, GString **policy_filename, GString **log_filename)
{
	int optc;
	bool_t help, ver;

	help = ver = FALSE;
	g_assert(*log_filename == NULL);
	g_assert(*policy_filename == NULL);
	while ( (optc = getopt_long(argc, argv, "l:p:hv", opts, NULL)) != -1)
	{
		switch(optc) {
		case 'l':
			*log_filename = g_string_new("");
			g_string_assign(*log_filename, optarg);
			break;
		case 'p':
			*policy_filename = g_string_new("");
			g_string_assign(*policy_filename, optarg);
			break;
		case '?': /* unrecognized argument give full usage */
			seaudit_print_usage_info(argv[0], FALSE);
			goto exit_main;
		case 'h':
			help = TRUE;
			break;
		case 'v':
			ver = TRUE;
			break;
		default:
			break;
		}
	}
	if (help || ver) {
		if (help)
			seaudit_print_usage_info(argv[0], FALSE);
		if (ver)
			seaudit_print_version_info();
		goto exit_main;
	}
	if (optind < argc) { /* trailing non-options */
		printf("non-option arguments: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		goto exit_main;
	}
	return;

 exit_main:
	if (*log_filename)
		g_string_free(*log_filename, TRUE);
	if (*policy_filename)
		g_string_free(*policy_filename, TRUE);
	exit(1);
}

static void seaudit_exit_app(void)
{
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));
	seaudit_destroy(seaudit_app);
	gtk_main_quit();
}

/* 
 * seaudit callbacks
 */
static void seaudit_update_title_bar(void *user_data)
{
	char str[STR_SIZE];
	char log_str[STR_SIZE];
	char policy_str[STR_SIZE];
	
	if (seaudit_app->cur_log != NULL) {
		g_assert(seaudit_app->audit_log_file->str);
		snprintf(log_str, STR_SIZE, "[Log file: %s]", (const char*)seaudit_app->audit_log_file->str);
	} else {
		snprintf(log_str, STR_SIZE, "[Log file: No Log]");
	}
	
	if (seaudit_app->cur_policy != NULL) {
		snprintf(policy_str, STR_SIZE, "[Policy file: %s]", (const char*)seaudit_app->policy_file->str);
	} else {
		snprintf(policy_str, STR_SIZE, "[Policy file: No Policy]");
	}
	snprintf(str, STR_SIZE, "seAudit - %s %s", log_str, policy_str);	
	gtk_window_set_title(seaudit_app->window->window, (gchar*) str);
}
