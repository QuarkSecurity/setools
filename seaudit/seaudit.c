/**
 *  @file seaudit.c
 *  Main driver for the seaudit application.  This file also
 *  implements the main class seaudit_t.
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

#include "seaudit.h"
#include "toplevel.h"

#include <apol/util.h>
#include <seaudit/model.h>
#include <seaudit/util.h>

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <glade/glade.h>
#include <glib.h>
#include <gtk/gtk.h>

struct seaudit
{
	preferences_t *prefs;
	apol_policy_t *policy;
	char *policy_path;
	seaudit_log_t *log;
	char *log_path;
	size_t num_log_messages;
	struct tm *first, *last;
	toplevel_t *top;
};

static struct option const opts[] = {
	{"log", required_argument, NULL, 'l'},
	{"policy", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

preferences_t *seaudit_get_prefs(seaudit_t * s)
{
	return s->prefs;
}

void seaudit_set_policy(seaudit_t * s, apol_policy_t * policy, const char *filename)
{
	if (policy != NULL) {
		/* do it in this order, for filename could be pointing to
		 * s->policy_path */
		char *t = NULL;
		if ((t = strdup(filename)) == NULL || preferences_add_recent_policy(s->prefs, filename) < 0) {
			toplevel_ERR(s->top, "%s", strerror(errno));
			free(t);
			apol_policy_destroy(&policy);
			return;
		}
		apol_policy_destroy(&s->policy);
		s->policy = policy;
		free(s->policy_path);
		s->policy_path = t;
	} else {
		apol_policy_destroy(&s->policy);
		free(s->policy_path);
		s->policy_path = NULL;
	}
}

apol_policy_t *seaudit_get_policy(seaudit_t * s)
{
	return s->policy;
}

char *seaudit_get_policy_path(seaudit_t * s)
{
	return s->policy_path;
}

void seaudit_set_log(seaudit_t * s, seaudit_log_t * log, const char *filename)
{
	if (log != NULL) {
		seaudit_model_t *model = NULL;
		apol_vector_t *messages = NULL;
		char *t = NULL;
		if ((model = seaudit_model_create(NULL, log)) == NULL ||
		    (messages = seaudit_model_get_messages(log, model)) == NULL ||
		    (t = strdup(filename)) == NULL || preferences_add_recent_log(s->prefs, filename) < 0) {
			toplevel_ERR(s->top, "%s", strerror(errno));
			seaudit_log_destroy(&log);
			seaudit_model_destroy(&model);
			apol_vector_destroy(&messages, NULL);
			free(t);
			return;
		}
		/* do it in this order, for filename could be pointing to
		 * s->log_path */
		seaudit_log_destroy(&s->log);
		s->log = log;
		free(s->log_path);
		s->log_path = t;
		s->num_log_messages = apol_vector_get_size(messages);
		if (s->num_log_messages == 0) {
			s->first = s->last = NULL;
		} else {
			seaudit_message_t *message = apol_vector_get_element(messages, 0);
			s->first = seaudit_message_get_time(message);
			message = apol_vector_get_element(messages, s->num_log_messages - 1);
			s->last = seaudit_message_get_time(message);
		}
		seaudit_model_destroy(&model);
		apol_vector_destroy(&messages, NULL);
	} else {
		seaudit_log_destroy(&s->log);
		free(s->log_path);
		s->log_path = NULL;
		s->num_log_messages = 0;
		s->first = s->last = NULL;
	}
}

seaudit_log_t *seaudit_get_log(seaudit_t * s)
{
	return s->log;
}

char *seaudit_get_log_path(seaudit_t * s)
{
	return s->log_path;
}

size_t seaudit_get_num_log_messages(seaudit_t * s)
{
	return s->num_log_messages;
}

struct tm *seaudit_get_log_first(seaudit_t * s)
{
	return s->first;
}

struct tm *seaudit_get_log_last(seaudit_t * s)
{
	return s->last;
}

static seaudit_t *seaudit_create(preferences_t * prefs)
{
	seaudit_t *s = calloc(1, sizeof(*s));
	if (s != NULL) {
		s->prefs = prefs;
	}
	return s;
}

static void seaudit_destroy(seaudit_t ** s)
{
	if (s != NULL && *s != NULL) {
		apol_policy_destroy(&(*s)->policy);
		seaudit_log_destroy(&(*s)->log);
		preferences_destroy(&(*s)->prefs);
		toplevel_destroy(&(*s)->top);
		free((*s)->policy_path);
		free((*s)->log_path);
		free(*s);
		*s = NULL;
	}
}

static void print_version_info(void)
{
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   GUI version %s\n", VERSION);
	printf("   libapol version %s\n", libapol_get_version());
	printf("   libseaudit version %s\n\n", libseaudit_get_version());
}

static void print_usage_info(const char *program_name, int brief)
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
}

static void seaudit_parse_command_line(seaudit_t * seaudit, int argc, char **argv, char **log, char **policy)
{
	int optc;
	*log = NULL;
	*policy = NULL;
	while ((optc = getopt_long(argc, argv, "l:p:hv", opts, NULL)) != -1) {
		switch (optc) {
		case 'l':{
				*log = optarg;
				break;
			}
		case 'p':{
				*policy = optarg;
				break;
			}
		case 'h':{
				print_usage_info(argv[0], 0);
				seaudit_destroy(&seaudit);
				exit(EXIT_SUCCESS);
			}
		case 'v':{
				print_version_info();
				seaudit_destroy(&seaudit);
				exit(EXIT_SUCCESS);
			}
		case '?':
		default:{
				/* unrecognized argument give full usage */
				print_usage_info(argv[0], 0);
				seaudit_destroy(&seaudit);
				exit(EXIT_FAILURE);
			}
		}
	}
	if (optind < argc) {	       /* trailing non-options */
		print_usage_info(argv[0], 0);
		seaudit_destroy(&seaudit);
		exit(EXIT_FAILURE);
	}
	if (*log == NULL) {
		*log = preferences_get_log(seaudit->prefs);
	}
	if (*policy == NULL) {
		*policy = preferences_get_policy(seaudit->prefs);
	}
}

/*
 * We don't want to do the heavy work of loading and displaying the
 * log and policy before the main loop has started because it will
 * freeze the gui for too long.  To solve this, the function is called
 * from an idle callback set-up in main.
 */
struct delay_file_data
{
	toplevel_t *top;
	char *log_filename;
	char *policy_filename;
};

static gboolean delayed_main(gpointer data)
{
	struct delay_file_data *dfd = (struct delay_file_data *)data;
	if (dfd->log_filename != NULL && strcmp(dfd->log_filename, "") != 0) {
		toplevel_open_log(dfd->top, dfd->log_filename);
	}
	if (dfd->policy_filename != NULL && strcmp(dfd->policy_filename, "") != 0) {
		toplevel_open_policy(dfd->top, dfd->policy_filename);
	}
	return FALSE;
}

int main(int argc, char **argv)
{
	preferences_t *prefs;
	seaudit_t *app;
	char *log, *policy;
	struct delay_file_data file_data;

	gtk_init(&argc, &argv);
	glade_init();
	if (!g_thread_supported())
		g_thread_init(NULL);
	if ((prefs = preferences_create()) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	if ((app = seaudit_create(prefs)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	seaudit_parse_command_line(app, argc, argv, &log, &policy);
	if ((app->top = toplevel_create(app)) == NULL) {
		ERR(NULL, "%s", strerror(ENOMEM));
		seaudit_destroy(&app);
		exit(EXIT_FAILURE);
	}
	file_data.top = app->top;
	file_data.log_filename = log;
	file_data.policy_filename = policy;
	g_idle_add(&delayed_main, &file_data);
	gtk_main();
	if (preferences_write_to_conf_file(app->prefs) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
	}
	seaudit_destroy(&app);
	exit(EXIT_SUCCESS);
}

#if 0

#include "auditlogmodel.h"
#include "filter_window.h"
#include "preferences.h"
#include "query_window.h"
#include "report_window.h"
#include "seaudit.h"
#include "seaudit_callback.h"
#include "utilgui.h"

#include <seaudit/log.h>
#include <seaudit/parse.h>

#include <stdio.h>
#include <string.h>

#include <gdk-pixbuf/gdk-pixbuf.h>

static void seaudit_set_real_time_log_button_state(bool_t state);
static int seaudit_read_policy_conf(const char *fname);
static void seaudit_print_version_info(void);
static void seaudit_print_usage_info(const char *program_name, bool_t brief);
static void seaudit_parse_command_line(int argc, char **argv, GString ** policy_filename, GString ** log_filename);
static void seaudit_update_title_bar(void *user_data);
static void seaudit_set_recent_logs_submenu(seaudit_conf_t * conf_file);
static void seaudit_set_recent_policys_submenu(seaudit_conf_t * conf_file);
static void seaudit_policy_file_open_from_recent_menu(GtkWidget * widget, gpointer user_data);
static void seaudit_log_file_open_from_recent_menu(GtkWidget * widget, gpointer user_data);
static gboolean seaudit_real_time_update_log(gpointer callback_data);
static void seaudit_exit_app(void);

void seaudit_on_open_view_clicked(GtkMenuItem * menu_item, gpointer user_data)
{
	seaudit_window_open_view(seaudit_app->window, seaudit_app->cur_log, seaudit_app->seaudit_conf.column_visibility);
}

void seaudit_on_save_view_clicked(GtkMenuItem * menu_item, gpointer user_data)
{
	seaudit_window_save_current_view(seaudit_app->window, FALSE);
}

void seaudit_on_saveas_view_clicked(GtkMenuItem * menu_item, gpointer user_data)
{
	seaudit_window_save_current_view(seaudit_app->window, TRUE);
}

/*
 * glade autoconnected callbacks for the main toolbar
 */
void seaudit_on_filter_log_button_clicked(GtkWidget * widget, GdkEvent * event, gpointer callback_data)
{
	seaudit_filtered_view_t *view;

	if (seaudit_app->cur_log == NULL) {
		message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, "There is no audit log loaded.");
		return;
	}

	view = seaudit_window_get_current_view(seaudit_app->window);
	seaudit_filtered_view_display(view, seaudit_app->window->window);
	return;
}

void seaudit_on_create_standard_report_activate()
{
	if (!seaudit_app->report_window) {
		seaudit_app->report_window = report_window_create(seaudit_app->window, &seaudit_app->seaudit_conf, "Create Report");
		if (!seaudit_app->report_window) {
			fprintf(stderr, "Error: Out of memory!");
			return;
		}
	}

	report_window_display(seaudit_app->report_window);
}

void seaudit_on_real_time_button_pressed(GtkButton * button, gpointer user_data)
{
	bool_t state = seaudit_app->real_time_state;
	seaudit_set_real_time_log_button_state(!state);
}

/*
 * Timeout function used to keep the log up to date, always
 * return TRUE so we get called repeatedly */
static gboolean seaudit_real_time_update_log(gpointer callback_data)
{
	unsigned int rt = 0;
#define MSG_SIZE 64		       /* should be big enough */

	/* simply return if the log is not open */
	if (!seaudit_app->log_file_ptr)
		return TRUE;

	rt |= audit_log_parse(seaudit_app->cur_log, seaudit_app->log_file_ptr);
	if (rt & PARSE_RET_NO_SELINUX_ERROR)
		return TRUE;
	seaudit_window_filter_views(seaudit_app->window);
	return TRUE;
}

/*
 * Helper functions for seaudit_t
 */
static void seaudit_set_real_time_log_button_state(bool_t state)
{
	GtkWidget *widget, *image, *text, *lbl;

	widget = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeButton");
	g_assert(widget);
	text = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeLabel");
	g_assert(text);
	image = glade_xml_get_widget(seaudit_app->window->xml, "RealTimeImage");
	g_assert(image);
	lbl = glade_xml_get_widget(seaudit_app->window->xml, "monitor_lbl");
	g_assert(lbl);
	gtk_label_set_text(GTK_LABEL(text), "Toggle Monitor");
	gtk_image_set_from_stock(GTK_IMAGE(image), GTK_STOCK_REFRESH, GTK_ICON_SIZE_SMALL_TOOLBAR);

	/* remove timeout function if exists */
	if (seaudit_app->timeout_key)
		gtk_timeout_remove(seaudit_app->timeout_key);

	if (!state) {
		/*gtk_image_set_from_stock(GTK_IMAGE(image), GTK_STOCK_STOP, GTK_ICON_SIZE_SMALL_TOOLBAR); */
		gtk_label_set_markup(GTK_LABEL(lbl), "Monitor status: <span foreground=\"red\">OFF</span>");
		/* make inactive */
		seaudit_app->timeout_key = 0;
		seaudit_app->real_time_state = state;
	} else {
		gtk_image_set_from_stock(GTK_IMAGE(image), GTK_STOCK_REFRESH, GTK_ICON_SIZE_SMALL_TOOLBAR);
		gtk_label_set_markup(GTK_LABEL(lbl), "Monitor status: <span foreground=\"green\">ON</span>");
		/* make active */
		seaudit_app->timeout_key = g_timeout_add(seaudit_app->seaudit_conf.real_time_interval,
							 &seaudit_real_time_update_log, NULL);
		seaudit_app->real_time_state = state;
	}
}

#endif
