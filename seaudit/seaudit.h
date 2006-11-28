/**
 *  @file seaudit.h
 *  Declaration of the main driver class for seaudit.
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

#ifndef SEAUDIT_H
#define SEAUDIT_H

#include "preferences.h"
#include <apol/policy.h>
#include <seaudit/log.h>

typedef struct seaudit seaudit_t;

/**
 * Retrieve the preferences object associated with the seaudit object.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to a preferences object.  Do not free() this pointer.
 */
preferences_t *seaudit_get_prefs(seaudit_t * s);

/**
 * Retrieve the currently loaded policy.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to an apol policy, or NULL if none loaded.  Treat
 * this as a const pointer.
 */
apol_policy_t *seaudit_get_policy(seaudit_t * s);

/**
 * Retrieve the currently loaded log file.
 *
 * @param s seaudit object to query.
 *
 * @return Pointer to a libseaudit log, or NULL if none loaded.  Treat
 * this as a const pointer.
 */
seaudit_log_t *seaudit_get_log(seaudit_t * s);

#define COPYRIGHT_INFO "Copyright (c) 2003-2006 Tresys Technology, LLC"

#if 0

#include "auditlogmodel.h"
#include "filter_window.h"
#include "preferences.h"
#include "report_window.h"
#include "seaudit_window.h"

#include <seaudit/log.h>
#include <seaudit/model.h>

#include <apol/util.h>
#include <apol/policy.h>
#include <apol/vector.h>

#include <glade/glade.h>
#include <gtk/gtk.h>

#include <assert.h>

#ifndef STR_SIZE
#define STR_SIZE  8192
#endif

#ifndef TIME_SIZE
#define TIME_SIZE 64
#endif

#ifndef DEFAULT_LOG
#define DEFAULT_LOG "/var/log/messages"
#endif

typedef struct seaudit
{
	gchar *last_log_message;
	int last_log_level;
	seaudit_window_t *window;
	GtkTextBuffer *policy_text;
	GList *callbacks;
	FILE *log_file_ptr;
	bool_t real_time_state;
	guint timeout_key;
	seaudit_conf_t seaudit_conf;
	GString *policy_file;
	GString *audit_log_file;
	bool_t column_visibility_changed;
	report_window_t *report_window;
} seaudit_t;

extern seaudit_t *seaudit_app;
#define SEAUDIT_VIEW_EXT ".vw"
#define SEAUDIT_FILTER_EXT ".ftr"

seaudit_t *seaudit_init(void);
void seaudit_destroy(seaudit_t * seaudit_ap);
int seaudit_open_policy(seaudit_t * seaudit_ap, const char *filename);
int seaudit_open_log_file(seaudit_t * seaudit_ap, const char *filename);
void seaudit_update_status_bar(seaudit_t * seaudit);
void seaudit_view_entire_selection_update_sensitive(bool_t disable);
/* Functions related to exporting log files */

void seaudit_save_log_file(bool_t selected_only);
int seaudit_write_log_file(const seaudit_model_t * log_view, const char *filename);
audit_log_view_t *seaudit_get_current_audit_log_view();
void generate_message_header(char *message_header, audit_log_t * audit_log, struct tm *date_stamp, char *host);
void write_avc_message_to_file(FILE * log_file, const avc_msg_t * message, const char *message_header, audit_log_t * audit_log);
void write_load_policy_message_to_file(FILE * log_file, const load_policy_msg_t * message, const char *message_header);
void write_boolean_message_to_file(FILE * log_file, const boolean_msg_t * message, const char *message_header,
				   audit_log_t * audit_log);
void seaudit_window_view_entire_message_in_textbox(int *tree_item_idx);
void seaudit_on_export_selection_activated(void);

#endif

#endif
