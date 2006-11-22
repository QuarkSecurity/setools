/**
 *  @file preferences.h
 *  Declaration of the current user's preferences for the seaudit
 *  application.
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

#ifndef PREFERENCES_H
#define PREFERENCES_H

typedef struct seaudit_prefs seaudit_prefs_t;

/**
 * Allocate and return a preferences object.  This function will first
 * initialize the object using the user's configuration file.  If that
 * is not readable then the system-wide configuration is attempted.
 * It is not an error if both files are not available.
 *
 * @return An initialized preferences object, or NULL upon error.  The
 * caller must call seaudit_prefs_destroy() afterwards.
 */
seaudit_prefs_t *seaudit_prefs_create(void);

/**
 * Destroy a preferences object, and all memory associated with it.
 * Does nothing if the pointer is already NULL.
 *
 * @param prefs Reference to a preferences object to destroy.  This
 * will be set to NULL afterwards.
 */
void seaudit_prefs_destroy(seaudit_prefs_t ** prefs);

/**
 * Write the preferences object to the user's configuration file,
 * overwriting any existing file.
 *
 * @param prefs Preferences object to write.
 *
 * @return 0 if successfully written, < 0 upon error.
 */
int seaudit_prefs_write_to_conf_file(seaudit_prefs_t * prefs);

/**
 * Set the filename for the preferred audit log file.  Unless
 * overridden by the command line, this log file will be opened when
 * seaudit is launched.
 *
 * @param prefs Preferences object to modify.
 * @param log Path to the log file.  The string will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_set_log(seaudit_prefs_t * prefs, const char *log);

/**
 * Get the filename for the preferred log file from the preferences
 * object.
 *
 * @param prefs Preferences object to query.
 *
 * @return Filename for the log file, or NULL if none set.  Do not
 * modify this string.
 */
char *seaudit_prefs_get_log(seaudit_prefs_t * prefs);

/**
 * Set the filename for the preferred policy.  Unless overridden by the
 * command line, this policy will be opened when seaudit is launched.
 *
 * @param prefs Preferences object to modify.
 * @param policy Path to the policy file.  The string will be
 * duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_set_policy(seaudit_prefs_t * prefs, const char *policy);

/**
 * Get the filename for the preferred policy from the preferences object.
 *
 * @param prefs Preferences object to query.
 *
 * @return Filename for the policy, or NULL if none set.  Do not
 * modify this string.
 */
char *seaudit_prefs_get_policy(seaudit_prefs_t * prefs);

/**
 * Set the default report filename.
 *
 * @param prefs Preferences object to modify.
 * @param report Path to the report.  The string will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_set_report(seaudit_prefs_t * prefs, const char *report);

/**
 * Get the default report filename.
 *
 * @param prefs Preferences object to query.
 *
 * @return Filename for the report, or NULL if none set.  Do not
 * modify this string.
 */
char *seaudit_prefs_get_report(seaudit_prefs_t * prefs);

/**
 * Set the default stylesheet filename.
 *
 * @param prefs Preferences object to modify.
 * @param stylesheet Path to the stylesheet.  The string will be
 * duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_set_stylesheet(seaudit_prefs_t * prefs, const char *stylesheet);

/**
 * Get the default stylesheet filename.
 *
 * @param prefs Preferences object to query.
 *
 * @return Filename for the stylesheet, or NULL if none set.  Do not
 * modify this string.
 */
char *seaudit_prefs_get_stylesheet(seaudit_prefs_t * prefs);

/**
 * Add a filename to the recently opened log files list.  If the name
 * is already in the list then do nothing.  Otherwise append the name
 * to the end of the list.  If the list grows too large then remove
 * the oldest entry.
 *
 * @param prefs Preferences object to modify.
 * @param log Path to the most recently opened log.  The string will
 * be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_add_recent_log(seaudit_prefs_t * prefs, const char *log);

/**
 * Add a filename to the recently opened policy files list.  If the
 * name is already in the list then do nothing.  Otherwise append the
 * name to the end of the list.  If the list grows too large then
 * remove the oldest entry.
 *
 * @param prefs Preferences object to modify.
 * @param policy Path to the most recently opened policy.  The string
 * will be duplicated.
 *
 * @return 0 on success, < 0 on error.
 */
int seaudit_prefs_add_recent_policy(seaudit_prefs_t * prefs, const char *policy);

#if 0

int save_seaudit_conf_file(seaudit_conf_t * conf_file);

/* load the preferences window */
void on_preferences_activate(GtkWidget * widget, GdkEvent * event, gpointer callback_data);

#endif

#endif
