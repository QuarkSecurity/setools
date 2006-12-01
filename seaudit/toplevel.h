/**
 *  @file toplevel.h
 *  Declaration of the main toplevel window for seaudit.
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

#ifndef TOPLEVEL_H
#define TOPLEVEL_H

#include "seaudit.h"
#include <glade/glade.h>
#include <gtk/gtk.h>
#include <seaudit/message.h>

typedef struct toplevel toplevel_t;

/**
 * Allocate and return an instance of the toplevel window object.
 * This will create the window, set up the menus and icons, create an
 * empty notebook, then display the window.
 *
 * @param s Main seaudit object that will control the toplevel.
 *
 * @return An initialized toplevel object, or NULL upon error.  The
 * caller must call toplevel_destroy() afterwards.
 */
toplevel_t *toplevel_create(seaudit_t * s);

/**
 * Destroy the toplevel window.  This function will recursively
 * destroy all other windows.  This does nothing if the pointer is set
 * to NULL.
 *
 * @param top Reference to a toplevel object.  Afterwards the pointer
 * will be set to NULL.
 */
void toplevel_destroy(toplevel_t ** top);

/**
 * Open a log file, destroying any existing logs and views first.
 * Afterwards, create a new view for the log.
 *
 * @param top Toplevel object, used for UI control.
 * @param filename Name of the log to open.
 */
void toplevel_open_log(toplevel_t * top, const char *filename);

/**
 * Open a policy file, destroying any existing policies first.
 *
 * @param top Toplevel object, used for UI control.
 * @param filename Name of the policy to open.
 */
void toplevel_open_policy(toplevel_t * top, const char *filename);

/**
 * Update the status bar to show the current policy, number of log
 * messages in the current view, range of messages in current view,
 * and monitor status.
 *
 * @param top Toplevel whose status bar to update.
 */
void toplevel_update_status_bar(toplevel_t * top);

/**
 * Update the menu items whenever a message is selected/deselected.
 * Certain commands are legal only when one or more messages are
 * selected.
 *
 * @param top Toplevel whose menu to update.
 */
void toplevel_update_selection_menu_item(toplevel_t * top);

/**
 * Return the current preferences object for the toplevel object.
 *
 * @param top Toplevel containing preferences.
 *
 * @return Pointer to a preferences object.  Do not free() this pointer.
 */
preferences_t *toplevel_get_prefs(toplevel_t * top);

/**
 * Return a seaudit_log_t object used for error reporting by
 * libseaudit.
 *
 * @param top Toplevel containing seaudit log object.
 *
 * @return libseaudit reporting object, or NULL if no log exists yet.
 * Treat this as a const pointer.
 */
seaudit_log_t *toplevel_get_log(toplevel_t * top);

/**
 * Return the currently loaded policy.
 *
 * @param top Toplevel containing policy.
 *
 * @return Current policy, or NULL if no policy is loaded yet.  Treat
 * this as a const pointer.
 */
apol_policy_t *toplevel_get_policy(toplevel_t * top);

/**
 * Return the glade XML object, so that other glade objects may be
 * created/modified.
 *
 * @param top Toplevel containing glade XML declarations.
 *
 * @return Glade XML declarations.
 */
GladeXML *toplevel_get_glade_xml(toplevel_t * top);

/**
 * Return the main application window.  Sub-windows should be set
 * transient to this window.
 *
 * @param top Toplevel containing main window.
 *
 * @return Main window.
 */
GtkWindow *toplevel_get_window(toplevel_t * top);

/**
 * (Re)open a dialog that allows the user to search for TE rules in
 * the currently opened policy.  If message is not NULL then set the
 * query's initial parameters to the message's source type, target
 * type, and object class.
 *
 * @param top Toplevel containing policy.
 * @param message If non-NULL, the initial parameters for query.
 */
void toplevel_find_terules(toplevel_t * top, seaudit_message_t * message);

/**
 * Pop-up an error dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_ERR(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

/**
 * Pop-up a warning dialog with a line of text and wait for the user
 * to dismiss the dialog.
 *
 * @param top Toplevel window; this message dialog will be centered
 * upon it.
 * @param format Format string to print, using syntax of printf(3).
 */
void toplevel_WARN(toplevel_t * top, const char *format, ...) __attribute__ ((format(printf, 2, 3)));

#endif
