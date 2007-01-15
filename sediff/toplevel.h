/**
 *  @file
 *  Headers for main toplevel window.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

typedef struct toplevel toplevel_t;

#include "progress.h"
#include "sediffx.h"
#include <apol/policy-path.h>
#include <gtk/gtk.h>
#include <poldiff/poldiff.h>

/**
 * Allocate and return an instance of the toplevel window object.
 * This will create the window, set up the menus and icons, then
 * display the window.
 *
 * @param s Main sediffx object that will control the toplevel.
 *
 * @return An initialized toplevel object, or NULL upon error.  The
 * caller must call toplevel_destroy() afterwards.
 */
toplevel_t *toplevel_create(sediffx_t * s);

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
 * Open the policy files.  Upon success destroy the existing policies
 * and current poldiff objects.
 *
 * @param top Toplevel object, used for UI control.
 * @param orig_path Path to the original policy.  This function takes
 * ownership of this object.
 * @param mod_path Path to the modified policy.  This function takes
 * ownership of this object.
 *
 * @return 0 on successful open, < 0 on error.
 */
int toplevel_open_policies(toplevel_t * top, apol_policy_path_t * orig_path, apol_policy_path_t * mod_path);

/**
 * Run the current poldiff object.  Afterwards this function will
 * notify the results object to update its view.
 *
 * @param top Toplevel object whose poldiff to run.
 */
void toplevel_run_diff(toplevel_t * top);

/**
 * Switch to the given policy's source tab, if not already visible,
 * and then scroll the view to show the given line.  Policy line
 * numbers are zero-indexed.
 *
 * @param top Toplevel object containing policy source tabs.
 * @param which Which policy's source tab to show.
 * @param line Line to show.
 */
void toplevel_show_policy_line(toplevel_t * top, sediffx_policy_e which, unsigned long line);

/**
 * Check if a loaded policy can show line numbers or not.  Note that
 * this is different than if a policy can show syntactic rules.
 *
 * @param top Toplevel object to query.
 * @param which Which loadad policy to check.
 *
 * @return Non-zero if the policy can show line numbers, zero if not.
 */
int toplevel_is_policy_capable_line_numbers(toplevel_t * top, sediffx_policy_e which);

/**
 * Enable or disable the toplevel's sort menu.  The sort menu should
 * be enabled only when showing the differences for TE rules;
 * otherwise it should be disabled.
 *
 * @param top Toplevel object containing sort menu.
 * @param sens New sensitivity for the menu.
 */
void toplevel_set_sort_menu_sensitivity(toplevel_t * top, gboolean sens);

/**
 * Return the filename containing sediffx's glade file.
 *
 * @param top Toplevel containing glade XML declarations.
 *
 * @return Name of the glade file.  Do not modify this string.
 */
char *toplevel_get_glade_xml(toplevel_t * top);

/**
 * Return the current page number for the toplevel main notebook.
 *
 * @param top Toplevel to query.
 *
 * @return Page number for the currently showing tab.
 */
gint toplevel_get_notebook_page(toplevel_t * top);

/**
 * Return the progress object, so that sub-windows may also show the
 * threaded progress object.
 *
 * @param top Toplevel containing progress object.
 *
 * @return Progress object.  Do not free() this pointer.
 */
progress_t *toplevel_get_progress(toplevel_t * top);

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
 * Retrieve the currently active poldiff object.  If policies have not
 * yet been loaded then this returns NULL.  Note that the poldiff
 * object will not be run yet; for that call toplevel_run_diff().
 *
 * @param top Toplevel containing poldiff object.
 *
 * @return poldiff object, or NULL if none availble or upon error.
 */
poldiff_t *toplevel_get_poldiff(toplevel_t * top);

/**
 * Get the flags that were used the most recently run poldiff.
 *
 * @param top Toplevel object to query.
 *
 * @return poldiff run flags, or 0 in none set.
 */
uint32_t toplevel_get_poldiff_run_flags(toplevel_t * top);

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

#if 0

/* STRUCT: sediff_app_t
   This structure is used to control the gui.  It contains the links
   to all necessary buffers, textviews, dlgs, etc that are needed.  */
typedef struct sediff_app
{
	GtkWindow *window;	       /* the main window */
	GtkWindow *open_dlg;	       /* dialog box used when opening up the policies */
	struct sediff_progress *progress;	/* dialog to show progress */
	struct sediff_results *results;	/* results display */
	GtkWidget *dummy_view;	       /* this is a view we put in the left hand pane when we have no diff, and therefore no treeview */
	GladeXML *window_xml;	       /* the main windows xml */
	GladeXML *open_dlg_xml;	       /* the open dialogs xml */
	GtkWidget *tree_view;	       /* the treeview seen on left hand pane */
	GList *callbacks;
	gint progress_completed;
	sediff_file_data_t p1_sfd;     /* file info for policy 1 */
	sediff_file_data_t p2_sfd;     /* file info for policy 2 */
	apol_policy_t *orig_pol, *mod_pol;
	poldiff_t *diff;
	struct sediff_remap_types *remap_types_window;	/* the remapped types window reference */
	struct sediff_find_window *find_window;	/* the find window reference */
	int tv_curr_buf;	       /* the buffer currently displayed for the treeview */
} sediff_app_t;

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t * app);

void sediff_initialize_diff(void);
void sediff_initialize_policies(void);
void run_diff_clicked(void);
#endif

#endif
