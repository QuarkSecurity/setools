/**
 *  @file progress.h
 *  Header for showing progress dialogs.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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
#ifndef PROGRESS_H
#define PROGRESS_H

#include "toplevel.h"

#include <apol/policy.h>
#include <seaudit/log.h>

typedef struct progress progress_t;

/**
 * Allocate and return a new progress dialog object.
 *
 * @param top Toplevel object that will control the progress object.
 * @param parent Window upon which the progress dialog will be centered.
 *
 * @return An initialized progress object, or NULL upon error.  The
 * caller is responsible for calling progress_destroy() afterwards.
 */
progress_t *progress_create(toplevel_t * top, GtkWindow * parent);

/**
 * Destroy a progress dialog.  Does nothing if the pointer is already
 * NULL.
 *
 * @param prefs Reference to a progress object to destroy.  This will
 * be set to NULL afterwards.
 */
void progress_destroy(progress_t ** progress);

/**
 * Display a progress dialog.
 *
 * @param progress Progress dialog to show.
 * @param title Title for the progress window.
 */
void progress_show(progress_t * progress, const char *title);

/**
 * Hide the progress dialog.  Note that this does not actually destroy
 * the object.
 *
 * @param progress Progress dialog to hide.
 */
void progress_hide(progress_t * progress);

/* the rest of these are for multi-threaded progress dialog */

/**
 * Block the current thread until the progress dialog receives a done
 * signal via progress_done() or progress_abort().  The dialog will
 * periodically awake and update the user interface, based upon
 * message received by its handle implementations.
 *
 * @param progress Progress object to wait against.
 *
 * @return 0 if the progress object got a progress_done(), < 0 if
 * progress_abort().
 */
int progress_wait(progress_t * progress);

/**
 * Signal to a progress object that this thread is ending
 * successfully.  This will cause all threads waiting upon the
 * progress object to resume.
 *
 * @param progress Progress object to signal completion.
 */
void progress_done(progress_t * progress);

/**
 * Signal to a progress object that this thread completed with
 * warnings.  This will cause all threads waiting upon the progress
 * object to resume.
 *
 * @param progress Progress object to signal completion.
 * @param reason Explanation for warning, or NULL to use most recently
 * written message as the reason.
 */
void progress_warn(progress_t * progress, char *reason, ...) __attribute__ ((format(printf, 2, 3)));

/**
 * Signal to a progress object that this thread is aborting.  This
 * will cause all threads waiting upon the progress object to resume.
 *
 * @param progress Progress object to signal completion.
 * @param reason Explanation for abort, or NULL to abort for no
 * reason.  The most recently written message will be used as the
 * reason.
 */
void progress_abort(progress_t * progress, char *reason, ...) __attribute__ ((format(printf, 2, 3)));

/**
 * Have the progress dialog show a message upon its next refresh.
 *
 * @param progress Progress object to update.
 * @param message String to show.  This string will be duplicated.
 */
void progress_update(progress_t * progress, char *fmt, ...);

void progress_seaudit_handle_func(void *arg, seaudit_log_t * log, int level, const char *fmt, va_list va_args);
void progress_apol_handle_func(void *varg, apol_policy_t * p, int level, const char *fmt, va_list argp);

#endif
