/**
 *  @file utilgui.h
 *  Miscellaneous helper functions for GTK+ applications.
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

#ifndef UTILGUI_H
#define UTILGUI_H

#include <gtk/gtk.h>

/**
 * Pop-up a dialog with a line of text and wait for the user to
 * dismiss the dialog.
 *
 * @param parent Parent window; this message dialog will be centered
 * upon the parent.
 * @param msg_type Type of message being displayed.
 * @param msg Text of message to display.
 */
void util_message(GtkWindow * parent, GtkMessageType msg_type, const char *msg);
/**
 * Set the cursor over a widget to the watch cursor.
 *
 * @param widget Widget whose cursor to set.
 */
void util_cursor_wait(GtkWidget * widget);

/**
 * Clear the cursor over a widget, setting it to the default arrow.
 *
 * @param widget Widget whose cursor to set.
 */
void util_cursor_clear(GtkWidget * widget);

#endif
