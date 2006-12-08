/**
 *  @file policy_components_view.c
 *  Run the dialog to select from lists of strings.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#include "policy_components_view.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>

struct polcomp_view
{
	GladeXML *xml;
	toplevel_t *top;
	GtkDialog *dialog;
};

static void policy_components_view_init_widgets(struct polcomp_view *pv)
{
	pv->dialog = GTK_DIALOG(glade_xml_get_widget(pv->xml, "PolicyComponentListsWindow"));
	assert(pv->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(pv->dialog), toplevel_get_window(pv->top));
}

void policy_components_view_run(toplevel_t * top, GtkWindow * parent,
				apol_vector_t * log_items, apol_vector_t * policy_items, apol_vector_t * included)
{
	struct polcomp_view pv;
	gint response;

	memset(&pv, 0, sizeof(pv));
	pv.top = top;
	pv.xml = glade_xml_new(toplevel_get_glade_xml(top), "PolicyComponentListsWindow", NULL);

	policy_components_view_init_widgets(&pv);

	do {
		response = gtk_dialog_run(pv.dialog);
	} while (response != GTK_RESPONSE_CLOSE);

	gtk_widget_destroy(GTK_WIDGET(pv.dialog));
}
