/**
 *  @file modify_view.c
 *  Run the dialog to modify a view.
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

#include "filter_view.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <glade/glade.h>

struct context_item
{
	GtkButton *button;
	GtkEntry *entry;
};

struct filter_view
{
	toplevel_t *top;
	seaudit_filter_t *filter;
	GladeXML *xml;

	GtkDialog *dialog;

	GtkEntry *name_entry;
	GtkComboBox *match_combo;

	struct context_item suser, srole, stype, tuser, trole, ttype, obj_class;
	GtkButton *context_clear_button;

	GtkEntry *ipaddr_entry, *port_entry, *netif_entry, *exe_entry, *path_entry, *host_entry, *comm_entry;
	GtkComboBox *message_combo;
	GtkButton *other_clear_button;

	GtkTextBuffer *description_buffer;
};

/**
 * Initialize pointers to widgets on the context tab.
 */
static void filter_view_init_widgets_context(struct filter_view *fv)
{
	fv->suser.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSUserButton"));
	fv->srole.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSRoleButton"));
	fv->stype.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewSTypeButton"));
	fv->tuser.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTUserButton"));
	fv->trole.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTRoleButton"));
	fv->ttype.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewTTypeButton"));
	fv->obj_class.button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewClassButton"));
	assert(fv->suser.button != NULL && fv->srole.button != NULL && fv->stype.button != NULL &&
	       fv->tuser.button != NULL && fv->trole.button != NULL && fv->ttype.button != NULL && fv->obj_class.button != NULL);

	fv->suser.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSUserEntry"));
	fv->srole.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSRoleEntry"));
	fv->stype.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewSTypeEntry"));
	fv->tuser.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTUserEntry"));
	fv->trole.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTRoleEntry"));
	fv->ttype.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewTTypeEntry"));
	fv->obj_class.entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewClassEntry"));
	assert(fv->suser.entry != NULL && fv->srole.entry != NULL && fv->stype.entry != NULL &&
	       fv->tuser.entry != NULL && fv->trole.entry != NULL && fv->ttype.entry != NULL && fv->obj_class.entry != NULL);

	fv->context_clear_button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewContextClearButton"));
	assert(fv->context_clear_button != NULL);
}

/**
 * Initialize pointers to widgets on the other tab.
 */
static void filter_view_init_widgets_other(struct filter_view *fv)
{
	fv->ipaddr_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewIPAddrEntry"));
	fv->port_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewPortEntry"));
	fv->netif_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewNetIfEntry"));
	assert(fv->ipaddr_entry != NULL && fv->port_entry != NULL && fv->netif_entry != NULL);

	fv->exe_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewExeEntry"));
	fv->path_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewPathEntry"));
	fv->host_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewHostEntry"));
	fv->comm_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewCommEntry"));
	assert(fv->exe_entry != NULL && fv->path_entry != NULL && fv->host_entry != NULL && fv->comm_entry != NULL);

	fv->message_combo = GTK_COMBO_BOX(glade_xml_get_widget(fv->xml, "FilterViewMessageCombo"));
	assert(fv->message_combo != NULL);

	fv->other_clear_button = GTK_BUTTON(glade_xml_get_widget(fv->xml, "FilterViewOtherClearButton"));
	assert(fv->other_clear_button != NULL);
}

/**
 * Initialize pointers to widgets on the date tab.
 */
static void filter_view_init_widgets_date(struct filter_view *fv)
{
}

static void filter_view_init_widgets(struct filter_view *fv)
{
	GtkTextView *description_view;

	fv->dialog = GTK_DIALOG(glade_xml_get_widget(fv->xml, "FilterWindow"));
	assert(fv->dialog != NULL);
	gtk_window_set_transient_for(GTK_WINDOW(fv->dialog), toplevel_get_window(fv->top));

	fv->name_entry = GTK_ENTRY(glade_xml_get_widget(fv->xml, "FilterViewNameEntry"));
	fv->match_combo = GTK_COMBO_BOX(glade_xml_get_widget(fv->xml, "FilterViewMatchCombo"));
	assert(fv->name_entry != NULL && fv->match_combo);

	filter_view_init_widgets_context(fv);
	filter_view_init_widgets_other(fv);
	filter_view_init_widgets_date(fv);

	fv->description_buffer = gtk_text_buffer_new(NULL);
	g_object_ref_sink(fv->description_buffer);
	description_view = GTK_TEXT_VIEW(glade_xml_get_widget(fv->xml, "FilterViewDescView"));
	assert(description_view != NULL);
	gtk_text_view_set_buffer(description_view, fv->description_buffer);
}

/********** functions that copies filter object values to widget **********/

/**
 * If the entry is empty, then call the modifier function passing NULL
 * as the second parameter.  Else call the function with the entry's
 * contents.
 */
static void filter_view_init_entry(struct filter_view *fv, char *(*accessor) (seaudit_filter_t *), GtkEntry * entry)
{
	char *s = accessor(fv->filter);
	if (s == NULL) {
		s = "";
	}
	gtk_entry_set_text(entry, s);
}

static void filter_view_init_other(struct filter_view *fv)
{
	char s[32];
	filter_view_init_entry(fv, seaudit_filter_get_ipaddress, fv->ipaddr_entry);
	if (seaudit_filter_get_port(fv->filter) <= 0) {
		s[0] = '\0';
	} else {
		snprintf(s, 32, "%d", seaudit_filter_get_port(fv->filter));
	}
	gtk_entry_set_text(fv->port_entry, s);
	filter_view_init_entry(fv, seaudit_filter_get_netif, fv->netif_entry);
	filter_view_init_entry(fv, seaudit_filter_get_executable, fv->exe_entry);
	filter_view_init_entry(fv, seaudit_filter_get_path, fv->path_entry);
	filter_view_init_entry(fv, seaudit_filter_get_host, fv->host_entry);
	filter_view_init_entry(fv, seaudit_filter_get_command, fv->comm_entry);
	switch (seaudit_filter_get_message_type(fv->filter)) {
	case SEAUDIT_AVC_DENIED:
		gtk_combo_box_set_active(fv->message_combo, 1);
		break;
	case SEAUDIT_AVC_GRANTED:
		gtk_combo_box_set_active(fv->message_combo, 2);
		break;
	default:
		gtk_combo_box_set_active(fv->message_combo, 0);
	}
}

/**
 * Copy values from seaudit filter object to GTK+ widgets.
 */
static void filter_view_init_dialog(struct filter_view *fv)
{
	char *name = seaudit_filter_get_name(fv->filter);
	char *desc = seaudit_filter_get_description(fv->filter);;
	if (name == NULL) {
		name = "Untitled";
	}
	gtk_entry_set_text(fv->name_entry, name);
	gtk_combo_box_set_active(fv->match_combo, seaudit_filter_get_match(fv->filter));

	filter_view_init_other(fv);

	if (desc == NULL) {
		desc = "";
	}
	gtk_text_buffer_set_text(fv->description_buffer, desc, -1);
}

/********** functions that copies widget values to filter object **********/

/**
 * If the entry is empty, then call the modifier function passing NULL
 * as the second parameter.  Else call the function with the entry's
 * contents.
 */
static void filter_view_apply_entry(struct filter_view *fv, GtkEntry * entry, int (*modifier) (seaudit_filter_t *, const char *))
{
	const char *s = gtk_entry_get_text(entry);
	if (strcmp(s, "") == 0) {
		s = NULL;
	}
	if (modifier(fv->filter, s) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
	}
}

/**
 * Copy values from the other tab to filter object.
 */
static void filter_view_apply_other(struct filter_view *fv)
{
	const char *s;
	int port = 0;
	seaudit_avc_message_type_e message_type;

	filter_view_apply_entry(fv, fv->ipaddr_entry, seaudit_filter_set_ipaddress);
	s = gtk_entry_get_text(fv->port_entry);
	if (strcmp(s, "") != 0) {
		port = atoi(s);
	}
	if (seaudit_filter_set_port(fv->filter, port) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
		return;
	}
	filter_view_apply_entry(fv, fv->netif_entry, seaudit_filter_set_netif);
	filter_view_apply_entry(fv, fv->exe_entry, seaudit_filter_set_executable);
	filter_view_apply_entry(fv, fv->path_entry, seaudit_filter_set_path);
	filter_view_apply_entry(fv, fv->host_entry, seaudit_filter_set_host);
	filter_view_apply_entry(fv, fv->comm_entry, seaudit_filter_set_command);
	switch (gtk_combo_box_get_active(fv->message_combo)) {
	case 1:
		message_type = SEAUDIT_AVC_DENIED;
		break;
	case 2:
		message_type = SEAUDIT_AVC_GRANTED;
		break;
	default:
		message_type = SEAUDIT_AVC_UNKNOWN;
	}
	if (seaudit_filter_set_message_type(fv->filter, message_type) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
		return;
	}
}

/**
 * Copy values from GTK+ widgets to the seaudit filter object.
 */
static void filter_view_apply(struct filter_view *fv)
{
	GtkTextIter start, end;
	char *s;
	seaudit_filter_match_e match = SEAUDIT_FILTER_MATCH_ALL;

	filter_view_apply_entry(fv, fv->name_entry, seaudit_filter_set_name);
	if (gtk_combo_box_get_active(fv->match_combo) == 1) {
		match = SEAUDIT_FILTER_MATCH_ANY;
	}
	if (seaudit_filter_set_match(fv->filter, match) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
	}

	filter_view_apply_other(fv);
	gtk_text_buffer_get_bounds(fv->description_buffer, &start, &end);
	s = gtk_text_buffer_get_text(fv->description_buffer, &start, &end, FALSE);
	if (strcmp(s, "") == 0) {
		free(s);
		s = NULL;
	}
	if (seaudit_filter_set_description(fv->filter, s) < 0) {
		toplevel_ERR(fv->top, "Error setting filter: %s", strerror(errno));
	}
	free(s);
}

/******************** signal handlers for dialog ********************/

static void filter_view_on_other_clear_click(GtkButton * widget, gpointer user_data)
{
}

static void filter_view_init_signals(struct filter_view *fv)
{
	g_signal_connect(fv->other_clear_button, "clicked", G_CALLBACK(filter_view_on_other_clear_click), fv);
}

/******************** public function below ********************/

void filter_view_run(seaudit_filter_t * filter, toplevel_t * top, GtkWindow * parent)
{
	struct filter_view fv;
	gint response;

	memset(&fv, 0, sizeof(fv));
	fv.top = top;
	fv.filter = filter;
	fv.xml = glade_xml_new(toplevel_get_glade_xml(top), "FilterWindow", NULL);
	filter_view_init_widgets(&fv);
	filter_view_init_signals(&fv);
	filter_view_init_dialog(&fv);
	do {
		response = gtk_dialog_run(fv.dialog);
	} while (response != GTK_RESPONSE_CLOSE);

	filter_view_apply(&fv);
	g_object_unref(fv.description_buffer);
	gtk_widget_destroy(GTK_WIDGET(fv.dialog));
}

#if 0

/* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Kevin Carr <kcarr@tresys.com>
 * Date: October 23, 2003
 *
 * Modified by Don Patterson <don.patterson@tresys.com>
 * Comment(s): Changed to a more object-oriented design.
 *
 * Karl MacMillan <kmacmillan@tresys.com>
 *
 */

#include <config.h>

#include "filter_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include "seaudit_callback.h"
#include <seaudit/filters.h>
#include <seaudit/auditlog.h>
#include <apol/policy.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#define TM_YEAR_ZERO 1900

enum
{
	ITEMS_LIST_COLUMN,
	NUMBER_ITEMS_LIST_COLUMNS
};

enum items_list_types_t
{
	SEAUDIT_SRC_TYPES,
	SEAUDIT_SRC_USERS,
	SEAUDIT_SRC_ROLES,
	SEAUDIT_TGT_TYPES,
	SEAUDIT_TGT_USERS,
	SEAUDIT_TGT_ROLES,
	SEAUDIT_OBJECTS
};

enum select_values_source_t
{
	SEAUDIT_FROM_LOG,
	SEAUDIT_FROM_POLICY,
	SEAUDIT_FROM_UNION
};

enum message_types
{
	SEAUDIT_MSG_NONE,
	SEAUDIT_MSG_AVC_DENIED,
	SEAUDIT_MSG_AVC_GRANTED
};

/* define the date time options */
#define SEAUDIT_DT_OPTION_NONE 0
#define SEAUDIT_DT_OPTION_BEFORE 1
#define SEAUDIT_DT_OPTION_AFTER 2
#define SEAUDIT_DT_OPTION_BETWEEN 3

#define SEAUDIT_MAX_U16_STRLEN 5       /* the max # of chars that can be in a string representing a 16 bit digit */

const char *msg_type_strs[] = { "none", "denied", "granted" };

typedef struct seaudit_filter_list
{
	char **list;
	int size;
} seaudit_filter_list_t;

struct filter_window;

typedef struct filters_select_items
{
	GtkListStore *selected_items;
	GtkListStore *unselected_items;
	enum items_list_types_t items_list_type;
	enum select_values_source_t items_source;
	GtkWindow *window;
	GladeXML *xml;
	struct filter_window *parent;
} filters_select_items_t;

typedef struct filters_date_item
{
	struct tm *start;
	struct tm *end;
	unsigned int option;
} filters_date_item_t;

extern seaudit_t *seaudit_app;

/* Given the year and the month set the spin button to have the correct number of
   days for that month */
static void filter_window_date_set_number_days(int month, GtkSpinButton * button)
{
	int days[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int cur_day;
	if (!button || month < 0)
		return;
	/* we have to get the current day because set_range moves the current day
	 * by the difference minus 1 day, i.e. going from jan 20 to february
	 * the day would automatically become 18 */
	cur_day = gtk_spin_button_get_value_as_int(button);
	gtk_spin_button_set_range(button, 1, days[month]);
	/* return to current day, or to the max value allowed in range */
	gtk_spin_button_set_value(button, cur_day);
	return;
}

/* this is called whenever the month or year is changed in the date filter*/
static void filter_window_date_update_days(GladeXML * xml)
{
	int month;
	GtkWidget *widget;

	if (!xml)
		return;

	widget = glade_xml_get_widget(xml, "DateStartMonth");
	/* remember that months start with 0 in this widget */
	month = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	widget = glade_xml_get_widget(xml, "DateStartDay");
	filter_window_date_set_number_days(month, GTK_SPIN_BUTTON(widget));

	widget = glade_xml_get_widget(xml, "DateEndMonth");
	/* remember that months start with 0 in this widget */
	month = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	widget = glade_xml_get_widget(xml, "DateEndDay");
	filter_window_date_set_number_days(month, GTK_SPIN_BUTTON(widget));

}

/* set the frames sorrounding date options sensitive based on toggle selections */
static void filter_window_date_set_sensitive(GtkToggleButton * tb, gpointer user_data)
{
	GtkWidget *startframe;
	GtkWidget *endframe;
	filter_window_t *fw = (filter_window_t *) user_data;
	const char *name;
	/* if this toggle button is the deselected one just return */
	if (!gtk_toggle_button_get_active(tb))
		return;
	startframe = glade_xml_get_widget(fw->xml, "DateStartFrame");
	endframe = glade_xml_get_widget(fw->xml, "DateEndFrame");
	if (!startframe || !endframe)
		return;
	name = gtk_widget_get_name(GTK_WIDGET(tb));
	if (strcmp(name, "MatchNoneRadio") == 0) {
		gtk_widget_set_sensitive(startframe, FALSE);
		gtk_widget_set_sensitive(endframe, FALSE);
	} else if (strcmp(name, "MatchBetweenRadio") == 0) {
		gtk_widget_set_sensitive(startframe, TRUE);
		gtk_widget_set_sensitive(endframe, TRUE);
	} else {
		gtk_widget_set_sensitive(startframe, TRUE);
		gtk_widget_set_sensitive(endframe, FALSE);
	}
}

/* get the option from the date filter gui */
int filters_window_get_tm_option(GladeXML * xml)
{
	GtkWidget *widget;
	widget = glade_xml_get_widget(xml, "MatchNoneRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_NONE;
	widget = glade_xml_get_widget(xml, "MatchBeforeRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_BEFORE;
	widget = glade_xml_get_widget(xml, "MatchAfterRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_AFTER;
	return SEAUDIT_DT_OPTION_BETWEEN;
}

/*
   get the current time stored in the window and place in parameter tm
   unless the year is not valid, then do not overwrite the year
*/
static int filters_window_update_tm(filter_window_t * fw, bool_t start, struct tm *tm)
{
	GladeXML *xml;
	GtkWidget *widget = NULL;

	if (!fw || !tm)
		return -1;
	xml = fw->xml;
	if (start) {
		/* get the date */
		widget = glade_xml_get_widget(xml, "DateStartMonth");
		tm->tm_mon = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
		widget = glade_xml_get_widget(xml, "DateStartDay");
		tm->tm_mday = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		tm->tm_year = 0;
		/* get the hour min sec */
		widget = glade_xml_get_widget(xml, "DateStartHour");
		tm->tm_hour = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateStartMinute");
		tm->tm_min = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateStartSecond");
		tm->tm_sec = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
	} else {
		/* get the date */
		widget = glade_xml_get_widget(xml, "DateEndMonth");
		tm->tm_mon = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
		widget = glade_xml_get_widget(xml, "DateEndDay");
		tm->tm_mday = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		tm->tm_year = 0;
		/* get the hour min sec */
		widget = glade_xml_get_widget(xml, "DateEndHour");
		tm->tm_hour = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateEndMinute");
		tm->tm_min = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateEndSecond");
		tm->tm_sec = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
	}
	return 0;
}

/******************************************************************
 * The following are private methods for the filters_select_items *
 * object. This object is encapsulated by the filters object.	  *
 ******************************************************************/
static GtkEntry *filters_select_items_get_entry(filters_select_items_t * s)
{
	GtkEntry *entry;
	GtkWidget *widget;

	switch (s->items_list_type) {
	case SEAUDIT_SRC_TYPES:
		widget = glade_xml_get_widget(s->parent->xml, "SrcTypesEntry");
		break;
	case SEAUDIT_TGT_TYPES:
		widget = glade_xml_get_widget(s->parent->xml, "TgtTypesEntry");
		break;

	case SEAUDIT_SRC_USERS:
		widget = glade_xml_get_widget(s->parent->xml, "SrcUsersEntry");
		break;
	case SEAUDIT_TGT_USERS:
		widget = glade_xml_get_widget(s->parent->xml, "TgtUsersEntry");
		break;

	case SEAUDIT_SRC_ROLES:
		widget = glade_xml_get_widget(s->parent->xml, "SrcRolesEntry");
		break;
	case SEAUDIT_TGT_ROLES:
		widget = glade_xml_get_widget(s->parent->xml, "TgtRolesEntry");
		break;

	case SEAUDIT_OBJECTS:
		widget = glade_xml_get_widget(s->parent->xml, "ObjClassEntry");
		break;
	default:
		fprintf(stderr, "Bad type specified!!\n");
		return NULL;
	};
	assert(widget);
	entry = GTK_ENTRY(widget);

	return entry;
}

/* Note: the caller must free the string */
static void filters_select_items_add_item_to_list_model(GtkTreeModel * model, const gchar * item)
{
	GtkTreeIter iter;
	gchar *str_data = NULL;
	gint row = 0;
	gboolean valid;

	/* As a defensive programming technique, we first make sure the string is */
	/* a valid size before adding it to the list store. If not, then ignore.  */
/*
	if (!is_valid_str_sz(item)) {
		fprintf(stderr, "Item string too large....Ignoring");
		return;
	}
*/

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) < 0)
			break;
		valid = gtk_tree_model_iter_next(model, &iter);
		row++;
	}
	/* now insert it into the specified list model */
	gtk_list_store_insert(GTK_LIST_STORE(model), &iter, row);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, ITEMS_LIST_COLUMN, item, -1);
}

static gboolean filters_select_items_is_value_selected(filters_select_items_t * filter_items_list, const gchar * item)
{
	gboolean valid;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL(filter_items_list->selected_items);
	gchar *str_data;

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) == 0)
			return TRUE;
		valid = gtk_tree_model_iter_next(model, &iter);
	}
	return FALSE;
}

static gboolean filters_select_items_is_value_unselected(filters_select_items_t * filter_items_list, const gchar * item)
{
	gboolean valid;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL(filter_items_list->unselected_items);
	gchar *str_data;

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) == 0)
			return TRUE;
		valid = gtk_tree_model_iter_next(model, &iter);
	}
	return FALSE;
}

static gboolean is_value_from_current_items_source(filters_select_items_t * filter_items_list, const gchar * item_str)
{
	qpol_type_t *type;
	qpol_user_t *user;
	qpol_role_t *role;
	qpol_class_t *class;

	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES || filter_items_list->items_list_type == SEAUDIT_TGT_TYPES)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_type_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_type_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &type) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_type_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_type_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &type) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS || filter_items_list->items_list_type == SEAUDIT_TGT_USERS)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_user_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_user_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &user) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_user_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_user_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &user) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES || filter_items_list->items_list_type == SEAUDIT_TGT_ROLES)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_role_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_role_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &role) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_role_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_role_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &role) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
	} else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_obj_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_class_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &class) ==
				0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_obj_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_class_by_name(apol_policy_get_qpol(seaudit_app->cur_policy), item_str, &class) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}
	return FALSE;
}

/* add an unselected item */
static void filters_select_items_add_unselected_value(filters_select_items_t * filter_items_list, const gchar * item)
{
	if (filters_select_items_is_value_selected(filter_items_list, item))
		return;
	if (filters_select_items_is_value_unselected(filter_items_list, item))
		return;
	filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items), item);
}

static void filters_select_items_add_selected_value(filters_select_items_t * filter_items_list, const gchar * item)
{
	if (filters_select_items_is_value_selected(filter_items_list, item))
		return;
	if (filters_select_items_is_value_unselected(filter_items_list, item))
		return;
	filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->selected_items), item);
}

static void filters_select_items_set_objects_list_stores_default_values(filters_select_items_t * filter_items_list)
{
	int i;
	const char *object;
	char *class_name;
	apol_vector_t *class_vector;
	qpol_class_t *class = NULL;

	apol_class_get_by_query(seaudit_app->cur_policy, NULL, &class_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (object = audit_log_get_obj(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(object, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, object);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; i < apol_vector_get_size(class_vector); i++) {
			/* Add to excluded objects list store */
			class = apol_vector_get_element(class_vector, i);
			qpol_class_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), class, &class_name);
			filters_select_items_add_unselected_value(filter_items_list, class_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (object = audit_log_get_obj(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(object, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, object);
		for (i = 0; i < apol_vector_get_size(class_vector); i++)
			/* Add to excluded objects list store */
			class = apol_vector_get_element(class_vector, i);
		qpol_class_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), class, &class_name);
		filters_select_items_add_unselected_value(filter_items_list, class_name);
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&class_vector, NULL);
}

static void filters_select_items_set_roles_list_stores_default_values(filters_select_items_t * filter_items_list)
{
	int i;
	const char *role;
	char *role_name;
	apol_vector_t *role_vector;
	qpol_role_t *role_type;

	apol_role_get_by_query(seaudit_app->cur_policy, NULL, &role_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (role = audit_log_get_role(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(role, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, role);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; i < apol_vector_get_size(role_vector); i++) {
			role_type = apol_vector_get_element(role_vector, i);
			qpol_role_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), role_type, &role_name);
			filters_select_items_add_unselected_value(filter_items_list, role_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (role = audit_log_get_role(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(role, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, role);
		for (i = 0; i < apol_vector_get_size(role_vector); i++) {
			role_type = apol_vector_get_element(role_vector, i);
			qpol_role_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), role_type, &role_name);
			filters_select_items_add_unselected_value(filter_items_list, role_name);
		}
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&role_vector, NULL);
}

static void filters_select_items_set_users_list_stores_default_values(filters_select_items_t * filter_items_list)
{
	const char *user_str;
	int i;
	apol_vector_t *user_vector;
	qpol_user_t *user;
	char *user_name;

	apol_user_get_by_query(seaudit_app->cur_policy, NULL, &user_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (user_str = audit_log_get_user(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(user_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, user_str);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; apol_vector_get_size(user_vector); i++) {
			user = apol_vector_get_element(user_vector, i);
			qpol_user_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), user, &user_name);
			filters_select_items_add_unselected_value(filter_items_list, user_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (user_str = audit_log_get_user(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(user_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, user_str);
		for (i = 0; apol_vector_get_size(user_vector); i++) {
			user = apol_vector_get_element(user_vector, i);
			qpol_user_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), user, &user_name);
			filters_select_items_add_unselected_value(filter_items_list, user_name);
		}
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&user_vector, NULL);
}

static void filters_select_items_set_types_list_stores_default_values(filters_select_items_t * filter_items_list)
{
	int i;
	const char *type_str;
	apol_vector_t *type_vector;
	qpol_type_t *type;
	char *type_name;

	apol_type_get_by_query(seaudit_app->cur_policy, NULL, &type_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (type_str = audit_log_get_type(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(type_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, type_str);
		break;
	case SEAUDIT_FROM_POLICY:
		/* start iteration of types at index 1 in order to skip 'self' type */
		for (i = 1; i < apol_vector_get_size(type_vector); i++) {
			type = apol_vector_get_element(type_vector, i);
			qpol_type_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), type, &type_name);
			filters_select_items_add_unselected_value(filter_items_list, type_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (type_str = audit_log_get_type(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(type_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list, type_str);
		for (i = 1; i < apol_vector_get_size(type_vector); i++) {
			type = apol_vector_get_element(type_vector, i);
			qpol_type_get_name(apol_policy_get_qpol(seaudit_app->cur_policy), type, &type_name);
			filters_select_items_add_unselected_value(filter_items_list, type_name);
		}
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
	}
	apol_vector_destroy(&type_vector, NULL);
}

static void filters_select_items_set_list_stores_default_values(filters_select_items_t * filter_items_list)
{
	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES || filter_items_list->items_list_type == SEAUDIT_TGT_TYPES)
		/* types */
		filters_select_items_set_types_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS || filter_items_list->items_list_type == SEAUDIT_TGT_USERS)
		/* users */
		filters_select_items_set_users_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES || filter_items_list->items_list_type == SEAUDIT_TGT_ROLES)
		/* roles */
		filters_select_items_set_roles_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS)
		/* objects */
		filters_select_items_set_objects_list_stores_default_values(filter_items_list);

	else
		fprintf(stderr, "Wrong filter parameter specified.\n");
}

static void filters_select_items_refresh_unselected_list_store(filters_select_items_t * filters_select)
{
	show_wait_cursor(GTK_WIDGET(filters_select->window));
	gtk_list_store_clear(filters_select->unselected_items);
	filters_select_items_set_list_stores_default_values(filters_select);
	clear_wait_cursor(GTK_WIDGET(filters_select->window));
}

static void filters_select_items_on_radio_button_toggled(GtkToggleButton * button, gpointer user_data)
{
	filters_select_items_t *filters_select = (filters_select_items_t *) user_data;

	if (gtk_toggle_button_get_active(button)) {
		if (strcmp("LogRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) == 0)
			filters_select->items_source = SEAUDIT_FROM_LOG;
		if (strcmp("PolicyRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) == 0)
			filters_select->items_source = SEAUDIT_FROM_POLICY;
		if (strcmp("UnionRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) == 0)
			filters_select->items_source = SEAUDIT_FROM_UNION;
		filters_select_items_refresh_unselected_list_store(filters_select);
	}
}

static void filters_select_items_fill_entry(filters_select_items_t * s)
{
	GtkTreeIter iter;
	gboolean valid, first = TRUE;
	GString *string;
	gchar *item;
	GtkEntry *entry;

	string = g_string_new("");

	valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->selected_items), &iter);
	while (valid) {
		if (first)
			first = FALSE;
		else
			g_string_append(string, ", ");
		gtk_tree_model_get(GTK_TREE_MODEL(s->selected_items), &iter, ITEMS_LIST_COLUMN, &item, -1);
		g_string_append(string, item);
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->selected_items), &iter);
	}
	entry = filters_select_items_get_entry(s);
	if (!entry) {
		fprintf(stderr, "Could not get entry widget!");
		return;
	}
	gtk_entry_set_text(entry, string->str);
	g_string_free(string, TRUE);
}

static void filters_select_items_move_to_selected_items_list(filters_select_items_t * filter_items_list)
{
	GtkTreeView *include_tree, *exclude_tree;
	GtkTreeModel *incl_model, *excl_model;
	GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path;
	gchar *item_str = NULL;

	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);

	incl_model = GTK_TREE_MODEL(filter_items_list->selected_items);
	excl_model = GTK_TREE_MODEL(filter_items_list->unselected_items);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);

	if (sel_rows == NULL)
		return;

	while (sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if (gtk_tree_model_get_iter(excl_model, &iter, path) == 0) {
			fprintf(stderr, "Could not get valid iterator for the selected path.\n");
			return;
		}
		gtk_tree_model_get(excl_model, &iter, ITEMS_LIST_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(excl_model), &iter);
		filters_select_items_add_item_to_list_model(incl_model, item_str);
		g_free(item_str);

		/* Free the list of selected tree paths; we have to get the list of selected items again since the list has now changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);
	}
	filters_select_items_fill_entry(filter_items_list);
}

static void filters_select_items_remove_selected_items(filters_select_items_t * filter_items_list)
{
	GtkTreeModel *incl_model;
	GtkTreeView *include_tree;
	GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path;
	gchar *item_str = NULL;

	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);

	incl_model = GTK_TREE_MODEL(filter_items_list->selected_items);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);

	if (sel_rows == NULL)
		return;

	while (sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if (gtk_tree_model_get_iter(incl_model, &iter, path) == 0) {
			fprintf(stderr, "Could not get valid iterator for the selected path.\n");
			return;
		}
		gtk_tree_model_get(incl_model, &iter, ITEMS_LIST_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(incl_model), &iter);
		if (is_value_from_current_items_source(filter_items_list, item_str))
			filters_select_items_add_unselected_value(filter_items_list, item_str);
		g_free(item_str);

		/* Free the list of selected tree paths; we have to get the list of selected items again since the list has now changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);
	}
	filters_select_items_fill_entry(filter_items_list);
}

/* filters_select_items events */
static void filters_select_items_on_add_button_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	filters_select_items_move_to_selected_items_list(filter_items_list);
}

static void filters_select_items_on_remove_button_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	filters_select_items_remove_selected_items(filter_items_list);
}

static void filters_select_on_policy_opened(void *filter_items_list)
{
	filters_select_items_t *s = (filters_select_items_t *) filter_items_list;
	GtkWidget *widget;

	widget = glade_xml_get_widget(s->xml, "PolicyRadioButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, TRUE);
	widget = glade_xml_get_widget(s->xml, "UnionRadioButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, TRUE);

	if (s->items_source == SEAUDIT_FROM_LOG)
		return;
	else
		filters_select_items_refresh_unselected_list_store(s);
}

static void filters_select_on_log_opened(void *filter_items_list)
{
	filters_select_items_t *s = (filters_select_items_t *) filter_items_list;

	if (s->items_source == SEAUDIT_FROM_POLICY)
		return;
	else
		filters_select_items_refresh_unselected_list_store(s);
}

static void filters_select_items_on_close_button_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	if (filter_items_list->window != NULL) {
		/* if there is an idle function for this window
		 * then we must remove it to avoid that function
		 * being executed after we delete the window.  This
		 * may happen if the window is closed during a search. */
		while (g_idle_remove_by_data(filter_items_list->window)) ;

		gtk_widget_destroy(GTK_WIDGET(filter_items_list->window));
		filter_items_list->window = NULL;
		filters_select_items_fill_entry(filter_items_list);
		log_load_callback_remove(&filters_select_on_log_opened, filter_items_list);
		policy_load_callback_remove(&filters_select_on_policy_opened, filter_items_list);
	}
}

static gboolean filters_select_items_on_window_destroy(GtkWidget * widget, GdkEvent * event,
						       filters_select_items_t * filter_items_list)
{

	filters_select_items_on_close_button_clicked(NULL, filter_items_list);
	return FALSE;
}

static void filters_select_items_on_Selected_SelectAllButton_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	GtkTreeView *include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	gtk_tree_selection_select_all(gtk_tree_view_get_selection(include_tree));
}

static void filters_select_items_on_Selected_ClearButton_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	GtkTreeView *include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(include_tree));
}

static void filters_select_items_on_Unselected_SelectAllButton_clicked(GtkButton * button,
								       filters_select_items_t * filter_items_list)
{
	GtkTreeView *exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	gtk_tree_selection_select_all(gtk_tree_view_get_selection(exclude_tree));
}

static void filters_select_items_on_Unselected_ClearButton_clicked(GtkButton * button, filters_select_items_t * filter_items_list)
{
	GtkTreeView *exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(exclude_tree));
}

/********************************************************************************
 * The following are public methods and callbacks for the filters_select_items
 * object only in the sense that they are exposed to the encapsulating filters
 * object.
 ********************************************************************************/
static void filters_select_items_reset_list_store(filters_select_items_t * item)
{
	/* Remove all rows from the both list stores */
	gtk_list_store_clear(item->selected_items);
	gtk_list_store_clear(item->unselected_items);

	filters_select_items_set_list_stores_default_values(item);
}

static void filters_select_items_destroy(filters_select_items_t * item)
{
	if (item == NULL)
		return;
	if (item->selected_items != NULL)
		g_object_unref(G_OBJECT(item->selected_items));
	if (item->unselected_items != NULL)
		g_object_unref(G_OBJECT(item->unselected_items));
	if (item->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(item->window));
	if (item->xml != NULL)
		g_object_unref(G_OBJECT(item->xml));
	free(item);
	item = NULL;
}

static void filters_select_items_parse_entry(filters_select_items_t * s)
{
	GtkTreeIter iter;
	gboolean valid;
	const gchar *entry_text;
	gchar **items, *cur, *item;
	int cur_index;
	GtkEntry *entry;

	entry = filters_select_items_get_entry(s);
	if (!entry) {
		fprintf(stderr, "Could not get entry widget!");
		return;
	}
	entry_text = gtk_entry_get_text(entry);

	filters_select_items_reset_list_store(s);

	if (strcmp(entry_text, "") != 0) {
		items = g_strsplit(entry_text, ",", -1);
		cur = items[0];
		cur_index = 0;
		while (cur) {
			/* remove whitespace from the beginning and end */
			g_strchug(cur);
			g_strchomp(cur);
			/* See if item exists in unselected list store; if so, remove */
			if (filters_select_items_is_value_unselected(s, cur)) {
				valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->unselected_items), &iter);
				while (valid) {
					gtk_tree_model_get(GTK_TREE_MODEL(s->unselected_items), &iter, ITEMS_LIST_COLUMN, &item,
							   -1);
					if (strcmp(cur, item) == 0) {
						gtk_list_store_remove(s->unselected_items, &iter);
						break;
					}
					valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->unselected_items), &iter);
					g_free(item);
				}
			}
			filters_select_items_add_selected_value(s, cur);
			cur_index++;
			cur = items[cur_index];
		}
		g_strfreev(items);
	}
}

static filters_select_items_t *filters_select_items_create(filter_window_t * parent, enum items_list_types_t items_type)
{
	filters_select_items_t *item = NULL;

	/* Create and initialize the object */
	item = (filters_select_items_t *) malloc(sizeof(filters_select_items_t));
	if (item == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset(item, 0, sizeof(filters_select_items_t));
	item->selected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);
	item->unselected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);
	item->items_list_type = items_type;
	item->parent = parent;

	return item;
}

static void filters_select_items_display(filters_select_items_t * filter_items_list, GtkWindow * parent)
{
	GladeXML *xml;
	GtkTreeView *include_tree, *exclude_tree;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *excl_column, *incl_column;
	GtkWindow *window;
	GtkWidget *widget;
	GString *path;
	char *dir;
	GtkLabel *lbl;
	GtkLabel *incl_lbl;
	GtkLabel *excl_lbl;

	/* Load the glade interface specifications */
	dir = apol_file_find("customize_filter_window.glade");
	if (!dir) {
		fprintf(stderr, "could not find customize_filter_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/customize_filter_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	filter_items_list->xml = xml;
	window = GTK_WINDOW(glade_xml_get_widget(xml, "CreateFilterWindow"));
	g_assert(window);
	filter_items_list->window = window;

	/* Set this new dialog transient for the parent filters dialog so that
	 * it will be destroyed when the parent filters dialog is destroyed */
	/* set this window to be transient on the parent window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered we have to hide and then show */
	gtk_window_set_transient_for(window, parent);
	gtk_window_set_position(window, GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_window_set_destroy_with_parent(window, FALSE);

	if (!seaudit_app->cur_policy) {
		widget = glade_xml_get_widget(xml, "PolicyRadioButton");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);
		widget = glade_xml_get_widget(xml, "UnionRadioButton");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);
	}

	/* Connect all signals to callback functions */
	g_signal_connect(G_OBJECT(window), "delete_event", G_CALLBACK(filters_select_items_on_window_destroy), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_radio_button_toggled",
				      G_CALLBACK(filters_select_items_on_radio_button_toggled), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_close_button_clicked",
				      G_CALLBACK(filters_select_items_on_close_button_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_add_button_clicked",
				      G_CALLBACK(filters_select_items_on_add_button_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_remove_button_clicked",
				      G_CALLBACK(filters_select_items_on_remove_button_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Selected_SelectAllButton_clicked",
				      G_CALLBACK(filters_select_items_on_Selected_SelectAllButton_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Selected_ClearButton_clicked",
				      G_CALLBACK(filters_select_items_on_Selected_ClearButton_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Unselected_SelectAllButton_clicked",
				      G_CALLBACK(filters_select_items_on_Unselected_SelectAllButton_clicked), filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Unselected_ClearButton_clicked",
				      G_CALLBACK(filters_select_items_on_Unselected_ClearButton_clicked), filter_items_list);

	/* Set labeling */
	lbl = GTK_LABEL(glade_xml_get_widget(xml, "TitleFrameLabel"));
	incl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "IncludeLabel"));
	excl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "ExcludeLabel"));

	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES) {
		gtk_window_set_title(window, "Select Source Types");
		gtk_label_set_text(lbl, "Source types:");
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES) {
		gtk_window_set_title(window, "Select Source Roles");
		gtk_label_set_text(lbl, "Source roles:");
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS) {
		gtk_window_set_title(window, "Select Source Users");
		gtk_label_set_text(lbl, "Source users:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_TYPES) {
		gtk_window_set_title(window, "Select Target Types");
		gtk_label_set_text(lbl, "Target types:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_USERS) {
		gtk_window_set_title(window, "Select Target Users");
		gtk_label_set_text(lbl, "Target users:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_ROLES) {
		gtk_window_set_title(window, "Select Target Roles");
		gtk_label_set_text(lbl, "Target roles:");
	} else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS) {
		gtk_window_set_title(window, "Select Object Classes");
		gtk_label_set_text(lbl, "Object classes:");
	} else {
		g_assert(window);
		message_display(window, GTK_MESSAGE_ERROR, "Wrong filter parameter specified.\n");
		return;
	}
	gtk_label_set_text(incl_lbl, "Selected:");
	gtk_label_set_text(excl_lbl, "Unselected:");

	/* Create the views */
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "ExcludeTreeView"));
	g_assert(exclude_tree);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		widget = glade_xml_get_widget(xml, "LogRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	case SEAUDIT_FROM_POLICY:
		widget = glade_xml_get_widget(xml, "PolicyRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	case SEAUDIT_FROM_UNION:
		widget = glade_xml_get_widget(xml, "UnionRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	default:
		break;
	}

	gtk_tree_view_set_model(include_tree, GTK_TREE_MODEL(filter_items_list->selected_items));
	gtk_tree_view_set_model(exclude_tree, GTK_TREE_MODEL(filter_items_list->unselected_items));

	/* Display the model with cell render; specify what column to use (ITEMS_LIST_COLUMN). */
	renderer = gtk_cell_renderer_text_new();
	incl_column = gtk_tree_view_column_new_with_attributes("", renderer, "text", ITEMS_LIST_COLUMN, NULL);
	excl_column = gtk_tree_view_column_new_with_attributes("", renderer, "text", ITEMS_LIST_COLUMN, NULL);

	/* Add the column to the view. */
	gtk_tree_view_append_column(include_tree, incl_column);
	gtk_tree_view_append_column(exclude_tree, excl_column);
	gtk_tree_view_column_set_clickable(incl_column, TRUE);
	gtk_tree_view_column_set_clickable(excl_column, TRUE);

	/* Set selection mode */
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(include_tree), GTK_SELECTION_MULTIPLE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(exclude_tree), GTK_SELECTION_MULTIPLE);

	policy_load_callback_register(&filters_select_on_policy_opened, filter_items_list);
	log_load_callback_register(&filters_select_on_log_opened, filter_items_list);
}

/********************************************************
 * Private methods and callbacks for the filters object *
 ********************************************************/
static int filter_window_verify_filter_values(filter_window_t * filter_window)
{
	char *text = NULL;
	GtkWidget *widget = NULL;
	int i, j;
	struct tm *t1 = NULL, *t2 = NULL;

	/* check for network port filter */
	/* since we do not know if this is an ipv4 or ipv6 port we check against
	 * ipv6 sizes since that is the larger of the two */
	widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
	text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	/* check to see if the strlen of this number is larger than
	 * the strlen of a __16 which is the
	 * maximum size a ipv6 port can be as defined in in6.h */
	if (strlen(text) > SEAUDIT_MAX_U16_STRLEN) {
		message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
		return -1;
	}
	if (strcmp(text, "") != 0) {
		for (i = 0; i < strlen(text); i++) {
			if (isdigit(text[i]) == 0) {
				message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
				return -1;
			}
		}
		j = atoi(text);
		/* now check that the number returned is within the range
		 * of #'s allowed for a ipv6 port */
		if (j < 0 || j > (1 << 16)) {
			message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
			return -1;
		}
	}

	/*check the date and time */
	if (filters_window_get_tm_option(filter_window->xml) == SEAUDIT_DT_OPTION_BETWEEN) {
		t1 = (struct tm *)calloc(1, sizeof(struct tm));
		t2 = (struct tm *)calloc(1, sizeof(struct tm));
		filters_window_update_tm(filter_window, TRUE, t1);
		filters_window_update_tm(filter_window, FALSE, t2);
		if (date_time_compare(t1, t2) > 0) {
			free(t1);
			free(t2);
			message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Date Filter.\n");
			return -1;
		}
		free(t1);
		free(t2);
	}
	return 0;
}

/* Note: the caller must free the returned list */
static seaudit_filter_list_t *filter_window_seaudit_filter_list_get(filters_select_items_t * filters_select_item)
{
	GtkTreeModel *incl_model;
	GtkTreeIter iter;
	gchar *str_data;
	int count = 0;
	seaudit_filter_list_t *flist;
	gboolean valid;

	flist = (seaudit_filter_list_t *) malloc(sizeof(seaudit_filter_list_t));
	if (flist == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset(flist, 0, sizeof(seaudit_filter_list_t));
	flist->list = NULL;
	flist->size = 0;

	/* Get the model and the create the array of strings to return */
	incl_model = GTK_TREE_MODEL(filters_select_item->selected_items);
	valid = gtk_tree_model_get_iter_first(incl_model, &iter);
	while (valid) {
		gtk_tree_model_get(incl_model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		count++;
		if (flist->list == NULL) {
			flist->list = (char **)malloc(sizeof(char *));
			if (flist->list == NULL) {
				fprintf(stderr, "out of memory\n");
				return NULL;
			}
		} else {
			flist->list = (char **)realloc(flist->list, count * sizeof(char *));
			if (flist->list == NULL) {
				filter_window_seaudit_filter_list_free(flist);
				fprintf(stderr, "out of memory\n");
				return NULL;
			}
		}
		/* We subtract 1 from the count to get the correct index because count is incremented above */
		flist->list[count - 1] = (char *)malloc(strlen((const char *)str_data) + 1);
		if (flist->list[count - 1] == NULL) {
			filter_window_seaudit_filter_list_free(flist);
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		strcpy(flist->list[count - 1], (const char *)str_data);
		valid = gtk_tree_model_iter_next(incl_model, &iter);
	}
	flist->size = count;

	return flist;
}

static void filter_window_on_ContextClearButton_clicked(GtkButton * button, filter_window_t * filter_window)
{
	filter_window_clear_context_tab_values(filter_window);
}

static void filter_window_on_OtherClearButton_clicked(GtkButton * button, filter_window_t * filter_window)
{
	filter_window_clear_other_tab_values(filter_window);
}

static void filter_window_on_radio_toggled(GtkToggleButton * tb, gpointer user_data)
{
	filter_window_date_set_sensitive(tb, user_data);
}

static void filter_window_on_month_changed(GtkComboBox * cb, gpointer user_data)
{
	filter_window_t *fw = (filter_window_t *) user_data;
	filter_window_date_update_days(fw->xml);
}

seaudit_filter_t *filter_window_get_filter(filter_window_t * filter_window)
{
	seaudit_filter_t *rt;
	GtkTreeIter iter;
	seaudit_filter_list_t *items_list = NULL;
	GtkWidget *widget;
	GtkTextBuffer *buffer;
	GtkTextIter start, end;
	char *text;
	int int_val;
	struct tm *dt_start, *dt_end;

	rt = seaudit_filter_create();

	/* check for src type filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_types_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_types_items);
		if (items_list) {
			rt->src_type_criteria = src_type_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}
	/* check for tgt type filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_types_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_types_items);
		if (items_list) {
			rt->tgt_type_criteria = tgt_type_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}
	/* check for obj class filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->obj_class_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->obj_class_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->obj_class_items);
		if (items_list) {
			rt->class_criteria = class_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for src user filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_users_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_users_items);
		if (items_list) {
			rt->src_user_criteria = src_user_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for src role filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_roles_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_roles_items);
		if (items_list) {
			rt->src_role_criteria = src_role_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for tgt user filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_users_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_users_items);
		if (items_list) {
			rt->tgt_user_criteria = tgt_user_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for tgt role filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_roles_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_roles_items);
		if (items_list) {
			rt->tgt_role_criteria = tgt_role_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for network address filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "IPAddressEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->ip_address->str;
	if (strcmp(text, "") != 0) {
		rt->ipaddr_criteria = ipaddr_criteria_create(text);
	}

	/* check for network port filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->port->str;
	if (strcmp(text, "") != 0) {
		int_val = atoi(text);
		rt->ports_criteria = ports_criteria_create(int_val);
	}

	/* check for network interface filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "InterfaceEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->interface->str;
	if (strcmp(text, "") != 0) {
		rt->netif_criteria = netif_criteria_create(text);
	}

	/* check for executable filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "ExeEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->executable->str;
	if (strcmp(text, "") != 0) {
		rt->exe_criteria = exe_criteria_create(text);
	}

	/* check for command filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "CommEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->comm->str;
	if (strcmp(text, "") != 0) {
		rt->comm_criteria = comm_criteria_create(text);
	}

	/* check for path filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "PathEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->path->str;
	if (strcmp(text, "") != 0) {
		rt->path_criteria = path_criteria_create(text);
	}

	dt_start = (struct tm *)calloc(1, sizeof(struct tm));
	dt_end = (struct tm *)calloc(1, sizeof(struct tm));

	*dt_start = *(filter_window->dates->start);
	*dt_end = *(filter_window->dates->end);
	if (filter_window->window) {
		filters_window_update_tm(filter_window, TRUE, dt_start);
		filters_window_update_tm(filter_window, FALSE, dt_end);
		int_val = filters_window_get_tm_option(filter_window->xml);
	} else {
		int_val = filter_window->dates->option;
	}
	/* check for date time filter */
	if (int_val != SEAUDIT_DT_OPTION_NONE) {
		switch (int_val) {
		case SEAUDIT_DT_OPTION_BEFORE:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_BEFORE);
			break;
		case SEAUDIT_DT_OPTION_AFTER:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_AFTER);
			break;
		default:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_BETWEEN);
			break;
		}
	}
	free(dt_start);
	free(dt_end);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "MatchEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->match->str;
	if (strcmp("All", text) == 0)
		seaudit_filter_set_match(rt, SEAUDIT_FILTER_MATCH_ALL);
	else
		seaudit_filter_set_match(rt, SEAUDIT_FILTER_MATCH_ANY);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "NameEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->name->str;
	if (strcmp(text, "") != 0)
		seaudit_filter_set_name(rt, text);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "HostEntry");
		text = (char *)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->host->str;
	if (strcmp(text, "") != 0)
		rt->host_criteria = host_criteria_create(text);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
		int_val = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	} else
		int_val = filter_window->msg;
	switch (int_val) {
	case SEAUDIT_MSG_AVC_DENIED:
		rt->msg_criteria = msg_criteria_create(AVC_DENIED);
		break;
	case SEAUDIT_MSG_AVC_GRANTED:
		rt->msg_criteria = msg_criteria_create(AVC_GRANTED);
		break;
	default:
		break;
	}

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "NotesTextView");
		buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
		gtk_text_buffer_get_start_iter(buffer, &start);
		gtk_text_buffer_get_end_iter(buffer, &end);
		text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
	} else
		text = filter_window->notes->str;
	if (strcmp(text, "") != 0)
		seaudit_filter_set_desc(rt, text);

	return rt;
}

void filter_window_set_values_from_filter(filter_window_t * filter_window, seaudit_filter_t * filter)
{
	apol_vector_t *strs;
	int i;
	char ports_str[16];
	const int ports_str_len = 16;

	if (!filter_window || !filter)
		return;
	if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
		filter_window->match = g_string_assign(filter_window->match, "All");
	else
		filter_window->match = g_string_assign(filter_window->match, "Any");

	if (filter->desc)
		filter_window->notes = g_string_assign(filter_window->notes, filter->desc);
	if (filter->src_type_criteria) {
		strs = src_type_criteria_get_strs(filter->src_type_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_types_items, apol_vector_get_element(strs, i));
	}
	if (filter->tgt_type_criteria) {
		strs = tgt_type_criteria_get_strs(filter->tgt_type_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_types_items, apol_vector_get_element(strs, i));
	}
	if (filter->src_user_criteria) {
		strs = src_user_criteria_get_strs(filter->src_user_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_users_items, apol_vector_get_element(strs, i));
	}
	if (filter->tgt_user_criteria) {
		strs = tgt_user_criteria_get_strs(filter->tgt_user_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_users_items, apol_vector_get_element(strs, i));
	}
	if (filter->src_role_criteria) {
		strs = src_role_criteria_get_strs(filter->src_role_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_roles_items, apol_vector_get_element(strs, i));
	}
	if (filter->tgt_role_criteria) {
		strs = tgt_role_criteria_get_strs(filter->tgt_role_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_roles_items, apol_vector_get_element(strs, i));
	}
	if (filter->class_criteria) {
		strs = class_criteria_get_strs(filter->class_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->obj_class_items, apol_vector_get_element(strs, i));
	}
	if (filter->ports_criteria) {
		snprintf(ports_str, ports_str_len, "%d", ports_criteria_get_val(filter->ports_criteria));
		filter_window->port = g_string_assign(filter_window->port, ports_str);
	}
	if (filter->ipaddr_criteria)
		filter_window->ip_address =
			g_string_assign(filter_window->ip_address, ipaddr_criteria_get_str(filter->ipaddr_criteria));
	if (filter->netif_criteria)
		filter_window->interface =
			g_string_assign(filter_window->interface, netif_criteria_get_str(filter->netif_criteria));
	if (filter->path_criteria)
		filter_window->path = g_string_assign(filter_window->path, path_criteria_get_str(filter->path_criteria));
	if (filter->exe_criteria)
		filter_window->executable = g_string_assign(filter_window->executable, exe_criteria_get_str(filter->exe_criteria));
	if (filter->comm_criteria)
		filter_window->comm = g_string_assign(filter_window->comm, comm_criteria_get_str(filter->comm_criteria));
	if (filter->host_criteria)
		filter_window->host = g_string_assign(filter_window->host, host_criteria_get_str(filter->host_criteria));
	if (filter->msg_criteria) {
		switch (msg_criteria_get_val(filter->msg_criteria)) {
		case AVC_GRANTED:
			filter_window->msg = SEAUDIT_MSG_AVC_GRANTED;
			break;
		case AVC_DENIED:
			filter_window->msg = SEAUDIT_MSG_AVC_DENIED;
			break;
		default:
			filter_window->msg = SEAUDIT_MSG_NONE;
			break;
		}
	}
	if (filter->date_time_criteria) {
		if (!filter_window->dates)
			filter_window->dates = (filters_date_item_t *) calloc(1, sizeof(filters_date_item_t));
		*(filter_window->dates->start) = *(date_time_criteria_get_date(filter->date_time_criteria, TRUE));
		*(filter_window->dates->end) = *(date_time_criteria_get_date(filter->date_time_criteria, FALSE));
		i = date_time_criteria_get_option(filter->date_time_criteria);
		switch (i) {
		case FILTER_CRITERIA_DT_OPTION_BEFORE:
			filter_window->dates->option = SEAUDIT_DT_OPTION_BEFORE;
			break;
		case FILTER_CRITERIA_DT_OPTION_AFTER:
			filter_window->dates->option = SEAUDIT_DT_OPTION_AFTER;
			break;

		case FILTER_CRITERIA_DT_OPTION_BETWEEN:
			filter_window->dates->option = SEAUDIT_DT_OPTION_BETWEEN;
			break;
		default:
			filter_window->dates->option = SEAUDIT_DT_OPTION_NONE;
			break;
		}
	}

}

#endif
