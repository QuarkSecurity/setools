/**
 *  @file message_view.c
 *  Implementation of the view for a libseaudit model.
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

#include "message_view.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <apol/util.h>

/** The tree view will have another hidden column that contains a
    pointer to the original libseaudit message. */
#define ID_FIELD (OTHER_FIELD + 1)

/**
 * A custom model that implements the interfaces GtkTreeModel and
 * GtkTreeSortable.
 */
typedef struct message_view_store
{
	/** this must be the first field, to satisfy glib */
	GObject parent;
	/* pointer to the store's controller */
	message_view_t *view;
	/** vector of seaudit_message_t, as returned by
         * seaudit_model_get_messages() */
	apol_vector_t *messages;
	/** column that is currently being sorted; use ID_FIELD to
         * indicate no sorting */
	gint sort_field;
	/* current sort direction, either 1 or ascending or -1 for
	 * descending */
	int sort_dir;
	/** unique integer for each instance of a model */
	gint stamp;
} message_view_store_t;

typedef struct message_view_store_class
{
	GObjectClass parent_class;
} message_view_store_class_t;

static GType message_view_store_get_type(void);
#define SEAUDIT_TYPE_MESSAGE_VIEW_STORE (message_view_store_get_type())
#define SEAUDIT_IS_MESSAGE_VIEW_STORE(obj) \
 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAUDIT_TYPE_MESSAGE_VIEW_STORE))

struct message_view
{
	seaudit_model_t *model;
	toplevel_t *top;
	/** toplevel of the view, currently a scrolled_window */
	GtkWidget *w;
	/** actual GTK+ tree view widget that displays the rows and
         * columns of message data */
	GtkWidget *tree;
	message_view_store_t *store;
};

typedef seaudit_sort_t *(*sort_generator_fn_t) (int direction);

struct view_column_record
{
	preference_field_e id;
	const char *name;
	const char *sample_text;
	sort_generator_fn_t sort;
};

static const struct view_column_record column_data[] = {
	{HOST_FIELD, "Hostname", "Hostname", seaudit_sort_by_host},
	{MESSAGE_FIELD, "Message", "Message", seaudit_sort_by_message_type},
	{DATE_FIELD, "Date", "Jan 01 00:00:00", seaudit_sort_by_date},
	{SUSER_FIELD, "Source\nUser", "Source", seaudit_sort_by_source_user},
	{SROLE_FIELD, "Source\nRole", "Source", seaudit_sort_by_source_role},
	{STYPE_FIELD, "Source\nType", "unlabeled_t", seaudit_sort_by_source_type},
	{TUSER_FIELD, "Target\nUser", "Target", seaudit_sort_by_target_user},
	{TROLE_FIELD, "Target\nRole", "Target", seaudit_sort_by_target_role},
	{TTYPE_FIELD, "Target\nType", "unlabeled_t", seaudit_sort_by_target_type},
	{OBJCLASS_FIELD, "Object\nClass", "Object", seaudit_sort_by_object_class},
	{PERM_FIELD, "Permission", "Permission", seaudit_sort_by_permission},
	{EXECUTABLE_FIELD, "Executable", "/usr/bin/cat", seaudit_sort_by_executable},
	{COMMAND_FIELD, "Command", "/usr/bin/cat", seaudit_sort_by_command},
	{PID_FIELD, "PID", "12345", seaudit_sort_by_pid},
	{INODE_FIELD, "Inode", "123456", seaudit_sort_by_inode},
	{PATH_FIELD, "Path", "/home/gburdell/foo", seaudit_sort_by_path},
	{OTHER_FIELD, "Other", "Lorem ipsum dolor sit amet, consectetur", NULL}
};

static const size_t num_columns = sizeof(column_data) / sizeof(column_data[0]);

/**
 * (Re)sort the view based upon which column is clicked.  If already
 * sorting on this column, then reverse the sort direction.  Also
 * update the sort indicator for this column.
 */
static gboolean message_view_on_column_click(GtkTreeViewColumn * column, gpointer user_data)
{
	return FALSE;
}

#if 0
gint column_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(column), "column id"));
preference_field_e id = column_id;
message_view_t *view = (message_view_t *) user_data;
int dir = 0;
seaudit_sort_t *sort;
GtkTreeViewColumn *prev_column;
if (id == view->current_sort) {
	dir = view->current_sort_dir * -1;
} else {
	dir = 1;
}

if ((sort = column_data[column_id].sort(dir)) == NULL) {
	toplevel_ERR(view->top, "%s", strerror(errno));
	return TRUE;
}
seaudit_model_remove_all_sort(view->model);
if (seaudit_model_append_sort(view->model, sort) < 0) {
	seaudit_sort_destroy(&sort);
	toplevel_ERR(view->top, "%s", strerror(errno));
}
prev_column = gtk_tree_view_get_column(GTK_TREE_VIEW(view->tree), view->current_sort);
if (prev_column != NULL) {
	gtk_tree_view_column_set_sort_indicator(prev_column, FALSE);
}
gtk_tree_view_column_set_sort_indicator(column, TRUE);
if (dir > 0) {
	gtk_tree_view_column_set_sort_order(column, GTK_SORT_ASCENDING);
} else {
	gtk_tree_view_column_set_sort_order(column, GTK_SORT_DESCENDING);
}

view->current_sort = column_id;
view->current_sort_dir = dir;
message_view_update_rows(view);
return TRUE;
}
#endif

/*************** implementation of a custom GtkTreeModel ***************/

static GObjectClass *parent_class = NULL;

static void message_view_store_init(message_view_store_t * m);
static void message_view_store_class_init(message_view_store_class_t * c);
static void message_view_store_tree_init(GtkTreeModelIface * iface);
static void message_view_store_finalize(GObject * object);
static GtkTreeModelFlags message_view_store_get_flags(GtkTreeModel * tree_model);
static gint message_view_store_get_n_columns(GtkTreeModel * tree_model);
static GType message_view_store_get_column_type(GtkTreeModel * tree_model, gint index);
static gboolean message_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path);
static GtkTreePath *message_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter);
static void message_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value);
static gboolean message_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean message_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent);
static gboolean message_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gint message_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter);
static gboolean message_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n);
static gboolean message_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child);

static GType message_view_store_get_type(void)
{
	static GType store_type = 0;
	static const GTypeInfo store_info = {
		sizeof(message_view_store_class_t),
		NULL,
		NULL,
		(GClassInitFunc) message_view_store_class_init,
		NULL,
		NULL,
		sizeof(message_view_store_t),
		0,
		(GInstanceInitFunc) message_view_store_init
	};
	static const GInterfaceInfo tree_model_info = {
		(GInterfaceInitFunc) message_view_store_tree_init,
		NULL,
		NULL
	};

	if (store_type)
		return store_type;

	store_type = g_type_register_static(G_TYPE_OBJECT, "message_view_store", &store_info, (GTypeFlags) 0);
	g_type_add_interface_static(store_type, GTK_TYPE_TREE_MODEL, &tree_model_info);
	return store_type;
}

static void message_view_store_init(message_view_store_t * m)
{
	static int next_stamp = 0;
	m->messages = NULL;
	m->sort_field = ID_FIELD;
	m->sort_dir = 1;
	m->stamp = next_stamp++;
}

static void message_view_store_class_init(message_view_store_class_t * c)
{
	GObjectClass *object_class;
	parent_class = g_type_class_peek_parent(c);
	object_class = (GObjectClass *) c;
	object_class->finalize = message_view_store_finalize;
}

static void message_view_store_tree_init(GtkTreeModelIface * iface)
{
	iface->get_flags = message_view_store_get_flags;
	iface->get_n_columns = message_view_store_get_n_columns;
	iface->get_column_type = message_view_store_get_column_type;
	iface->get_iter = message_view_store_get_iter;
	iface->get_path = message_view_store_get_path;
	iface->get_value = message_view_store_get_value;
	iface->iter_next = message_view_store_iter_next;
	iface->iter_children = message_view_store_iter_children;
	iface->iter_has_child = message_view_store_iter_has_child;
	iface->iter_n_children = message_view_store_iter_n_children;
	iface->iter_nth_child = message_view_store_iter_nth_child;
	iface->iter_parent = message_view_store_iter_parent;
}

static void message_view_store_finalize(GObject * object)
{
	(*parent_class->finalize) (object);
}

static GtkTreeModelFlags message_view_store_get_flags(GtkTreeModel * tree_model)
{
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), 0);
	return GTK_TREE_MODEL_ITERS_PERSIST | GTK_TREE_MODEL_LIST_ONLY;
}

static gint message_view_store_get_n_columns(GtkTreeModel * tree_model)
{
	return ID_FIELD + 1;
}

static GType message_view_store_get_column_type(GtkTreeModel * tree_model, gint index)
{
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), G_TYPE_INVALID);
	/* everything is a string for now */
	return G_TYPE_STRING;
}

static gboolean message_view_store_get_iter(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreePath * path)
{
	gint i;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(gtk_tree_path_get_depth(path) > 0, FALSE);
	i = gtk_tree_path_get_indices(path)[0];
	if (i >= apol_vector_get_size(store->messages))
		return FALSE;

	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, i);
	iter->user_data2 = GINT_TO_POINTER(i);
	iter->user_data3 = NULL;
	return TRUE;
}

static GtkTreePath *message_view_store_get_path(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	GtkTreePath *retval;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), NULL);
	g_return_val_if_fail(iter->stamp == store->stamp, NULL);
	retval = gtk_tree_path_new();
	gtk_tree_path_append_index(retval, GPOINTER_TO_INT(iter->user_data2));
	return retval;
}

/**
 * Given a string, check that it is UTF8 legal.  If not, or if the
 * string is NULL, then return an empty string.  Otherwise return the
 * original string.
 */
static void message_view_to_utf8(GValue * value, const char *s)
{
	if (s == NULL || !g_utf8_validate(s, -1, NULL)) {
		g_value_set_string(value, "");
	}
	g_value_set_string(value, s);
}

static void message_view_store_get_value(GtkTreeModel * tree_model, GtkTreeIter * iter, gint column, GValue * value)
{
	message_view_store_t *store;
	message_view_t *view;
	seaudit_message_t *m;
	seaudit_message_type_e type;
	void *data;
	seaudit_avc_message_t *avc;
	g_return_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model));
	g_return_if_fail(iter != NULL);
	g_return_if_fail(column < ID_FIELD);
	g_value_init(value, G_TYPE_STRING);
	store = (message_view_store_t *) tree_model;
	view = store->view;
	m = (seaudit_message_t *) iter->user_data;
	data = seaudit_message_get_data(m, &type);
	preference_field_e field = column;

	switch (field) {
	case HOST_FIELD:{
			message_view_to_utf8(value, seaudit_message_get_host(m));
			return;
		}
	case MESSAGE_FIELD:{
			char *message = "Invalid";
			switch (type) {
			case SEAUDIT_MESSAGE_TYPE_BOOL:{
					message = "Boolean";
					break;
				}
			case SEAUDIT_MESSAGE_TYPE_LOAD:{
					message = "Load";
					break;
				}
			case SEAUDIT_MESSAGE_TYPE_AVC:{
					avc = (seaudit_avc_message_t *) data;
					seaudit_avc_message_type_e avc_type;
					avc_type = seaudit_avc_message_get_message_type(avc);
					switch (avc_type) {
					case SEAUDIT_AVC_DENIED:{
							message = "Denied";
							break;
						}
					case SEAUDIT_AVC_GRANTED:{
							message = "Granted";
							break;
						}
					default:{
							/* should never get here */
							toplevel_ERR(view->top, "Got an invalid AVC message type %d!", avc_type);
							assert(0);
							return;
						}
					}
					break;
				}
			default:{
					/* should never get here */
					toplevel_ERR(view->top, "Got an invalid message type %d!", type);
					assert(0);
					return;
				}
			}
			message_view_to_utf8(value, message);
			return;
		}
	case DATE_FIELD:{
			struct tm *tm = seaudit_message_get_time(m);
			char date[256];
			/* check to see if we have been given a valid year, if
			 * so display, otherwise no year displayed */
			if (tm->tm_year == 0) {
				strftime(date, 256, "%b %d %H:%M:%S", tm);
			} else {
				strftime(date, 256, "%b %d %H:%M:%S %Y", tm);
			}
			message_view_to_utf8(value, date);
			return;
		}
	case OTHER_FIELD:{
			char *other = seaudit_message_to_misc_string(m);;
			if (other == NULL) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, other);
			free(other);
			return;
		}
	default:		       /* FALLTHROUGH */
		break;
	}

	if (type != SEAUDIT_MESSAGE_TYPE_AVC) {
		/* the rest of the columns are blank for non-AVC
		 * messages */
		message_view_to_utf8(value, "");
		return;
	}
	avc = (seaudit_avc_message_t *) data;

	switch (field) {
	case SUSER_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_user(avc));
			return;
		}
	case SROLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_role(avc));
			return;
		}
	case STYPE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_source_type(avc));
			return;
		}
	case TUSER_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_user(avc));
			return;
		}
	case TROLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_role(avc));
			return;
		}
	case TTYPE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_target_type(avc));
			return;
		}
	case OBJCLASS_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_object_class(avc));
			return;
		}
	case PERM_FIELD:{
			apol_vector_t *perms = seaudit_avc_message_get_perm(avc);
			char *perm = NULL;
			size_t i, len = 0;
			for (i = 0; perms != NULL && i < apol_vector_get_size(perms); i++) {
				char *p = apol_vector_get_element(perms, i);
				if (apol_str_appendf(&perm, &len, "%s%s", (i > 0 ? "," : ""), p) < 0) {
					toplevel_ERR(view->top, "%s", strerror(errno));
					return;
				}
			}
			message_view_to_utf8(value, perm);
			free(perm);
			return;
		}
	case EXECUTABLE_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_exe(avc));
			return;
		}
	case COMMAND_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_comm(avc));
			return;
		}
	case PID_FIELD:{
			char *s;
			if (asprintf(&s, "%u", seaudit_avc_message_get_pid(avc)) < 0) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, s);
			free(s);
			return;
		}
	case INODE_FIELD:{
			char *s;
			if (asprintf(&s, "%lu", seaudit_avc_message_get_inode(avc)) < 0) {
				toplevel_ERR(view->top, "%s", strerror(errno));
				return;
			}
			message_view_to_utf8(value, s);
			free(s);
			return;
		}
	case PATH_FIELD:{
			message_view_to_utf8(value, seaudit_avc_message_get_path(avc));
			return;
		}
	default:		       /* FALLTHROUGH */
		break;
	}
	/* should never get here */
	toplevel_ERR(view->top, "Got an invalid column %d!", field);
	assert(0);
}

static gboolean message_view_store_iter_next(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	gint i;
	message_view_store_t *store = (message_view_store_t *) tree_model;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	g_return_val_if_fail(iter->stamp == store->stamp, FALSE);
	if (iter == NULL || iter->user_data == NULL)
		return FALSE;
	i = GPOINTER_TO_INT(iter->user_data2) + 1;
	if (i >= apol_vector_get_size(store->messages)) {
		return FALSE;
	}
	iter->user_data = apol_vector_get_element(store->messages, i);
	iter->user_data2 = GINT_TO_POINTER(i);
	iter->user_data3 = NULL;
	return TRUE;
}

static gboolean message_view_store_iter_children(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent)
{
	message_view_store_t *store;
	g_return_val_if_fail(parent == NULL || parent->user_data != NULL, FALSE);
	if (parent)
		return FALSE;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);

	/* set iterator to first row, if possible */
	store = (message_view_store_t *) tree_model;
	if (store->messages == NULL || apol_vector_get_size(store->messages) == 0)
		return FALSE;

	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, 0);
	iter->user_data2 = GINT_TO_POINTER(0);
	iter->user_data3 = NULL;
	return TRUE;
}

static gboolean message_view_store_iter_has_child(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	return FALSE;
}

static gint message_view_store_iter_n_children(GtkTreeModel * tree_model, GtkTreeIter * iter)
{
	message_view_store_t *store;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), -1);
	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, 0);
	store = (message_view_store_t *) tree_model;
	/* return the number of rows, if iterator is at the top;
	 * otherwise return 0 because this store is just a list */
	if (iter != NULL || store->messages == NULL) {
		return 0;
	}
	return apol_vector_get_size(store->messages);
}

static gboolean message_view_store_iter_nth_child(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * parent, gint n)
{
	message_view_store_t *store;
	g_return_val_if_fail(SEAUDIT_IS_MESSAGE_VIEW_STORE(tree_model), FALSE);
	store = (message_view_store_t *) tree_model;
	if (store->messages == NULL || parent != NULL) {
		return FALSE;
	}
	if (n >= apol_vector_get_size(store->messages)) {
		return FALSE;
	}
	iter->stamp = store->stamp;
	iter->user_data = apol_vector_get_element(store->messages, n);
	iter->user_data2 = GINT_TO_POINTER(n);
	iter->user_data3 = NULL;
	return TRUE;
}

static gboolean message_view_store_iter_parent(GtkTreeModel * tree_model, GtkTreeIter * iter, GtkTreeIter * child)
{
	return FALSE;
}

/*************** end of custom GtkTreeModel implementation ***************/

message_view_t *message_view_create(toplevel_t * top, seaudit_model_t * model)
{
	message_view_t *view;
	GtkTreeSelection *selection;
	GtkCellRenderer *renderer;
	size_t i;

	if ((view = calloc(1, sizeof(*view))) == NULL) {
		int error = errno;
		toplevel_ERR(top, "%s", strerror(error));
		message_view_destroy(&view);
		errno = error;
		return NULL;
	}
	view->model = model;
	view->top = top;
	view->store = (message_view_store_t *) g_object_new(SEAUDIT_TYPE_MESSAGE_VIEW_STORE, NULL);
	view->store->view = view;
	view->store->sort_field = OTHER_FIELD;
	view->store->sort_dir = 1;
	view->w = gtk_scrolled_window_new(NULL, NULL);
	view->tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(view->store));
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view->tree));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_container_add(GTK_CONTAINER(view->w), view->tree);
	gtk_widget_show(view->tree);
	gtk_widget_show(view->w);

	renderer = gtk_cell_renderer_text_new();
	for (i = 0; i < num_columns; i++) {
		struct view_column_record r = column_data[i];
		PangoLayout *layout = gtk_widget_create_pango_layout(GTK_WIDGET(view->tree), r.sample_text);
		gint width;
		GtkTreeViewColumn *column;
		pango_layout_get_pixel_size(layout, &width, NULL);
		g_object_unref(G_OBJECT(layout));
		width += 12;
		column = gtk_tree_view_column_new_with_attributes(r.name, renderer, "text", r.id, NULL);
		gtk_tree_view_column_set_clickable(column, TRUE);
		gtk_tree_view_column_set_resizable(column, TRUE);
		if (r.sort != NULL) {
			g_object_set_data(G_OBJECT(column), "column id", GINT_TO_POINTER(r.id));
			g_signal_connect_after(G_OBJECT(column), "clicked", G_CALLBACK(message_view_on_column_click), view);
		}
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_fixed_width(column, width);
		gtk_tree_view_append_column(GTK_TREE_VIEW(view->tree), column);
	}

	/*
	 * g_signal_connect(G_OBJECT(tree_view), "row_activated", G_CALLBACK(message_view_on_select), view);
	 * g_signal_connect(G_OBJECT(tree_view), "button-press-event", G_CALLBACK(message_view_on_button_press), view);
	 * g_signal_connect(G_OBJECT(tree_view), "popup-menu", G_CALLBACK(message_view_on_popup_menu), view);
	 */
	message_view_update_visible_columns(view);
	message_view_update_rows(view);
	return view;
}

void message_view_destroy(message_view_t ** view)
{
	if (view != NULL && *view != NULL) {
		seaudit_model_destroy(&(*view)->model);
		apol_vector_destroy(&((*view)->store->messages), NULL);
		/* let glib handle destruction of object */
		g_object_unref((*view)->store);
		free(*view);
		*view = NULL;
	}
}

GtkWidget *message_view_get_view(message_view_t * view)
{
	return view->w;
}

size_t message_view_get_num_log_messages(message_view_t * view)
{
	if (view->store->messages == NULL) {
		return 0;
	}
	return apol_vector_get_size(view->store->messages);
}

/**
 * Given the name of a column, return its column record data.
 */
static const struct view_column_record *get_record(const char *name)
{
	size_t i;
	for (i = 0; i < num_columns; i++) {
		const struct view_column_record *r = column_data + i;
		if (strcmp(r->name, name) == 0) {
			return r;
		}
	}
	return NULL;
}

void message_view_update_visible_columns(message_view_t * view)
{
	GList *columns, *c;
	preferences_t *prefs = toplevel_get_prefs(view->top);
	columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(view->tree));
	c = columns;
	while (c != NULL) {
		GtkTreeViewColumn *vc = GTK_TREE_VIEW_COLUMN(c->data);
		const gchar *title = gtk_tree_view_column_get_title(vc);
		const struct view_column_record *r = get_record(title);
		if (preferences_is_column_visible(prefs, r->id)) {
			gtk_tree_view_column_set_visible(vc, TRUE);
		} else {
			gtk_tree_view_column_set_visible(vc, FALSE);
		}
		c = g_list_next(c);
	}
	g_list_free(columns);
}

void message_view_update_rows(message_view_t * view)
{
	/* Remove all existing rows, then insert them back into the
	 * view according to the model. */
	GtkTreePath *path;
	GtkTreeIter iter;
	size_t i;
	seaudit_log_t *log = toplevel_get_log(view->top);

	if (view->store->messages != NULL) {
		for (i = apol_vector_get_size(view->store->messages); i >= 0; i--) {
			path = gtk_tree_path_new();
			gtk_tree_path_append_index(path, i);
			gtk_tree_model_row_deleted(GTK_TREE_MODEL(view->store), path);
			gtk_tree_path_free(path);
		}
	}
	apol_vector_destroy(&view->store->messages, NULL);
	if (log == NULL) {
		return;
	}
	view->store->messages = seaudit_model_get_messages(log, view->model);
	for (i = 0; i < apol_vector_get_size(view->store->messages); i++) {
		path = gtk_tree_path_new();
		gtk_tree_path_append_index(path, i);
		iter.user_data = apol_vector_get_element(view->store->messages, i);
		iter.user_data2 = GINT_TO_POINTER(i);
		iter.user_data3 = NULL;
		gtk_tree_model_row_inserted(GTK_TREE_MODEL(view->store), path, &iter);
		gtk_tree_path_free(path);
	}
}

#if 0

#include "filtered_view.h"
#include "filter_window.h"
#include "utilgui.h"
#include <string.h>

void seaudit_filtered_view_display(seaudit_filtered_view_t * filtered_view, GtkWindow * parent)
{
	if (!filtered_view)
		return;
	multifilter_window_display(filtered_view->multifilter_window, parent);
}

void seaudit_filtered_view_save_view(seaudit_filtered_view_t * filtered_view, gboolean saveas)
{
	if (!filtered_view)
		return;
	multifilter_window_save_multifilter(filtered_view->multifilter_window, saveas, FALSE);
}

void seaudit_filtered_view_set_multifilter_window(seaudit_filtered_view_t * filtered_view, multifilter_window_t * window)
{
	multifilter_window_destroy(filtered_view->multifilter_window);
	filtered_view->multifilter_window = window;
	g_string_assign(window->name, filtered_view->name->str);
	window->parent = filtered_view;
}

#endif
