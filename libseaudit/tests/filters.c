/**
 *  @file
 *
 *  Test libseaudit's filtering capabilities.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include <CUnit/CUnit.h>
#include <apol/util.h>
#include <seaudit/log.h>
#include <seaudit/message.h>
#include <seaudit/model.h>
#include <seaudit/parse.h>

#include <stdbool.h>
#include <stdio.h>

#define MESSAGES_NOWARNS TEST_POLICIES "/setools-3.1/seaudit/messages-nowarns"

static seaudit_log_t *l = NULL;
static seaudit_model_t *m = NULL;

static void filters_simple(void)
{
	seaudit_filter_t *f = seaudit_filter_create("simple filter");
	CU_ASSERT_PTR_NOT_NULL_FATAL(f);
	int retval = seaudit_model_append_filter(m, f);
	CU_ASSERT(retval == 0);

	apol_vector_t *v = apol_str_split("system_u", ":");
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	retval = seaudit_filter_set_source_user(f, v);
	CU_ASSERT(retval == 0);
	apol_vector_destroy(&v);

	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5 + 5);
	apol_vector_destroy(&v);

	retval = seaudit_filter_set_strict(f, true);
	CU_ASSERT(retval == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5);
	apol_vector_destroy(&v);

	retval = seaudit_filter_set_strict(f, false);
	CU_ASSERT(retval == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5 + 5);
	apol_vector_destroy(&v);

	CU_ASSERT(seaudit_model_remove_filter(m, f) == 0);
}

static void filters_more(void)
{
	seaudit_filter_t *f = seaudit_filter_create("filter 2");
	CU_ASSERT_PTR_NOT_NULL_FATAL(f);
	CU_ASSERT(seaudit_model_append_filter(m, f) == 0);
	CU_ASSERT(seaudit_filter_set_strict(f, true) == 0);

	CU_ASSERT(seaudit_filter_set_avcname(f, "etc") == 0);
	CU_ASSERT_STRING_EQUAL(seaudit_filter_get_avcname(f), "etc");
	apol_vector_t *v = seaudit_model_get_messages(l, m);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 2);
	bool found_netif = false, found_capability = false;
	size_t i;
	seaudit_message_t *msg;
	seaudit_message_type_e msg_type;
	seaudit_avc_message_t *avc;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		msg = (seaudit_message_t *) apol_vector_get_element(v, i);
		avc = (seaudit_avc_message_t *) seaudit_message_get_data(msg, &msg_type);
		CU_ASSERT_FATAL(msg_type == SEAUDIT_MESSAGE_TYPE_AVC);
		CU_ASSERT_PTR_NOT_NULL_FATAL(avc);
		const char *netif = seaudit_avc_message_get_netif(avc);
		int cap = seaudit_avc_message_get_cap(avc);
		if (netif != NULL && strcmp(netif, "marker0") == 0) {
			found_netif = true;
		} else if (cap == 20) {
			found_capability = true;
		} else {
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_netif && found_capability);
	apol_vector_destroy(&v);

	CU_ASSERT(seaudit_filter_set_avcname(f, "resolv.*") == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 1);
	msg = (seaudit_message_t *) apol_vector_get_element(v, 0);
	avc = (seaudit_avc_message_t *) seaudit_message_get_data(msg, &msg_type);
	CU_ASSERT_FATAL(msg_type == SEAUDIT_MESSAGE_TYPE_AVC);
	CU_ASSERT_PTR_NOT_NULL_FATAL(avc);
	const char *name = seaudit_avc_message_get_name(avc);
	CU_ASSERT(name != NULL && strcmp(name, "resolv.conf") == 0);
	apol_vector_destroy(&v);

	CU_ASSERT(seaudit_filter_set_avcname(f, "non.existant.glob.*") == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	CU_ASSERT(seaudit_filter_set_avcname(f, "[invalid_glob-") == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	CU_ASSERT(seaudit_model_remove_filter(m, f) == 0);
}

CU_TestInfo filters_tests[] = {
	{"simple filter", filters_simple},
	{"more filter", filters_more},
	CU_TEST_INFO_NULL
};

int filters_init()
{
	l = seaudit_log_create(NULL, NULL);
	if (l == NULL) {
		return 1;
	}
	m = seaudit_model_create("filters", l);
	if (m == NULL) {
		return 1;
	}

	FILE *f = fopen(MESSAGES_NOWARNS, "r");
	if (f == NULL) {
		return 1;
	}
	int retval;
	retval = seaudit_log_parse(l, f);
	if (retval != 0) {
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

int filters_cleanup()
{
	seaudit_log_destroy(&l);
	seaudit_model_destroy(&m);
	return 0;
}
