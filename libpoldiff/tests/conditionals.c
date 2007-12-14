/**
 *  @file
 *
 *  Test libpoldiff's conditional equivalencies.
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

#include "libpoldiff-tests.h"

#include <CUnit/CUnit.h>

#include <stdbool.h>

#define SIMPLE_CONDS_ORIG TEST_POLICIES "/setools-3.3/sediff/cond_test_policy.orig.conf"
#define SIMPLE_CONDS_MOD TEST_POLICIES "/setools-3.3/sediff/cond_test_policy.mod.conf"

static poldiff_test_structs_t *simple = NULL;

struct diff_answer
{
	const char *result;
	const poldiff_form_e form;
	bool found;
};

static void conditionals_simple_bools(void)
{
	size_t i;
	struct diff_answer *da;

	const apol_vector_t *bool_diffs_v = poldiff_get_bool_vector(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bool_diffs_v);
	struct diff_answer bool_answers[] = {
		{"+ my_b", POLDIFF_FORM_ADDED, 0},
		{"+ your_b", POLDIFF_FORM_ADDED, 0},
		{"- this_b", POLDIFF_FORM_REMOVED, 0},
		{"- that_b", POLDIFF_FORM_REMOVED, 0},
		{"* south_b (changed from false to true)", POLDIFF_FORM_MODIFIED, 0},
		{"* in_b (changed from true to false)", POLDIFF_FORM_MODIFIED, 0},
		{NULL, 0, 0}
	};
	for (i = 0; i < apol_vector_get_size(bool_diffs_v); i++) {
		const poldiff_bool_t *b = apol_vector_get_element(bool_diffs_v, i);
		char *result = poldiff_bool_to_string(simple->diff, b);
		poldiff_form_e form = poldiff_bool_get_form(b);
		for (da = bool_answers; da->result != NULL; da++) {
			if (strcmp(da->result, result) == 0) {
				CU_ASSERT(da->form == form && da->found == 0);
				da->found = true;
				break;
			}
		}
		CU_ASSERT(da->result != NULL);
		free(result);
	}
	for (da = bool_answers; da->result != NULL; da++) {
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_avrules_allow(void)
{
	size_t i;
	struct diff_answer *da;

	const apol_vector_t *allow_diffs_v = poldiff_get_avrule_vector_allow(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(allow_diffs_v);
	struct diff_answer allow_answers[] = {
		{"+ allow one_t two_t : dir { search };  [up_b]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"+ allow six_t five_t : blk_file { read };  [in_b]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"+ allow seven_t eight_t : file { read write };  [my_b your_b ||]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"+ allow seven_t eight_t : file { read };  [my_b your_b ||]:FALSE", POLDIFF_FORM_ADDED, 0},
		{"+ allow one_t five_t : fd { use };", POLDIFF_FORM_ADDED, 0},
		{"+ allow two_t two_t : file { setattr };  [east_b]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"+ allow three_t three_t : file { setattr };  [east_b]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"+ allow five_t five_t : file { setattr };  [east_b]:TRUE", POLDIFF_FORM_ADDED, 0},
		{"- allow five_t six_t : socket { connect ioctl };  [in_b ! up_b down_b && ||]:TRUE", POLDIFF_FORM_REMOVED, 0},
		{"- allow one_t one_t : process { setexec };  [up_b down_b && left_b && right_b out_b && ||]:TRUE",
		 POLDIFF_FORM_REMOVED, 0},
		{"- allow seven_t eight_t : file { read write };  [this_b that_b ||]:TRUE", POLDIFF_FORM_REMOVED, 0},
		{"- allow seven_t eight_t : file { read };  [this_b that_b ||]:FALSE", POLDIFF_FORM_REMOVED, 0},
		{"- allow one_t five_t : fd { use };  [left_b right_b && left_b right_b ! && ||]:FALSE", POLDIFF_FORM_REMOVED, 0},
		{"- allow two_t two_t : file { setattr };  [east_b]:FALSE", POLDIFF_FORM_REMOVED, 0},
		{"- allow three_t three_t : file { setattr };  [east_b]:FALSE", POLDIFF_FORM_REMOVED, 0},
		{"- allow five_t five_t : file { setattr };  [east_b]:FALSE", POLDIFF_FORM_REMOVED, 0},
		{"* allow four_t five_t : dir { add_name search +read };  [north_b west_b &&]:TRUE", POLDIFF_FORM_MODIFIED, 0},
		{"* allow five_t one_t : process { transition -signal };  [up_b down_b && left_b && right_b out_b && ||]:TRUE",
		 POLDIFF_FORM_MODIFIED, 0},
		{"* allow one_t three_t : dir { search +read };", POLDIFF_FORM_MODIFIED, 0},
		{"* allow one_t three_t : socket { sendto -recvfrom };  [north_b south_b ^ up_b ! down_b && ||]:TRUE",
		 POLDIFF_FORM_MODIFIED, 0},
		{NULL, 0, 0}
	};
	/* these rules are actually unmodified, but show up as added/removed in SETools 3.3 */
	struct diff_answer unmodified_allow_answers[] = {
		{"+ allow one_t four_t : dir { getattr read search };  [left_b]:FALSE", POLDIFF_FORM_ADDED, 0},
		{"- allow one_t four_t : dir { getattr read search };  [left_b right_b && left_b right_b ! && ||]:FALSE",
		 POLDIFF_FORM_REMOVED, 0},
		{"+ allow six_t one_t : file { relabelfrom relabelto };  [left_b]:FALSE", POLDIFF_FORM_ADDED, 0},
		{"- allow six_t one_t : file { relabelfrom relabelto };  [left_b right_b && left_b right_b ! && ||]:FALSE",
		 POLDIFF_FORM_REMOVED, 0},
		{"+ allow six_t two_t : file { relabelfrom relabelto };  [left_b]:FALSE", POLDIFF_FORM_ADDED, 0},
		{"- allow six_t two_t : file { relabelfrom relabelto };  [left_b right_b && left_b right_b ! && ||]:FALSE",
		 POLDIFF_FORM_REMOVED, 0},
		{"+ allow six_t three_t : file { relabelfrom relabelto };  [left_b]:FALSE", POLDIFF_FORM_ADDED, 0},
		{"- allow six_t three_t : file { relabelfrom relabelto };  [left_b right_b && left_b right_b ! && ||]:FALSE",
		 POLDIFF_FORM_REMOVED, 0},
		{NULL, 0, 0}
	};

	for (i = 0; i < apol_vector_get_size(allow_diffs_v); i++) {
		const poldiff_avrule_t *a = apol_vector_get_element(allow_diffs_v, i);
		char *result = poldiff_avrule_to_string(simple->diff, a);
		poldiff_form_e form = poldiff_avrule_get_form(a);
		for (da = allow_answers; da->result != NULL; da++) {
			if (strcmp(da->result, result) == 0) {
				CU_ASSERT(da->form == form && da->found == 0);
				da->found = true;
				break;
			}
		}
		if (da->result == NULL) {
			for (da = unmodified_allow_answers; da->result != NULL; da++) {
				if (strcmp(da->result, result) == 0) {
					CU_ASSERT(da->form == form && da->found == 0);
					da->found = true;
					break;
				}
			}
		}
		CU_ASSERT(da->result != NULL);
		free(result);
	}
	for (da = allow_answers; da->result != NULL; da++) {
		CU_ASSERT(da->found);
	}
	for (da = unmodified_allow_answers; da->result != NULL; da++) {
		CU_ASSERT(da->found);
	}
}

/*
 * FIX ME: do auditallow and dontaudit tests
    const apol_vector_t *auditallow_diffs_v = poldiff_get_avrule_vector_auditallow(simple->diff);
    const apol_vector_t *dontaudit_diffs_v = poldiff_get_avrule_vector_dontaudit(simple->diff);
    CU_ASSERT_PTR_NOT_NULL_FATAL(auditallow_diffs_v);
    CU_ASSERT_PTR_NOT_NULL_FATAL(dontaudit_diffs_v);
*/

/*
 * FIX ME: do type rules
 */

CU_TestInfo conditionals_tests[] = {
	{"simple booleans", conditionals_simple_bools}
	,
	{"simple avrules: allow", conditionals_simple_avrules_allow}
	,
	CU_TEST_INFO_NULL
};

int conditionals_init(void)
{
	uint32_t run_flags = POLDIFF_DIFF_BOOLS | POLDIFF_DIFF_AVRULES | POLDIFF_DIFF_TERULES;
	simple = poldiff_test_structs_create(SIMPLE_CONDS_ORIG, SIMPLE_CONDS_MOD);
	if (simple == NULL) {
		return 1;
	}
	if (poldiff_run(simple->diff, run_flags) != 0) {
		return 1;
	}
	return 0;
}

int conditionals_cleanup(void)
{
	poldiff_test_structs_destroy(&simple);
	return 0;
}
