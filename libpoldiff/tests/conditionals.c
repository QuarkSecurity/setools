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
#include <stdio.h>

#define SIMPLE_CONDS_ORIG TEST_POLICIES "/setools-3.3/sediff/cond_test_policy.orig.conf"
#define SIMPLE_CONDS_MOD TEST_POLICIES "/setools-3.3/sediff/cond_test_policy.mod.conf"

static poldiff_test_structs_t *simple = NULL;

static void conditionals_simple_bools(void)
{
	size_t i;
	struct poldiff_test_symbol_answer *da;

	const apol_vector_t *bool_diffs_v = poldiff_get_bool_vector(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bool_diffs_v);
	struct poldiff_test_symbol_answer bool_answers[] = {
		{POLDIFF_FORM_ADDED, "my_b", 0},
		{POLDIFF_FORM_ADDED, "your_b", 0},
		{POLDIFF_FORM_REMOVED, "this_b", 0},
		{POLDIFF_FORM_REMOVED, "that_b", 0},
		{POLDIFF_FORM_MODIFIED, "south_b", 0},
		{POLDIFF_FORM_MODIFIED, "in_b", 0},
		{POLDIFF_FORM_NONE, NULL, 0}
	};
	for (i = 0; i < apol_vector_get_size(bool_diffs_v); i++) {
		const poldiff_bool_t *b = apol_vector_get_element(bool_diffs_v, i);
		const char *name = poldiff_bool_get_name(b);
		poldiff_form_e form = poldiff_bool_get_form(b);
		for (da = bool_answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (strcmp(da->name, name) == 0) {
				CU_ASSERT(da->form == form && da->found == 0);
				da->found = true;
				break;
			}
		}
		CU_ASSERT(da->name != NULL);
	}
	for (da = bool_answers; da->name != NULL; da++) {
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_avrules_allow(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_avrule_vector_allow(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "one_t", "two_t", "dir", "+search", "up_b", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "six_t", "five_t", "blk_file", "+read", "in_b", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "seven_t", "eight_t", "file", "+read +write", "my_b your_b ||", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "seven_t", "eight_t", "file", "+read", "my_b your_b ||", 0, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "one_t", "five_t", "fd", "+use", NULL, 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "two_t", "two_t", "file", "+setattr", "east_b", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "three_t", "three_t", "file", "+setattr", "east_b", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "five_t", "five_t", "file", "+setattr", "east_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "five_t", "six_t", "socket", "-connect -ioctl", "in_b ! up_b down_b && ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "one_t", "one_t", "process", "-setexec", "up_b down_b && left_b && right_b out_b && ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "seven_t", "eight_t", "file", "-read -write", "this_b that_b ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "seven_t", "eight_t", "file", "-read", "this_b that_b ||", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "one_t", "five_t", "fd", "-use", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "two_t", "two_t", "file", "-setattr", "east_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "three_t", "three_t", "file", "-setattr", "east_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "five_t", "five_t", "file", "-setattr", "east_b", 0, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_ALLOW,
		 "four_t", "five_t", "dir", "add_name search +read", "north_b west_b &&", 1, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_ALLOW,
		 "five_t", "one_t", "process", "transition -signal", "up_b down_b && left_b && right_b out_b && ||", 1, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_ALLOW,
		 "one_t", "three_t", "dir", "search +read", NULL, 1, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_ALLOW,
		 "one_t", "three_t", "socket", "sendto -recvfrom", "north_b south_b ^ up_b ! down_b && ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};
	/* these rules are actually unmodified, but show up as
	   added/removed in SETools 3.3 */
	struct poldiff_test_rule_answer unmodified_answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "one_t", "four_t", "dir", "+getattr +read +search", "left_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "one_t", "four_t", "dir", "-getattr -read -search", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "six_t", "one_t", "file", "+relabelfrom +relabelto", "left_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "six_t", "one_t", "file", "-relabelfrom -relabelto", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "six_t", "two_t", "file", "+relabelfrom +relabelto", "left_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "six_t", "two_t", "file", "-relabelfrom -relabelto", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_ALLOW,
		 "six_t", "three_t", "file", "+relabelfrom +relabelto", "left_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_ALLOW,
		 "six_t", "three_t", "file", "-relabelfrom -relabelto", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_avrule_t *a = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_avrule_check(simple->diff, a, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			for (da = unmodified_answers; da->form != POLDIFF_FORM_NONE; da++) {
				if (da->found) {
					continue;
				}
				if (poldiff_test_avrule_check(simple->diff, a, da)) {
					CU_ASSERT(!da->found);
					da->found = true;
					break;
				}
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_avrule_to_string(simple->diff, a);
			printf("Unknown avrule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
	for (da = unmodified_answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule2: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_avrules_auditallow(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_avrule_vector_auditallow(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_AUDITALLOW,
		 "four_t", "five_t", "sock_file", "+write", NULL, 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_AUDITALLOW,
		 "three_t", "two_t", "lnk_file", "+write", "south_b right_b &&", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_AUDITALLOW,
		 "one_t", "two_t", "file", "+read", "south_b right_b ||", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_AUDITALLOW,
		 "one_t", "two_t", "file", "-read", "south_b right_b ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};
	/* these rules are actually unmodified, but show up as
	   added/removed in SETools 3.3 */
	struct poldiff_test_rule_answer unmodified_answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_AUDITALLOW,
		 "one_t", "five_t", "fd", "+use", "left_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_AUDITALLOW,
		 "one_t", "five_t", "fd", "-use", "left_b right_b && left_b right_b ! && ||", 0, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_avrule_t *a = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_avrule_check(simple->diff, a, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			for (da = unmodified_answers; da->form != POLDIFF_FORM_NONE; da++) {
				if (da->found) {
					continue;
				}
				if (poldiff_test_avrule_check(simple->diff, a, da)) {
					CU_ASSERT(!da->found);
					da->found = true;
					break;
				}
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_avrule_to_string(simple->diff, a);
			printf("Unknown avrule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
	for (da = unmodified_answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule2: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_avrules_dontaudit(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_avrule_vector_dontaudit(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_DONTAUDIT,
		 "one_t", "two_t", "file", "+write", "left_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_DONTAUDIT,
		 "one_t", "three_t", "dir", "-write", NULL, 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_DONTAUDIT,
		 "one_t", "two_t", "file", "-write", "south_b right_b ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};
	/* these rules are actually unmodified, but show up as
	   added/removed in SETools 3.3 */
	struct poldiff_test_rule_answer modified_answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_DONTAUDIT,
		 "one_t", "three_t", "file", "+getattr", "left_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_DONTAUDIT,
		 "one_t", "three_t", "file", "-setattr", "left_b right_b && left_b right_b ! && ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_avrule_t *a = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_avrule_check(simple->diff, a, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			for (da = modified_answers; da->form != POLDIFF_FORM_NONE; da++) {
				if (da->found) {
					continue;
				}
				if (poldiff_test_avrule_check(simple->diff, a, da)) {
					CU_ASSERT(!da->found);
					da->found = true;
					break;
				}
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_avrule_to_string(simple->diff, a);
			printf("Unknown avrule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
	for (da = modified_answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found avrule2: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_terules_transition(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_terule_vector_trans(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "one_t", "two_t", "file", "+one_t", "up_b", 0, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "six_t", "one_t", "node", "+two_t", "in_b", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "four_t", "five_t", "process", "+one_t", "south_b right_b &&", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "five_t", "one_t", "sem", "+three_t", "south_b right_b ||", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "one_t", "three_t", "shm", "+six_t", "up_b down_b && left_b && right_b out_b && ||", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "three_t", "four_t", "ipc", "+five_t", NULL, 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "three_t", "five_t", "filesystem", "+two_t", "east_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "six_t", "four_t", "file", "-three_t", NULL, 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "five_t", "six_t", "msg", "-two_t", "up_b down_b && left_b && right_b out_b && ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "four_t", "dir", "-six_t", "in_b ! up_b down_b && ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "five_t", "one_t", "sem", "-three_t", "south_b right_b ||", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "one_t", "three_t", "shm", "-six_t", "up_b", 0, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "three_t", "four_t", "ipc", "-five_t", "south_b right_b ||", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "three_t", "five_t", "filesystem", "-two_t", "east_b", 0, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_TYPE_TRANS,
		 "four_t", "three_t", "sem", "-five_t +six_t", "up_b", 1, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "three_t", "fd", "-five_t +four_t", "north_b west_b &&", 1, 0},
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_TYPE_TRANS,
		 "four_t", "six_t", "process", "+three_t -two_t", "north_b south_b ^ up_b ! down_b && ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};
	/* these rules are actually unmodified, but show up as
	   added/removed in SETools 3.3 */
	struct poldiff_test_rule_answer modified_answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "one_t", "netif", "+five_t", "left_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "one_t", "netif", "-five_t", "left_b right_b && left_b right_b ! && ||", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "two_t", "netif", "+five_t", "left_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "two_t", "netif", "-five_t", "left_b right_b && left_b right_b ! && ||", 1, 0},
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "six_t", "netif", "+five_t", "left_b", 1, 0},
		{POLDIFF_FORM_REMOVED, QPOL_RULE_TYPE_TRANS,
		 "two_t", "six_t", "netif", "-five_t", "left_b right_b && left_b right_b ! && ||", 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_terule_t *t = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_terule_check(simple->diff, t, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			for (da = modified_answers; da->form != POLDIFF_FORM_NONE; da++) {
				if (da->found) {
					continue;
				}
				if (poldiff_test_terule_check(simple->diff, t, da)) {
					CU_ASSERT(!da->found);
					da->found = true;
					break;
				}
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_terule_to_string(simple->diff, t);
			printf("Unknown terule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found terule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
	for (da = modified_answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found terule2: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_terules_member(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_terule_vector_member(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_ADDED, QPOL_RULE_TYPE_MEMBER,
		 "five_t", "four_t", "file", "+six_t", NULL, 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_terule_t *t = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_terule_check(simple->diff, t, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_terule_to_string(simple->diff, t);
			printf("Unknown terule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found terule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

static void conditionals_simple_terules_change(void)
{
	size_t i;
	struct poldiff_test_rule_answer *da;

	const apol_vector_t *diffs_v = poldiff_get_terule_vector_change(simple->diff);
	CU_ASSERT_PTR_NOT_NULL_FATAL(diffs_v);
	struct poldiff_test_rule_answer answers[] = {
		{POLDIFF_FORM_MODIFIED, QPOL_RULE_TYPE_CHANGE,
		 "five_t", "three_t", "dir", "+one_t -two_t", NULL, 1, 0},
		{POLDIFF_FORM_NONE, 0, NULL, NULL, NULL, NULL, NULL, 0, 0},
	};

	for (i = 0; i < apol_vector_get_size(diffs_v); i++) {
		const poldiff_terule_t *t = apol_vector_get_element(diffs_v, i);
		for (da = answers; da->form != POLDIFF_FORM_NONE; da++) {
			if (da->found) {
				continue;
			}
			if (poldiff_test_terule_check(simple->diff, t, da)) {
				CU_ASSERT(!da->found);
				da->found = true;
				break;
			}
		}
		if (da->form == POLDIFF_FORM_NONE) {
			char *result = poldiff_terule_to_string(simple->diff, t);
			printf("Unknown terule: %s\n", result);
			free(result);
		}
		CU_ASSERT(da->form != POLDIFF_FORM_NONE);
	}
	for (da = answers, i = 0; da->form != POLDIFF_FORM_NONE; da++, i++) {
		if (!da->found) {
			printf("Not found terule: %zd\n", i);
		}
		CU_ASSERT(da->found);
	}
}

CU_TestInfo conditionals_tests[] = {
	{"simple booleans", conditionals_simple_bools}
	,
	{"simple avrules: allow", conditionals_simple_avrules_allow}
	,
	{"simple avrules: auditallow", conditionals_simple_avrules_auditallow}
	,
	{"simple avrules: dontaudit", conditionals_simple_avrules_dontaudit}
	,
	{"simple terules: type_transition", conditionals_simple_terules_transition}
	,
	{"simple terules: type_member", conditionals_simple_terules_member}
	,
	{"simple avrules: type_change", conditionals_simple_terules_change}
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
