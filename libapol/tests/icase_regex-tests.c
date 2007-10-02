/**
 *  @file
 *
 *  Test case insensitive and regular expression searches in libapol.
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
#include <apol/avrule-query.h>
#include <apol/bool-query.h>
#include <apol/class-perm-query.h>
#include <apol/constraint-query.h>
#include <apol/condrule-query.h>
#include <apol/mls-query.h>
#include <apol/range_trans-query.h>
#include <apol/rbacrule-query.h>
#include <apol/role-query.h>
#include <apol/terule-query.h>
#include <apol/type-query.h>
#include <apol/user-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <qpol/policy_extend.h>
#include <stdbool.h>
#include <stdio.h>

#define SOURCE_POLICY TEST_POLICIES "/setools-3.4/apol/icase.conf"

static int test_num = 0;
static apol_policy_t *sp = NULL;
static apol_vector_t *results = NULL;

static void check_vector(apol_vector_t ** v, size_t expected_num)
{
	size_t actual = apol_vector_get_size(*v);
	bool pass = (actual == expected_num);
	if (!pass) {
		printf("TEST #%d FAILURE: Expected %d matches but got %d\n", (int)test_num, (int)expected_num, (int)actual);
		CU_ASSERT(0);
	} else {
		CU_ASSERT_TRUE(pass);
	}
	apol_vector_destroy(v);
	test_num++;
}

static void avrule_test(void)
{
	test_num = 0;
	/* target */
	apol_avrule_query_t *a = apol_avrule_query_create();

	CU_ASSERT_FALSE(apol_avrule_query_set_target(sp, a, "Koala_T", 0));
	CU_ASSERT_FALSE(apol_avrule_get_by_query(sp, a, &results));
	check_vector(&results, 3);

	CU_ASSERT_FALSE(apol_avrule_query_set_target(sp, a, "koala_t", 0));
	CU_ASSERT_FALSE(apol_avrule_get_by_query(sp, a, &results));
	check_vector(&results, 0);

	CU_ASSERT_FALSE(apol_avrule_query_set_icase(sp, a, 1));
	CU_ASSERT_FALSE(apol_avrule_get_by_query(sp, a, &results));
	check_vector(&results, 3);

	CU_ASSERT_FALSE(apol_avrule_query_set_target(sp, a, "ALA_t", 0));
	CU_ASSERT_FALSE(apol_avrule_query_set_icase(sp, a, 0));
	CU_ASSERT_FALSE(apol_avrule_query_set_regex(sp, a, 1));
	CU_ASSERT_FALSE(apol_avrule_get_by_query(sp, a, &results));
	check_vector(&results, 2);

	CU_ASSERT_FALSE(apol_avrule_query_set_icase(sp, a, 1));
	CU_ASSERT_FALSE(apol_avrule_get_by_query(sp, a, &results));
	check_vector(&results, 5);

	apol_avrule_query_destroy(&a);

	/* classes */
	a = apol_avrule_query_create();

	apol_avrule_query_append_class(sp, a, "file");
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 8);

	apol_avrule_query_append_class(sp, a, NULL);
	apol_avrule_query_append_class(sp, a, "FILE");
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 0);

	apol_avrule_query_set_regex(sp, a, 1);
	apol_avrule_query_set_icase(sp, a, 0);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_avrule_query_set_regex(sp, a, 0);
	apol_avrule_query_set_icase(sp, a, 1);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 8);

	apol_avrule_query_append_class(sp, a, NULL);
	apol_avrule_query_append_class(sp, a, "FiLE");
	apol_avrule_query_set_regex(sp, a, 1);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 9);

	apol_avrule_query_destroy(&a);
	a = apol_avrule_query_create();

	apol_avrule_query_append_perm(sp, a, "write");
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	/* perms */
	apol_avrule_query_append_perm(sp, a, NULL);
	apol_avrule_query_append_perm(sp, a, "WRITE");
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 0);

	apol_avrule_query_append_perm(sp, a, NULL);
	apol_avrule_query_append_perm(sp, a, "WRiTE");
	apol_avrule_query_set_icase(sp, a, 1);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_avrule_query_set_icase(sp, a, 0);
	apol_avrule_query_set_regex(sp, a, 1);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_avrule_query_set_icase(sp, a, 1);
	apol_avrule_get_by_query(sp, a, &results);
	check_vector(&results, 2);

	apol_avrule_query_destroy(&a);
}

static void bool_test(void)
{
	test_num = 0;
	apol_bool_query_t *b = apol_bool_query_create();

	apol_bool_query_set_bool(sp, b, "DOG");
	apol_bool_get_by_query(sp, b, &results);
	check_vector(&results, 0);

	apol_bool_query_set_bool(sp, b, "dOG");
	apol_bool_get_by_query(sp, b, &results);
	check_vector(&results, 1);

	apol_bool_query_set_bool(sp, b, "OG");
	apol_bool_query_set_regex(sp, b, 1);
	apol_bool_get_by_query(sp, b, &results);
	check_vector(&results, 1);

	apol_bool_query_set_icase(sp, b, 1);
	apol_bool_get_by_query(sp, b, &results);
	check_vector(&results, 2);

	apol_bool_query_destroy(&b);
}

static void class_test(void)
{
	test_num = 0;

	/* class */
	apol_class_query_t *c = apol_class_query_create();
	apol_class_query_set_class(sp, c, "file");
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 1);

	apol_class_query_set_class(sp, c, "FILE");
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 0);

	apol_class_query_set_icase(sp, c, 1);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 1);

	apol_class_query_set_regex(sp, c, 1);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 7);

	apol_class_query_set_icase(sp, c, 0);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 2);
	apol_class_query_destroy(&c);

	/* common */
	c = apol_class_query_create();

	apol_class_query_set_common(sp, c, "file");
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 5);

	apol_class_query_set_common(sp, c, "FILE");
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 0);

	apol_class_query_set_icase(sp, c, 1);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 5);

	apol_class_query_set_icase(sp, c, 0);
	apol_class_query_set_regex(sp, c, 1);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 1);

	apol_class_query_set_icase(sp, c, 1);
	apol_class_get_by_query(sp, c, &results);
	check_vector(&results, 6);

	apol_class_query_destroy(&c);

	/* perm */
	apol_perm_query_t *pq = apol_perm_query_create();
	apol_perm_query_set_perm(sp, pq, "read");
	apol_perm_get_by_query(sp, pq, &results);
	check_vector(&results, 1);

	apol_perm_query_set_perm(sp, pq, "READ");
	apol_perm_get_by_query(sp, pq, &results);
	check_vector(&results, 0);

	apol_perm_query_set_icase(sp, pq, 1);
	apol_perm_get_by_query(sp, pq, &results);
	check_vector(&results, 2);

	apol_perm_query_set_perm(sp, pq, "write");
	apol_perm_query_set_icase(sp, pq, 0);
	apol_perm_query_set_regex(sp, pq, 1);
	apol_perm_get_by_query(sp, pq, &results);
	check_vector(&results, 2);

	apol_perm_query_set_icase(sp, pq, 1);
	apol_perm_get_by_query(sp, pq, &results);
	check_vector(&results, 3);

	apol_perm_query_destroy(&pq);
}

static void mls_test(void)
{
	test_num = 0;

	/* level: cat */
	apol_level_query_t *l = apol_level_query_create();

	apol_level_query_set_cat(sp, l, "spoon");
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 3);

	apol_level_query_set_icase(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 4);

	apol_level_query_set_cat(sp, l, "SpO");
	apol_level_query_set_icase(sp, l, 0);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 0);

	apol_level_query_set_regex(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 2);

	apol_level_query_set_icase(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 6);

	apol_level_query_destroy(&l);

	/* level: sens */
	l = apol_level_query_create();
	apol_level_query_set_sens(sp, l, "ss02");
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 0);

	apol_level_query_set_sens(sp, l, "Ss0");
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 1);

	apol_level_query_set_icase(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 2);

	apol_level_query_set_icase(sp, l, 0);
	apol_level_query_set_regex(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 2);

	apol_level_query_set_icase(sp, l, 1);
	apol_level_get_by_query(sp, l, &results);
	check_vector(&results, 3);

	apol_level_query_destroy(&l);

	/* category */
	apol_cat_query_t *c = apol_cat_query_create();

	apol_cat_query_set_cat(sp, c, "spoon");
	apol_cat_get_by_query(sp, c, &results);
	check_vector(&results, 1);

	apol_cat_query_set_cat(sp, c, "SPOON");
	apol_cat_get_by_query(sp, c, &results);
	check_vector(&results, 0);

	apol_cat_query_set_icase(sp, c, 1);
	apol_cat_get_by_query(sp, c, &results);
	check_vector(&results, 2);

	apol_cat_query_set_cat(sp, c, "ORK");
	apol_cat_query_set_icase(sp, c, 0);
	apol_cat_query_set_regex(sp, c, 1);
	apol_cat_get_by_query(sp, c, &results);
	check_vector(&results, 1);

	apol_cat_query_set_icase(sp, c, 1);
	apol_cat_get_by_query(sp, c, &results);
	check_vector(&results, 3);

	apol_cat_query_destroy(&c);
}
static void rangetrans_test(void)
{
	test_num = 0;

	apol_range_trans_query_t *rt = apol_range_trans_query_create();

	apol_range_trans_query_set_target(sp, rt, "Koala_T", 0);
	apol_range_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 3);

	apol_range_trans_query_set_target(sp, rt, "koala_t", 0);
	apol_range_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 0);

	apol_range_trans_query_set_icase(sp, rt, 1);
	apol_range_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 3);

	apol_range_trans_query_set_target(sp, rt, "ALA_t", 0);
	apol_range_trans_query_set_icase(sp, rt, 0);
	apol_range_trans_query_set_regex(sp, rt, 1);
	apol_range_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 1);

	apol_range_trans_query_set_icase(sp, rt, 1);
	apol_range_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 4);

	apol_range_trans_query_destroy(&rt);
}

static void rbac_test(void)
{
	test_num = 0;
/* role trans */
	apol_role_trans_query_t *rt = apol_role_trans_query_create();

	apol_role_trans_query_set_target(sp, rt, "Koala_T", 0);
	apol_role_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 2);

	apol_role_trans_query_set_target(sp, rt, "koala_t", 0);
	apol_role_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 0);

	apol_role_trans_query_set_icase(sp, rt, 1);
	apol_role_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 2);

	apol_role_trans_query_set_target(sp, rt, "ALA_t", 0);
	apol_role_trans_query_set_icase(sp, rt, 0);
	apol_role_trans_query_set_regex(sp, rt, 1);
	apol_role_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 1);

	apol_role_trans_query_set_icase(sp, rt, 1);
	apol_role_trans_get_by_query(sp, rt, &results);
	check_vector(&results, 3);

	apol_role_trans_query_destroy(&rt);

/* role allow */
	apol_role_allow_query_t *ra = apol_role_allow_query_create();

	apol_role_allow_query_set_target(sp, ra, "MICHELINMAN_r");
	apol_role_allow_get_by_query(sp, ra, &results);
	check_vector(&results, 1);

	apol_role_allow_query_set_target(sp, ra, "michelinman_r");
	apol_role_allow_get_by_query(sp, ra, &results);
	check_vector(&results, 0);

	apol_role_allow_query_set_icase(sp, ra, 1);
	apol_role_allow_get_by_query(sp, ra, &results);
	check_vector(&results, 1);

	apol_role_allow_query_set_target(sp, ra, "man_r");
	apol_role_allow_query_set_icase(sp, ra, 0);
	apol_role_allow_query_set_regex(sp, ra, 1);
	apol_role_allow_get_by_query(sp, ra, &results);
	check_vector(&results, 2);

	apol_role_allow_query_set_icase(sp, ra, 1);
	apol_role_allow_get_by_query(sp, ra, &results);
	check_vector(&results, 3);

	apol_role_allow_query_destroy(&ra);
}

static void role_test(void)
{
	test_num = 0;
	/* roles */
	apol_role_query_t *r = apol_role_query_create();

	apol_role_query_set_role(sp, r, "MICHELINMAN_r");
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 1);

	apol_role_query_set_role(sp, r, "michelinman_r");
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 0);

	apol_role_query_set_icase(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 1);

	apol_role_query_set_role(sp, r, "man_r");
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 1);

	apol_role_query_set_icase(sp, r, 0);
	apol_role_query_set_regex(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 2);

	apol_role_query_set_icase(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 3);

	apol_role_query_destroy(&r);

	/* types */
	r = apol_role_query_create();
	apol_role_query_set_type(sp, r, "range_rover_t");
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 3);

	apol_role_query_set_type(sp, r, "rover_t");
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 0);

	apol_role_query_set_icase(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 3);

	apol_role_query_set_icase(sp, r, 0);
	apol_role_query_set_regex(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 3);

	apol_role_query_set_icase(sp, r, 1);
	apol_role_get_by_query(sp, r, &results);
	check_vector(&results, 4);

	apol_role_query_destroy(&r);
}

static void type_test(void)
{
	test_num = 0;
	/* type */
	apol_type_query_t *t = apol_type_query_create();

	apol_type_query_set_type(sp, t, "impALA_t");
	apol_type_get_by_query(sp, t, &results);
	check_vector(&results, 1);

	apol_type_query_set_type(sp, t, "impala_t");
	apol_type_get_by_query(sp, t, &results);
	check_vector(&results, 0);

	apol_type_query_set_icase(sp, t, 1);
	apol_type_get_by_query(sp, t, &results);
	check_vector(&results, 1);

	apol_type_query_set_type(sp, t, "ala_T");
	apol_type_query_set_icase(sp, t, 0);
	apol_type_query_set_regex(sp, t, 1);
	apol_type_get_by_query(sp, t, &results);
	check_vector(&results, 1);

	apol_type_query_set_icase(sp, t, 1);
	apol_type_get_by_query(sp, t, &results);
	check_vector(&results, 2);

	apol_type_query_destroy(&t);

	/* attr */
	apol_attr_query_t *a = apol_attr_query_create();
	apol_attr_query_set_attr(sp, a, "car");
	apol_attr_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_attr_query_set_attr(sp, a, "CAR");
	apol_attr_get_by_query(sp, a, &results);
	check_vector(&results, 0);

	apol_attr_query_set_icase(sp, a, 1);
	apol_attr_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_attr_query_set_icase(sp, a, 0);
	apol_attr_query_set_regex(sp, a, 1);
	apol_attr_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_attr_query_set_icase(sp, a, 1);
	apol_attr_get_by_query(sp, a, &results);
	check_vector(&results, 2);

	apol_attr_query_destroy(&a);
}

static void user_test(void)
{
	test_num = 0;
	/* user */
	apol_user_query_t *a = apol_user_query_create();
	apol_user_query_set_user(sp, a, "superman_u");
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_user(sp, a, "batman_u");
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 0);

	apol_user_query_set_icase(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_user(sp, a, "man_u");
	apol_user_query_set_icase(sp, a, 0);
	apol_user_query_set_regex(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_icase(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 2);

	apol_user_query_destroy(&a);

	/* role */
	a = apol_user_query_create();
	apol_user_query_set_role(sp, a, "aquaman_r");
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_role(sp, a, "MAN_r");
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 0);

	apol_user_query_set_icase(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_icase(sp, a, 0);
	apol_user_query_set_regex(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 1);

	apol_user_query_set_icase(sp, a, 1);
	apol_user_get_by_query(sp, a, &results);
	check_vector(&results, 3);

	apol_user_query_destroy(&a);
}

CU_TestInfo icase_regex_tests[] = {
	{"AV Rule Search", avrule_test}
	,
	{"Bool Search", bool_test}
	,
	{"Class/Perm Search", class_test}
	,
/* TODO:
	{"Conditional Search",cond_test}
	,
	{"Constraint Search", constraint_test}
	,
*/
	{"MLS Query Search", mls_test}
	,
	{"Range Transition Search", rangetrans_test}
	,
	{"RBAC Search", rbac_test}
	,
	{"Role Search", role_test}
	,
/* TODO:
	{"TE Rule Search", terule_test}
	,
*/
	{"Type Search", type_test}
	,
	{"User Search", user_test}
	,
	CU_TEST_INFO_NULL
};

int icase_regex_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int icase_regex_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
