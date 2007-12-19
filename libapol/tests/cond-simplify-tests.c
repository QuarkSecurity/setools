/**
 *  @file
 *
 *  Test the conditional simplification algorithm.
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

#include <apol/cond-simplify.h>
#include <apol/policy.h>
#include <apol/condrule-query.h>

#include <stdio.h>

#define SOURCE_POLICY TEST_POLICIES "/setools-3.3/sediff/cond_test_policy.orig.conf"

static apol_policy_t *sp = NULL;

static void simple_test(void)
{
	qpol_policy_t *q = apol_policy_get_qpol(sp);
	qpol_iterator_t *iter = NULL;
	qpol_policy_get_cond_iter(q, &iter);
	CU_ASSERT_PTR_NOT_NULL_FATAL(iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cond_t *cond;
		qpol_iterator_get_item(iter, (void **)&cond);
		CU_ASSERT_PTR_NOT_NULL_FATAL(cond);
		char *s = apol_cond_expr_render(sp, cond);
		printf("Pre-simplified expression:  %s\n", s);
		free(s);
		apol_vector_t *v = apol_cond_simplify(sp, cond);
		CU_ASSERT_PTR_NOT_NULL_FATAL(v);
		size_t i, j;
		for (i = 0; i < apol_vector_get_size(v); i++) {
			apol_cond_term_t *t = (apol_cond_term_t *) apol_vector_get_element(v, i);
			if (i > 0) {
				printf(" + ");
			}
			printf("(");
			for (j = 0; j < apol_vector_get_size(t->included); j++) {
				qpol_bool_t *b = (qpol_bool_t *) apol_vector_get_element(t->included, j);
				const char *name;
				qpol_bool_get_name(q, b, &name);
				printf(" %s", name);
			}
			for (j = 0; j < apol_vector_get_size(t->excluded); j++) {
				qpol_bool_t *b = (qpol_bool_t *) apol_vector_get_element(t->excluded, j);
				const char *name;
				qpol_bool_get_name(q, b, &name);
				printf(" !%s", name);
			}
			printf(" )");
		}
		printf("\n");
	}

	qpol_iterator_destroy(&iter);
}

CU_TestInfo cond_simplify_tests[] = {
	{"Simple Policies", simple_test}
	,
	CU_TEST_INFO_NULL
};

int cond_simplify_init()
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

int cond_simplify_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
