/**
 *  @file
 *
 *  Test the conditional simplification algorithm.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007-2008 Tresys Technology, LLC
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

#include <apol/policy.h>
#include <apol/cond-simplify.h>
#include <apol/condrule-query.h>
#include <apol/util.h>

#include <stdio.h>
#include <stdbool.h>

#define SOURCE_POLICY TEST_POLICIES "/setools-3.4/poldiff/more-conditionals.orig.conf"

static apol_policy_t *sp = NULL;

static const char *answers[] = {
	"north_b,west_b",
	"north_b + !south_b",
	"north_b,!south_b + north_b,west_b + south_b,!east_b,!west_b",
	"north_b,south_b,east_b,west_b,up_b,down_b",
	"south_b + right_b",
	"left_b",
	"east_b",
	"north_b,!south_b + !north_b,south_b + down_b,!up_b",
	NULL
};

struct canonical_form
{
	apol_vector_t *minterms;
	bool found;
};

struct minterm
{
	apol_vector_t *inc;
	apol_vector_t *exc;
	bool found;
};

static void minterm_free(void *elem)
{
	if (elem != NULL) {
		struct minterm *m = (struct minterm *)elem;
		apol_vector_destroy(&(m->inc));
		apol_vector_destroy(&(m->exc));
		free(m);
	}
}

static void canonical_free(void *elem)
{
	if (elem != NULL) {
		struct canonical_form *c = (struct canonical_form *)elem;
		apol_vector_destroy(&(c->minterms));
		free(c);
	}
}

static apol_vector_t *create_answers(void)
{
	apol_vector_t *v = apol_vector_create(canonical_free);
	const char **s;
	for (s = answers; *s != NULL; s++) {
		apol_vector_t *tv = apol_str_split(*s, "+");
		size_t i, j;
		struct canonical_form *c = calloc(1, sizeof(*c));
		c->minterms = apol_vector_create(minterm_free);
		for (i = 0; i < apol_vector_get_size(tv); i++) {
			char *vs = (char *)apol_vector_get_element(tv, i);
			apol_vector_t *vv = apol_str_split(vs, ",");
			struct minterm *m = calloc(1, sizeof(*m));
			m->inc = apol_vector_create(free);
			m->exc = apol_vector_create(free);
			for (j = 0; j < apol_vector_get_size(vv); j++) {
				char *vs = (char *)apol_vector_get_element(vv, j);
				apol_str_trim(vs);
				if (*vs == '!') {
					apol_vector_append(m->exc, strdup(vs + 1));
				} else {
					apol_vector_append(m->inc, strdup(vs));
				}
			}
			apol_vector_destroy(&vv);
			apol_vector_append(c->minterms, m);
		}
		apol_vector_destroy(&tv);
		apol_vector_append(v, c);
	}
	return v;
}

static bool found_match(qpol_policy_t * q, struct canonical_form *c, apol_vector_t * v)
{
	size_t i, j, k, l;
	if (apol_vector_get_size(v) != apol_vector_get_size(c->minterms)) {
		return false;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		apol_cond_minterm_t *t = (apol_cond_minterm_t *) apol_vector_get_element(v, i);
		const apol_vector_t *inc = apol_cond_minterm_get_variables(t);
		const apol_vector_t *exc = apol_cond_minterm_get_comp_variables(t);
		size_t inc_size = apol_vector_get_size(inc);
		size_t exc_size = apol_vector_get_size(exc);
		bool found_a_minterm = false;
		for (j = 0; j < apol_vector_get_size(c->minterms); j++) {
			struct minterm *m = (struct minterm *)apol_vector_get_element(c->minterms, j);
			if (m->found) {
				continue;
			}
			if (apol_vector_get_size(m->inc) != inc_size || apol_vector_get_size(m->exc) != exc_size) {
				continue;
			}
			bool minterm_matched = true;
			const char *name;
			for (k = 0; k < apol_vector_get_size(inc); k++) {
				qpol_bool_t *b = (qpol_bool_t *) apol_vector_get_element(inc, k);
				qpol_bool_get_name(q, b, &name);
				if (apol_vector_get_index(m->inc, name, apol_str_strcmp, NULL, &l) < 0) {
					minterm_matched = false;
					break;
				}
			}
			for (k = 0; minterm_matched && k < apol_vector_get_size(exc); k++) {
				qpol_bool_t *b = (qpol_bool_t *) apol_vector_get_element(exc, k);
				qpol_bool_get_name(q, b, &name);
				if (apol_vector_get_index(m->exc, name, apol_str_strcmp, NULL, &l) < 0) {
					minterm_matched = false;
					break;
				}
			}
			if (minterm_matched) {
				m->found = true;
				found_a_minterm = true;
				break;
			}
		}
		if (!found_a_minterm) {
			goto reset_minterms;
		}
	}

	for (j = 0; j < apol_vector_get_size(c->minterms); j++) {
		struct minterm *m = (struct minterm *)apol_vector_get_element(c->minterms, j);
		if (!m->found) {
			goto reset_minterms;
		}
	}
	return true;

      reset_minterms:
	for (j = 0; j < apol_vector_get_size(c->minterms); j++) {
		struct minterm *m = (struct minterm *)apol_vector_get_element(c->minterms, j);
		m->found = false;
	}
	return false;
}

static void simple_test(void)
{
	qpol_policy_t *q = apol_policy_get_qpol(sp);
	apol_vector_t *answers_v = create_answers();

	qpol_iterator_t *iter = NULL;
	qpol_policy_get_cond_iter(q, &iter);
	CU_ASSERT_PTR_NOT_NULL_FATAL(iter);
	size_t i;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cond_t *cond;
		qpol_iterator_get_item(iter, (void **)&cond);
		CU_ASSERT_PTR_NOT_NULL_FATAL(cond);
		apol_vector_t *v = apol_cond_simplify(sp, cond);
		CU_ASSERT_PTR_NOT_NULL_FATAL(v);
#ifdef SETOOLS_DEBUG
		{
			char *s = apol_cond_expr_render(sp, cond);
			printf("Finding a match for '%s'\n", s);
			free(s);
		}
#endif

		bool found_answer = false;
		for (i = 0; i < apol_vector_get_size(answers_v); i++) {
			struct canonical_form *c = (struct canonical_form *)apol_vector_get_element(answers_v, i);
			if (c->found) {
				continue;
			}
			if (found_match(q, c, v)) {
				c->found = true;
				found_answer = true;
				break;
			}
		}

#ifdef SETOOLS_DEBUG
		if (!found_answer) {
			printf("Did not find a match for this expression.\n");
		}
#endif
		CU_ASSERT(found_answer);
		apol_vector_destroy(&v);
	}
	for (i = 0; i < apol_vector_get_size(answers_v); i++) {
		struct canonical_form *c = (struct canonical_form *)apol_vector_get_element(answers_v, i);
		if (!c->found) {
			printf("Did not match answer %zd.\n", i);
		}
		CU_ASSERT(c->found);
	}

	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&answers_v);
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
