/**
 *  @file
 *
 *  CUnit testing framework for libpoldiff's correctness.
 *
 *  @author Paul Rosenfeld prosenfeld@tresys.com
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

#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include <apol/util.h>
#include <apol/vector.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "components-tests.h"
#include "rules-tests.h"
#include "mls-tests.h"
#include "nomls-tests.h"
#include "conditionals.h"

apol_vector_t *added_v;
apol_vector_t *removed_v;
apol_vector_t *modified_v;
apol_vector_t *modified_name_only_v;

static int test_string_compare(const void *a, const void *b, void *data)
{
	const char *intended = (const char *)a;
	const char *actual = (const char *)b;
	const char *key = (const char *)data;
	/* check if the intended string begins with the key character */
	if (*intended != *key) {
		return -1;
	}
	return strcmp(intended + 1, actual);
}

bool poldiff_test_avrule_check(const poldiff_t * diff, const poldiff_avrule_t * actual,
			       const struct poldiff_test_rule_answer * intended)
{
	if (poldiff_avrule_get_form(actual) != intended->form) {
		return false;
	}
	if (poldiff_avrule_get_rule_type(actual) != intended->rule_type) {
		return false;
	}
	if (strcmp(poldiff_avrule_get_source_type(actual), intended->source_type) != 0) {
		return false;
	}
	if (strcmp(poldiff_avrule_get_target_type(actual), intended->target_type) != 0) {
		return false;
	}
	if (strcmp(poldiff_avrule_get_object_class(actual), intended->object_class) != 0) {
		return false;
	}

	apol_vector_t *v = apol_str_split(intended->perm_default, " ");
	size_t perms_found = 0, i, j;
	const apol_vector_t *av = poldiff_avrule_get_unmodified_perms(actual);
	for (i = 0; i < apol_vector_get_size(av); i++) {
		const char *s = (const char *)apol_vector_get_element(av, i);
		if (apol_vector_get_index(v, s, apol_str_strcmp, NULL, &j) < 0) {
			apol_vector_destroy(&v);
			return false;
		}
		perms_found++;
	}
	av = poldiff_avrule_get_added_perms(actual);
	for (i = 0; i < apol_vector_get_size(av); i++) {
		const char *s = (const char *)apol_vector_get_element(av, i);
		if (apol_vector_get_index(v, s, test_string_compare, "+", &j) < 0) {
			apol_vector_destroy(&v);
			return false;
		}
		perms_found++;
	}
	av = poldiff_avrule_get_removed_perms(actual);
	for (i = 0; i < apol_vector_get_size(av); i++) {
		const char *s = (const char *)apol_vector_get_element(av, i);
		if (apol_vector_get_index(v, s, test_string_compare, "-", &j) < 0) {
			apol_vector_destroy(&v);
			return false;
		}
		perms_found++;
	}
	if (perms_found != apol_vector_get_size(v)) {
		apol_vector_destroy(&v);
		return false;
	}
	apol_vector_destroy(&v);

	const qpol_cond_t *cond;
	uint32_t which_list;
	const apol_policy_t *p;
	poldiff_avrule_get_cond(diff, actual, &cond, &which_list, &p);
	if (which_list != intended->which_list) {
		return false;
	}
	if ((cond == NULL && intended->cond_expr != NULL) || (cond != NULL && intended->cond_expr == NULL)) {
		return false;
	}
	if (cond == NULL) {
		/* both actual and intended are not conditional expressions */
		return true;
	}

	char *cond_expr = apol_cond_expr_render(p, cond);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cond_expr);
	if (strcmp(cond_expr, intended->cond_expr) != 0) {
		free(cond_expr);
		return false;
	}
	free(cond_expr);
	return true;
}

bool poldiff_test_terule_check(const poldiff_t * diff, const poldiff_terule_t * actual,
			       const struct poldiff_test_rule_answer * intended)
{
	if (poldiff_terule_get_form(actual) != intended->form) {
		return false;
	}
	if (poldiff_terule_get_rule_type(actual) != intended->rule_type) {
		return false;
	}
	if (strcmp(poldiff_terule_get_source_type(actual), intended->source_type) != 0) {
		return false;
	}
	if (strcmp(poldiff_terule_get_target_type(actual), intended->target_type) != 0) {
		return false;
	}
	if (strcmp(poldiff_terule_get_object_class(actual), intended->object_class) != 0) {
		return false;
	}

	if (intended->form == POLDIFF_FORM_ADDED || intended->form == POLDIFF_FORM_ADD_TYPE) {
		if (strcmp(poldiff_terule_get_modified_default(actual), intended->perm_default + 1) != 0) {
			return false;
		}
	} else if (intended->form == POLDIFF_FORM_REMOVED || intended->form == POLDIFF_FORM_REMOVE_TYPE) {
		if (strcmp(poldiff_terule_get_original_default(actual), intended->perm_default + 1) != 0) {
			return false;
		}
	} else {
		apol_vector_t *v = apol_str_split(intended->perm_default, " ");
		size_t i;
		const char *d = poldiff_terule_get_original_default(actual);
		if (apol_vector_get_index(v, d, test_string_compare, "-", &i) < 0) {
			apol_vector_destroy(&v);
			return false;
		}
		d = poldiff_terule_get_modified_default(actual);
		if (apol_vector_get_index(v, d, test_string_compare, "+", &i) < 0) {
			apol_vector_destroy(&v);
			return false;
		}
		apol_vector_destroy(&v);
	}

	const qpol_cond_t *cond;
	uint32_t which_list;
	const apol_policy_t *p;
	poldiff_terule_get_cond(diff, actual, &cond, &which_list, &p);
	if (which_list != intended->which_list) {
		return false;
	}
	if ((cond == NULL && intended->cond_expr != NULL) || (cond != NULL && intended->cond_expr == NULL)) {
		return false;
	}
	if (cond == NULL) {
		/* both actual and intended are not conditional expressions */
		return true;
	}

	char *cond_expr = apol_cond_expr_render(p, cond);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cond_expr);
	if (strcmp(cond_expr, intended->cond_expr) != 0) {
		free(cond_expr);
		return false;
	}
	free(cond_expr);
	return true;
}

poldiff_test_structs_t *poldiff_test_structs_create(const char *orig_base_path, const char *mod_base_path)
{
	poldiff_test_structs_t *t = NULL;
	apol_policy_path_t *mod_pol_path = NULL;
	apol_policy_path_t *orig_pol_path = NULL;

	orig_pol_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, orig_base_path, NULL);
	if (!orig_pol_path) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	mod_pol_path = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, mod_base_path, NULL);
	if (!mod_pol_path) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	if ((t = calloc(1, sizeof(*t))) == NULL) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	t->orig_pol = apol_policy_create_from_policy_path(orig_pol_path, 0, NULL, NULL);
	if (!t->orig_pol) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	t->mod_pol = apol_policy_create_from_policy_path(mod_pol_path, 0, NULL, NULL);
	if (!t->mod_pol) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}

	if (!(t->diff = poldiff_create(t->orig_pol, t->mod_pol, NULL, NULL))) {
		ERR(NULL, "%s", strerror(errno));
		goto err;
	}
	apol_policy_path_destroy(&orig_pol_path);
	apol_policy_path_destroy(&mod_pol_path);
	return t;
      err:
	apol_policy_path_destroy(&orig_pol_path);
	apol_policy_path_destroy(&mod_pol_path);
	poldiff_test_structs_destroy(&t);
	return NULL;
}

void poldiff_test_structs_destroy(poldiff_test_structs_t ** t)
{
	if (t != NULL) {
		if ((*t)->diff == NULL) {
			/* poldiff has not yet taken ownership of the policies */
			apol_policy_destroy(&((*t)->orig_pol));
			apol_policy_destroy(&((*t)->mod_pol));
		} else {
			/* poldiff owns the policies */
			poldiff_destroy(&((*t)->diff));
		}
		free(*t);
		*t = NULL;
	}
}

apol_vector_t *string_array_to_vector(char *arr[])
{
	apol_vector_t *v = apol_vector_create(free);
	int i;
	for (i = 0; arr[i] != NULL; ++i) {
		apol_vector_append(v, strdup(arr[i]));
	}
	return v;
}

char *vector_to_string(const apol_vector_t * v, const char *pre, const char *sep)
{
	char *item = NULL, *str = NULL, *tmp = NULL;
	size_t i = 0, str_len = 0, tmp_len = 0;
	size_t num_elements = apol_vector_get_size(v);
	for (i = 0; v && i < num_elements; i++) {
		item = apol_vector_get_element(v, i);
		if (apol_str_appendf(&tmp, &tmp_len, "%s%s", sep, item) < 0) {
			return NULL;
		}
	}
	apol_str_trim(tmp);
	if (tmp) {
		apol_str_appendf(&str, &str_len, "%s%s", pre, tmp);
	} else {
		str = strdup("");
	}
	free(tmp);
	return str;
}

apol_vector_t *shallow_copy_str_vec_and_sort(const apol_vector_t * v)
{
	apol_vector_t *copy = apol_vector_create_from_vector(v, NULL, NULL, NULL);
	apol_vector_sort(copy, apol_str_strcmp, NULL);
	return copy;
}

void run_test(component_funcs_t * component_funcs, poldiff_test_answers_t * poldiff_test_answers, test_numbers_e test_num)
{
	added_v = apol_vector_create(free);
	removed_v = apol_vector_create(free);
	modified_v = apol_vector_create(free);
	modified_name_only_v = apol_vector_create(free);
	switch (test_num) {
	case COMPONENT:
		build_component_vecs(component_funcs);
		break;
	case RULES_AVRULE:
		build_avrule_vecs();
		break;
	case RULES_TERULE:
		build_terule_vecs();
		break;
	case RULES_ROLEALLOW:
		build_roleallow_vecs();
		break;
	case RULES_ROLETRANS:
		build_roletrans_vecs();
		break;
	case MLS_CATEGORY:
		build_category_vecs();
		break;
	case MLS_LEVEL:
		build_level_vecs();
		break;
	case MLS_RANGETRANS:
		build_rangetrans_vecs();
		break;
	case MLS_USER:
		build_user_vecs();
		break;
	}
	size_t first_diff;
	apol_vector_t *intersect = NULL, *all_changes = NULL;
	if (!(all_changes = apol_vector_create(NULL))) {
		goto err;
	}
	apol_vector_cat(all_changes, added_v);
	apol_vector_cat(all_changes, removed_v);
	apol_vector_cat(all_changes, modified_name_only_v);
	if (!
	    (intersect =
	     apol_vector_create_from_intersection(all_changes, poldiff_test_answers->correct_unchanged_v, compare_str, NULL))) {
		goto err;
	}
	/* unchanged */
	CU_ASSERT_EQUAL(apol_vector_get_size(intersect), 0);
	/* added */
	apol_vector_sort(added_v, compare_str, NULL);
	apol_vector_sort(poldiff_test_answers->correct_added_v, compare_str, NULL);
	int test_result;
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(added_v, poldiff_test_answers->correct_added_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(added_v, poldiff_test_answers->correct_added_v, first_diff, "Added");
	}
	/* removed */
	apol_vector_sort(removed_v, compare_str, NULL);
	apol_vector_sort(poldiff_test_answers->correct_removed_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(removed_v, poldiff_test_answers->correct_removed_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(removed_v, poldiff_test_answers->correct_removed_v, first_diff, "Removed");
	}
	/* modified */
	apol_vector_sort(modified_v, compare_str, NULL);
	apol_vector_sort(poldiff_test_answers->correct_modified_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(modified_v, poldiff_test_answers->correct_modified_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(modified_v, poldiff_test_answers->correct_modified_v, first_diff, "Modified");
	}

	apol_vector_destroy(&intersect);
	apol_vector_destroy(&added_v);
	apol_vector_destroy(&removed_v);
	apol_vector_destroy(&modified_name_only_v);
	apol_vector_destroy(&modified_v);
	apol_vector_destroy(&all_changes);
	return;
      err:
	apol_vector_destroy(&intersect);
	apol_vector_destroy(&added_v);
	apol_vector_destroy(&removed_v);
	apol_vector_destroy(&modified_name_only_v);
	apol_vector_destroy(&modified_v);
	apol_vector_destroy(&all_changes);
	CU_FAIL_FATAL("Could not initialize vectors for test");
}

void print_test_failure(apol_vector_t * actual, apol_vector_t * expected, size_t first_diff, const char *test_name)
{
	printf("\nTEST FAILED\n");
	size_t i;
	printf("--- ACTUAL RESULT (%s) -----\n", test_name);
	for (i = first_diff; i < apol_vector_get_size(actual); ++i) {
		char *item = (char *)apol_vector_get_element(actual, i);
		printf("\t%3d. %s\n", (int)i, item);
	}
	printf("--- EXPECTED RESULT (%s) ---\n", test_name);
	for (i = first_diff; i < apol_vector_get_size(expected); ++i) {
		char *item = (char *)apol_vector_get_element(expected, i);
		printf("\t%3d. %s\n", (int)i, item);
	}
}

int compare_str(const void *s1, const void *s2, void *debug)
{
	char *str1 = strdup((char *)s1);
	char *str2 = strdup((char *)s2);
	apol_str_trim(str1);
	apol_str_trim(str2);
	int result = strcmp(str1, str2);
	free(str1);
	free(str2);
	return result;
}

poldiff_test_answers_t *init_answer_vectors(char *added_arr[], char *removed_arr[], char *unchanged_arr[], char *modified_arr[])
{
	poldiff_test_answers_t *answers = (poldiff_test_answers_t *) malloc(sizeof(poldiff_test_answers_t));
	answers->correct_added_v = string_array_to_vector(added_arr);
	answers->correct_removed_v = string_array_to_vector(removed_arr);
	answers->correct_unchanged_v = string_array_to_vector(unchanged_arr);
	answers->correct_modified_v = string_array_to_vector(modified_arr);
	return answers;
}

component_funcs_t *init_test_funcs(poldiff_get_diff_vector get_diff_vector, poldiff_get_name get_name, poldiff_get_form get_form,
				   poldiff_get_added get_added, poldiff_get_removed get_removed)
{
	component_funcs_t *funcs = (component_funcs_t *) malloc(sizeof(component_funcs_t));
	funcs->get_diff_vector = get_diff_vector;
	funcs->get_name = get_name;
	funcs->get_form = get_form;
	funcs->get_added = get_added;
	funcs->get_removed = get_removed;
	return funcs;
}

void cleanup_test(poldiff_test_answers_t * answers)
{
	if (answers != NULL) {
		apol_vector_destroy(&answers->correct_added_v);
		apol_vector_destroy(&answers->correct_unchanged_v);
		apol_vector_destroy(&answers->correct_removed_v);
		apol_vector_destroy(&answers->correct_modified_v);
		free(answers);
	}
}

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS) {
		return CU_get_error();
	}

	CU_SuiteInfo suites[] = {
		{"Components", components_test_init, components_test_cleanup, components_tests}
		,
		{"Rules", rules_test_init, rules_test_cleanup, rules_tests}
		,
		{"MLS", mls_test_init, mls_test_cleanup, mls_tests}
		,
		{"Non-MLS vs. MLS Users", nomls_test_init, nomls_test_cleanup, nomls_tests}
		,
		{"Conditionals", conditionals_init, conditionals_cleanup, conditionals_tests}
		,
		CU_SUITE_INFO_NULL
	};

	CU_register_suites(suites);
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	unsigned int num_failures = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return (int)num_failures;
}
