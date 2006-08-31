#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>

#define QPOL_RULE_ALL 135 /* bitwise OR of all types */
#define QPOL_RULE_TYPE_ALL 112

#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle);
void call_type_set_tests(qpol_policy_t *policy, qpol_handle_t *handle, qpol_type_set_t *ts);

int main(void)
{
	qpol_policy_t *policy;
	qpol_handle_t *handle;
/*	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle); */
	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle)
{
	qpol_iterator_t *avrules, *syn_avrules, *terules, *syn_terules, *classes, *perms;
	qpol_avrule_t *avrule;
	qpol_syn_avrule_t *syn_avrule;
	qpol_terule_t *terule;
	qpol_syn_terule_t *syn_terule;
	qpol_type_set_t *source_set, *target_set;
	uint32_t is_self, is_enabled, rule_type;
	unsigned long lineno;
	qpol_cond_t *cond;
	struct qpol_type *dflt_type;

	qpol_policy_get_avrule_iter(handle, policy, QPOL_RULE_ALL, &avrules);
	while (!qpol_iterator_end(avrules)) {
		qpol_iterator_get_item(avrules, (void **)&avrule);
		TEST("get iterator of syn_avrules", !(qpol_avrule_get_syn_avrule_iter(handle, policy, avrule, &syn_avrules)));
		while (!qpol_iterator_end(syn_avrules)) {
			qpol_iterator_get_item(syn_avrules, (void **)&syn_avrule);
			TEST("get rule type", !(qpol_syn_avrule_get_rule_type(handle, policy, syn_avrule, &rule_type)));
			TEST("validity of rule type", (rule_type >=QPOL_RULE_ALLOW && rule_type <= QPOL_RULE_NEVERALLOW));
			TEST("get source type set", !(qpol_syn_avrule_get_source_type_set(handle, policy, syn_avrule, &source_set)));
			call_type_set_tests(policy, handle, source_set);
			TEST("get target type set", !(qpol_syn_avrule_get_target_type_set(handle, policy, syn_avrule, &target_set)));
			call_type_set_tests(policy, handle, target_set);
			TEST("see if self is targeted", !(qpol_syn_avrule_get_is_target_self(handle, policy, syn_avrule, &is_self)));
			TEST("get class iterator", !(qpol_syn_avrule_get_class_iter(handle, policy, syn_avrule, &classes)));
			TEST("get permissions iterator", !(qpol_syn_avrule_get_perm_iter(handle, policy, syn_avrule, &perms)));
			TEST("get line number", !(qpol_syn_avrule_get_lineno(handle, policy, syn_avrule, &lineno)));
			TEST("get conditional", !(qpol_syn_avrule_get_cond(handle, policy, syn_avrule, &cond)));
			if (cond != NULL) {
				TEST("is enabled", !(qpol_syn_avrule_get_is_enabled(handle, policy, syn_avrule, &is_enabled)));
			}

			qpol_iterator_next(syn_avrules);
		}
		qpol_iterator_destroy(&syn_avrules);

		qpol_iterator_next(avrules);
	}
	qpol_iterator_destroy(&avrules);

	qpol_policy_get_terule_iter(handle, policy, QPOL_RULE_TYPE_ALL, &terules);
	while (!qpol_iterator_end(terules)) {
		qpol_iterator_get_item(terules, (void **)&terule);
		qpol_terule_get_syn_terule_iter(handle, policy, terule, &syn_terules);
		while (!qpol_iterator_end(syn_terules)) {
			qpol_iterator_get_item(syn_terules, (void **)&syn_terule);
			TEST("get rule type", !(qpol_syn_terule_get_rule_type(handle, policy, syn_terule, &rule_type)));
			TEST("validity of rule type", (rule_type >= QPOL_RULE_TYPE_TRANS && rule_type <= QPOL_RULE_TYPE_MEMBER));
			TEST("get source type set", !(qpol_syn_terule_get_source_type_set(handle, policy, syn_terule, &source_set)));
			call_type_set_tests(policy, handle, source_set);
			TEST("get target type set", !(qpol_syn_terule_get_target_type_set(handle, policy, syn_terule, &target_set)));
			call_type_set_tests(policy, handle, target_set);
			TEST("get class iterator", !(qpol_syn_terule_get_class_iter(handle, policy, syn_terule, &classes)));
			TEST("get default type", !(qpol_syn_terule_get_default_type(handle, policy, syn_terule, &dflt_type)));
			TEST("get line number", !(qpol_syn_terule_get_lineno(handle, policy, syn_terule, &lineno)));
			TEST("get conditional", !(qpol_syn_terule_get_cond(handle, policy, syn_terule, &cond)));
			if (cond != NULL) {
				TEST("is enabled", !(qpol_syn_terule_get_is_enabled(handle, policy, syn_terule, &is_enabled)));
			}

			qpol_iterator_next(syn_terules);
		}
		qpol_iterator_destroy(&syn_terules);

		qpol_iterator_next(terules);
	}
	qpol_iterator_destroy(&terules);
}

void call_type_set_tests(qpol_policy_t *policy, qpol_handle_t *handle, qpol_type_set_t *ts)
{
	qpol_iterator_t *types, *sub_types;
	uint32_t is_star, is_comp;

	TEST("get included types", !(qpol_type_set_get_included_types_iter(handle, policy, ts, &types)));
	TEST("get subtracted types", !(qpol_type_set_get_subtracted_types_iter(handle, policy, ts, &sub_types)));
	TEST("check for \"*\"", !(qpol_type_set_get_is_star(handle, policy, ts, &is_star)));
	TEST("check for complement", !(qpol_type_set_get_is_comp(handle, policy, ts, &is_comp)));
}
