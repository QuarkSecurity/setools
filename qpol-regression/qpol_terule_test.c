#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

#define QPOL_RULE_TYPE_ALL 112 /* bitwise OR of all rule types */
#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"

void call_test_funcs(qpol_policy_t *policy);

int main(void)
{
	qpol_policy_t *policy;
	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC, &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *terule_iter;
	qpol_terule_t *rule;
	qpol_type_t *source, *target, *dflt;
	qpol_class_t *object;
	uint32_t rule_type, is_enabled, which_list;
	qpol_cond_t *cond;

	TEST("get iterator of type_trans rules", !(qpol_policy_get_terule_iter(policy, QPOL_RULE_TYPE_TRANS, &terule_iter)));
	if (!qpol_iterator_end(terule_iter)) {
		qpol_iterator_get_item(terule_iter, (void **) &rule);
		qpol_terule_get_rule_type(policy, rule, &rule_type);
		TEST("whether iterator is of correct type", (rule_type == QPOL_RULE_TYPE_TRANS));
	}
	qpol_iterator_destroy(&terule_iter);

	TEST("get iterator of type_change rules", !(qpol_policy_get_terule_iter(policy, QPOL_RULE_TYPE_CHANGE, &terule_iter)));
	if (!qpol_iterator_end(terule_iter)) {
		qpol_iterator_get_item(terule_iter, (void **) &rule);
		qpol_terule_get_rule_type(policy, rule, &rule_type);
		TEST("whether iterator is of correct type", (rule_type == QPOL_RULE_TYPE_CHANGE));
	}
	qpol_iterator_destroy(&terule_iter);

	TEST("get iterator of type_member rules", !(qpol_policy_get_terule_iter(policy, QPOL_RULE_TYPE_MEMBER, &terule_iter)));
	if (!qpol_iterator_end(terule_iter)) {
		qpol_iterator_get_item(terule_iter, (void **) &rule);
		qpol_terule_get_rule_type(policy, rule, &rule_type);
		TEST("whether iterator is of correct type", (rule_type == QPOL_RULE_TYPE_MEMBER));
	}
	qpol_iterator_destroy(&terule_iter);

	TEST("get iterator of all type rules", !(qpol_policy_get_terule_iter(policy, QPOL_RULE_TYPE_ALL, &terule_iter)));
	while (!qpol_iterator_end(terule_iter)) {
		qpol_iterator_get_item(terule_iter, (void **) &rule);
		TEST("get source type", !(qpol_terule_get_source_type(policy, rule, &source)));
		TEST("get target type", !(qpol_terule_get_target_type(policy, rule, &target)));
		TEST("get object class", !(qpol_terule_get_object_class(policy, rule, &object)));
		TEST("get default type", !(qpol_terule_get_default_type(policy, rule, &dflt)));
		TEST("get conditional", !(qpol_terule_get_cond(policy, rule, &cond)));
		if (cond != NULL) {
			TEST("whether rule is enabled", !(qpol_terule_get_is_enabled(policy, rule, &is_enabled)));
			TEST("get which list", !(qpol_terule_get_which_list(policy, rule, &which_list)));
		}

		qpol_iterator_next(terule_iter);
	}
	qpol_iterator_destroy(&terule_iter);
}
