#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

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
	qpol_iterator_t *rule_iter;
	qpol_range_trans_t *rule;
	qpol_type_t *source, *target;
	qpol_mls_range_t *range;

	TEST("get iterator of range transition rules", !(qpol_policy_get_range_trans_iter(policy, &rule_iter)));
	while (!qpol_iterator_end(rule_iter)) {
		qpol_iterator_get_item(rule_iter, (void **)&rule);
		TEST("get source type from rule", !(qpol_range_trans_get_source_type(policy, rule, &source)));
		TEST("get target type from rule", !(qpol_range_trans_get_target_type(policy, rule, &target)));
		TEST("get range from rule", !(qpol_range_trans_get_range(policy, rule, &range)));

		qpol_iterator_next(rule_iter);
	}
	qpol_iterator_destroy(&rule_iter);
}
