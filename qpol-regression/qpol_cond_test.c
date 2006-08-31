#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

#define QPOL_ALL_AVRULE_TYPES 135 /* Bitwise OR of all types */
#define QPOL_ALL_TERULE_TYPES 112
#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle);

int main(void)
{
	qpol_policy_t *policy;
	qpol_handle_t *handle;
	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle)
{
	qpol_iterator_t *conds, *nodes, *av_true, *av_false, *te_true, *te_false;
	qpol_bool_t *node_bool;
	qpol_cond_t *tmp_cond;
	qpol_cond_expr_node_t *tmp_node;
	uint32_t rule_mask, is_true, expr_type;

	TEST("get conditional iterator", !(qpol_policy_get_cond_iter(handle, policy, &conds)));
	while (!qpol_iterator_end(conds))
	{
		TEST("get conditional", !(qpol_iterator_get_item(conds, (void**)&tmp_cond)));

		rule_mask = QPOL_ALL_AVRULE_TYPES;
		TEST("get node iterator", !(qpol_cond_get_expr_node_iter(handle, policy, tmp_cond, &nodes)));
		TEST("get avrule true iterator", !(qpol_cond_get_av_true_iter(handle, policy, tmp_cond, rule_mask, &av_true)));
		TEST("get avrule false iterator", !(qpol_cond_get_av_false_iter(handle, policy, tmp_cond, rule_mask, &av_false)));

		rule_mask = QPOL_ALL_TERULE_TYPES;
		TEST("get terule true iterator", !(qpol_cond_get_te_true_iter(handle, policy, tmp_cond, rule_mask, &te_true)));
		TEST("get terule false iterator", !(qpol_cond_get_te_false_iter(handle, policy, tmp_cond, rule_mask, &te_false)));

		TEST("evaulate conditional", !(qpol_cond_eval(handle, policy, tmp_cond, &is_true)));
		
		while (!qpol_iterator_end(nodes))
		{
			TEST("get expression node", !(qpol_iterator_get_item(nodes, (void**)&tmp_node)));
			TEST("get node expression type", !(qpol_cond_expr_node_get_expr_type(handle, policy, tmp_node, &expr_type)));
			if (expr_type == QPOL_COND_EXPR_BOOL) {
				TEST("get node boolean", !(qpol_cond_expr_node_get_bool(handle, policy, tmp_node, &node_bool)));
			}
			qpol_iterator_next(nodes);
		}
		qpol_iterator_destroy(&nodes);
		qpol_iterator_next(conds);
	}
	qpol_iterator_destroy(&conds);
}
