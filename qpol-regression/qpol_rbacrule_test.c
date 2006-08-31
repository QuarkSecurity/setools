#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

#define RBAC_TEST_POLICY "../regression/policy/rbac1.conf"

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle);

int main(void)
{
	qpol_policy_t *policy;
	qpol_handle_t *handle;
	TEST("open source policy", ! (qpol_open_policy_from_file(RBAC_TEST_POLICY, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle)
{
	qpol_iterator_t *allow_iter, *trans_iter;
	qpol_role_t *source, *target, *dflt;
	qpol_type_t *tgt_type;
	qpol_role_allow_t *allow_rule;
	qpol_role_trans_t *trans_rule;

	TEST("get role allow iterator", !(qpol_policy_get_role_allow_iter(handle, policy, &allow_iter)));
	while (!qpol_iterator_end(allow_iter)) {
		qpol_iterator_get_item(allow_iter, (void **)&allow_rule);
		TEST("get source role", !(qpol_role_allow_get_source_role(handle, policy, allow_rule, &source)));
		TEST("get target role", !(qpol_role_allow_get_target_role(handle, policy, allow_rule, &target)));
		
		qpol_iterator_next(allow_iter);
	}
	qpol_iterator_destroy(&allow_iter);

	TEST("get role transition iterator", !(qpol_policy_get_role_trans_iter(handle, policy, &trans_iter)));
	while (!qpol_iterator_end(trans_iter)) {
		qpol_iterator_get_item(trans_iter, (void **)&trans_rule);
		TEST("get source role", !(qpol_role_trans_get_source_role(handle, policy, trans_rule, &source)));
		TEST("get target type", !(qpol_role_trans_get_target_type(handle, policy, trans_rule, &tgt_type)));
		TEST("get default role", !(qpol_role_trans_get_default_role(handle, policy, trans_rule, &dflt)));

		qpol_iterator_next(trans_iter);
	}
	qpol_iterator_destroy(&trans_iter);
}
