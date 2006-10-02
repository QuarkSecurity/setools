#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

void call_test_funcs(qpol_policy_t *policy);

int main(int argc, char *argv[])
{
	qpol_policy_t *policy;
	TEST("number of arguments", (argc == 2 || argc == 3));
	if (argc == 2)
	{
		/* can be run alone with one argument */
		TEST("open source policy", ! (qpol_open_policy_from_file(argv[1], &policy, NULL, NULL) < 0));
	}
	else if (argc == 3)
	{
		/* Makefile passes two arguments, use only the second */
		TEST("open source policy", !(qpol_open_policy_from_file(argv[2], &policy, NULL, NULL) < 0));
	}
	call_test_funcs(policy);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *allow_iter, *trans_iter;
	qpol_role_t *source, *target, *dflt;
	qpol_type_t *tgt_type;
	qpol_role_allow_t *allow_rule;
	qpol_role_trans_t *trans_rule;

	TEST("get role allow iterator", !(qpol_policy_get_role_allow_iter(policy, &allow_iter)));
	while (!qpol_iterator_end(allow_iter)) {
		qpol_iterator_get_item(allow_iter, (void **)&allow_rule);
		TEST("get source role", !(qpol_role_allow_get_source_role(policy, allow_rule, &source)));
		TEST("get target role", !(qpol_role_allow_get_target_role(policy, allow_rule, &target)));
		
		qpol_iterator_next(allow_iter);
	}
	qpol_iterator_destroy(&allow_iter);

	TEST("get role transition iterator", !(qpol_policy_get_role_trans_iter(policy, &trans_iter)));
	while (!qpol_iterator_end(trans_iter)) {
		qpol_iterator_get_item(trans_iter, (void **)&trans_rule);
		TEST("get source role", !(qpol_role_trans_get_source_role(policy, trans_rule, &source)));
		TEST("get target type", !(qpol_role_trans_get_target_type(policy, trans_rule, &tgt_type)));
		TEST("get default role", !(qpol_role_trans_get_default_role(policy, trans_rule, &dflt)));

		qpol_iterator_next(trans_iter);
	}
	qpol_iterator_destroy(&trans_iter);
}
