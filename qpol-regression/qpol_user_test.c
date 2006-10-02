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
	TEST("number of arguments", (argc == 3));
	TEST("open binary policy", ! (qpol_open_policy_from_file(argv[1], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	TEST("open source policy", ! (qpol_open_policy_from_file(argv[2], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *user_iter, *role_iter;
	qpol_user_t *user, *dup_user;
	char *name;
	uint32_t value;
	qpol_mls_range_t *range;
	qpol_mls_level_t *level;

	TEST("get user iterator", !(qpol_policy_get_user_iter(policy, &user_iter)));
	while (!qpol_iterator_end(user_iter)) {
		qpol_iterator_get_item(user_iter, (void **) &user);
		TEST("get value of user", !(qpol_user_get_value(policy, user, &value)));
		TEST("get role iterator", !(qpol_user_get_role_iter(policy, user, &role_iter)));
		TEST("get range of user", !(qpol_user_get_range(policy, user, &range)));
		TEST("get default level", !(qpol_user_get_dfltlevel(policy, user, &level)));
		TEST("get name of user", !(qpol_user_get_name(policy, user, &name)));
		TEST("get same user by name", !(qpol_policy_get_user_by_name(policy, name, &dup_user)));
		TEST("whether users are the same", (user == dup_user));

		qpol_iterator_destroy(&role_iter);
		qpol_iterator_next(user_iter);
	}
	qpol_iterator_destroy(&user_iter);
}
