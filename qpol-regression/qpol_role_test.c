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
	qpol_iterator_t *role_iter, *dominate_iter, *type_iter;
	qpol_role_t *role, *dup_role;
	char *name;
	uint32_t value;

	TEST("get role iterator", !(qpol_policy_get_role_iter(handle, policy, &role_iter)));
	while (!qpol_iterator_end(role_iter)) {
		qpol_iterator_get_item(role_iter, (void **) &role);
		TEST("get value of role", !(qpol_role_get_value(handle, policy, role, &value)));
		TEST("get iterator of dominated roles", !(qpol_role_get_dominate_iter(handle, policy, role, &dominate_iter)));
		TEST("get iterator of types", !(qpol_role_get_type_iter(handle, policy, role, &type_iter)));
		TEST("get name of role", !(qpol_role_get_name(handle, policy, role, &name)));
		TEST("get same role by name", !(qpol_policy_get_role_by_name(handle, policy, name, &dup_role)));
		TEST("whether both roles are the same", (role == dup_role));
		
		qpol_iterator_destroy(&dominate_iter);
		qpol_iterator_destroy(&type_iter);
		qpol_iterator_next(role_iter);
	}
	qpol_iterator_destroy(&role_iter);
}
