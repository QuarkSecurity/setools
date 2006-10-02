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
	qpol_iterator_t *portcons = 0;
	qpol_portcon_t *tmp_portcon = 0;
	qpol_context_t *context = 0;
	qpol_user_t *user = 0;
	qpol_role_t *role = 0;
	qpol_type_t *type = 0;
	qpol_mls_range_t *mls_range = 0;
	
	/* set up a context to test */
	qpol_policy_get_portcon_iter(policy, &portcons);
	while (!qpol_iterator_end(portcons)) {
		qpol_iterator_get_item(portcons, (void **)&tmp_portcon);
		qpol_portcon_get_context(policy, tmp_portcon, &context);

		TEST("get user from context", !(qpol_context_get_user(policy, context, &user)));
		TEST("get role from context", !(qpol_context_get_role(policy, context, &role)));
		TEST("get type from context", !(qpol_context_get_type(policy, context, &type)));
		TEST("get range from context", !(qpol_context_get_range(policy, context, &mls_range)));
		qpol_iterator_next(portcons);
	}
	qpol_iterator_destroy(&portcons);
}
