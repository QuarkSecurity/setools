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
	qpol_iterator_t *isids_iter;
	qpol_isid_t *isid, *dup_isid;
	char *name;
	qpol_context_t *context;

	TEST("get iterator of initial SIDs", !(qpol_policy_get_isid_iter(policy, &isids_iter)));
	while (!qpol_iterator_end(isids_iter)) {
		qpol_iterator_get_item(isids_iter, (void **)&isid);
		TEST("get name of initial SID", !(qpol_isid_get_name(policy, isid, &name)));
		TEST("get same SID from policy by name", !(qpol_policy_get_isid_by_name(policy, name, &dup_isid)));
		TEST("whether SIDs are the same", (isid == dup_isid));
		TEST("get context from SID", !(qpol_isid_get_context(policy, isid, &context)));
		qpol_iterator_next(isids_iter);
	}
	qpol_iterator_destroy(&isids_iter);
}
