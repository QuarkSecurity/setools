#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>

#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"

void call_test_funcs(qpol_policy_t *policy);
void call_type_set_tests(qpol_policy_t *policy, qpol_type_set_t *ts);

int main(void)
{
	qpol_policy_t *policy;
	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
/*	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC, &policy, NULL, NULL) < 0));
	call_test_funcs(policy); */
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *fs_use_iter;
	char *name;
	qpol_fs_use_t *data, *dup;
	uint32_t behavior;
	qpol_context_t *context;

	TEST("get fs_use iterator", !(qpol_policy_get_fs_use_iter(policy, &fs_use_iter)));
	while (!qpol_iterator_end(fs_use_iter)) {
		qpol_iterator_get_item(fs_use_iter, (void **)&data);
		TEST("get fs_use name", !(qpol_fs_use_get_name(policy, data, &name)));
		TEST("get same item by name", !(qpol_policy_get_fs_use_by_name(policy, name, &dup)));
		TEST("whether items are the same", (dup == data));
		TEST("get behavior", !(qpol_fs_use_get_behavior(policy, data, &behavior)));
		TEST("validity of behavior", (behavior >= QPOL_FS_USE_XATTR && behavior <= QPOL_FS_USE_PSID));
		if (behavior != QPOL_FS_USE_PSID) {
			TEST("get context", !(qpol_fs_use_get_context(policy, data, &context)));
		}
		qpol_iterator_next(fs_use_iter);
	}
	qpol_iterator_destroy(&fs_use_iter);
}
