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
/*	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC, &policy, NULL, NULL) < 0));
	call_test_funcs(policy); */
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *portcon_iter;
	qpol_portcon_t *portcon, *dup_portcon;
	uint16_t low, high;
	uint8_t protocol;
	qpol_context_t *context;

	TEST("get portcon iterator", !(qpol_policy_get_portcon_iter(policy, &portcon_iter)));
	while (!qpol_iterator_end(portcon_iter)) {
		qpol_iterator_get_item(portcon_iter, &portcon);
		TEST("get protocol", !(qpol_portcon_get_protocol(policy, portcon, &protocol)));
		TEST("get low port", !(qpol_portcon_get_low_port(policy, portcon, &low)));
		TEST("get high port", !(qpol_portcon_get_high_port(policy, portcon, &high)));
		TEST("get same portcon by port", !(qpol_policy_get_portcon_by_port(policy, low, high, protocol, &dup_portcon)));
		TEST("whether the results are the same", (portcon == dup_portcon));
		TEST("get context of portcon", !(qpol_portcon_get_context(policy, portcon, &context)));

		qpol_iterator_next(portcon_iter);
	}
	qpol_iterator_destroy(&portcon_iter);
}
