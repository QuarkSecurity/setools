#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>
#include "test_bools.h"

void call_test_funcs(qpol_policy_t *policy);

int main(int argc, char* argv[])
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
	qpol_bool_t * search_bool_datum, *tmp_bool_datum;
	char * bool_name;
	size_t num_items;
	uint32_t tmp_bool_val;
	int state;
	int n = 0;
	int found;
	qpol_iterator_t * qpol_iter;

	TEST("extracting boolean \"allow_execmem\"",
			!qpol_policy_get_bool_by_name(policy, "allow_execmem",
				&search_bool_datum));
	qpol_bool_get_name(policy,	search_bool_datum, &bool_name);

	TEST("comparing returned name with correct name",
			!strcmp(bool_name, EXECMEM_BOOL));

	TEST("get state of the bool", !qpol_bool_get_state( policy, search_bool_datum, &state));
	TEST("check state", 1 == state);

	TEST("get iterator for booleans in policy",
			!qpol_policy_get_bool_iter(policy, &qpol_iter));
	qpol_iterator_get_size(qpol_iter, &num_items);
	TEST("comparing num of bools returned", num_items == NUM_BOOL_ITEMS);
	while (!qpol_iterator_end(qpol_iter))
	{
		qpol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));
		qpol_bool_get_name( policy, tmp_bool_datum, &bool_name );
		qpol_bool_get_value( policy, tmp_bool_datum, &tmp_bool_val);
		qpol_bool_get_state( policy, tmp_bool_datum, &state);
		found = 0;
		for(n=0 ; n < NUM_BOOL_ITEMS; n++)
		{
			if(!strcmp(bool_name, all_bools_names_states[n].name) && 
					state == all_bools_names_states[n].state ){
				found = 1;
				break;
			}
		}
		TEST("if found", found);
		qpol_iterator_next(qpol_iter);
	}

	TEST("extracting boolean \"allow_execmem\"",
			!qpol_policy_get_bool_by_name(policy, "allow_execmem",
				&search_bool_datum));
	TEST("setting the state to False", !qpol_bool_set_state( policy, search_bool_datum, 0));
	TEST("get state of the bool", !qpol_bool_get_state( policy, search_bool_datum, &state));
	TEST("check state", 0 == state);

	/* free memory allocated */	
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy( &policy );
}
