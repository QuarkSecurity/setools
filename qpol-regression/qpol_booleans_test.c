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

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle);

int main()
{
	qpol_policy_t *policy;
	qpol_handle_t *handle;
	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC , &policy, &handle, NULL, NULL) < 0));
	call_test_funcs(policy, handle);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy, qpol_handle_t *handle)
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
			!qpol_policy_get_bool_by_name( handle, 
				policy, 
				"allow_execmem",
				&search_bool_datum
				));
	qpol_bool_get_name(handle,
			policy,
			search_bool_datum,
			&bool_name);

	TEST("comparing returned name with correct name",
			!strcmp(bool_name, EXECMEM_BOOL));

	TEST("get state of the bool", !qpol_bool_get_state(handle, policy, search_bool_datum, &state));
	TEST("check state", 1 == state);

	TEST("get iterator for booleans in policy",
			!qpol_policy_get_bool_iter(handle, 
				policy,
				&qpol_iter)
	    );
	qpol_iterator_get_size(qpol_iter, &num_items);
	TEST("comparing num of bools returned", num_items == NUM_BOOL_ITEMS);
	while (!qpol_iterator_end(qpol_iter))
	{
		qpol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));
		qpol_bool_get_name(handle, policy,
				tmp_bool_datum, &bool_name );
		qpol_bool_get_value(handle, policy, 
				tmp_bool_datum, &tmp_bool_val);
		qpol_bool_get_state(handle, policy,
				tmp_bool_datum, &state);
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
			!qpol_policy_get_bool_by_name( handle, 
				policy, 
				"allow_execmem",
				&search_bool_datum
				));
	TEST("setting the state to False", !qpol_bool_set_state(handle, policy, search_bool_datum, 0));
	TEST("get state of the bool", !qpol_bool_get_state(handle, policy, search_bool_datum, &state));
	TEST("check state", 0 == state);

	/* free memory allocated */	
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy( &policy );
	qpol_handle_destroy( &handle );
}
