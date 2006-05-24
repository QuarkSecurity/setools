#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"

/* qpol */
#include <qpol/policy_query.h>

#define MLS_POL "../regression/policy/mls_policy.19"
#define EXECMEM_BOOL "allow_execmem"
#define NUM_BOOL_ITEMS 18
qpol_t * quer_policy;

int main(int argc, char **argv)
{
	qpol_bool_t * search_bool_datum, *tmp_bool_datum;
	char * bool_name;
	size_t num_items;
	uint32_t tmp_bool_val;
	int state;
	char *pol_filename;
	qpol_iterator_t * qpol_iter;
	if( argc < 2)
	{
		pol_filename = MLS_POL;
	}
	else
	{
		pol_filename = argv[1];
	}
	/* open the binary policy */	
	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));

	TEST("extracting boolean \"allow_exec_mem\"",
			!qpol_policy_get_bool_by_name( quer_policy->handle, 
				quer_policy->policy, 
				"allow_execmem",
				&search_bool_datum	
				));
	qpol_bool_get_name(quer_policy->handle,
			quer_policy->policy,
			search_bool_datum,
			&bool_name);

	TEST("comparing returned name with correct name",
			!strcmp(bool_name, EXECMEM_BOOL));	

	TEST("get iterator for booleans in policy",
			!qpol_policy_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter)
	    );
	qpol_iterator_get_size(qpol_iter, &num_items);

	TEST("comparing num of bools returned", num_items == NUM_BOOL_ITEMS);

	while(! qpol_iterator_end(qpol_iter))
	{

		qpol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));

		qpol_bool_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		qpol_bool_get_value(quer_policy->handle, quer_policy->policy, 
				tmp_bool_datum, &tmp_bool_val);

		qpol_bool_get_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &state);

		printf( "%d: %s - %d\n", tmp_bool_val, bool_name, state); 

		qpol_iterator_next(qpol_iter);
	}
	qpol_policy_get_bool_by_name( quer_policy->handle, quer_policy->policy,
			"read_default_t", &tmp_bool_datum);

	qpol_bool_set_state( quer_policy->handle, quer_policy->policy, tmp_bool_datum, 1);

	qpol_iterator_destroy(&qpol_iter);

	printf("\n\n");

	TEST("get iterator for booleans in policy",
			!qpol_policy_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter) );
	printf("\n\n");

	while(! qpol_iterator_end(qpol_iter))
	{

		qpol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));

		qpol_bool_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		qpol_bool_set_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, 1);

		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);
	TEST("get iterator for booleans in policy",
			!qpol_policy_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter) );

	while(! qpol_iterator_end(qpol_iter))
	{

		qpol_iterator_get_item( qpol_iter, (void**)&tmp_bool_datum);

		qpol_bool_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		qpol_bool_get_value(quer_policy->handle, quer_policy->policy, 
				tmp_bool_datum, &tmp_bool_val);

		qpol_bool_get_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &state);

		printf( "%d: %s - %d\n", tmp_bool_val, bool_name, state); 

		qpol_iterator_next(qpol_iter);
	}

	/* free memory allocated */	
	qpol_iterator_destroy(&qpol_iter);
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);
	return 0;
}
