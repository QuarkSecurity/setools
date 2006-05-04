#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <sepol/bool_query.h>

#define MLS_POL "../regression/policy/mls_policy.19"
#define EXECMEM_BOOL "allow_execmem"
#define NUM_BOOL_ITEMS 18
qpol_t * quer_policy;

int main(int argc, char **argv)
{
	sepol_bool_datum_t * search_bool_datum, *tmp_bool_datum;
	char * bool_name;
	size_t num_items;
	uint32_t tmp_bool_val;
	int state;
	char *pol_filename;
	sepol_iterator_t * qpol_iter;
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
			!sepol_policydb_get_bool_by_name( quer_policy->handle, 
				quer_policy->policy, 
				"allow_execmem",
				&search_bool_datum	
				));
	sepol_bool_datum_get_name(quer_policy->handle,
			quer_policy->policy,
			search_bool_datum,
			&bool_name);

	TEST("comparing returned name with correct name",
			!strcmp(bool_name, EXECMEM_BOOL));	

	TEST("get iterator for booleans in policy",
			!sepol_policydb_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter)
	    );
	sepol_iterator_get_size(qpol_iter, &num_items);

	TEST("comparing num of bools returned", num_items == NUM_BOOL_ITEMS);

	while(! sepol_iterator_end(qpol_iter))
	{

		sepol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));

		sepol_bool_datum_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		sepol_bool_datum_get_value(quer_policy->handle, quer_policy->policy, 
				tmp_bool_datum, &tmp_bool_val);

		sepol_bool_datum_get_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &state);

		printf( "%d: %s - %d\n", tmp_bool_val, bool_name, state); 

		sepol_iterator_next(qpol_iter);
	}
	sepol_policydb_get_bool_by_name( quer_policy->handle, quer_policy->policy,
			"read_default_t", &tmp_bool_datum);

	sepol_bool_datum_set_state( quer_policy->handle, quer_policy->policy, tmp_bool_datum, 1);

	sepol_iterator_destroy(&qpol_iter);

	printf("\n\n");

	TEST("get iterator for booleans in policy",
			!sepol_policydb_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter) );
	printf("\n\n");

	while(! sepol_iterator_end(qpol_iter))
	{

		sepol_iterator_get_item( qpol_iter, (void**) (&tmp_bool_datum));

		sepol_bool_datum_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		sepol_bool_datum_set_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, 1);

		sepol_iterator_next(qpol_iter);
	}
	sepol_iterator_destroy(&qpol_iter);
	TEST("get iterator for booleans in policy",
			!sepol_policydb_get_bool_iter(quer_policy->handle, 
				quer_policy->policy,
				&qpol_iter) );

	while(! sepol_iterator_end(qpol_iter))
	{

		sepol_iterator_get_item( qpol_iter, (void**)&tmp_bool_datum);

		sepol_bool_datum_get_name(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &bool_name );

		sepol_bool_datum_get_value(quer_policy->handle, quer_policy->policy, 
				tmp_bool_datum, &tmp_bool_val);

		sepol_bool_datum_get_state(quer_policy->handle, quer_policy->policy,
				tmp_bool_datum, &state);

		printf( "%d: %s - %d\n", tmp_bool_val, bool_name, state); 

		sepol_iterator_next(qpol_iter);
	}

	/* free memory allocated */	
	sepol_iterator_destroy(&qpol_iter);
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);
	return 0;
}
