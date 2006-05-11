#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <sepol/type_query.h>
#define BINARY_SMALL_17 "../regression/policy/binary_small.17"
#define MLS_POL_19 "../regression/policy/mls_policy.19"
#define MLS_POL_19_NUM_TYPES 334
#define BINARY_SMALL_17_NUM_TYPES 14
#define BINARY_SMALL_SEARCH_STRING "one_t"
#define MLS_POL_19_SEARCH_STRING "nfsd_fs_t"
#define STAFF_T_NUM_ALIASES 4
char *binary_small_17_types_list[BINARY_SMALL_17_NUM_TYPES] = {
	"self",
	"one_exec_t",
	"file_exec_t",
	"sysadm_t",
	"system_t",
	"file_t",
	"fs_t",
	"one_t",
	"two_t",
	"net_foo_t",
	"sys_foo_t",
	"dir_t",
	"user_t",
	"two_exec_t"
};
char * mls_staff_t_aliases[STAFF_T_NUM_ALIASES] = {
	"staff_screensaver_t",
	"staff_screensaver_tmpfs_t",
	"staff_screensaver_ro_t",
	"staff_screensaver_rw_t"	
};
qpol_t * quer_policy;

int main(int argc, char** argv)
{
	sepol_iterator_t * qpol_iter;
	char *pol_filename, *type_name;
	size_t num_items= 0;
	uint32_t tmp_type_val;
	unsigned char isalias;
	unsigned char isattr;
	sepol_type_datum_t * qpol_type_obj;
	int r = 0 ;
	uint32_t value;
	int found= 0;
	int num_types;
	char * alias_name;
	if( argc < 2)
	{
		/*	pol_filename = BINARY_SMALL_17; */
		pol_filename = MLS_POL_19;  /* uncomment this line and comment out the one before 
					       to switch policies tested against */
	}
	else
	{
		pol_filename = argv[1];
	}
	if(!strcmp( pol_filename, BINARY_SMALL_17))
	{
		num_types = BINARY_SMALL_17_NUM_TYPES;
	}
	else if( !strcmp( pol_filename, MLS_POL_19))
	{
		num_types = MLS_POL_19_NUM_TYPES;
	}

	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));
	TEST("get all types", !sepol_policydb_get_type_iter(quer_policy->handle, quer_policy->policy, &qpol_iter) );

	if (!strcmp(pol_filename, BINARY_SMALL_17) ) {
		while( ! sepol_iterator_end(qpol_iter) ) {
			sepol_iterator_get_item( qpol_iter, (void**)&qpol_type_obj);
			sepol_type_datum_get_isalias(quer_policy->handle, quer_policy->policy, qpol_type_obj, &isalias);
			sepol_type_datum_get_isattr(quer_policy->handle, quer_policy->policy, qpol_type_obj, &isattr);

			if(! isalias && ! isattr ) {
				sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy,
						qpol_type_obj, &type_name );

				sepol_type_datum_get_value(quer_policy->handle, quer_policy->policy, 
						qpol_type_obj, &tmp_type_val);

				printf( "%d: %s\n", tmp_type_val, type_name);
				for( r = 0; r <BINARY_SMALL_17_NUM_TYPES ; r++) {

					if( ! strcmp(type_name, binary_small_17_types_list[r])) {
						found = 1;
					}

				} 
				if( !found ) {
					printf("Did not find type %s value: %d, aborting\n", type_name, tmp_type_val);
					return -1;
				}
				found = 0;
				num_items++;
			}
			sepol_iterator_next(qpol_iter);
		}
		sepol_iterator_destroy(&qpol_iter);
		printf("number of items is: %d\n", num_items);
		TEST ("compare returned num types with real num types", num_items == MLS_POL_19_NUM_TYPES);

	} else if (!strcmp(pol_filename,MLS_POL_19 ) ) { 
		while( ! sepol_iterator_end(qpol_iter) ) {
			sepol_iterator_get_item( qpol_iter, (void**)&qpol_type_obj);
			sepol_type_datum_get_isalias(quer_policy->handle, quer_policy->policy, qpol_type_obj, &isalias);
			sepol_type_datum_get_isattr(quer_policy->handle, quer_policy->policy, qpol_type_obj, &isattr);

			if(! isalias && ! isattr ) {
				sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy,
						qpol_type_obj, &type_name );

				sepol_type_datum_get_value(quer_policy->handle, quer_policy->policy, 
						qpol_type_obj, &tmp_type_val);

				printf( "%d: %s\n", tmp_type_val, type_name);
				num_items++;
			}
			sepol_iterator_next(qpol_iter);
		}
		sepol_iterator_destroy(&qpol_iter);
		printf("number of items is: %d\n", num_items);
	}

	if( !strcmp(pol_filename, MLS_POL_19 ) )
	{
		sepol_policydb_get_type_by_name(quer_policy->handle, quer_policy->policy,MLS_POL_19_SEARCH_STRING, &qpol_type_obj);
	}
	else if( !strcmp(pol_filename, BINARY_SMALL_17 ) )
	{
		sepol_policydb_get_type_by_name (quer_policy->handle, quer_policy->policy,BINARY_SMALL_SEARCH_STRING, &qpol_type_obj);
	}

	sepol_type_datum_get_name(quer_policy->handle,
			quer_policy->policy,
			qpol_type_obj,
			&type_name);
	sepol_type_datum_get_value(quer_policy->handle,
			quer_policy->policy,
			qpol_type_obj,
			&value);

	if( !strcmp(pol_filename, BINARY_SMALL_17 ))
	{
		TEST("compare returned name with true name", !strcmp(type_name, BINARY_SMALL_SEARCH_STRING));
	}
	else if (!strcmp(pol_filename, MLS_POL_19))
	{
		TEST("compare returned name with true name", !strcmp(type_name, MLS_POL_19_SEARCH_STRING ));
	}

	if (!strcmp (pol_filename, MLS_POL_19) ) {

		TEST("get datum to test alias iter",! sepol_policydb_get_type_by_name(quer_policy->handle, quer_policy->policy,
					"user_home_t", &qpol_type_obj));

		sepol_type_datum_get_name( quer_policy->handle, quer_policy->policy, qpol_type_obj, &type_name);
		sepol_type_datum_get_value(quer_policy->handle, quer_policy->policy, qpol_type_obj, &value );

		printf("value is: %d THE NAME IS: %s\n",value, type_name);

		TEST("get alias iter",!sepol_type_datum_get_alias_iter(
					quer_policy->handle, 
					quer_policy->policy,
					qpol_type_obj, &qpol_iter)); 
		sepol_iterator_get_size( qpol_iter, &num_items); 
		printf("there are %d aliases\n", num_items);
		while( ! sepol_iterator_end(qpol_iter) )
		{
			sepol_iterator_get_item( qpol_iter, (void**)&alias_name);
			sepol_policydb_get_type_by_name( quer_policy->handle, quer_policy->policy, alias_name, &qpol_type_obj);
			sepol_type_datum_get_value(quer_policy->handle, quer_policy->policy, qpol_type_obj, &value);
			sepol_type_datum_get_isalias( quer_policy->handle, quer_policy->policy, qpol_type_obj, &isalias);
			printf("value: %d alias name: %s, isalias: %d\n",value, alias_name, isalias);
			sepol_iterator_next(qpol_iter);
		}
	}
	sepol_iterator_destroy(&qpol_iter);
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);

	return 0;
}
