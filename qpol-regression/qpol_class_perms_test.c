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

qpol_t * quer_policy;

/* true information about mls_policy.19 policy file
   this information is used to compare against qpol's 
   returned values in this regression test in an effort
   to automate the test more */ 
/*
typedef struct common_perms
{
	char * common;
	char ** perms;
	int 	num_perms;
}common_perms_stats;

typedef struct mls_pol_19_struct{
	char *mls_pol_19_commons[] = ("socket", "ipc", "file");
	common_perms_stats perms_stats[] = ( "socket", 
}mls_pol_19_struct_stats;
*/

int main(int argc, char ** argv)
{
	char *pol_filename;
	qpol_class_t * tmp_class_datum;
	qpol_common_t * tmp_common_datum;
	qpol_iterator_t * qpol_iter, *qpol_perm_iter;
	char * class_name;
	char *common_name;
	char * perm_name;
	int n = 0;
	uint32_t val;
	if( argc < 2)
	{
		pol_filename = MLS_POL;
	}
	else
	{
		pol_filename = argv[1];
	}

	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));
	TEST("getting all object classes",! qpol_policy_get_class_iter(quer_policy->handle, quer_policy->policy, &qpol_iter));
	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**) (&tmp_class_datum)));

		TEST("get name from datum", !qpol_class_get_name(quer_policy->handle, quer_policy->policy,
					tmp_class_datum, &class_name ));

		TEST("get value of class datum", !qpol_class_get_value(quer_policy->handle, quer_policy->policy, 
					tmp_class_datum, &val));

		printf( "%d: %s\n",val, class_name);

		TEST("getting permissions iterator from class", !qpol_class_get_perm_iter(quer_policy->handle, quer_policy->policy,
					tmp_class_datum, &qpol_perm_iter));

		while( ! qpol_iterator_end(qpol_perm_iter))
		{
			TEST("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			printf("\t%s\n", perm_name);	
			qpol_iterator_next(qpol_perm_iter);
		}

		qpol_iterator_destroy(&qpol_perm_iter);

		qpol_iterator_next(qpol_iter);	
	}
	qpol_iterator_destroy(&qpol_iter);

	TEST("getting iterator over all classes with permission \"create\"", 
			!qpol_perm_get_class_iter ( quer_policy->handle, quer_policy->policy, "create", &qpol_iter )); 

	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&tmp_class_datum));

		TEST("get name from datum", !qpol_class_get_name(quer_policy->handle, quer_policy->policy,
					tmp_class_datum, &class_name ));

		TEST("get value of class datum", !qpol_class_get_value(quer_policy->handle, quer_policy->policy, 
					tmp_class_datum, &val));

		printf( "%d: %s\n",val, class_name);

		TEST("getting permissions iterator from class", !qpol_class_get_perm_iter(quer_policy->handle, quer_policy->policy,
					tmp_class_datum, &qpol_perm_iter));

		while( ! qpol_iterator_end(qpol_perm_iter))
		{
			TEST("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			printf("\t%s\n", perm_name);	
			qpol_iterator_next(qpol_perm_iter);
		}

		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);	
	} 

	qpol_iterator_destroy(&qpol_iter);

	TEST("get all commons in policy", !qpol_policy_get_common_iter(quer_policy->handle, quer_policy->policy, &qpol_iter ) );

	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&tmp_common_datum));
		TEST("get name of common", ! qpol_common_get_name(quer_policy->handle, quer_policy->policy, tmp_common_datum, &common_name));
		qpol_common_get_value( quer_policy->handle, quer_policy->policy, tmp_common_datum, &val);
		printf("Common: %s, value: %d\n", common_name, val);
		qpol_common_get_perm_iter(quer_policy->handle, quer_policy->policy,tmp_common_datum, &qpol_perm_iter);
		printf("%s's permissions\n", common_name);	
		while( ! qpol_iterator_end(qpol_perm_iter) )
		{
			n++;
			TEST("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			printf("\t%s\n", perm_name);	
			qpol_iterator_next(qpol_perm_iter);
		}
		printf("%d permissions\n\n", n);
		n = 0;
		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);


	qpol_policy_get_common_by_name(quer_policy->handle, quer_policy->policy, "socket", &tmp_common_datum);
	qpol_common_get_name(quer_policy->handle, quer_policy->policy, tmp_common_datum, &common_name);
	TEST("testing against true common name", !strcmp("socket", common_name));		



	TEST("getting all commons with permission \"create\"", !qpol_perm_get_common_iter(quer_policy->handle, quer_policy->policy,
				"create", &qpol_iter));

		
	while( ! qpol_iterator_end(qpol_iter))
	{
		qpol_iterator_get_item( qpol_iter, (void**)&tmp_common_datum);
		qpol_common_get_name(quer_policy->handle, quer_policy->policy, tmp_common_datum, &common_name);
		qpol_common_get_value( quer_policy->handle, quer_policy->policy, tmp_common_datum, &val);
		printf("Common: %s, value: %d\n", common_name, val);
		qpol_common_get_perm_iter(quer_policy->handle, quer_policy->policy,tmp_common_datum, &qpol_perm_iter);
		printf("%s's permissions\n", common_name);	
		while( ! qpol_iterator_end(qpol_perm_iter) )
		{
			n++;
			TEST("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			if( !strcmp(perm_name, "create") )
				printf("*******");
			printf("\t%s", perm_name);
			 if( strcmp(perm_name, "create") )
				printf("\n");
			if( !strcmp(perm_name, "create") )
				printf("\t*******  \n");
			qpol_iterator_next(qpol_perm_iter);
		}
		printf("%d permissions\n\n", n);
		n = 0;
		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);
	}
	
	qpol_iterator_destroy(&qpol_iter); 


	TEST("getting a datum for the \"class blk_file\"", !qpol_policy_get_class_by_name(quer_policy->handle, quer_policy->policy,
			"blk_file", &tmp_class_datum ));
	TEST("getting name of class datum retrieved", !qpol_class_get_name(quer_policy->handle,
				quer_policy->policy, tmp_class_datum, &class_name));
	printf("name of class is: %s\n", class_name);
	TEST("getting the common used by the class \"blk_file\"", !qpol_class_get_common(quer_policy->handle, quer_policy->policy,
				tmp_class_datum, &tmp_common_datum ));
	TEST("", !qpol_common_get_name( quer_policy->handle, quer_policy->policy, tmp_common_datum, &common_name));
	printf("the common name is: %s\n", common_name);
		
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);

	return 0;
}
