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

int main(int argc, char ** argv)
{
	char *pol_filename, *genfscon_name, *qpol_path_string;
	qpol_genfscon_t * qpol_genfscon_obj, *qpol_tmp_path;
	qpol_iterator_t *qpol_iter;
	qpol_context_t * qpol_context_struct;
	qpol_user_t * user;
	qpol_role_t * role;
	qpol_type_t *  type;
	char *user_str, *role_str, *type_str;

	if( argc < 2)
	{
		pol_filename = MLS_POL;
	}
	else
	{
		pol_filename = argv[1];
	}

	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));

	TEST("getting iterator for all genfscons", !qpol_policy_get_genfscon_iter( quer_policy->handle, quer_policy->policy,
				&qpol_iter));
	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&qpol_genfscon_obj));
		TEST("get name of genfscon", !qpol_genfscon_get_name( quer_policy->handle, quer_policy->policy,
					qpol_genfscon_obj, &genfscon_name));
		printf("\n\n%s\n\n", genfscon_name);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	/* Here you are, Dave: getting genfscon by name doesnt seem to work, check path parameter */
	TEST("getting genfscon by name: \"selinuxfs\"", !qpol_policy_get_genfscon_by_name( quer_policy->handle, quer_policy->policy,
											   "selinuxfs", "/", &qpol_genfscon_obj ));
		
	TEST("getting iterator for named genfscon", !qpol_policy_get_genfscon_iter( quer_policy->handle, quer_policy->policy,
			&qpol_iter));

	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&qpol_tmp_path));
		TEST("getting path string from  genfscon statement", !qpol_genfscon_get_path(quer_policy->handle, quer_policy->policy,
					qpol_tmp_path, &qpol_path_string));
		printf("path is: %s\n", qpol_path_string);
		TEST("get context from path of genfscon statement", !qpol_genfscon_get_context(quer_policy->handle, quer_policy->policy,
					qpol_tmp_path, &qpol_context_struct));

		TEST("get user", !qpol_context_get_user(quer_policy->handle, quer_policy->policy,qpol_context_struct , &user));
		TEST("get user string", !qpol_user_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !qpol_context_get_role(quer_policy->handle, quer_policy->policy,qpol_context_struct , &role));
		TEST("get role string", !qpol_role_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !qpol_context_get_type(quer_policy->handle, quer_policy->policy,qpol_context_struct , &type));
		TEST("get type string", !qpol_type_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));
		printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );
		qpol_iterator_next(qpol_iter);
	}

	qpol_iterator_destroy(&qpol_iter);
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);
	return 0;
}
