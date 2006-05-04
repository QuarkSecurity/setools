#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <sepol/genfscon_query.h>

#define MLS_POL "../regression/policy/mls_policy.19"

qpol_t * quer_policy;

static void construct_string_con(sepol_handle_t *handle, sepol_policydb_t *policy,sepol_context_struct_t * con_struct, char **str_con);

int main(int argc, char ** argv)
{
	char *pol_filename, *genfscon_name, *qpol_path_string, *context_string = NULL;
	sepol_genfscon_t * qpol_genfscon_obj;
	sepol_iterator_t *qpol_iter;
	sepol_context_struct_t * qpol_context_struct;
	sepol_genfspath_t * qpol_tmp_path;
	sepol_user_datum_t * user;
	sepol_role_datum_t * role;
	sepol_type_datum_t *  type;
	char * name_str, *user_str, *role_str, *type_str, *mls_str;

	if( argc < 2)
	{
		pol_filename = MLS_POL;
	}
	else
	{
		pol_filename = argv[1];
	}

	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));

	TEST("getting iterator for all genfscons", !sepol_policydb_get_genfscon_iter( quer_policy->handle, quer_policy->policy,
				&qpol_iter));
	while( ! sepol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !sepol_iterator_get_item( qpol_iter, (void**)&qpol_genfscon_obj));
		TEST("get name of genfscon", !sepol_genfscon_get_name( quer_policy->handle, quer_policy->policy,
					qpol_genfscon_obj, &genfscon_name));
		printf("\n\n%s\n\n", genfscon_name);
		sepol_iterator_next(qpol_iter);
	}
	sepol_iterator_destroy(&qpol_iter);

	TEST("getting genfscon by name: \"selinuxfs\"", !sepol_policydb_get_genfscon_by_name( quer_policy->handle, quer_policy->policy,
				"selinuxfs", &qpol_genfscon_obj ));
		
	TEST("getting paths of genfscon retrieved", !sepol_genfscon_get_path_iter( quer_policy->handle, quer_policy->policy,
			qpol_genfscon_obj, &qpol_iter));

	while( ! sepol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !sepol_iterator_get_item( qpol_iter, (void**)&qpol_tmp_path));
		TEST("getting path string from  genfscon statement", !sepol_genfscon_path_get_path(quer_policy->handle, quer_policy->policy,
					qpol_tmp_path, &qpol_path_string));
		printf("path is: %s\n", qpol_path_string);
		TEST("get context from path of genfscon statement", !sepol_genfscon_path_get_context(quer_policy->handle, quer_policy->policy,
					qpol_tmp_path, &qpol_context_struct));

		TEST("get user", !sepol_context_struct_get_user(quer_policy->handle, quer_policy->policy,qpol_context_struct , &user));
		TEST("get user string", !sepol_user_datum_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !sepol_context_struct_get_role(quer_policy->handle, quer_policy->policy,qpol_context_struct , &role));
		TEST("get role string", !sepol_role_datum_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !sepol_context_struct_get_type(quer_policy->handle, quer_policy->policy,qpol_context_struct , &type));
		TEST("get type string", !sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));
		printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );
		sepol_iterator_next(qpol_iter);
	}

	sepol_iterator_destroy(&qpol_iter);
	sepol_policydb_free ( quer_policy->policy );
	sepol_handle_destroy( quer_policy->handle );
	free(quer_policy);
	return 0;
}
