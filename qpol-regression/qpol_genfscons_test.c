#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"

/* qpol */
#include <qpol/policy_query.h>
#include "test_genfscon.h"

void call_test_funcs( qpol_policy_t *policy);

int main(int argc, char *argv[])
{
	qpol_policy_t *policy;
	
	TEST("number of arguments", (argc == 3))
	TEST("open binary policy", !(qpol_open_policy_from_file(argv[1], &policy, NULL, NULL) < 0) );
	call_test_funcs( policy);
	TEST("open source policy", !(qpol_open_policy_from_file(argv[2] , &policy, NULL, NULL) < 0));
	call_test_funcs( policy);
	return 0;
}

void call_test_funcs( qpol_policy_t *policy)
{
	char *pol_filename, *genfscon_name, *qpol_path_string;
	qpol_genfscon_t * qpol_genfscon_obj, *qpol_tmp_path;
	qpol_iterator_t *qpol_iter;
	qpol_context_t * qpol_context_struct;
	qpol_user_t * user;
	qpol_role_t * role;
	qpol_type_t *  type;
	char * ret_name;
	char *user_str, *role_str, *type_str;
	int n = 0;
	size_t num_items;
	int found;
	uint32_t class;

	TEST("getting iterator for all genfscons", !qpol_policy_get_genfscon_iter( policy,
				&qpol_iter));
	TEST("get size", !qpol_iterator_get_size(qpol_iter, &num_items));
	TEST("size", num_items == NUM_GENFSCONS );

	while( ! qpol_iterator_end(qpol_iter)) {
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&qpol_genfscon_obj));
		TEST("get name of genfscon", !qpol_genfscon_get_name( policy,
					qpol_genfscon_obj, &genfscon_name));
		TEST("getting path string from  genfscon statement", !qpol_genfscon_get_path(policy,
					qpol_genfscon_obj, &qpol_path_string));
		TEST("get context from path of genfscon statement", !qpol_genfscon_get_context(policy,
					qpol_genfscon_obj, &qpol_context_struct));
		TEST("get user", !qpol_context_get_user(policy,qpol_context_struct , &user));
		TEST("get user string", !qpol_user_get_name(policy , user, &user_str ));
		TEST("get role", !qpol_context_get_role(policy,qpol_context_struct , &role));
		TEST("get role string", !qpol_role_get_name(policy, role, &role_str ));
		TEST("get type", !qpol_context_get_type(policy,qpol_context_struct , &type));
		TEST("get type string", !qpol_type_get_name(policy, type, &type_str ));
		found = 0;
		for( n=0 ; n <NUM_GENFSCONS	; n++){
			if (!strcmp (genfscon_name, genfscon_list[n].fs_name) &&
					!strcmp (qpol_path_string, genfscon_list[n].path) &&
					!strcmp (user_str, genfscon_list[n].user)  	      &&
					!strcmp(role_str, genfscon_list[n].role)	&&
					!strcmp(type_str, genfscon_list[n].type) ){
				found = 1;
				break;
			}
		}
		TEST("found", found);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);
	
	TEST("get fs \"binfmt_misc\"",!qpol_policy_get_genfscon_by_name(policy, "binfmt_misc", "/", &qpol_genfscon_obj));
	TEST("get name of returned object", !qpol_genfscon_get_name(policy, qpol_genfscon_obj, &ret_name));
	TEST("check name", !strcmp(ret_name, "binfmt_misc"));
	TEST("get class of genfscon", !qpol_genfscon_get_class(policy, qpol_genfscon_obj, &class));
	TEST("get fs \"binfmt_misc\"",!qpol_policy_get_genfscon_by_name(policy, "proc", "/sys/kernel/hotplug", &qpol_genfscon_obj));
	TEST("get class of genfscon", !qpol_genfscon_get_class(policy, qpol_genfscon_obj, &class));
	
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy( &policy );
}
