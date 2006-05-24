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
	char *pol_filename, *netifcon_name;
	qpol_netifcon_t * qpol_netifcon_obj;
	qpol_context_t * msg_con, *if_con;
	qpol_user_t * user;
	qpol_role_t * role;
	qpol_type_t *  type;
	qpol_iterator_t * qpol_iter;
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
	TEST("get netifcon datum for name \"eth0\"", !qpol_policy_get_netifcon_by_name(quer_policy->handle, quer_policy->policy,
				"eth0", &qpol_netifcon_obj));
	TEST("get the name of the netifcon structure", !qpol_netifcon_get_name(quer_policy->handle, quer_policy->policy,
				qpol_netifcon_obj, &netifcon_name)); 
	printf("name of netifcon is: %s\n", netifcon_name);

	TEST("getting the message context of netifcon", !qpol_netifcon_get_msg_con( quer_policy->handle, quer_policy->policy,
				qpol_netifcon_obj, &msg_con));

	TEST("get user", !qpol_context_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
	TEST("get user string", !qpol_user_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
	TEST("get role", !qpol_context_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
	TEST("get role string", !qpol_role_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
	TEST("get type", !qpol_context_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
	TEST("get type string", !qpol_type_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));

	printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

	TEST("get inteface context from netif object", !qpol_netifcon_get_if_con( quer_policy->handle, quer_policy->policy, 
				qpol_netifcon_obj, &if_con));

	TEST("get user", !qpol_context_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
	TEST("get user string", !qpol_user_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
	TEST("get role", !qpol_context_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
	TEST("get role string", !qpol_role_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
	TEST("get type", !qpol_context_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
	TEST("get type string", !qpol_type_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));
	printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

	TEST("get all netifcons in policy through iterator", !qpol_policy_get_netifcon_iter(quer_policy->handle, quer_policy->policy,
				&qpol_iter));
	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&qpol_netifcon_obj));
		TEST("get the name of the netifcon structure", !qpol_netifcon_get_name(quer_policy->handle, quer_policy->policy,
					qpol_netifcon_obj, &netifcon_name)); 
		printf("netifcon name: %s\n", netifcon_name);
		TEST("get user", !qpol_context_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
		TEST("get user string", !qpol_user_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !qpol_context_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
		TEST("get role string", !qpol_role_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !qpol_context_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
		TEST("get type string", !qpol_type_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));

		printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

		TEST("get inteface context from netif object", !qpol_netifcon_get_if_con( quer_policy->handle, quer_policy->policy, 
					qpol_netifcon_obj, &if_con));

		TEST("get user", !qpol_context_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
		TEST("get user string", !qpol_user_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !qpol_context_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
		TEST("get role string", !qpol_role_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !qpol_context_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
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
