#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <sepol/netifcon_query.h>

#define MLS_POL "../regression/policy/mls_policy.19"

qpol_t * quer_policy;

int main(int argc, char ** argv)
{
	char *pol_filename, *netifcon_name;
	sepol_netifcon_t * qpol_netifcon_obj;
	sepol_context_struct_t * msg_con, *if_con;
	sepol_user_datum_t * user;
	sepol_role_datum_t * role;
	sepol_type_datum_t *  type;
	sepol_iterator_t * qpol_iter;
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
	TEST("get netifcon datum for name \"eth0\"", !sepol_policydb_get_netifcon_by_name(quer_policy->handle, quer_policy->policy,
				"eth0", &qpol_netifcon_obj));
	TEST("get the name of the netifcon structure", !sepol_netifcon_get_name(quer_policy->handle, quer_policy->policy,
				qpol_netifcon_obj, &netifcon_name)); 
	printf("name of netifcon is: %s\n", netifcon_name);

	TEST("getting the message context of netifcon", !sepol_netifcon_get_msg_con( quer_policy->handle, quer_policy->policy,
				qpol_netifcon_obj, &msg_con));

	TEST("get user", !sepol_context_struct_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
	TEST("get user string", !sepol_user_datum_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
	TEST("get role", !sepol_context_struct_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
	TEST("get role string", !sepol_role_datum_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
	TEST("get type", !sepol_context_struct_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
	TEST("get type string", !sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));

	printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

	TEST("get inteface context from netif object", !sepol_netifcon_get_if_con( quer_policy->handle, quer_policy->policy, 
				qpol_netifcon_obj, &if_con));

	TEST("get user", !sepol_context_struct_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
	TEST("get user string", !sepol_user_datum_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
	TEST("get role", !sepol_context_struct_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
	TEST("get role string", !sepol_role_datum_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
	TEST("get type", !sepol_context_struct_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
	TEST("get type string", !sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));
	printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

	TEST("get all netifcons in policy through iterator", !sepol_policydb_get_netifcon_iter(quer_policy->handle, quer_policy->policy,
				&qpol_iter));
	while( ! sepol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !sepol_iterator_get_item( qpol_iter, (void**)&qpol_netifcon_obj));
		TEST("get the name of the netifcon structure", !sepol_netifcon_get_name(quer_policy->handle, quer_policy->policy,
					qpol_netifcon_obj, &netifcon_name)); 
		printf("netifcon name: %s\n", netifcon_name);
		TEST("get user", !sepol_context_struct_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
		TEST("get user string", !sepol_user_datum_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !sepol_context_struct_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
		TEST("get role string", !sepol_role_datum_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !sepol_context_struct_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
		TEST("get type string", !sepol_type_datum_get_name(quer_policy->handle, quer_policy->policy, type, &type_str ));

		printf("user:role:type -> %s:%s:%s\n", user_str, role_str, type_str );

		TEST("get inteface context from netif object", !sepol_netifcon_get_if_con( quer_policy->handle, quer_policy->policy, 
					qpol_netifcon_obj, &if_con));

		TEST("get user", !sepol_context_struct_get_user(quer_policy->handle, quer_policy->policy,msg_con , &user));
		TEST("get user string", !sepol_user_datum_get_name(quer_policy->handle,quer_policy->policy , user, &user_str ));
		TEST("get role", !sepol_context_struct_get_role(quer_policy->handle, quer_policy->policy,msg_con , &role));
		TEST("get role string", !sepol_role_datum_get_name(quer_policy->handle, quer_policy->policy, role, &role_str ));
		TEST("get type", !sepol_context_struct_get_type(quer_policy->handle, quer_policy->policy,msg_con , &type));
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
