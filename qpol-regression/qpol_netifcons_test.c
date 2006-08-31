#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"

/* qpol */
#include <qpol/policy_query.h>
#include "test_mls.h"

#define MLS_POL "../regression/policy/mls_policy.19"

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle);
#define MLS_TEST_POL_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_POL_SRC "../regression/policy/mls_test.conf"
int main(int argc, char ** argv)
{

	qpol_policy_t *policy;
	sepol_handle_t *handle;

	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_POL_BIN, &policy, &handle, NULL, NULL) < 0) );
	call_test_funcs( policy, handle);

	TEST("open source policy",!( qpol_open_policy_from_file(MLS_TEST_POL_SRC , &policy, &handle, NULL, NULL) < 0));
	call_test_funcs( policy, handle);

	return 0;
}

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle)
{
	char *pol_filename, *netifcon_name;
	qpol_netifcon_t * qpol_netifcon_obj;
	qpol_context_t * msg_con, *if_con;
	qpol_user_t * user;
	qpol_role_t * role;
	qpol_type_t *  type;
	qpol_iterator_t * qpol_iter;
	char *msg_user_str, *msg_role_str, *msg_type_str, *if_user_str, *if_role_str, *if_type_str;
	int p = 0;
	int found;
	uint32_t num_items;
	TEST("get netifcon datum for name \"eth0\"", !qpol_policy_get_netifcon_by_name(handle, policy,
				"eth0", &qpol_netifcon_obj));

	TEST("get the name of the netifcon structure", !qpol_netifcon_get_name(handle, policy,
				qpol_netifcon_obj, &netifcon_name)); 

	TEST("name of netifcon", !strcmp("eth0", netifcon_name));	

	TEST("getting the message context of netifcon", !qpol_netifcon_get_msg_con( handle, policy,
				qpol_netifcon_obj, &msg_con));

	TEST("get user", !qpol_context_get_user(handle, policy,msg_con , &user));
	TEST("get user string", !qpol_user_get_name(handle,policy , user, &msg_user_str ));
	TEST("get role", !qpol_context_get_role(handle, policy,msg_con , &role));
	TEST("get role string", !qpol_role_get_name(handle, policy, role, &msg_role_str ));
	TEST("get type", !qpol_context_get_type(handle, policy,msg_con , &type));
	TEST("get type string", !qpol_type_get_name(handle, policy, type, &msg_type_str ));
	TEST("check user", !strcmp("system_u", msg_user_str));
	TEST("check role", !strcmp("object_r", msg_role_str));
	TEST("check type", !strcmp("unlabeled_t", msg_type_str));


	TEST("get inteface context from netif object", !qpol_netifcon_get_if_con( handle, policy, 
				qpol_netifcon_obj, &if_con));

	TEST("get user", !qpol_context_get_user(handle, policy,if_con , &user));
	TEST("get user string", !qpol_user_get_name(handle,policy , user, &if_user_str ));
	TEST("get role", !qpol_context_get_role(handle, policy,if_con , &role));
	TEST("get role string", !qpol_role_get_name(handle, policy, role, &if_role_str ));
	TEST("get type", !qpol_context_get_type(handle, policy, if_con , &type));
	TEST("get type string", !qpol_type_get_name(handle, policy, type, &if_type_str ));
	TEST("check user", !strcmp("system_u", if_user_str));
	TEST("check role", !strcmp("object_r", if_role_str));
	TEST("check type", !strcmp("netif_eth0_t", if_type_str));
	TEST("get all netifcons in policy through iterator", !qpol_policy_get_netifcon_iter(handle, policy,
				&qpol_iter));
	TEST("get size", !qpol_iterator_get_size(qpol_iter, &num_items));
	TEST("the size", num_items == NUM_IFCONS);

	while( ! qpol_iterator_end(qpol_iter))
	{
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&qpol_netifcon_obj));
		TEST("get the name of the netifcon structure", !qpol_netifcon_get_name(handle, policy,
					qpol_netifcon_obj, &netifcon_name)); 
		found = 0;

		TEST("get user", !qpol_context_get_user(handle, policy,msg_con , &user));
		TEST("get user string", !qpol_user_get_name(handle,policy , user, &msg_user_str ));
		TEST("get role", !qpol_context_get_role(handle, policy,msg_con , &role));
		TEST("get role string", !qpol_role_get_name(handle, policy, role, &msg_role_str ));
		TEST("get type", !qpol_context_get_type(handle, policy,msg_con , &type));
		TEST("get type string", !qpol_type_get_name(handle, policy, type, &msg_type_str ));

		TEST("get inteface context from netif object", !qpol_netifcon_get_if_con( handle, policy, 
					qpol_netifcon_obj, &if_con));

		TEST("get user", !qpol_context_get_user(handle, policy,if_con , &user));
		TEST("get user string", !qpol_user_get_name(handle,policy , user, &if_user_str ));
		TEST("get role", !qpol_context_get_role(handle, policy,if_con , &role));
		TEST("get role string", !qpol_role_get_name(handle, policy, role, &if_role_str ));
		TEST("get type", !qpol_context_get_type(handle, policy,if_con , &type));
		TEST("get type string", !qpol_type_get_name(handle, policy, type, &if_type_str ));

		for( p = 0; p < NUM_IFCONS; p++)
		{
			if (!strcmp(netifcon_name, ifcon_list[p].if_name) && 
					!strcmp(msg_user_str, ifcon_list[p].user_msg_con) &&
					!strcmp(msg_role_str, ifcon_list[p].role_msg_con) &&
					!strcmp(msg_type_str, ifcon_list[p].type_msg_con) &&
					!strcmp(if_user_str , ifcon_list[p].user_if_con) &&
					!strcmp(if_role_str , ifcon_list[p].role_if_con) &&
					!strcmp(if_type_str , ifcon_list[p].type_if_con))
			{
				found = 1;
				break;
			}
		}
		TEST("if found", found);
		qpol_iterator_next(qpol_iter);

	}
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy ( &policy );
	sepol_handle_destroy( handle );
	return 0;
}
