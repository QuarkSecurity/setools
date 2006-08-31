#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <qpol/policy_query.h>
#define SMALL_BINARY_17_POL "../regression/policy/test_small.17"
#define NUM_ADDRS 1
#define ADDR_PROTO 1
#define MASK_PROTO 1

/*qpol_t * quer_policy;*/
/*qpol_policy_t * quer_policy;*/

/*	printf("addr: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n", 
	addr[0]%(1<<8),addr[0]/(1<<8)%(1<<8),addr[0]/(1<<16)%(1<<8),addr[0]/(1<<24)%(1<<8),
	addr[1]%(1<<8),addr[1]/(1<<8)%(1<<8),addr[1]/(1<<16)%(1<<8),addr[1]/(1<<24)%(1<<8),
	addr[2]%(1<<8),addr[2]/(1<<8)%(1<<8),addr[2]/(1<<16)%(1<<8),addr[2]/(1<<24)%(1<<8),
	addr[3]%(1<<8),addr[3]/(1<<8)%(1<<8),addr[3]/(1<<16)%(1<<8),addr[3]/(1<<24)%(1<<8)); */


uint8_t x[16] = {
	0x00,
	0x11,
	0x22,
	0x33,
	0x44,
	0x55,
	0x66,
	0x77,
	0x88,
	0x99,
	0xAA,
	0xBB,
	0xCC,
	0xDD,
	0xEE,	
	0xFF
};
uint8_t y[16] = {
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
	0xff,
};
#define MLS_TEST_POL_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_POL_SRC "../regression/policy/mls_test.conf"
void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle);
int main(int argc, char **argv)
{
	qpol_policy_t * policy;
	sepol_handle_t *handle;

	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_POL_BIN, &policy, &handle, NULL, NULL) < 0) );
	call_test_funcs( policy, handle);

	TEST("open source policy",!( qpol_open_policy_from_file(MLS_TEST_POL_SRC , &policy, &handle, NULL, NULL) < 0));
	call_test_funcs( policy, handle);

	return 0;
}

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle)
{
	qpol_nodecon_t * tmp_nodecon_obj;
	qpol_user_t * tmp_user;
	unsigned char proto;
	char * user_name, *role_name,*type_name;
	qpol_role_t * role_obj;
	uint32_t * addr, * mask;
	char * pol_filename;
	size_t num_items;
	qpol_context_t * tmp_context_obj;
	qpol_iterator_t * qpol_iter;
	qpol_type_t * type_obj;
	int i= 1;
	uint32_t in_addr[4];
	uint32_t in_mask[4];
	qpol_nodecon_t * ocon_obj;

	for( ; i <=16;i++)
	{
		in_addr[i/4] |= ((uint32_t)x[i] % (1<<8) ) << (8*i%4);
	}
	for(i = 1 ; i <=16;i++)
	{
		in_mask[i/4] |= ((uint32_t)y[i] % (1<<8) ) << (8*i%4);
	}


	TEST("get all nodecons in policy",!qpol_policy_get_nodecon_iter(handle, policy, &qpol_iter));
	
	TEST("get iterator size", !qpol_iterator_get_size(qpol_iter, &num_items));
	printf("iter size: %d\n", num_items);

	TEST("num nodecons returned with true value", num_items == NUM_ADDRS );

	TEST("get item", !qpol_iterator_get_item( qpol_iter, (void**) (&tmp_nodecon_obj)));

	TEST("get address", !qpol_nodecon_get_addr(handle, policy, tmp_nodecon_obj, &addr, &proto));


	TEST("1st set", 0x00 == addr[0]%(1<<8));
	TEST("2nd set", 0x11 == addr[0]/(1<<8)%(1<<8));
	TEST("3rd set", 0x22 == addr[0]/(1<<16)%(1<<8));
	TEST("4th set", 0x33 == addr[0]/(1<<24)%(1<<8));
	TEST("5th set", 0x44 == addr[1]%(1<<8));
	TEST("6th set", 0x55 == addr[1]/(1<<8)%(1<<8));
	TEST("7th set", 0x66 == addr[1]/(1<<16)%(1<<8));
	TEST("8th set", 0x77 == addr[1]/(1<<24)%(1<<8));
	TEST("9th set", 0x88 == addr[2]%(1<<8) );
	TEST("10th set", 0x99 ==addr[2]/(1<<8)%(1<<8)  );
	TEST("11th set", 0xaa == addr[2]/(1<<16)%(1<<8) );
	TEST("12th set", 0xbb == addr[2]/(1<<24)%(1<<8) );
	TEST("13th set", 0xcc ==addr[3]%(1<<8)  );
	TEST("14th set", 0xdd == addr[3]/(1<<8)%(1<<8) );
	TEST("15th set", 0xee == addr[3]/(1<<16)%(1<<8) );
	TEST("16th set", 0xff == addr[3]/(1<<24)%(1<<8) );

	TEST("compare protocols", proto == ADDR_PROTO );

	TEST("get nodecon mask", !qpol_nodecon_get_mask(handle, policy, tmp_nodecon_obj, &mask, &proto));

	TEST("compare masks protocols", proto == MASK_PROTO); 


	TEST("1st set", 0xff == mask[0]%(1<<8));
	TEST("2nd set", 0xff == mask[0]/(1<<8)%(1<<8));
	TEST("3rd set", 0xff == mask[0]/(1<<16)%(1<<8));
	TEST("4th set", 0xff == mask[0]/(1<<24)%(1<<8));
	TEST("5th set", 0xff == mask[1]%(1<<8));
	TEST("6th set", 0xff == mask[1]/(1<<8)%(1<<8));
	TEST("7th set", 0xff == mask[1]/(1<<16)%(1<<8));
	TEST("8th set", 0xff == mask[1]/(1<<24)%(1<<8));
	TEST("9th set", 0x00 == mask[2]%(1<<8) );
	TEST("10th set", 0x00 ==mask[2]/(1<<8)%(1<<8)  );
	TEST("11th set", 0x00 == mask[2]/(1<<16)%(1<<8) );
	TEST("12th set", 0x00 == mask[2]/(1<<24)%(1<<8) );
	TEST("13th set", 0x00 ==mask[3]%(1<<8)  );
	TEST("14th set", 0x00 == mask[3]/(1<<8)%(1<<8) );
	TEST("15th set", 0x00 == mask[3]/(1<<16)%(1<<8) );
	TEST("16th set", 0x00 == mask[3]/(1<<24)%(1<<8) );
	TEST("get context of nodecon",! qpol_nodecon_get_context(handle, policy,tmp_nodecon_obj, &tmp_context_obj));
	TEST("get user of context", !qpol_context_get_user(handle, policy,tmp_context_obj, &tmp_user ));
	TEST("get name string from user datum", !qpol_user_get_name(handle, policy, tmp_user, &user_name));
	TEST("compare name", !strcmp( user_name, "system_u"));
	TEST("get role struct of context", !qpol_context_get_role(handle, policy, tmp_context_obj, &role_obj));
	TEST("get role string from datum", !qpol_role_get_name(handle, policy, role_obj, &role_name));
	TEST("compare roles", !strcmp( role_name, "object_r"));

	TEST("get type of context", !qpol_context_get_type(handle, policy,tmp_context_obj, &type_obj));
	TEST("get the name of the type", !qpol_type_get_name(handle, policy,type_obj, &type_name));
	TEST("compare type names", !strcmp(type_name, "unlabeled_t"));
	TEST("get a nodecon by a node", !qpol_policy_get_nodecon_by_node(handle, policy, addr, mask, ADDR_PROTO, 
				&ocon_obj));

	TEST("get address", !qpol_nodecon_get_addr(handle, policy, tmp_nodecon_obj, &addr, &proto));
	TEST("get context of nodecon",! qpol_nodecon_get_context(handle, policy,tmp_nodecon_obj, &tmp_context_obj));
	TEST("get user of context", !qpol_context_get_user(handle, policy,tmp_context_obj, &tmp_user ));
	TEST("get name string from user datum", !qpol_user_get_name(handle, policy, tmp_user, &user_name));
	TEST("compare name", !strcmp( user_name, "system_u"));
	TEST("get role struct of context", !qpol_context_get_role(handle, policy, tmp_context_obj, &role_obj));
	TEST("get role string from datum", !qpol_role_get_name(handle, policy, role_obj, &role_name));
	TEST("compare roles", !strcmp( role_name, "object_r"));

	TEST("get type of context", !qpol_context_get_type(handle, policy,tmp_context_obj, &type_obj));
	TEST("get the name of the type", !qpol_type_get_name(handle, policy,type_obj, &type_name));
	TEST("compare type names", !strcmp(type_name, "unlabeled_t"));

	free (tmp_nodecon_obj);
	qpol_iterator_next(qpol_iter);
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy ( &policy );
}
