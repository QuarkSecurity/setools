#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_test_lib.h"
#include "test_types.h"
#include <qpol/type_query.h>
#define MLS_TEST_POL_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_POL_SRC "../regression/policy/mls_test.conf"

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle, int is_src);

int main(int argc, char** argv)
{
	qpol_policy_t *policy;
	sepol_handle_t *handle;

	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_POL_BIN, &policy, &handle, NULL, NULL) < 0) );
	call_test_funcs( policy, handle, 0);

	TEST("open source policy",!( qpol_open_policy_from_file(MLS_TEST_POL_SRC , &policy, &handle, NULL, NULL) < 0));
	call_test_funcs( policy, handle, 1);
	return 0;
}

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle, int is_src)
{
	qpol_iterator_t * qpol_iter;
	char *pol_filename;
	char * type_name = NULL;
	size_t num_items= 0;
	uint32_t tmp_type_val;
	unsigned char isalias;
	unsigned char isattr;
	qpol_type_t * qpol_type_obj, *qpol_type_attrs;
	int r = 0, p = 0;
	uint32_t value;
	int found= 0;
	size_t num_types;
	char * alias_name;
	uint32_t val;
	int num_actual_types = 0;
	int n;

	TEST("get all types", !qpol_policy_get_type_iter(handle, policy, &qpol_iter) );
	qpol_iterator_get_size(qpol_iter, &num_items);

	while (! qpol_iterator_end(qpol_iter) ) {
		TEST("get item",!qpol_iterator_get_item( qpol_iter, (void**)&qpol_type_obj));
		qpol_type_get_isalias(handle, policy, qpol_type_obj, &isalias);
		qpol_type_get_isattr(handle, policy, qpol_type_obj, &isattr);
		TEST("getting the name of the item", !qpol_type_get_name(handle, policy,
					qpol_type_obj, &type_name ));
		TEST("dummy call to value getter", !qpol_type_get_value(handle, policy, qpol_type_obj, &val));
		TEST("see if attribute", !qpol_type_get_isattr(handle, policy,qpol_type_obj, &isattr)); 
		found = 0;
		if (strncmp(type_name, "@ttr", 4) && !isattr)
		{
			for (r = 0; r < MLS_TEST_NUM_TYPES; r++) {
				if (! strcmp( mls_test_all_types_and_attrs[r].type_name, type_name)) {
					found = 1;
				}
				if (is_src){
					for (p = 0; p <  mls_test_all_types_and_attrs[r].num_attrs; p++){
						if (!strcmp( type_name, mls_test_all_types_and_attrs[r].attrs_list[p])){
							found = 1;
							break;
						}
					}
					if (! found ){
						for (p = 0; p <  mls_test_all_types_and_attrs[r].num_aliases; p++){
							if (!strcmp( type_name, mls_test_all_types_and_attrs[r].alias_list[p])){
								found = 1;
								break;
							}
						}
					}
				}
			}
			printf("name: %s\n", type_name);
			TEST("if found", found);
		}
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	for (r = 0; r < MLS_TEST_NUM_TYPES; r++) {
		TEST("get all types", !qpol_policy_get_type_iter(handle, policy, &qpol_iter) );
		found = 0;
		while (! qpol_iterator_end(qpol_iter) ) {
			qpol_iterator_get_item( qpol_iter, (void**)&qpol_type_obj);
			qpol_type_get_name(handle, policy, qpol_type_obj, &type_name );
			if (!strcmp(type_name,mls_test_all_types_and_attrs[r].type_name)) {
				found = 1;
				break;
			}
			qpol_iterator_next(qpol_iter);
		}
		qpol_iterator_destroy(&qpol_iter);
		TEST("if found", found);
	}

	TEST("get type by name", 
			!qpol_policy_get_type_by_name(handle, policy, MLS_TTY_DEVICE_T_SEARCH_STRING, &qpol_type_obj));
	TEST("get string name of type", !qpol_type_get_name(handle, policy, qpol_type_obj, &type_name));
	TEST("compare returned name with true name", !strcmp(type_name, MLS_TTY_DEVICE_T_SEARCH_STRING));

	TEST("get list of aliases for type \"tty_device_t\"", 
			!qpol_type_get_alias_iter(handle, policy,qpol_type_obj, &qpol_iter)); 

	TEST("get size of iterator", !qpol_iterator_get_size( qpol_iter, &num_items));	
	TEST("size of iterator", num_items == TTY_DEVICE_NUM_ALIASES);

	while (! qpol_iterator_end(qpol_iter) ) {
		TEST("get item",!qpol_iterator_get_item( qpol_iter, (void**)&type_name));
		found = 0;
		for (r = 0; r < TTY_DEVICE_NUM_ALIASES; r++){
			if (!strcmp( type_name, tty_device_t_alias_list[r])){
				found = 1;
				break;
			}
		}
		printf("alias: %s\n", type_name);
		TEST("see if found", found);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	for (n = 0; n < TTY_DEVICE_NUM_ALIASES; n ++){
		TEST("get list of aliases for type \"tty_device_t\"", 
				!qpol_type_get_alias_iter(handle, policy,qpol_type_obj, &qpol_iter));
		found = 0;
		while (! qpol_iterator_end(qpol_iter) ) {
			TEST("get item",!qpol_iterator_get_item( qpol_iter, (void**)&type_name));
			if( strcmp( type_name, tty_device_t_alias_list[n])){
				found = 1;
				break;
			}
			qpol_iterator_next(qpol_iter);
		}
		TEST("if found", found);
	}

	TEST("get an alias by name",!qpol_policy_get_type_by_name(handle, policy, MLS_TEST_ALIAS_SEARCH_STRING, &qpol_type_obj));
	qpol_type_get_isalias(handle, policy, qpol_type_obj, &isalias);
	TEST("see if alias", isalias);

	TEST ("get type \"tty_device_t\"",
			!qpol_policy_get_type_by_name(handle, policy, MLS_TTY_DEVICE_T_SEARCH_STRING , &qpol_type_obj));
	TEST("get attribute iter", !qpol_type_get_attr_iter(handle, policy, qpol_type_obj, &qpol_iter));
	TEST("get iter size", !qpol_iterator_get_size( qpol_iter, &num_items));
	TEST("check size", num_items == TTY_DEVICE_NUM_ATTRS);
	if( is_src){
		while (! qpol_iterator_end(qpol_iter) ) {
			TEST("get item",!qpol_iterator_get_item( qpol_iter, (void**)&qpol_type_obj));
			TEST("get if attr", !qpol_type_get_isattr(handle, policy,
						qpol_type_obj, &isattr));
			TEST("check if attr", isattr);
			found = 0;
			TEST("get the name of the attribute", !qpol_type_get_name(handle, policy,
						qpol_type_obj, &type_name));
			for( n = 0; n < TTY_DEVICE_NUM_ATTRS; n++){
				if (!strcmp( type_name, tty_device_attr_list[n])){
					found = 1;
				}
			}
			TEST("if found", found);
			qpol_iterator_next(qpol_iter);
		}
	}
	qpol_iterator_destroy(&qpol_iter);
	qpol_policy_destroy ( &policy );
	sepol_handle_destroy( handle );
	free(policy);
}
