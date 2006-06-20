#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"

/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"

#include "class_perms.h"

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle);

int main(int argc, char ** argv)
{
	qpol_policy_t *policy;
	sepol_handle_t *handle;
	TEST("open binary policy", ! (qpol_open_policy_from_file(MLS_TEST_BIN, &policy, &handle, NULL, NULL)<0));
	call_test_funcs( policy, handle);
	TEST("open source policy", ! (qpol_open_policy_from_file(MLS_TEST_SRC , &policy, &handle, NULL, NULL)<0));
	call_test_funcs( policy, handle);
	return 0;
}

void call_test_funcs( qpol_policy_t *policy, sepol_handle_t *handle)
{
	qpol_class_t * tmp_class_datum;
	qpol_common_t * tmp_common_datum;
	qpol_iterator_t * qpol_iter, *qpol_perm_iter;
	char * class_name;
	char *common_name;
	char * perm_name;
	int n = 0;
	uint32_t val;
	int found = 0;
	int r = 0;
	int u = 0;
	int idx = 0;
	int perm_found = 0;
	size_t  num_items= 0;
	
	TEST("getting all object classes",! qpol_policy_get_class_iter(handle, policy, &qpol_iter));
	while (! qpol_iterator_end(qpol_iter))
	{
		TEST ("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**) (&tmp_class_datum)));
		TEST ("get name from datum", !qpol_class_get_name(handle, policy,
					tmp_class_datum, &class_name ));
		for (r = 0; r < MLS_TEST_NUM_CLASSES ; r++) {
			if (! strcmp(class_name, mls_test_all_classes[r])) {
				found = 1;
				idx = r;
				break;
			}
		} 
		TEST ("if found class", found);

		TEST ("getting permissions iterator from class", !qpol_class_get_perm_iter(handle, policy,
					tmp_class_datum, &qpol_perm_iter));
		found = 0;	
		while (! qpol_iterator_end(qpol_perm_iter))
		{
			TEST ("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			perm_found = 0;
			for (r = 0; r < mls_test_all_classes_and_perms[idx].len_perm; r++)
			{
				if (! strcmp(perm_name, mls_test_all_classes_and_perms[idx].perm_list[r])) {
					perm_found = 1;	
				}
			}
			TEST("found permission", perm_found);
			qpol_iterator_next(qpol_perm_iter);
		}
		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);	
		n++;
	}

	qpol_iterator_destroy(&qpol_iter);
	TEST("compare total number classes", n == MLS_TEST_NUM_CLASSES );

	for (r = 0; r < MLS_TEST_NUM_CLASSES ; r++) 
	{
		TEST("getting all object classes",! qpol_policy_get_class_iter(handle, policy, &qpol_iter));
		found = 0;
		while (! qpol_iterator_end(qpol_iter))
		{
			TEST ("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**) (&tmp_class_datum)));
			TEST ("get name from datum", !qpol_class_get_name(handle, policy,
						tmp_class_datum, &class_name ));
			if (! strcmp(class_name, mls_test_all_classes[r])) 
			{
				found = 1;
				idx = r;
				break;
			}
			qpol_iterator_next(qpol_iter);
		}

		TEST("if found class", found);

		for( u = 0; u < mls_test_all_classes_and_perms[idx].len_perm; u++)
		{
			qpol_policy_get_class_by_name(handle, policy,mls_test_all_classes_and_perms[idx].class_name,
					&tmp_class_datum);
			TEST ("getting permissions iterator from class", !qpol_class_get_perm_iter(handle, policy,
						tmp_class_datum, &qpol_perm_iter));

			while (! qpol_iterator_end(qpol_perm_iter))
			{
				TEST ("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));	
				if (! strcmp(perm_name, mls_test_all_classes_and_perms[idx].perm_list[u])) {
					perm_found = 1;
					break;
				}
				qpol_iterator_next(qpol_perm_iter);
			}
		}
		qpol_iterator_destroy(&qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	TEST("getting iterator over all classes with permission \"create\"", 
			!qpol_perm_get_class_iter ( handle, policy, "create", &qpol_iter )); 
	qpol_iterator_get_size( qpol_iter, &num_items);
	TEST("check num classes with perm create", num_items == MLS_TEST_NUM_CLASSES_W_PERM_CREAT);
	while (! qpol_iterator_end(qpol_iter)) 
	{
		found = 0;
		TEST ("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&tmp_class_datum));
		TEST ("get name from datum", !qpol_class_get_name(handle, policy,
					tmp_class_datum, &class_name ));
		for( r = 0; r < MLS_TEST_NUM_CLASSES_W_PERM_CREAT; r ++){
			if( !strcmp( class_name, mls_test_classes_w_perm_create[r]))
				found = 1;
		}
		TEST("if found", found );
		qpol_iterator_next(qpol_iter);	
	} 
	qpol_iterator_destroy(&qpol_iter);
	for( r = 0; r < MLS_TEST_NUM_CLASSES_W_PERM_CREAT; r ++){
		TEST("getting iterator over all classes with permission \"create\"", 
				!qpol_perm_get_class_iter ( handle, policy, "create", &qpol_iter )); 
		found = 0;
		while(! qpol_iterator_end(qpol_iter)) 
		{
			TEST ("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&tmp_class_datum));
			TEST ("get name from datum", !qpol_class_get_name(handle, policy,
						tmp_class_datum, &class_name ));
			if( !strcmp( class_name, mls_test_classes_w_perm_create[r]))
				found = 1;
			qpol_iterator_next(qpol_iter);
		}
		TEST("if found", found);
	}
	
	TEST("get all commons in policy", !qpol_policy_get_common_iter(handle, policy, &qpol_iter ) );
	qpol_iterator_get_size(qpol_iter, &num_items);

	TEST("commons iter size", num_items == MLS_TEST_NUM_COMMONS);

	while (! qpol_iterator_end(qpol_iter))
	{
		found = 0;
		TEST("get item from iterator", !qpol_iterator_get_item( qpol_iter, (void**)&tmp_common_datum));
		TEST("get name of common", !qpol_common_get_name(handle, policy, tmp_common_datum, &common_name));
		for (r = 0; r < MLS_TEST_NUM_COMMONS; r++)
		{
			if (! strcmp(common_name, mls_test_all_commons[r].common_name)) 
			{
				idx = r;
				found = 1;
				break;
			}
		}
		TEST("if found", found);

		qpol_common_get_perm_iter(handle, policy,tmp_common_datum, &qpol_perm_iter);
		while (!qpol_iterator_end(qpol_perm_iter))
		{
			TEST ("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			for( u = 0; u < mls_test_all_commons[idx].len_perm; u++)
			{
				if (! strcmp(perm_name, mls_test_all_commons[idx].perm_list[u])){
					perm_found = 1;
					break;
				}
			}
			TEST("if found perm", perm_found);
			qpol_iterator_next(qpol_perm_iter);
		}
		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	qpol_policy_get_common_by_name(handle, policy, "socket", &tmp_common_datum);
	qpol_common_get_name(handle, policy, tmp_common_datum, &common_name);
	TEST("testing against true common name", !strcmp("socket", common_name));		

	TEST("getting all commons with permission \"create\"", !qpol_perm_get_common_iter(handle, policy,
				"create", &qpol_iter));
	qpol_iterator_get_size(qpol_iter, &num_items);

	TEST("size common iter", num_items == MLS_TEST_NUM_COMMONS);

	while (! qpol_iterator_end(qpol_iter))
	{
		qpol_iterator_get_item( qpol_iter, (void**)&tmp_common_datum);
		qpol_common_get_name(handle, policy, tmp_common_datum, &common_name);
		for( r = 0; r < MLS_TEST_NUM_COMMONS; r++)
		{
			if (! strcmp(common_name, mls_test_all_commons[r].common_name)){
				found = 1;
				idx = r;
				break;
			}
		}
		TEST("found", found);
		qpol_common_get_perm_iter(handle, policy,tmp_common_datum, &qpol_perm_iter);
		while (! qpol_iterator_end(qpol_perm_iter) )
		{
			perm_found =0;
			TEST ("get perm name", !qpol_iterator_get_item( qpol_perm_iter, (void**)&perm_name));
			for( u = 0; u < mls_test_all_commons[idx].len_perm; u++)
			{
				if (! strcmp(perm_name, mls_test_all_commons[idx].perm_list[u])){
					perm_found = 1;
					break;
				}
			}
			TEST("if found perm", perm_found);
			qpol_iterator_next(qpol_perm_iter);
		}
		qpol_iterator_destroy(&qpol_perm_iter);
		qpol_iterator_next(qpol_iter);
	}
	qpol_iterator_destroy(&qpol_iter);

	TEST("getting a datum for the \"class blk_file\"", !qpol_policy_get_class_by_name(handle, policy,
				"blk_file", &tmp_class_datum ));
	TEST("getting name of class datum retrieved", !qpol_class_get_name(handle,
				policy, tmp_class_datum, &class_name));
	TEST("compare names", !strcmp( "blk_file", class_name));
	TEST("getting the common used by the class \"blk_file\"", !qpol_class_get_common(handle, policy,
				tmp_class_datum, &tmp_common_datum ));
	TEST("get name of common", !qpol_common_get_name( handle, policy, tmp_common_datum, &common_name));
	TEST("compare common names with returned name", !strcmp("file", common_name));

	qpol_close_policy ( &policy );
	sepol_handle_destroy( handle );
}
