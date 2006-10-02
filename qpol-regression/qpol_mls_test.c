#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"

/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>
#include "test_mls.h"
void call_test_funcs(qpol_policy_t *policy);

int main(int argc, char ** argv)
{
	qpol_policy_t *policy;
	TEST("number of arguments", (argc == 3));
	TEST("open binary policy", !(qpol_open_policy_from_file(argv[1], &policy, NULL, NULL)<0));
	call_test_funcs(policy);
	TEST("open source policy", !(qpol_open_policy_from_file(argv[2], &policy, NULL, NULL)<0));
	call_test_funcs(policy);
	return 0;
}
void call_test_funcs(qpol_policy_t *policy)
{
	qpol_level_t * tmp_mls_lvl;
	qpol_iterator_t * iter, *alias_iter;
	qpol_cat_t * tmp_cat;
	char * lvl_name, *cat_name;
	unsigned char isalias;
	size_t num_items;
	int u, found;
	int p = 0;
	char * alias_name;
	int n =0;
	uint32_t val;
	qpol_policy_get_level_by_name(policy, "boot_sens", &tmp_mls_lvl);
	qpol_level_get_name(policy, tmp_mls_lvl, &lvl_name);
	printf("lvl name: %s\n", lvl_name);
	qpol_level_get_cat_iter(policy, tmp_mls_lvl, &iter);
	qpol_iterator_get_size(iter, &num_items);
	printf("%d cats\n", num_items);
	while (! qpol_iterator_end(iter) ) {
		TEST("get item",!qpol_iterator_get_item( iter, (void**)&tmp_cat));
		qpol_cat_get_name (policy,tmp_cat, &cat_name);
		for( p = 0; p < NUM_CATS_BOOT_SENS; p++){
			if( !strcmp( cat_name,cats_lvl_boot_sens[p])){
				found = 1;
				break;
			} 		
		}
		TEST("found", found);
		qpol_iterator_next(iter);
	}
	qpol_iterator_destroy(&iter);
	qpol_policy_get_level_by_name(policy, "boot_sens", &tmp_mls_lvl);
	TEST("get value of level", !qpol_level_get_value(policy,tmp_mls_lvl, &val));
	qpol_level_get_alias_iter (policy, tmp_mls_lvl, &alias_iter);
	qpol_iterator_get_size(alias_iter, &num_items);
	TEST("num aliases", num_items == NUM_ALIASES_BOOT_SENS);

	TEST("get cat \"alessandro_file0\"", !qpol_policy_get_cat_by_name(policy, "alessandro_file0", &tmp_cat));
	TEST("get name from cat datum", !qpol_cat_get_name(policy, tmp_cat, &cat_name));
	TEST("check name", !strcmp("alessandro_file0", cat_name));

	qpol_iterator_destroy(&iter);
	TEST("get all cats in policy", !qpol_policy_get_cat_iter(policy, &iter));
	while (! qpol_iterator_end(iter) ) {
		TEST("get item",!qpol_iterator_get_item( iter, (void**)&tmp_cat));
		TEST("get cat val", !qpol_cat_get_value(policy, tmp_cat, &val));
		TEST("get the cat's name", !qpol_cat_get_name (policy,tmp_cat, &cat_name));
		found = 0;
		for( p = 0; p < NUM_CATS; p++){
			if( !strcmp(cat_name, cats_aliases_list[p].cat_name)){
				found = 1;
				break;
			}
		}
		TEST("found", found);
		qpol_iterator_next(iter);
	}
	TEST("get cat \"intern_name\"", !qpol_policy_get_cat_by_name(policy, "intern_name", &tmp_cat));
	TEST("see if alias", !qpol_cat_get_isalias(policy, tmp_cat, &isalias));
	printf("isalias: %d\n", isalias);
	TEST("if alias", isalias);

	TEST("get all levels", !qpol_policy_get_level_iter(policy, &iter));
	TEST("get size", !qpol_iterator_get_size(iter, &num_items));
	printf("size of all levels is: %d\n", num_items);
	num_items = 0;	
	while (! qpol_iterator_end(iter) ) {
		TEST("get item",!qpol_iterator_get_item( iter, (void**)&tmp_mls_lvl));
		TEST("get isalias", !qpol_level_get_isalias(policy,
					tmp_mls_lvl, &isalias));
		if( ! isalias){
			num_items++;
			TEST("get name", !qpol_level_get_name(policy, tmp_mls_lvl, &lvl_name));
			found = 0;
			for( n = 0; n < TOT_NUM_LVLS; n++){
				if( !strcmp(lvl_name, lvls_list[n])){
					found = 1;
					break;
				}
			}
			TEST("found", found);
		}
		/*printf(".....................................................\n");
		printf("name: %s, alias: %d\n", lvl_name, isalias);
		printf(".....................................................\n");*/
		qpol_iterator_next(iter);
	}
	TEST("num levels", num_items == TOT_NUM_LVLS);
	qpol_iterator_destroy(&iter);
	TEST("get cat \"alessandro_file0\"", !qpol_policy_get_cat_by_name(policy, "alessandro_file0", &tmp_cat));
	TEST("get alias iterator for cat",  !qpol_cat_get_alias_iter(policy, tmp_cat, &iter));
	TEST("get size", !qpol_iterator_get_size(iter, &num_items));
	while (! qpol_iterator_end(iter) ) {
		TEST("get item",!qpol_iterator_get_item( iter, (void**)&alias_name));
		found = 0;
		for( p = 0 ; p < ALESSANDRO_0_ALIAS_NUMS; p++){
			if( !strcmp( alias_name, alessandro_alias_list[p])){
				found = 1;
				break;
			}
		}
		TEST("found", found);
		qpol_iterator_next(iter);
	}
	/*TEST("get level \"force_public\"",!qpol_policy_get_level_by_name( policy, "force_public", &tmp_mls_lvl));
	  TEST("see if is alias",!qpol_level_get_isalias( policy,tmp_mls_lvl, &isalias));	
	  TEST("see if it's alias", !isalias);
	  TEST("getting cat iter", !qpol_level_get_cat_iter( policy, tmp_mls_lvl, &iter));
	  qpol_iterator_get_size( iter, &num_items);
	  TEST("number of cats received", FORCE_PUBLIC_LVL_NUM_CATS == num_items);
	  TEST("get name of level", !qpol_level_get_name(policy, tmp_mls_lvl, &lvl_name));
	  TEST("compare name", !strcmp(lvl_name, "force_public"));
	  TEST("get value of level", !qpol_level_get_value(policy,tmp_mls_lvl, &val));
	  TEST("get all levels", !qpol_policy_get_level_iter(policy, &iter));
	  TEST("get size", !qpol_iterator_get_size(iter, &num_items));
	  printf("size is: %d\n", num_items);
	  while (! qpol_iterator_end(iter) ) {
	  
	  TEST("get item",!qpol_iterator_get_item( iter, (void**)&tmp_mls_lvl));
	  qpol_level_get_name(policy, tmp_mls_lvl, &lvl_name);
	  qpol_level_get_isalias(policy, tmp_mls_lvl, &isalias);
	  if( ! isalias){
	  p++;
	  }
	  qpol_iterator_next(iter);
	  }
	  TEST("number of non-alias levels", p==NUM_NON_ALIAS_LVLS);
	  qpol_iterator_destroy(&iter);
	  TEST("get all levels", !qpol_policy_get_level_iter(policy, &iter));
	  while (! qpol_iterator_end(iter) ) {
	  qpol_iterator_get_item( iter, (void**)&tmp_mls_lvl);
	  qpol_level_get_name(policy, tmp_mls_lvl, &lvl_name);
	  qpol_level_get_isalias(policy, tmp_mls_lvl, &isalias);
	  if( ! isalias){
	  printf("%s\n", lvl_name);
	  qpol_level_get_alias_iter(policy, tmp_mls_lvl, &alias_iter);
	  qpol_iterator_get_size(alias_iter, &num_items);
	  printf("\t it has %d aliases\n", num_items);
	  while( !qpol_iterator_end(alias_iter)){
	  qpol_iterator_get_item( iter, (void**)&alias_name);
	  printf("\t%s\n", alias_name);
	  qpol_iterator_next(alias_iter);
	  }
	  qpol_iterator_destroy(&alias_iter);
	  p++;
	  }
	  qpol_iterator_next(iter);
	  }*/
	/*	TEST("get level \"lowestS_three\"",
		!qpol_policy_get_level_by_name( policy, "lowestS_three", &tmp_mls_lvl));
		TEST("see if level is alias",
		!qpol_level_get_isalias(policy, tmp_mls_lvl, &isalias));
		printf("isalias is: %d\n", isalias);
		TEST("get level \"s3\"",
		!qpol_policy_get_level_by_name( policy, "s3", &tmp_mls_lvl));
		qpol_iterator_destroy(&iter);
		TEST("get alias iterator for level \"s3\"",!qpol_level_get_alias_iter(policy,tmp_mls_lvl, &iter)); 
		qpol_iterator_get_size(iter, &num_items);
		printf("num items is: %d\n", num_items);
		TEST("get cat \"alessandro_file0\"",
		!qpol_policy_get_cat_by_name(policy, "alessandro_file0", &tmp_cat));
		TEST("get name from cat datum", !qpol_cat_get_name(policy, tmp_cat, &cat_name));
		printf("cat name: %s\n", cat_name);
		qpol_iterator_destroy(&iter);
		TEST("get cat \"alessandro_file0\"",
		!qpol_policy_get_cat_by_name(policy, "alessandro_file0", &tmp_cat));
		TEST("get iterator for aliases of \"alessandro_file0\"",
		!qpol_cat_get_alias_iter(policy, tmp_cat, &iter));
		qpol_iterator_get_size(iter, &num_items);
		printf("the size of iterator is: %d\n", num_items);
		TEST("check num of categories", num_items == FORCE_PUBLIC_LVL_NUM_CATS);
		while (!qpol_iterator_end(iter))
		{
		found = 0;
		TEST ("get perm name", !qpol_iterator_get_item( iter, (void**)&cat_name));
		for( u = 0; u < FORCE_PUBLIC_LVL_NUM_CATS; u++){
		if( !strcmp(alias_list_cat[u], cat_name))
		found = 1;
		}
		TEST("if found cat", found);
		qpol_iterator_next(iter);
		}
		qpol_iterator_destroy(&iter);
		for( u = 0; u < FORCE_PUBLIC_LVL_NUM_CATS; u++){
		TEST("get iterator for aliases of \"alessandro_file0\"",
		!qpol_cat_get_alias_iter(policy, tmp_cat, &iter));
		found = 0;
		while (!qpol_iterator_end(iter))
		{
		TEST ("get perm name", !qpol_iterator_get_item( iter, (void**)&cat_name));
		if( !strcmp( cat_name, alias_list_cat[u]))
		found = 1;
		qpol_iterator_next(iter);
		}
		TEST("if found cat", found);	
		}
		qpol_iterator_destroy(&iter);
		qpol_policy_get_cat_iter(policy, &iter);
		while (!qpol_iterator_end(iter))
		{
		TEST ("get perm name", !qpol_iterator_get_item( iter, (void**)&cat_name));
		printf("%s\n", cat_name);
		qpol_iterator_next(iter);	
		}*/
	qpol_policy_destroy ( &policy );
}
