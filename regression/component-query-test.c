#include "sepol/handle.h"
#include "sepol/policydb.h"
#include "sepol/policydb-query.h"
#include <stdio.h>
#include "component-query.h"
#include <errno.h>
#include "test.h"
int main()
{
	sepol_handle_t * h;
	apol_policy_t * p;
	apol_type_query_t * t;
	apol_vector_t * v;
	size_t  *num_results;
	int n = 0;
	int vector_size = 0;
	char * type_name;
	sepol_class_datum_t ** class_dat;
	apol_attr_query_t *attr_s;
	apol_user_query_t * user_s;
	apol_role_query_t * query_s_role;
	sepol_role_datum_t * role_datum_ptr;
	sepol_bool_datum_t * bool_datum_ptr;
	sepol_type_datum_t* type_datum_ptr;
	sepol_user_datum_t * user_datum_ptr;

	if( apol_policy_open_binary( "/home/aferrucci/svn/working/setools/trunk/tests/regression/policy/binary_small.17", &p) != 0) {
		perror("open binary policy error");
		exit(-1);
	}
	if( p == NULL)
	{
		fprintf(stderr, "policy p is null\n");
		exit(-1);
	}
	printf("============================================ QUERY TYPES ==========================================\n\n\n");
	TEST("querying the policy for all types", !apol_get_type_by_query(p, NULL, &v));
	if(v == NULL) {
		fprintf(stderr, "apol vector struct NULL ... FAILED\n");
		perror("apol vector struct null...FAILED");
		exit(errno);
	} else{ 
		printf("Got queries out of apol_get_type_by_query...PASS\n");
	}
	vector_size = apol_vector_get_size(v);
	printf("the size of the apol_vector structure passed in is %d\n", vector_size);
	printf("printing all the names of each of the datums in the vector\n"); 

	for( ; n < vector_size;n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v,NULL);

	printf("\n\n---------------GET dir_t TYPE---------------\n");
	TEST("creating a new apol_type_query_t structure t", (t = apol_type_query_create()));
	TEST("setting the apol_type_query_t structure to type dir_t", !apol_type_query_set_type(t, "dir_t"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));
	vector_size = apol_vector_get_size(v);

	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}

	TEST("unsetting my type_query_t structure to NULL name", !apol_type_query_set_type(t, NULL) );
	printf("\n\n---------------GET REGEX \"se\" TYPE---------------\n");
	TEST("setting the type_query_t structure to use regex",  !apol_type_query_set_regex(t, 1));
	TEST("setting the apol_type_query_t structure to regex se", !apol_type_query_set_type(t, "se"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));

	vector_size = apol_vector_get_size(v);

	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}

	printf("destroying the query structure\n");
	apol_type_query_destroy(&t);

	printf("\n\n---------------GET REGEX \"ex\" TYPE---------------\n");
	TEST("re-creating a new apol_type_query_t structure t", (t = apol_type_query_create()));
	TEST("setting this query structure to do regex", !apol_type_query_set_regex(t, 1));
	TEST("setting the apol_type_query_t structure to regex ex", !apol_type_query_set_type(t, "ex"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));

	vector_size = apol_vector_get_size(v);
	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}

	printf("Destroying query structure\n");
	apol_type_query_destroy(&t);
	apol_vector_destroy(&v,NULL);


	printf("============================================ QUERY ATTRIBUTES ==========================================\n\n\n");
	TEST("querying the policy for all attributes", !apol_get_attr_by_query(p, NULL, &v));

	if(v == NULL) {
		fprintf(stderr, "apol vector struct NULL ... FAILED\n");
		perror("apol vector struct null...FAILED");
		exit(errno);
	} else{ 
		printf("Got queries out of apol_get_type_by_query...PASS\n");
	}
	vector_size = apol_vector_get_size(v);
	printf("the size of the apol_vector structure passed in is %d\n", vector_size);
	printf("printing all the names of each of the datums in the vector\n"); 
	if( vector_size == 0) {
		printf("------------------------------------\n");
		printf("THERE WERE NO ATTRIBUTES PASSED BACK\n");
		printf("------------------------------------\n");

	} else{
		for( ; n < vector_size;n++) {
			printf("item %d: ", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
			sepol_type_datum_get_name(h, p->p, (sepol_type_datum_t*)apol_vector_get_element(v, n), &type_name);
			printf("%s\n", type_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("\n\n---------------GET ATTRIBUTE \"RANDOM\"---------------\n");

	TEST("creating an apol attribute query structure", (attr_s = apol_attr_query_create())!= NULL);
	TEST("setting attribute name to \"random\" in the attribute query structure", !apol_attr_query_set_attr(attr_s, "random"));
	TEST("doing an attribute query with attribute name = \'random\'", !apol_get_attr_by_query( p, attr_s, &v));
	vector_size = apol_vector_get_size(v);

	if(v == NULL) {
		fprintf(stderr, "apol vector struct NULL ... FAILED\n");
		perror("apol vector struct null...FAILED");
		exit(errno);
	} else{ 
		printf("The vector after get attribute is not NULL...PASS\n");
	}

	if( vector_size == 0 ) {
		printf("the vector size is 0\n");
	} else{
		for( n = 0 ; n < vector_size; n++){

			printf("item %d\n", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
			printf("attribute: %s\n",type_name );
		}
	}
	apol_vector_destroy(&v, NULL);
	apol_attr_query_destroy( &attr_s);

	printf("\n\n---------------GET REGEX ATTRIBUTE \"re*\"---------------\n");
	TEST("creating an apol attribute query structure", (attr_s = apol_attr_query_create())!= NULL);
	TEST("setting the attribute query structure to be regex'ed", !apol_attr_query_set_regex(attr_s, 1));
	TEST("setting the regex of the query structure", !apol_attr_query_set_attr(attr_s, "re*"));
	TEST("re'querying the policy with regex attribute structure", !apol_get_attr_by_query(p, attr_s, &v));
	if(v == NULL) {
		fprintf(stderr, "v returned NULL, get attribute by query failed\n");
		perror("attribute failed");
	} else{
		fprintf(stderr, "v returned non-NULL...PASS\n");
	}
	vector_size = apol_vector_get_size(v);
	if(!vector_size){
		fprintf(stderr, "the vector is empty\n");
	} else{
		for( n = 0; n < vector_size ;n++) {
			printf("item %d\n", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(h, p->p, type_datum_ptr, &type_name);
			printf("attribute: %s\n",type_name );

		}
	}
	apol_vector_destroy(&v,NULL);
	apol_attr_query_destroy(&attr_s);

	printf("============================================ QUERY ROLES ==========================================\n\n\n");
	TEST("querying the policy for all roles", !apol_get_role_by_query(p, NULL, &v));
	if ( v == NULL) {
		fprintf(stderr, "the vector is NULL, either no results or error");
	} else{
		fprintf(stderr,"there were some roles passed back!");
	}
	vector_size = apol_vector_get_size(v);
	printf("the size of the apol_vector structure passed in is %d\n", vector_size);
	printf("printing all the names of each of the datums in the vector\n"); 
	for( n = 0 ; n < vector_size;n++) {
		printf("item %d: ", n);
		role_datum_ptr = (sepol_role_datum_t*)apol_vector_get_element(v, n);
		sepol_role_datum_get_name(h, p->p, role_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v,NULL);

	query_s_role = apol_role_query_create();
	TEST("setting a role name in the apol role query structure", !apol_role_query_set_role(query_s_role, "user_r"));
	TEST("re-querying the policy for the specified role", !apol_get_role_by_query(p, query_s_role, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr,"There were no roles with name role_r found\n");
	} else {
		for( n = 0; n < vector_size; n++) {
			printf("item %d: ", n);
			role_datum_ptr = (sepol_role_datum_t*)apol_vector_get_element(v, n);
			sepol_role_datum_get_name(h, p->p, role_datum_ptr, &type_name);
			printf("%s\n", type_name);
		}
	}
	printf("destroying apol vector\n");
	apol_vector_destroy(&v, NULL);
	printf("destroying role type query structure\n");
	apol_role_query_destroy( &query_s_role );
	printf("============================================ QUERY USERS ==========================================\n\n\n");
	TEST("querying the policy for all users", !apol_get_user_by_query(p, NULL, &v));
	if ( v == NULL) {
		fprintf(stderr, "the vector is NULL, either no results or error");
	} else{
		fprintf(stderr,"there were some users passed back!");
	}
	vector_size = apol_vector_get_size(v);
	printf("the size of the apol_vector structure passed in is %d\n", vector_size);
	printf("printing all the names of each of the datums in the vector\n"); 
	for( n = 0 ; n < vector_size;n++) {
		printf("item %d: ", n);
		user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
		sepol_user_datum_get_name(h, p->p, user_datum_ptr, &type_name);
		printf("%s\n", type_name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v,NULL);

	printf("\n\n---------------GET USER \"joe\"---------------\n");
	user_s = apol_user_query_create();
	if( user_s == NULL){
		fprintf(stderr, "user_s is null\n");
		perror("NULL structure");
	}
	TEST("setting a role name in the apol role query structure", !apol_user_query_set_user(user_s, "joe"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr,"There were no roles with name role_r found\n");
	} else {
		for( n = 0; n < vector_size; n++) {
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(h, p->p, user_datum_ptr, &type_name);
			printf("%s\n", type_name);
		}
	}
	printf("destroying apol vector\n");
	if( user_s == NULL)
	{
		fprintf(stderr, "user_s is null\n");
		exit(-1);
	}
	apol_vector_destroy(&v, NULL);
	printf("\n\n---------------GET REGEX USER \"ro*\"---------------\n");	
	TEST("setting the user query structure to be regex'ed", !apol_user_query_set_regex(user_s, 1));
	TEST("setting the user query strcuture reg ex", !apol_user_query_set_user(user_s, "syst*"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(h, p->p, user_datum_ptr, &type_name);
			printf("%s\n", type_name);
		}
	}
	TEST("setting role to user query structure",!apol_user_query_set_role(user_s, "system_r"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(h, p->p, user_datum_ptr, &type_name);
			printf("%s\n", type_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("\n\n---------------RANDOM MISC. OPERATIONS----------------\n");		
	TEST("calling apol_user_query_set_role on user query structure", !apol_user_query_set_role( user_s, "sysadmin_r"));
	TEST("calling apol_user_query_set_user on user query structure", !apol_user_query_set_user( user_s, "root"));
	apol_mls_level_t * mls_v = apol_mls_level_create();
	TEST("setting the mls_level with sensitivity \"s0\"", !apol_mls_level_set_sens( mls_v, "s0"));
	TEST("appending \"random_cat0\" as a category to the apol_mls_level structure", !apol_mls_level_append_cats( mls_v, "random_cat0"));
	TEST("calling apol_user_query_set_default_level on user query structure", !apol_user_query_set_default_level( user_s, mls_v ));

	printf("destroying the query structure ");
	apol_user_query_destroy(&user_s);
	printf(". . . done\n");
	
	return 0;
}
