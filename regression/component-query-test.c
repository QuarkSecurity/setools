#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb_query.h>
#include "policy-io.h"
#include <stdio.h>
#include "component-query.h"
#include <sepol/portcon_query.h>
#include <sepol/netifcon_query.h>
#include <errno.h>
#include "test.h"
#include "context-query.h"
#define DEF_MLS_POL "policy/mls_policy.19"
#define DEF_NON_MLS_POL "policy/binary_small.17"
#define NON_MLS_CON_TYPE "net_foo_t"
#define NON_MLS_CON_USER "system_u"
#define NON_MLS_CON_ROLE "object_r"
#define MLS_CON_TYPE "netif_lo_t"
#define MLS_CON_USER "system_u"
#define MLS_CON_ROLE "object_r"
static int bin_open_policy(char * pol_path, apol_policy_t** p);
static int type_query(apol_policy_t* p);
static int attribute_query(apol_policy_t *p);
static int role_query (apol_policy_t *p);
static int user_query(  apol_policy_t *p);
static int classes_query(apol_policy_t *p);
static int common_classes_query( apol_policy_t *p);
static int permissions_query (apol_policy_t *p);
static int netifcon_query( apol_policy_t *p);
static int category_query( apol_policy_t *p);
static int levels_query( apol_policy_t * p);
static char * pol_path = DEF_MLS_POL;
int main(int argc, char ** argv)
{
	apol_policy_t * p;
	
	if (argc > 1) {
		pol_path = argv[1];
	}

	TEST("opening the binary policy file", !bin_open_policy(pol_path, &p));

	TEST("querying for types\n", !type_query(p) );

	TEST("querying for attributes\n", !attribute_query(p) );

	TEST("querying for roles\n", !role_query(p) );

	TEST("querying for users\n", !user_query(p) );

	TEST("querying for classes\n",  !classes_query(p));

	TEST("querying for common classes\n", !common_classes_query(p ));

	TEST("querying for permissions\n",!permissions_query(p));

	TEST("querying for ports\n", !portcon_query(p));

	TEST("querying for network interfaces\n", !netifcon_query(p));

	TEST("querying for categories\n", !category_query(p));
	
	TEST("querying for levels\n", !levels_query(p));

	apol_policy_destroy(&p);

	return 0;
}

/**
 *  Open a Binary Policy
 *
 * @param pol_path The full path to the binary policy file
 * @param p Reference to a binary policy structure
 * The caller must free the binary policy structure afterwards
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success, negative on error.
 */
int bin_open_policy(char *pol_path, apol_policy_t ** p)
{
	if(apol_policy_open_binary( 
				pol_path, p) != 0) {
		perror("open binary policy error");
		return(-1);
	}
	if( *p == NULL){
		return -1;
	}
	return 0;
}

/**
 *  Do type query tests on a binary policy
 *
 * @param p The binary policy to do type query tests on.
 *
 * @return 0 on success, negative on error
 */

int type_query(apol_policy_t* p)
{
	sepol_type_datum_t* type_datum_ptr;
	size_t vector_size;
	unsigned int n;
	char *name;
	apol_type_query_t * t;
	apol_vector_t * v;

	printf("============================================ QUERY TYPES ==========================================\n\n\n");
	TEST("querying the policy for all types", !apol_get_type_by_query(p, NULL, &v));
	if(v == NULL) {
		fprintf(stderr, "apol vector struct NULL ... FAILED\n");
		perror("apol vector struct null...FAILED");
		return(-1);
	} else{ 
		printf("Got queries out of apol_get_type_by_query...PASS\n");
	}
	vector_size = apol_vector_get_size(v);
	printf("the size of the apol_vector structure passed in is %d\n", vector_size);
	printf("printing all the names of each of the datums in the vector\n"); 

	for(n = 0 ; n < vector_size;n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(p->sh , p->p, type_datum_ptr, &name);
		printf("%s\n", name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v, NULL);

	printf("\n\n---------------GET dir_t TYPE---------------\n");
	TEST("creating a new apol_type_query_t structure t", (t = apol_type_query_create()));
	TEST("setting the apol_type_query_t structure to type dir_t", !apol_type_query_set_type(p,t, "dir_t"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));
	vector_size = apol_vector_get_size(v);

	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
		printf("%s\n", name);
	}
	apol_type_query_destroy(&t);
	apol_vector_destroy(&v, NULL);
	TEST("creating a new apol_type_query_t structure t", (t = apol_type_query_create()));
	TEST("unsetting my type_query_t structure to NULL name", !apol_type_query_set_type(p,t, NULL) );
	printf("\n\n---------------GET REGEX \"se\" TYPE---------------\n");
	TEST("setting the type_query_t structure to use regex",  !apol_type_query_set_regex(p,t, 1));
	TEST("setting the apol_type_query_t structure to regex se", !apol_type_query_set_type(p,t, "se"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));

	vector_size = apol_vector_get_size(v);

	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
		printf("%s\n", name);
	}

	printf("destroying the query structure\n");
	apol_type_query_destroy(&t);
	apol_vector_destroy(&v, NULL);
	TEST("creating a new apol_type_query_t structure t", (t = apol_type_query_create()));
	printf("\n\n---------------GET REGEX \"ex\" TYPE---------------\n");
	TEST("setting this query structure to do regex", !apol_type_query_set_regex(p,t, 1));
	TEST("setting the apol_type_query_t structure to regex ex", !apol_type_query_set_type(p,t, "ex"));
	TEST("querying the policy with the newly set apol_type_query_t structure", !apol_get_type_by_query(p, t, &v));

	vector_size = apol_vector_get_size(v);
	for( n = 0; n < vector_size; n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
		printf("%s\n", name);
	}

	printf("Destroying query structure\n");
	apol_type_query_destroy(&t);
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;
}

/**
 *  Do attribute query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */

int attribute_query(apol_policy_t *p)
{
	size_t vector_size;
	unsigned int n;
	sepol_type_datum_t* type_datum_ptr;
	apol_attr_query_t *attr_s;
	char * name;
	apol_vector_t * v;
	printf("============================================ QUERY ATTRIBUTES ==========================================\n\n\n");
	TEST("querying the policy for all attributes", !apol_get_attr_by_query(p, NULL, &v));

	if(v == NULL) {
		return -1;
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
		for(n = 0 ; n < vector_size;n++) {
			printf("item %d: ", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
			sepol_type_datum_get_name(p->sh, p->p, (sepol_type_datum_t*)apol_vector_get_element(v, n), &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("\n\n---------------GET ATTRIBUTE \"RANDOM\"---------------\n");

	TEST("creating an apol attribute query structure", (attr_s = apol_attr_query_create())!= NULL);
	TEST("setting attribute name to \"random\" in the attribute query structure", !apol_attr_query_set_attr(p,attr_s, "random"));
	TEST("doing an attribute query with attribute name = \'random\'", !apol_get_attr_by_query( p, attr_s, &v));
	vector_size = apol_vector_get_size(v);

	if(v == NULL) {
		return -1;
	} else{ 
		printf("The vector after get attribute is not NULL...PASS\n");
	}

	if( vector_size == 0 ) {
		printf("the vector size is 0\n");
	} else{
		for( n = 0 ; n < vector_size; n++){

			printf("item %d\n", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
			printf("attribute: %s\n",name );
		}
	}
	apol_vector_destroy(&v, NULL);

	printf("\n\n---------------GET REGEX ATTRIBUTE \"re*\"---------------\n");
	TEST("setting the attribute query structure to be regex'ed", !apol_attr_query_set_regex(p,attr_s, 1));
	TEST("setting the regex of the query structure", !apol_attr_query_set_attr(p,attr_s, "re*"));
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
			sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
			printf("attribute: %s\n",name );

		}
	}
	apol_attr_query_destroy(&attr_s);
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;
}
/**
 *  Do role query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int role_query(apol_policy_t *p)
{
	unsigned int n;
	size_t vector_size;
	sepol_role_datum_t * role_datum_ptr;
	apol_role_query_t * query_s_role;
	char *name;
	apol_vector_t * v;
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
		sepol_role_datum_get_name(p->sh, p->p, role_datum_ptr, &name);
		printf("%s\n", name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v,NULL);

	query_s_role = apol_role_query_create();
	TEST("setting a role name in the apol role query structure", !apol_role_query_set_role(p,query_s_role, "user_r"));
	TEST("re-querying the policy for the specified role", !apol_get_role_by_query(p, query_s_role, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr,"There were no roles with name role_r found\n");
	} else {
		for( n = 0; n < vector_size; n++) {
			printf("item %d: ", n);
			role_datum_ptr = (sepol_role_datum_t*)apol_vector_get_element(v, n);
			sepol_role_datum_get_name(p->sh, p->p, role_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	printf("destroying role type query structure\n");
	apol_role_query_destroy( &query_s_role );
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;	
}

/**
 *  Do user query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int user_query(apol_policy_t *p)
{
	unsigned int n;
	size_t vector_size;
	sepol_user_datum_t * user_datum_ptr;
	apol_user_query_t * user_s;
	char *name;
	apol_mls_range_t * mls_range_var;
	apol_mls_level_t * mls_v_high;
	apol_mls_level_t * mls_v_low;	
	apol_vector_t * v;
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
		sepol_user_datum_get_name(p->sh, p->p, user_datum_ptr, &name);
		printf("%s\n", name);
	}
	printf("destroying all the elements in v\n");
	apol_vector_destroy(&v, NULL);

	printf("\n\n---------------GET USER \"joe\"---------------\n");
	user_s = apol_user_query_create();
	if( user_s == NULL){
		fprintf(stderr, "user_s is null\n");
		perror("NULL structure");
	}
	TEST("setting a role name in the apol role query structure", !apol_user_query_set_user(p,user_s, "joe"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr,"There were no roles with name role_r found\n");
	} else {
		for( n = 0; n < vector_size; n++) {
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(p->sh, p->p, user_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	printf("destroying apol vector\n");
	apol_vector_destroy(&v, NULL);

	apol_user_query_destroy(&user_s);
	user_s = apol_user_query_create();
	if( user_s == NULL)
	{
		fprintf(stderr, "user_s is null\n");
		exit(-1);
	}
	printf("\n\n---------------GET REGEX USER \"ro*\"---------------\n");	
	TEST("setting the user query structure to be regex'ed", !apol_user_query_set_regex(p,user_s, 1));
	TEST("setting the user query strcuture reg ex", !apol_user_query_set_user(p,user_s, "syst*"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(p->sh, p->p, user_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting role to user query structure",!apol_user_query_set_role(p,user_s, "system_r"));
	TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
			sepol_user_datum_get_name(p->sh, p->p, user_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	if( apol_policy_is_mls(p) ){
		printf("\n\n---------------MLS QUERIES----------------\n");		
		TEST("calling apol_user_query_set_role on user query structure", 
				!apol_user_query_set_role(p, user_s,NULL ));
		TEST("calling apol_user_query_set_user on user query structure", 
				!apol_user_query_set_user(p, user_s, NULL));

		mls_v_high = apol_mls_level_create_from_string(p, "s9:c0.c127");
		if( mls_v_high == NULL)
		{
			printf("mls_v_high is NULL\n");
			exit(-1);
		}
		printf("The high level has categories: \n");	
		for( n; (unsigned int)n < apol_vector_get_size( mls_v_high->cats);n++)
		{
			printf("cat[%d]: %s\n",n, (char*)apol_vector_get_element(mls_v_high->cats, n));
		}
		mls_v_low = apol_mls_level_create_from_string(p, "s0");
		if( mls_v_low == NULL)
		{
			printf("mls_v_high is NULL\n");
			exit(-1);
		}
		printf("The low level has sensitivity: %s\n", mls_v_low->sens); 
		printf("The low level has categories: \n");	
		for( n; (unsigned int)n < apol_vector_get_size( mls_v_low->cats);n++)
		{
			printf("cat[%d]: %s\n",n, (char*)apol_vector_get_element(mls_v_high->cats, n));
		}
		apol_vector_destroy(&v, NULL);
		
		mls_range_var = apol_mls_range_create();
		
		TEST( "setting the low level of the mls range structure", 
				!apol_mls_range_set_low(p, mls_range_var, mls_v_low));
		TEST( "setting the high level of the mls range structure", 
				!apol_mls_range_set_high(p, mls_range_var, mls_v_high));

		TEST("calling apol_user_query_set_range on user query structure",  
				!apol_user_query_set_range(p, user_s, mls_range_var, APOL_QUERY_EXACT));
		TEST("re-querying the policy for the specified user", !apol_get_user_by_query(p, user_s, &v));
		vector_size = apol_vector_get_size(v);
		if( vector_size == 0) {
			fprintf(stderr, "vector size is 0, no results\n");
		} else {
			for( n = 0 ; n < vector_size ; n++){
				printf("item %d: ", n);
				user_datum_ptr = (sepol_user_datum_t*)apol_vector_get_element(v, n);
				sepol_user_datum_get_name(p->sh, p->p, user_datum_ptr, &name);
				printf("%s\n", name);
			}
		}
		apol_vector_destroy(&v, NULL);
	}
	printf("about to destroy the user query structure\n");
	apol_user_query_destroy(&user_s);
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;
}

/**
 *  Do classes query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int classes_query(apol_policy_t *p)
{
	size_t vector_size;
	apol_class_query_t * query_s_class;
	sepol_class_datum_t * class_datum_ptr;
	unsigned int n;
	char *name;
	apol_vector_t * v;
	printf("============================================ QUERY CLASSES ==========================================\n\n\n");
	printf("--------LISTING ALL OBJECT CLASSES-------\n");
	TEST("querying policy for all object classes", !apol_get_class_by_query(p, NULL, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			class_datum_ptr = (sepol_class_datum_t*)apol_vector_get_element(v, n);
			sepol_class_datum_get_name(p->sh, p->p, class_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("--------LISTING OBJECT CLASS \"process\"--------\n");
	TEST("creating a class query structure", (query_s_class = apol_class_query_create())!= NULL);
	TEST("assigning class query structure a name", !apol_class_query_set_class(p,query_s_class, "process"));
	TEST("querying the policy for object class \"process\"", !apol_get_class_by_query(p, query_s_class, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0)
	{
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			class_datum_ptr = (sepol_class_datum_t*)apol_vector_get_element(v, n);
			sepol_class_datum_get_name(p->sh, p->p, class_datum_ptr, &name);
			printf("%s\n", name);
		}
	}

	apol_vector_destroy(&v, NULL);
	printf("--------LISTING OBJECT CLASS WITH REGEX \"fi\"--------\n");
	TEST("setting the class query structure to have regex", !apol_class_query_set_regex(p,query_s_class, 1));
	TEST("assigning class query structure a regex", !apol_class_query_set_class(p,query_s_class, "fi"));
	TEST("querying the policy for class", !apol_get_class_by_query(p, query_s_class, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0)
	{
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			class_datum_ptr = (sepol_class_datum_t*)apol_vector_get_element(v, n);
			sepol_class_datum_get_name(p->sh, p->p, class_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("--------LISTING OBJECT CLASSES THAT INHERIT FROM  \"socket\"--------\n");
	TEST("setting query class to have no regex", !apol_class_query_set_regex(p,query_s_class, 0));
	TEST("unsetting name in query class", !apol_class_query_set_class(p,query_s_class, NULL));
	TEST("setting query class common", !apol_class_query_set_common(p,query_s_class, "ipc"));
	TEST("querying the policy for class", !apol_get_class_by_query(p, query_s_class, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			class_datum_ptr = (sepol_class_datum_t*)apol_vector_get_element(v, n);
			sepol_class_datum_get_name(p->sh, p->p, class_datum_ptr, &name);
			printf("%s\n", name);
		}
	}

	apol_class_query_destroy(&query_s_class);
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;
}
/**
 *  Do common classes query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int common_classes_query( apol_policy_t *p)
{
	unsigned int n;
	size_t vector_size;
	char * name;
	apol_common_query_t * query_s_common;
	sepol_common_datum_t* common_datum_ptr;
	apol_vector_t * v;
	printf("============================================ QUERY COMMON CLASSES ==========================================\n\n\n");
	printf("--------LISTING ALL COMMON CLASSES--------\n");
	TEST("querying the policy for all the common classes", !apol_get_common_by_query(p, NULL, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			common_datum_ptr = (sepol_common_datum_t*)apol_vector_get_element(v, n);
			sepol_common_datum_get_name(p->sh, p->p, common_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("--------LISTING COMMON CLASS \"ipc\"--------\n");
	TEST("creating a common query structure", (query_s_common = apol_common_query_create() ) != NULL);
	TEST("setting the common structure with common name \"ipc\"", !apol_common_query_set_common(p, query_s_common, "ipc"));
	TEST("querying the policy for all the common classes", !apol_get_common_by_query(p, query_s_common, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			common_datum_ptr = (sepol_common_datum_t*)apol_vector_get_element(v, n);
			sepol_common_datum_get_name(p->sh, p->p, common_datum_ptr, &name);
			printf("%s\n", name);
		}
	}
	printf("Destroying the vector\n");
	apol_common_query_destroy(&query_s_common);
	apol_vector_destroy(&v,NULL);
	return 0;
}

/**
 *  Do permissions query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int permissions_query (apol_policy_t *p)
{
	unsigned int n;
	int vector_size = 0;
	apol_perm_query_t * query_s_perm;
	char * name;
	apol_vector_t * v;
	printf("============================================ QUERY PERMISSIONS ==========================================\n\n\n");
	printf("--------LISTING ALL PERMISSIONS--------\n");
	TEST("query policy for all permissions", !apol_get_perm_by_query(p, NULL, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			name = (char*)apol_vector_get_element(v, n);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("--------LISTING PERMISSIONS \"bind\"--------\n");
	TEST("creating the permission query structure", (query_s_perm = apol_perm_query_create())!= NULL);
	TEST("setting the permission query structure with permission name \"bind\"", !apol_perm_query_set_perm(p, query_s_perm, "bind"));
	TEST("querying the policy with the permission structure", !apol_get_perm_by_query(p, query_s_perm, &v ));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			name = (char*)apol_vector_get_element(v, n);
			printf("%s\n", name);
		}
	}
	apol_vector_destroy(&v, NULL);
	printf("--------LISTING PERMISSIONS WITH REGEX \"ge\"--------\n");
	TEST("setting the permission structure to be regex'ed" ,!apol_perm_query_set_regex(p, query_s_perm, 1));
	TEST("setting the regex of the permission structure to be \"ge\"", !apol_perm_query_set_perm(p, query_s_perm, "ge"));
	TEST("querying the policy with the new regex'ed permission structure", !apol_get_perm_by_query(p, query_s_perm, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("item %d: ", n);
			name = (char*)apol_vector_get_element(v, n);
			printf("%s\n", name);
		}
	}
	apol_perm_query_destroy(&query_s_perm);	
	printf("Destroying the vector\n");
	apol_vector_destroy(&v,NULL);
	return 0;
}

/**
 *  Do portcon query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return 0 on success, negative on error
 */
int portcon_query(apol_policy_t *p)
{	
	unsigned int n;
	int vector_size = 0;
	char * name;
	char * role_name;
	char * type_name;
	sepol_portcon_t *portcon_tmp_p;
	apol_portcon_query_t * apol_portcon_query_p;
	apol_vector_t * v;
	uint16_t port_p;
	sepol_context_struct_t *context_p = NULL;
	apol_context_t *apol_context_p = NULL;
	sepol_user_datum_t * user_datum_p;
	sepol_role_datum_t * role_datum_p;
	sepol_type_datum_t * type_datum_p;
	apol_mls_range_t * apol_mls_range_p;
	apol_mls_level_t * apol_mls_low_lvl_p;
	apol_mls_level_t * apol_mls_high_lvl_p;

	char * tmp_str = NULL;
	char * context_role, *context_type, *context_user;

	printf("\n============================================ QUERY PORTCONS ==========================================\n\n\n");

	printf("-------- LISTING ALL PORTCONS --------\n");
	TEST("query policy for all portcons", !apol_get_portcon_by_query(p, NULL, &v));

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("port %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			sepol_portcon_get_low_port(p->sh, p->p, portcon_tmp_p, &port_p);
			printf("%d\n", port_p);
		}
	}
	printf("-------- LISTING ALL PORT CONTEXTS --------\n");
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("portcon %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			printf("%d ", port_p);
			sepol_portcon_get_context(p->sh, p->p, portcon_tmp_p, &context_p);
			sepol_context_struct_get_user(p->sh, p->p, context_p, &user_datum_p);
			sepol_user_datum_get_name(p->sh, p->p, user_datum_p, &name);
			sepol_context_struct_get_role(p->sh, p->p, context_p, &role_datum_p);
			sepol_role_datum_get_name(p->sh, p->p, role_datum_p, &role_name);
			sepol_context_struct_get_type(p->sh, p->p, context_p, &type_datum_p);
			sepol_type_datum_get_name(p->sh, p->p, type_datum_p, &type_name);
			printf("%s:%s:%s\n",name, role_name, type_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	/* --- DONE WITH ALL PORTS AND PORT CONTEXTS --- */
	
	TEST("creating an apol portcon structure", (apol_portcon_query_p = apol_portcon_query_create()));

	TEST("setting the protocol of the portcon structure", !apol_portcon_query_set_proto(p, apol_portcon_query_p, 6));
	TEST("setting the low port of the portcon structure", !apol_portcon_query_set_low(p, apol_portcon_query_p, 21));
	TEST("setting the high port of the portcon structure", !apol_portcon_query_set_high(p, apol_portcon_query_p, 21));
	
	if( context_p != NULL){
		TEST("creating an apol context struct from an old sepol context struct",
				(apol_context_p = apol_context_create_from_sepol_context(p, context_p))); 
	}
	else{
		TEST("creating an apol context from scratch", (apol_context_p = apol_context_create()));
		TEST("setting the user of the context structure", !apol_context_set_user(p, apol_context_p, "system_u"));
		TEST("setting the role of the context structure", !apol_context_set_role(p, apol_context_p, "object_r" ));
		TEST("setting the type of the context structure", !apol_context_set_type( p, apol_context_p, "net_foo_t"));
		TEST("creating an mls range", (apol_mls_range_p = apol_mls_range_create()));
		TEST("creating low level", (apol_mls_low_lvl_p = apol_mls_level_create_from_string(p, "s1:c0.c2")));
		TEST("creating high level", (apol_mls_high_lvl_p = apol_mls_level_create_from_string(p, "s2:c0.c4")));
		TEST("setting the low level of the range", !apol_mls_range_set_low(p, apol_mls_range_p, apol_mls_low_lvl_p));
		TEST("setting the high level of the range", !apol_mls_range_set_high(p, apol_mls_range_p, apol_mls_high_lvl_p));
		TEST("setting the range of the context structure", !apol_context_set_range(p, apol_context_p, apol_mls_range_p));
	}
	
	TEST("setting the context of the portcon structure", 
			!apol_portcon_query_set_context(p, apol_portcon_query_p, apol_context_p, APOL_QUERY_EXACT));
		
	TEST("query policy using the created portcon query structure", !apol_get_portcon_by_query(p, apol_portcon_query_p, &v));
	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("port %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			sepol_portcon_get_low_port(p->sh, p->p, portcon_tmp_p, &port_p);
			printf("%d\n", port_p);
		}
	}
	printf("-------- LISTING PORT CONTEXTS THAT MATCH THE QUERY --------\n");

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("portcon %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			printf("%d ", port_p);
			sepol_portcon_get_context(p->sh, p->p, portcon_tmp_p, &context_p);
			sepol_context_struct_get_user(p->sh, p->p, context_p, &user_datum_p);
			sepol_user_datum_get_name(p->sh, p->p, user_datum_p, &name);
			sepol_context_struct_get_role(p->sh, p->p, context_p, &role_datum_p);
			sepol_role_datum_get_name(p->sh, p->p, role_datum_p, &role_name);
			sepol_context_struct_get_type(p->sh, p->p, context_p, &type_datum_p);
			sepol_type_datum_get_name(p->sh, p->p, type_datum_p, &type_name);
			printf("%s:%s:%s\n",name, role_name, type_name);
		}
	}

	apol_vector_destroy(&v, NULL);

	/* --- DONE WITH PORTS AND CONTEXTS USING --- */
	
	printf("-------- QUERYING FOR PORTS WITH SLIGHTLY CHANGED CONTEXT --------\n");

	context_user = strdup("system_u");
	context_role = strdup("object_r");

	if( !strcmp( pol_path, DEF_MLS_POL) )
		context_type = strdup("ssh_port_t");
	else
		context_type = strdup("net_foo_t");
	
	TEST("setting the user of the context structure", !apol_context_set_user(p, apol_context_p, context_user));
	TEST("setting the role of the context structure", !apol_context_set_role(p, apol_context_p, context_role ));
	TEST("setting the type of the context structure", !apol_context_set_type( p, apol_context_p, context_type));
	
	free(context_user);
	free(context_role);
	free(context_type);

	TEST("creating an mls range", (apol_mls_range_p = apol_mls_range_create()));

	TEST("creating low level", (apol_mls_low_lvl_p = apol_mls_level_create_from_string(p, "s1:c0.c2")));
	TEST("creating high level", (apol_mls_high_lvl_p = apol_mls_level_create_from_string(p, "s2:c0.c4")));
	
	TEST("setting the low level of the range", !apol_mls_range_set_low(p, apol_mls_range_p, apol_mls_low_lvl_p));
	TEST("setting the high level of the range", !apol_mls_range_set_high(p, apol_mls_range_p, apol_mls_high_lvl_p));
	TEST("setting the range of the context structure", !apol_context_set_range(p, apol_context_p, apol_mls_range_p));

	TEST("query policy second time with same portcon query structure", !apol_get_portcon_by_query(p, apol_portcon_query_p, &v));

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("port %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			sepol_portcon_get_low_port(p->sh, p->p, portcon_tmp_p, &port_p);
			printf("%d\n", port_p);
		}
	}

	printf("-------- LISTING PORT CONTEXTS THAT MATCH THE QUERY --------\n");

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("portcon %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			printf("%d ", port_p);
			TEST("", !sepol_portcon_get_context(p->sh, p->p, portcon_tmp_p, &context_p));
			TEST("", !sepol_context_struct_get_user(p->sh, p->p, context_p, &user_datum_p));
			TEST("getting the name from the user datum", !sepol_user_datum_get_name(p->sh, p->p, user_datum_p, &name));
			TEST("", !sepol_context_struct_get_role(p->sh, p->p, context_p, &role_datum_p));
			TEST("", !sepol_role_datum_get_name(p->sh, p->p, role_datum_p, &role_name));
			TEST("", !sepol_context_struct_get_type(p->sh, p->p, context_p, &type_datum_p));
			TEST("", !sepol_type_datum_get_name(p->sh, p->p, type_datum_p, &type_name));
			printf("%s:%s:%s\n",name, role_name, type_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	
	printf("-------- QUERYING WITH INVALID STRUCTURE --------\n");
	TEST("setting the user of the context structure", !apol_context_set_user(p, apol_context_p, "random_u"));

	if( ! strcmp(pol_path, DEF_NON_MLS_POL))
	{
		TEST("query policy second time with same portcon query structure (this call fails)", 
				apol_get_portcon_by_query(p, apol_portcon_query_p, &v));
	}
	else
	{
		TEST("query policy second time with same portcon query structure (this call fails)", 
				!apol_get_portcon_by_query(p, apol_portcon_query_p, &v));
	}
	
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("port %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			sepol_portcon_get_low_port(p->sh, p->p, portcon_tmp_p, &port_p);
			printf("%d\n", port_p);
		}
	}

	printf("-------- LISTING PORT CONTEXTS THAT MATCH THE QUERY --------\n");

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("portcon %d: ", n);
			portcon_tmp_p = (sepol_portcon_t*)apol_vector_get_element(v, n);
			printf("%d ", port_p);
			TEST("", !sepol_portcon_get_context(p->sh, p->p, portcon_tmp_p, &context_p));
			TEST("", !sepol_context_struct_get_user(p->sh, p->p, context_p, &user_datum_p));
			TEST("getting the name from the user datum", !sepol_user_datum_get_name(p->sh, p->p, user_datum_p, &name));
			TEST("", !sepol_context_struct_get_role(p->sh, p->p, context_p, &role_datum_p));
			TEST("", !sepol_role_datum_get_name(p->sh, p->p, role_datum_p, &role_name));
			TEST("", !sepol_context_struct_get_type(p->sh, p->p, context_p, &type_datum_p));
			TEST("", !sepol_type_datum_get_name(p->sh, p->p, type_datum_p, &type_name));
			printf("%s:%s:%s\n",name, role_name, type_name);
		}
	}
	apol_portcon_query_destroy(&apol_portcon_query_p);
	apol_vector_destroy(&v,NULL);
	return 0;
}

/**
 *  Do netifcon query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return always returns 0, aborts if any of the tests fail
 */

int netifcon_query(apol_policy_t *p)
{
	apol_vector_t * v;
	sepol_netifcon_t * sepol_netifcon_p;
	char * netifcon_name = NULL;	
	size_t vector_size;
	int n;
	char* dev_name;
	apol_netifcon_query_t * apol_netifcon_query_p;
	apol_context_t * apol_context_p;
	char *tmp_dev_name;

	char * context_user;
	char * context_role;
	char * context_type;

	printf("\n============================================ QUERY NETIFCONS ==========================================\n\n\n");

	TEST("creating a apol netifcon query structure", (apol_netifcon_query_p = apol_netifcon_query_create()));
	
	TEST("creating an apol context from scratch", (apol_context_p = apol_context_create( )));
	
	if( strcmp( pol_path,DEF_MLS_POL )==0){
		TEST("setting the type of the context structure", 
				!apol_context_set_type(p, apol_context_p, "unlabeled_t"));
		TEST("setting the user of the context structure", 
				!apol_context_set_user(p, apol_context_p, "system_u"));
		TEST("setting the role of the context structure", 
				!apol_context_set_role(p, apol_context_p, "object_r")); 
	}
	else{
		TEST("setting the type of the context structure", 
				!apol_context_set_type(p, apol_context_p, "net_foo_t"));
		TEST("setting the user of the context structure", 
				!apol_context_set_user(p, apol_context_p, "system_u"));
		TEST("setting the role of the context structure", 
				!apol_context_set_role(p, apol_context_p, "object_r")); 
	}
	
	TEST("setting the interface messages context", 
			!apol_netifcon_query_set_msg_context(p, apol_netifcon_query_p,apol_context_p,APOL_QUERY_EXACT));
	TEST("query policy all netifcons with matching msg contexts",	 
			!apol_get_netifcon_by_query(p,apol_netifcon_query_p , &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0)
	{
		fprintf(stderr, "vector size is 0, no results\n");
	} 
	else 
	{
		for( n = 0 ; n < vector_size ; n++)
		{
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name);
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the interface messages context", 
			!apol_netifcon_query_set_msg_context(p, apol_netifcon_query_p,NULL,APOL_QUERY_EXACT));
		

	/*apol_context_destroy(&apol_context_p);*/
	/*TEST("creating a apol netifcon query structure", !(apol_netifcon_query_p = apol_netifcon_query_create())==NULL);*/

	TEST("setting the netifcon query structure's device to \"lo\"", 
			!apol_netifcon_query_set_device(p, apol_netifcon_query_p, "lo"));

	TEST("query policy for netifcons that fit query structure", 
			!apol_get_netifcon_by_query(p, apol_netifcon_query_p, &v));

	printf("-------- LISTING NETIFCONS WITH INTERFACE NAME \"lo\"  --------\n");

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			TEST("getting the name of the netifcon", 
					!sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name));
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	printf("-------- LISTING ALL NETIFCONS --------\n");
	TEST("query policy all netifcons (NULL)", 
			!apol_get_netifcon_by_query(p, NULL, &v));

	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name);
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	printf("-------- DOING ANOTHER QUERY, STRUCTURE ONLY HAS DEVICE SET TO \"lo1\" --------\n");
	TEST("setting the netifcon query structure's device to \"l01\"", 
			!apol_netifcon_query_set_device(p, apol_netifcon_query_p, "lo1"));

	TEST("query policy with query structure", !apol_get_netifcon_by_query(p, apol_netifcon_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if(vector_size == 0){
		fprintf(stderr, "vector size is 0, no results\n");
	}else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			TEST("getting the name of the netifcon", 
					!sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name));
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v,NULL);
	printf("-------- DOING QUERY WITH DEVICE \"lo\" AND CONTEXT \"system_u:object_r:netif_lo_t\" --------\n");
	TEST("setting the netifcon query structure's device to \"lo\"", 
			!apol_netifcon_query_set_device(p, apol_netifcon_query_p, "lo"));
	TEST("creating an apol context from scratch", (apol_context_p = apol_context_create( )));
	
	if( !strcmp(pol_path,DEF_NON_MLS_POL) )
	{
		context_type = strdup(NON_MLS_CON_TYPE);
		context_role = strdup(NON_MLS_CON_ROLE);
		context_user = strdup(NON_MLS_CON_USER);
	}
	else
	{
		context_type = strdup(MLS_CON_TYPE);
		context_role = strdup(MLS_CON_ROLE);
		context_user = strdup(MLS_CON_USER);
	}
	
	TEST("setting the type of the context structure", !apol_context_set_type(p, apol_context_p, context_type));
	TEST("setting the user of the context structure", !apol_context_set_user(p, apol_context_p, context_user));
	TEST("setting the role of the context structure", !apol_context_set_role(p, apol_context_p, context_role)); 
	free(context_type);
	free(context_role);
	free(context_user);

	TEST("querying netifcons based on a context and a netifcon query structure",
			!apol_netifcon_query_set_if_context(p, apol_netifcon_query_p, apol_context_p, APOL_QUERY_EXACT)); 

	TEST("query policy all netifcons (NULL)", 
			!apol_get_netifcon_by_query(p,apol_netifcon_query_p , &v));

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name);
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v,NULL);

	printf("-------- DOING QUERY WITH DEVICE \"eth1\" --------\n");
	TEST("setting the netifcon query structure's device to \"eth1\"", 
			!apol_netifcon_query_set_device(p, apol_netifcon_query_p, "eth1"));
	TEST("querying netifcons based on a context and a netifcon query structure",
			!apol_netifcon_query_set_if_context(p, apol_netifcon_query_p, NULL, APOL_QUERY_EXACT)); 
	TEST("query policy all netifcons (NULL)", 
			!apol_get_netifcon_by_query(p,apol_netifcon_query_p , &v));

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
			sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name);
			printf("%s\n", netifcon_name);
		}
	}
	apol_vector_destroy(&v,NULL);

	if( strcmp(pol_path, DEF_MLS_POL)==0)
	{
		TEST("unsetting the netifcon's device to \"NULL\"", 
			!apol_netifcon_query_set_device(p, apol_netifcon_query_p, NULL));
		TEST("creating an apol context from scratch", (apol_context_p = apol_context_create( )));
		printf("I'M IN MLS POLICY AND DOING MSG CONTEXT!!!!!!!!!!!!!!!!\n");
		
		context_type = strdup("system_u");
		context_role = strdup("object_r");
		context_user = strdup("unlabeled_t");

		TEST("setting the type of the context structure", 
				!apol_context_set_type(p, apol_context_p, "unlabeled_t"));
		TEST("setting the user of the context structure", 
				!apol_context_set_user(p, apol_context_p, "system_u"));
		TEST("setting the role of the context structure", 
				!apol_context_set_role(p, apol_context_p, "object_r")); 

		free(context_type);
		free(context_role);
		free(context_user);

		TEST("setting the interface messages context", 
				!apol_netifcon_query_set_msg_context(p, apol_netifcon_query_p,apol_context_p,APOL_QUERY_EXACT));
		
		TEST("query policy all netifcons with matching msg contexts", 
				!apol_get_netifcon_by_query(p,apol_netifcon_query_p , &v));
			
		vector_size = apol_vector_get_size(v);

		if( vector_size == 0) {
			fprintf(stderr, "vector size is 0, no results\n");
		} else {
			for( n = 0 ; n < vector_size ; n++){
				printf("netif %d: ", n);
				sepol_netifcon_p = (sepol_netifcon_t*)apol_vector_get_element(v, n);
				sepol_netifcon_get_name(p->sh, p->p, sepol_netifcon_p, &netifcon_name);
				printf("%s\n", netifcon_name);
			}
		}
	}

	apol_vector_destroy(&v,NULL);
	apol_netifcon_query_destroy( &apol_netifcon_query_p);
	return 0;
}

/**
 *  Do category query tests on a binary policy
 *
 * @param p The binary policy to do query query tests on.
 *
 * @return always returns 0, aborts if any of the tests fail
 */
static int category_query( apol_policy_t *p)
{
	apol_vector_t * v;
	int vector_size;
	sepol_cat_datum_t * cat_datum_p;
	char * cat_name;
	apol_cat_query_t * apol_cat_query_p;
	int n;
	TEST("getting all categories in the policy", !apol_get_cat_by_query(p, NULL, &v));	
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			cat_datum_p = (sepol_cat_datum_t*)apol_vector_get_element(v, n);
			sepol_cat_datum_get_name(p->sh, p->p, cat_datum_p, &cat_name);
			printf("%s\n",cat_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("creating a category structure", !((apol_cat_query_p = apol_cat_query_create())==NULL));
	TEST("setting the name of the category query", !apol_cat_query_set_cat(p, apol_cat_query_p, "c9"));
	
	TEST("getting the categories that match the name \"c9\"", 
			!apol_get_cat_by_query(p, apol_cat_query_p, &v));	
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			cat_datum_p = (sepol_cat_datum_t*)apol_vector_get_element(v, n);
			sepol_cat_datum_get_name(p->sh, p->p, cat_datum_p, &cat_name);
			printf("%s\n",cat_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	
	TEST("setting the category name to \"c245\"", !apol_cat_query_set_cat(p, apol_cat_query_p, "c245"));
	TEST("getting the categories that match the name \"c245\"", 
			!apol_get_cat_by_query(p, apol_cat_query_p, &v));

	vector_size = apol_vector_get_size(v);

	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			cat_datum_p = (sepol_cat_datum_t*)apol_vector_get_element(v, n);
			sepol_cat_datum_get_name(p->sh, p->p, cat_datum_p, &cat_name);
			printf("%s\n",cat_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	TEST("setting the catagory structure to use regexes\n", !apol_cat_query_set_regex(p, apol_cat_query_p, 1) );
	TEST("setting the regex of the catagory structure\n", !apol_cat_query_set_cat(p, apol_cat_query_p, "c"));
	TEST("getting the queries that match the regex",
			!apol_get_cat_by_query(p, apol_cat_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			cat_datum_p = (sepol_cat_datum_t*)apol_vector_get_element(v, n);
			sepol_cat_datum_get_name(p->sh, p->p, cat_datum_p, &cat_name);
			printf("%s\n",cat_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	TEST("setting the regex of the catagory structure\n", !apol_cat_query_set_cat(p, apol_cat_query_p, "x"));
	TEST("getting the queries that match the regex",
			!apol_get_cat_by_query(p, apol_cat_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("netif %d: ", n);
			cat_datum_p = (sepol_cat_datum_t*)apol_vector_get_element(v, n);
			sepol_cat_datum_get_name(p->sh, p->p, cat_datum_p, &cat_name);
			printf("%s\n",cat_name);
		}
	}
	apol_cat_query_destroy(&apol_cat_query_p);
	apol_vector_destroy(&v, NULL);
	return 0;
}
int levels_query( apol_policy_t * p)
{
	int n, r;
	apol_vector_t * v = NULL;
	sepol_level_datum_t * se_lvl_datum_p = NULL ;
	/*apol_mls_level_t * apol_level_query_p = NULL;*/
	apol_level_query_t * ap_lvl_query_p;
	char * level_name;
	int vector_size;
	int sz;
	printf("\n============================================ QUERY LEVELS ==========================================\n\n\n");
	TEST("getting all levels defined in the policy", !apol_get_level_by_query(p, NULL, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	TEST("creating a level query structure", (ap_lvl_query_p = apol_level_query_create()));
	TEST("setting the sensitivity of the level structure to s8", !apol_level_query_set_sens(p, ap_lvl_query_p, "s8"));
	apol_vector_destroy(&v, NULL);
	TEST("re-querying the policy with new structure with sensititivy \"s8\"", !apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);

	TEST("setting the sensitivity of the level structure to s56", !apol_level_query_set_sens(p, ap_lvl_query_p, "s56"));
	TEST("re-querying the policy with new structure with sensititivy \"s56\"", !apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the sensitivity to NULL\n", !apol_level_query_set_sens(p, ap_lvl_query_p, NULL));
	TEST("setting level query structure to return levels with category \"c5\"", !apol_level_query_set_cat(p, ap_lvl_query_p, "c5"));
	TEST("re-querying the policy with the new structure with category \"c5\" and sensitivity: NULL\n", 
			!apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the level to use regex", 	!apol_level_query_set_regex(p, ap_lvl_query_p, 1));
	TEST("setting the category to regex \"c*\"", !apol_level_query_set_cat(p, ap_lvl_query_p, "c"));
	TEST("re-querying the policy with the new structure with category rexeg \"c*\" and sensitivity: NULL\n", 
			!apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the category to regex \"s*\"", !apol_level_query_set_cat(p, ap_lvl_query_p, "u"));
	TEST("re-querying the policy with the new structure with category regex \"u*\" and sensitivity: NULL\n", 
			!apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the category NULL", !apol_level_query_set_cat(p, ap_lvl_query_p, NULL));
	TEST("setting the category to regex \"s*\"", !apol_level_query_set_sens(p, ap_lvl_query_p, "s"));
	TEST("re-querying the policy with the new structure with sensitivity regex \"s*\" and category: NULL\n", 
			!apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_vector_destroy(&v, NULL);
	TEST("setting the category to regex \"s*\"", !apol_level_query_set_sens(p, ap_lvl_query_p, "p"));
	TEST("re-querying the policy with the new structure with sensitivity regex \"p*\" and category: NULL\n", 
			!apol_get_level_by_query(p, ap_lvl_query_p, &v));
	vector_size = apol_vector_get_size(v);
	if( vector_size == 0) {
		fprintf(stderr, "vector size is 0, no results\n");
	} else {
		for( n = 0 ; n < vector_size ; n++){
			printf("level %d: ", n);
			se_lvl_datum_p = (sepol_level_datum_t*)apol_vector_get_element(v, n);
			sepol_level_datum_get_name(p->sh, p->p, se_lvl_datum_p, &level_name);
			printf("%s\n",level_name);
		}
	}
	apol_level_query_destroy(&ap_lvl_query_p);
	apol_vector_destroy(&v, NULL);
	return 0;
}
