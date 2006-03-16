#include "sepol/handle.h"
#include "sepol/policydb.h"
#include "sepol/policydb-query.h"
#include "policy-io.h"
#include <stdio.h>
#include "component-query.h"
#include <errno.h>
#include "test.h"

static int bin_open_policy(char * pol_path, apol_policy_t** p);
static int type_query(apol_policy_t* p);
static int attribute_query(apol_policy_t *p);
static int role_query (apol_policy_t *p);
static int user_query(  apol_policy_t *p);
static int classes_query(apol_policy_t *p);
static int common_classes_query( apol_policy_t *p);
static int  permissions_query (apol_policy_t *p);
int main(int argc, char ** argv)
{
	apol_policy_t * p;
	char *pol_path = "/home/aferrucci/svn/working/setools/trunk/tests/regression/policy/binary_small.17";
	if (argc > 1) {
		pol_path = argv[1];
	}

	TEST("opening the binary policy file", !bin_open_policy(pol_path, &p));

	if( type_query(p) < 0)
	{
		printf("type_query failed\n");
		exit(-1);
	}

	if( attribute_query(p)< 0)
	{
		printf("attribute_query failed\n");
		exit(-1);
	}
	if( role_query(p) < 0 )
	{
		printf("role_query failed\n");
		exit(-1);
	}
	if( user_query(p) < 0)
	{
		printf("user_query failed\n");
		exit(-1);
	}

	if( classes_query(p) < 0)
	{
		printf("classes_query failed\n");
		exit(-1);
	}
	if( common_classes_query(p ) < 0)
	{
		printf("common_classes_query failed\n");
		exit(-1);
	}

	if( permissions_query(p)< 0)
	{
		printf("permissions_query failed\n");
		exit(-1);
	}
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

	for( ; n < vector_size;n++) {
		printf("item %d: ", n);
		type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
		sepol_type_datum_get_name(p->sh , p->p, type_datum_ptr, &name);
		printf("%s\n", name);
	}
	printf("destroying all the elements in v\n");

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
		for( ; n < vector_size;n++) {
			printf("item %d: ", n);
			type_datum_ptr = (sepol_type_datum_t*)apol_vector_get_element(v, n);
			sepol_type_datum_get_name(p->sh, p->p, type_datum_ptr, &name);
			sepol_type_datum_get_name(p->sh, p->p, (sepol_type_datum_t*)apol_vector_get_element(v, n), &name);
			printf("%s\n", name);
		}
	}
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
	if( apol_policy_is_mls(p) ){
		printf("\n\n---------------MLS QUERIES----------------\n");		
		TEST("calling apol_user_query_set_role on user query structure", !apol_user_query_set_role(p, user_s,NULL ));
		TEST("calling apol_user_query_set_user on user query structure", !apol_user_query_set_user(p, user_s, NULL));
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
		mls_range_var = apol_mls_range_create();
		TEST( "setting the low level of the mls range structure", !apol_mls_range_set_low(p, mls_range_var, mls_v_low));
		TEST( "setting the high level of the mls range structure", !apol_mls_range_set_high(p, mls_range_var, mls_v_high));
		TEST("calling apol_user_query_set_default_level on user query structure", !apol_user_query_set_range(p, user_s, mls_range_var, APOL_QUERY_EXACT));
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
		apol_mls_range_destroy(&mls_range_var);
		apol_vector_destroy(&v, NULL);
	}	
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
