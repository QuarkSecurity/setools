#include <sepol/policydb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h" 
#include "qpol_wrapper.h"
#include "qpol_test_lib.h"
#include <sepol/bool_query.h>

#define MLS_POL "../regression/policy/mls_policy.19"
qpol_t * quer_policy;

int main(int argc, char **argv)
{
	char *pol_filename;
	if( argc < 2)
	{
		pol_filename = MLS_POL;
	}
	else
	{
		pol_filename = argv[1];
	}
	TEST("open binary policy", !qpol_bin_pol_open( pol_filename, &quer_policy));
	
	return 0;
}
