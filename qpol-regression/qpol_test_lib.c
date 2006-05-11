#include "qpol_test_lib.h"
#include <stdlib.h>
int qpol_bin_pol_open( const char* path, qpol_t ** qpol_policy )
{
	if ((*qpol_policy = calloc(1, sizeof(**qpol_policy))) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return -1;
	}
	return sepol_policydb_open(path, &(*qpol_policy)->policy, &(*qpol_policy)->handle);
}
