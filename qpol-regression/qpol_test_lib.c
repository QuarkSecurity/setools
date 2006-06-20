#include "qpol_test_lib.h"
#include <stdlib.h>
#include <qpol/policy.h>
int qpol_bin_pol_open( const char* path, qpol_t ** qpol_policy )
{
	if ((*qpol_policy = calloc(1, sizeof(**qpol_policy))) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return -1;
	}
	return qpol_open_policy_from_file(path, &(*qpol_policy)->policy, &(*qpol_policy)->handle, NULL, NULL);

}
