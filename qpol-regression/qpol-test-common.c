#include "qpol-test-common.h"
int bin_open_policy(char * pol_path, apol_policy_t ** p)
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
