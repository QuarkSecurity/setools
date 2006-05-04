#include <sepol/policydb.h>
#include "qpol_wrapper.h"
#include <stdio.h>
/** Open a binary policy using qpol wrapper representation 
    @return 0 on sucess < 0 on error
*/
int qpol_bin_pol_open( const char* path, qpol_t ** qpol_policy );
