#ifndef QPOL_WRAPPER_H
#define QPOL_WRAPPER_H
#include <sepol/policydb.h>

/* define a temporary wrapper until we decide what
   to do with sepol_policydb_t and querpol */
typedef struct qpol_wrapper{
	sepol_policydb_t * policy;
	sepol_handle_t * handle;
}qpol_t;
#endif
