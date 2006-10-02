#ifndef QPOL_WRAPPER_H
#define QPOL_WRAPPER_H
#include <qpol/policy.h>

/* define a temporary wrapper until we decide what
   to do with sepol_policydb_t and querpol */
typedef struct qpol_wrapper{
	qpol_policy_t * policy;
}qpol_t;
#endif
