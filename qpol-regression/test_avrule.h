#ifndef TEST_AVRULE_H
#define TEST_AVRULE_H

#include <stdint.h>
#include <string.h>

#define MLS_TEST_BIN "../regression/policy/mls_test.20"
#define MLS_TEST_SRC "../regression/policy/mls_test.conf"
#define NUM_RULETYPES 4

/* rule type defines (values copied from "sepol/policydb/policydb.h") */
#define QPOL_RULE_ALLOW         1
#define QPOL_RULE_NEVERALLOW  128
#define QPOL_RULE_AUDITALLOW    2
/* dontaudit is actually stored as auditdeny so that value is used here */
#define QPOL_RULE_DONTAUDIT     4
/* bitwise OR of all rules */
#define QPOL_RULE_ALL			135

typedef struct qpol_rule_type
{
	uint32_t rule;
	char* name;
} QPOL_RULE;

QPOL_RULE rule_types[] =
{
	{
		QPOL_RULE_ALLOW,
		"ALLOW",
	},
	{
		QPOL_RULE_NEVERALLOW,
		"NEVERALLOW",
	},
	{
		QPOL_RULE_AUDITALLOW,
		"AUDITALLOW",
	},
	{
		QPOL_RULE_DONTAUDIT,
		"DONTAUDIT",
	}
};

#endif
