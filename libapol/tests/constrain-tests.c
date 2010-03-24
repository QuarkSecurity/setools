/**
 *  @file
 *
 *  Test the information flow analysis code.
 *
 *
 *  Copyright (C) 2010 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <config.h>

#include <CUnit/CUnit.h>
#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>
#include <string.h>
#include <apol/constraint-query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/constraint.h>

#define CONSTR_SOURCE TEST_POLICIES "/snapshots/rawhide-2.1.6-strict-mls-policy.conf"
#define CONSTR_BINARY TEST_POLICIES "/snapshots/rawhide-2.1.6-strict-mls-policy.20"
// Not sure glob will work 
#define CONSTR_MODULAR TEST_POLICIES "/setools-3.1/modules/*.pp"

static apol_policy_t *ps = NULL;	// Source policy
static apol_policy_t *pb = NULL;	// Binary policy
static apol_policy_t *pm = NULL;	// Modular policy

// The following stolen from constraint_query.c
struct qpol_constraint
{
	const qpol_class_t *obj_class;
	constraint_node_t *constr;
};


static void print_class_perms(FILE * fp, const qpol_class_t * class_datum, const apol_policy_t * policydb, const int expand)
{
	const char *class_name = NULL, *perm_name = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_common_t *common_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (!class_datum)
		goto cleanup;

	if (qpol_class_get_name(q, class_datum, &class_name))
		goto cleanup;
	fprintf(fp, "   %s\n", class_name);

	if (expand) {
		/* get commons for this class */
		if (qpol_class_get_common(q, class_datum, &common_datum))
			goto cleanup;
		if (common_datum) {
			if (qpol_common_get_perm_iter(q, common_datum, &iter))
				goto cleanup;
			/* print perms for the common */
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&perm_name))
					goto cleanup;
				fprintf(fp, "      %s\n", perm_name);
			}
			qpol_iterator_destroy(&iter);
		}
		/* print unique perms for this class */
		if (qpol_class_get_perm_iter(q, class_datum, &iter))
			goto cleanup;
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&perm_name))
				goto cleanup;
			fprintf(fp, "      %s\n", perm_name);
		}
		qpol_iterator_destroy(&iter);
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return;
}

static void constrain_binary(void)
{
	CU_PASS("Not yet implemented")
}

/*	General concepts:  The constraints are stored in the policy by class,
 *	that is, the list of classes stored in the policy has attached to it
 *	whatever constraints affect that class.
 *	The "policy_iter" iterator is a structure which contains a pointer to the
 *	list of classes from the loaded policy, and another pointer to the list of
 *	constraints associated with the current class. This latter pointer is
 *	traversed to its end, at which point the class pointer is updated, and the new class' list of constraints is put in its place. 
 *
 */
static void constrain_source(void)
{
	int i;
	int retval = -1;
	int err=0;
	const char *class_name = NULL;
	const char *constrain_type = "?constrain";
	char *perm_list = "No Perms Extracted";
	const qpol_constraint_expr_node_t *expr = NULL;
	qpol_iterator_t *policy_iter = NULL;	// Iterates over all constraints in a policy
	qpol_iterator_t *perm_iter = NULL;		// Iterates over permissions in a constraint
	qpol_iterator_t *expr_iter = NULL;		// Iterates over expression in a constraint
	qpol_policy_t *q = apol_policy_get_qpol(ps);
	qpol_constraint_t *constraint = NULL;
	const qpol_class_t *class;
//	qpol_constraint_expr_node_t *cexpr = NULL;
//	void *constraintNode = NULL;
	size_t n_constraints = 0;

	err = qpol_policy_get_constraint_iter(q, &policy_iter);
	if (err != 0)
	{
		CU_FAIL("Policy iterator not accessible");
		goto cleanup;
	}
	err = qpol_iterator_get_size(policy_iter, &n_constraints);
	if (err != 0)
	{
		CU_FAIL("Policy size computation failed");
		goto cleanup;
	}

	CU_ASSERT_EQUAL(n_constraints, 158);	// Count of constraints split among all classes

	i=0;
	// Iterate through constraints
	for (; qpol_iterator_end(policy_iter) == 0; qpol_iterator_next(policy_iter))
	{
		i++;
		/* The qpol_constraint_t that is returned below consists of
		 * 	struct qpol_constraint	<<<from constraint_query.c
		 * 	{
		 * 		const qpol_class_t *obj_class;
		 * 		constraint_node_t *constr;
		 * 	};
		 * the qpol_class_t is a pseudonym for class_datum_t from policydb.h
		 * constraint_node_t is defined in sepol/policydb/constraint.h
		 */
		err = qpol_iterator_get_item(policy_iter, (void **)&constraint);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen

		err = qpol_constraint_get_class(q, constraint, &class);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen
		err = qpol_class_get_name(q, class, &class_name);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen

	// print permissions
		printf ("%s { %s } { ", constrain_type, class_name);

		err = qpol_constraint_get_perm_iter (q, constraint, &perm_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		for (; qpol_iterator_end(perm_iter) == 0; qpol_iterator_next(perm_iter))
		{
			err = qpol_iterator_get_item(perm_iter, (void **)&perm_list);
			CU_ASSERT_EQUAL_FATAL(err,0)

			printf ("%s ", perm_list);
			free (perm_list);		// Strdup created the string.
		}
		printf (" } ");

	// dump RPN expressions
		err = qpol_constraint_get_expr_iter (q, constraint, &expr_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		printf ("\n( ");
		for (; qpol_iterator_end(expr_iter) == 0; qpol_iterator_next(expr_iter))
		{
			int expr_type = 0;
			int sym_type = 0;		// 'attr' in struct constraint_expr
			int op = 0;
			qpol_iterator_t *names_iter = NULL;

			err = qpol_iterator_get_item(expr_iter, (void **)&expr);
			CU_ASSERT_EQUAL_FATAL(err,0)

			err = qpol_constraint_expr_node_get_op (q, expr, &op);
			CU_ASSERT_EQUAL_FATAL(err,0)

			err = qpol_constraint_expr_node_get_sym_type(q, expr, &sym_type);
			CU_ASSERT_EQUAL_FATAL(err,0)

			err = qpol_constraint_expr_node_get_expr_type(q, expr, &expr_type);
			CU_ASSERT_EQUAL_FATAL(err,0)

			printf ("\n\t( expr_type=%d attr=%d op=%d", expr_type, sym_type, op);

			CU_ASSERT_PTR_NOT_NULL(q);
			CU_ASSERT_PTR_NOT_NULL(expr);
			CU_ASSERT_PTR_NOT_NULL(&names_iter);
			if (expr_type == QPOL_CEXPR_TYPE_NAMES)
			{
				printf (" names='", expr_type, sym_type, op);
				err = qpol_constraint_expr_node_get_names_iter (q, expr, &names_iter);
				CU_ASSERT_EQUAL_FATAL(err,0)

				for (; qpol_iterator_end(names_iter) == 0; qpol_iterator_next(names_iter))
				{
					char *lname = NULL;

					err = qpol_iterator_get_item (names_iter, (void **)&lname);
					CU_ASSERT_EQUAL_FATAL(err,0)
					printf ("%s ", lname);
					free (lname);

				}
				printf ("'");
			}
			printf (" )");
		}
		printf ("\n);\n\n");
	}

	CU_PASS();

cleanup:
	return;
	// close and destroy iterators/policy pointers
}

static void constrain_modular(void)
{
	CU_PASS("Not yet implemented")
}

CU_TestInfo constrain_tests[] = {
	{"constrain from source policy", constrain_source},
//	{"constrain from binary policy", constrain_binary},
//	{"constrain from modular policy", constrain_modular},
	CU_TEST_INFO_NULL
};

int constrain_init()
{
	// Probably should move this to individual tests, just fstat policy to see if it is there!
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, CONSTR_SOURCE, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((ps = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int constrain_cleanup()
{
	apol_policy_destroy(&ps);
	return 0;
}
