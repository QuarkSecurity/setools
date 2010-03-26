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
#include <libqpol/src/queue.h>

#define CONSTR_SOURCE TEST_POLICIES "/setools-3.3/apol/constrain_test_policy.conf"
#define CONSTR_BINARY TEST_POLICIES "/snapshots/rawhide-2.1.6-strict-mls-policy.20"
// Glob won't work, but this gives the idea of where we are trying to go
#define CONSTR_MODULAR TEST_POLICIES "/setools-3.1/modules/*.pp"

#define JJODEBUG 1


/*	General concepts:  The constraints are stored in the policy by class,
 *	that is, the list of classes stored in the policy has attached to it
 *	whatever constraints affect that class.
 *	The "policy_iter" iterator is a structure which contains a pointer to the
 *	list of classes from the loaded policy, and another pointer to the list of
 *	constraints associated with the current class. This latter pointer is
 *	traversed to its end, at which point the class pointer is updated, and the
 *	new class' list of constraints is put in its place. The switch from one
 *	class to the next is done behind the scenes by the iterator. Thus each time
 *	a new item is retrieved from policy_iter, it needs to have all info (class,
 *	permissions, expression) extracted from it.
 *
 *	The input file must be a known file.  The class and permissions are used as
 *	a key by this test routine to determine what the expected expression will
 *	be. Thus, if the input file is modified, this test becomes invalid. The file
 *	(defined above) resides in the 'testing-policies' repository.
 *
 *	The statements validatetrans and mlsvalidatetrans, although similar to
 *	constrain and mlsconstrain, are not considered here.
 *
 */

// Define data for expected policy. This is a hack, but what I could think of
// on short notice.

// Similar to struct constraint_expr from sepol/policydb/constraint.h
// but want char * list of names, not internal representations.
typedef struct local_expr {
	uint32_t expr_type;
	uint32_t attr;
	uint32_t op;
	size_t   name_count;
	char 	**namelist;
} local_expr_t;

typedef struct constrain_test_list {
	char **class;
	char **permissions;	// Must end with NULL
	int test_found;
	int  expr_count;
	local_expr_t **expr_list;
} constrain_test_list_t;


// TODO Need to make local_expr_t entries have parameters not hardcoded numbers
// TODO Need to finish code to compare expression lists
// TODO Need to count number of constrains matched, compare to number existing
// 		to see if test really passed.
char *class0 = "file";
char *perm0[] = { "create", "relabelto", NULL };
local_expr_t expr00 = { 4, 1024, 1, 0, NULL };
local_expr_t *expr0[] = { &expr00 };

char *class1 = "lnk_file";
char *perm1[10] = { "create", "relabelto", NULL };
local_expr_t expr10 = { 4, 1024, 2, 0, NULL };
local_expr_t *expr1[] = { &expr10 };


char *class2 = "fifo_file";
char *perm2[] = { "create", "relabelto", NULL };
local_expr_t expr20 = { 4, 1024, 3, 0, NULL };
local_expr_t *expr2[] = { &expr20 };

constrain_test_list_t test_list[] = {
	{ &class0, perm0, 0, 1, expr0 },
	{ &class1, perm1, 0, 1, expr1 },
	{ &class2, perm2, 0, 1, expr2 }
};

typedef struct compare_perm_str {
	int list_length;
	int list_found;
	char **list;
} compare_perm_str_t;

typedef struct compare_expr_str {
	int list_length;
	int list_found;
	local_expr_t **list;
} compare_expr_str_t;


static apol_policy_t *ps = NULL;	// Source policy
static apol_policy_t *pb = NULL;	// Binary policy
static apol_policy_t *pm = NULL;	// Modular policy

static int doprintstr (queue_element_t e, void *p)
{
	char *s = (char *)e;
	// Second arg is not used

	printf ("%s ", s);
	return 0;
}

static int compare_expr_to_iter(queue_element_t e, void *v)
{
return 0;
}

static int compare_perm_to_queue(queue_element_t e, void *v)
{
	char *pe = (char *)e;
	compare_perm_str_t *x = (compare_perm_str_t *)v;
	char **permlist = x->list;
	char *perm;

	while ((perm=*permlist++) != NULL)
	{
#ifdef JJODEBUG
		printf ("pe = %s\n", pe);
		printf ("perm = %s\n", perm);
#endif
		if (strcmp(pe, perm) == 0)
			x->list_found++;
	}
	return 0;
}

static int compare_perm_list(queue_t perm_q, char **permissions)
{
	compare_perm_str_t x;
	
	x.list_length = 0;
	x.list_found = 0;
	x.list = permissions;

	while (*permissions++ != NULL)
		x.list_length++;

#ifdef JJODEBUG
	printf ("list_length = %d\n", x.list_length);
#endif
	if (queue_map(perm_q, compare_perm_to_queue, &x) != 0)
		return 1;

#ifdef JJODEBUG
	printf ("list length=%d, list_found=%d\n", x.list_length, x.list_found);
#endif
	if (x.list_length != x.list_found)
		return 1;

	return 0;
}
static int compare_expr_list(qpol_iterator_t *expr_iter, local_expr_t **expr_list)
{
	return 0;
}

static void constrain_binary(void)
{
	CU_PASS("Not yet implemented")
}

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
	size_t n_constraints = 0;
	size_t counted_constraints = 0;
	size_t tests_not_found = 0;
	int test_count = sizeof(test_list) / sizeof(constrain_test_list_t);

	queue_t perm_q;		// holds list of permissions, in case more than one

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

	counted_constraints=0;
	// Iterate through constraints
	for (; qpol_iterator_end(policy_iter) == 0; qpol_iterator_next(policy_iter))
	{
		counted_constraints++;
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

#ifdef JJODEBUG
		printf ("Found class %s\n", class_name);
#endif
		// get permission(s)
		err = qpol_constraint_get_perm_iter (q, constraint, &perm_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		perm_q = queue_create();
		for (; qpol_iterator_end(perm_iter) == 0; qpol_iterator_next(perm_iter))
		{
			err = qpol_iterator_get_item(perm_iter, (void **)&perm_list);
			CU_ASSERT_EQUAL_FATAL(err,0)

			err = queue_insert (perm_q, perm_list);
			CU_ASSERT_EQUAL_FATAL(err,0)
//			printf ("%s ", perm_list);
//			free (perm_list);		// Strdup created the string.
		}
//		printf (" } ");
#ifdef JJODEBUG
		printf ("perms: ");
		queue_map(perm_q, doprintstr, NULL);
		printf ("\n");
#endif

		// get RPN expressions
		err = qpol_constraint_get_expr_iter (q, constraint, &expr_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		// At this point, the class, permission list, and expression list (in
		// the iterator) have been identified. Based on expected class/permission
		// combinations, find one which matches, and note that it was found.
		// If not found, count that too.
#ifdef JJODEBUG
		printf ("test count is %d\n", test_count);
#endif
		for (i=0; i<test_count; i++)
		{
			if (strcmp(*(test_list[i].class), class_name) == 0)
			{
#ifdef JJODEBUG
				printf ("Got class match %s\n", class_name);
#endif
				if (compare_perm_list(perm_q, test_list[i].permissions) == 0)
				{
#ifdef JJODEBUG
					printf ("Got permissions list match\n");
#endif
					if (compare_expr_list(expr_iter, test_list[i].expr_list) == 0)
					{
#ifdef JJODEBUG
						printf ("Matched test %d\n", i);
#endif
						test_list[i].test_found = 1;
						break;
					}
#ifdef JJODEBUG
					else
					{
						printf ("Mismatch comparing expression list\n");
					}
#endif
				}
#ifdef JJODEBUG
				else
				{
					printf ("Mismatch comparing permission list\n");
				}
#endif
			}
#ifdef JJODEBUG
			else
			{
				printf ("Mismatch comparing classes %s,%s\n", *(test_list[i].class),class_name);
			}
#endif
		}
#if 1
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
#endif
		printf ("\n);\n\n");
		queue_destroy(perm_q);
	}
#ifdef JJODEBUG
	printf ("\ncounted_constraints=%d, n_constraints=%d\n", counted_constraints, n_constraints);
#endif
	CU_ASSERT_EQUAL(counted_constraints, n_constraints);

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
