#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "test.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

void call_test_funcs(qpol_policy_t *policy);

int main(int argc, char* argv[])
{
	qpol_policy_t *policy;
	TEST("number of arguments", (argc == 3));
	TEST("open binary policy", ! (qpol_open_policy_from_file(argv[1], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	TEST("open source policy", ! (qpol_open_policy_from_file(argv[2], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *constrs, *vtransits, *perms, *expr_nodes, *node_names, *more_constr, *more_vtrans;
	qpol_constraint_t *tmp_constr;
	qpol_class_t *obj_class;
	qpol_constraint_expr_node_t *tmp_node;
	qpol_validatetrans_t *vtrans;
	uint32_t expr_type, sym_type, op;

	constrs = vtransits = perms = expr_nodes = node_names = more_constr = more_vtrans = 0;

	TEST("get constraint iterator", !(qpol_policy_get_constraint_iter(policy, &constrs)));
	while (!qpol_iterator_end(constrs)) {
		TEST("get constraint", !(qpol_iterator_get_item(constrs, (void**)&tmp_constr)));
		TEST("get constraint class", !(qpol_constraint_get_class(policy, tmp_constr, &obj_class)));
		TEST("get constraint iter from class", !(qpol_class_get_constraint_iter(policy, obj_class, &more_constr)));
		TEST("get vtrans inter from class", !(qpol_class_get_validatetrans_iter(policy, obj_class, &more_vtrans)));
		TEST("get permission iterator", !(qpol_constraint_get_perm_iter(policy, tmp_constr, &perms)));
		TEST("get node iterator", !(qpol_constraint_get_expr_iter(policy, tmp_constr, &expr_nodes)));
		while (!qpol_iterator_end(expr_nodes)) {
			qpol_iterator_get_item(expr_nodes, (void**) &tmp_node);
			TEST("get expression type", !(qpol_constraint_expr_node_get_expr_type(policy, tmp_node, &expr_type)));
			TEST("validity of expression type", (expr_type >= 1 && expr_type <= 5));
			if (expr_type == QPOL_CEXPR_TYPE_ATTR || expr_type == QPOL_CEXPR_TYPE_NAMES) {
				TEST("get symbol type", !(qpol_constraint_expr_node_get_sym_type(policy, tmp_node, &sym_type)));
				TEST("validity of symbol type", (sym_type >= 1 && sym_type <= 2047));
				TEST("get operator of expression", !(qpol_constraint_expr_node_get_op(policy, tmp_node, &op)));
				TEST("validity of operator", (op >= 1 && op <= 5));
			}
			if (expr_type == QPOL_CEXPR_TYPE_NAMES) {
				TEST("get iterator of names", !(qpol_constraint_expr_node_get_names_iter(policy, tmp_node, &node_names)));
			}

			qpol_iterator_destroy(&node_names);
			qpol_iterator_next(expr_nodes);
		}
		
		qpol_iterator_destroy(&more_constr);
		qpol_iterator_destroy(&more_vtrans);
		qpol_iterator_destroy(&perms);
		qpol_iterator_destroy(&expr_nodes);
		qpol_iterator_next(constrs);
	}
	qpol_iterator_destroy(&constrs);

	TEST("get validatetrans iterator", !(qpol_policy_get_validatetrans_iter(policy, &vtransits)));
	while (!qpol_iterator_end(vtransits)) {
		qpol_iterator_get_item(vtransits, (void**) &vtrans);
		TEST("get object class from validatetrans statement",
				!(qpol_validatetrans_get_class(policy, vtrans, &obj_class)));
		TEST("get node iterator", !(qpol_validatetrans_get_expr_iter(policy, vtrans, &expr_nodes)));

		qpol_iterator_next(vtransits);
	}
	qpol_iterator_destroy(&vtransits);
}
