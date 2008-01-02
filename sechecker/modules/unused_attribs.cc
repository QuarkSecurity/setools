/**
 *  @file
 *  Implementation of the unused attributes module.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "unused_attribs.hh"
#include "sechecker.hh"
#include "module.hh"
#include "result.hh"

#include <polsearch/polsearch.hh>

#include <apol/policy.h>
#include <qpol/policy_extend.h>

#include <vector>
#include <string>
#include <map>
#include <stdexcept>

using std::vector;
using std::string;
using std::map;
using std::pair;
using std::make_pair;
using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::bad_alloc;

void *unused_attribs_init(void)
{
	return static_cast < void *>(new sechk::unused_attribs_module());
}

namespace sechk
{
	unused_attribs_module::unused_attribs_module() throw(std::invalid_argument, std::out_of_range):module("unused_attribs",
													      SECHK_SEV_LOW,
													      "Find attributes not used in rules or constraints.",
													      "Attributes not used in a rule or constraint do not change the enforcement of \n"
													      "the policy; it is usually safe to remove these attributes.")
	{
		requirement req_attr_names(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES);
		if (_requirements.insert(make_pair(req_attr_names.name(), req_attr_names)).second == false)
		{
			throw out_of_range("Error setting requirements");
		}
		requirement rec_neverallow(SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW);
		if (_recommendations.insert(make_pair(rec_neverallow.name(), rec_neverallow)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
		requirement rec_syn_rules(SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES);
		if (_recommendations.insert(make_pair(rec_syn_rules.name(), rec_syn_rules)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
	}

	unused_attribs_module::unused_attribs_module(const unused_attribs_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	unused_attribs_module::~unused_attribs_module()
	{
		// nothing to do
	}

	void unused_attribs_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		apol_vector_t *attributes = NULL;
		apol_attr_get_by_query(pol, NULL, &attributes);

		apol_avrule_query_t *avq = apol_avrule_query_create();
		if (!avq)
			throw bad_alloc();
		if (_recommendations.at(require_code_name(SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW)).check(pol, list))
		{
			apol_avrule_query_set_rules(pol, avq,
						    (QPOL_RULE_ALLOW | QPOL_RULE_DONTAUDIT | QPOL_RULE_AUDITALLOW |
						     QPOL_RULE_NEVERALLOW));
		}
		else
		{
			apol_avrule_query_set_rules(pol, avq, (QPOL_RULE_ALLOW | QPOL_RULE_DONTAUDIT | QPOL_RULE_AUDITALLOW));
		}
		apol_avrule_query_set_source_component(pol, avq, APOL_QUERY_SYMBOL_IS_ATTRIBUTE);
		apol_avrule_query_set_source_any(pol, avq, 1);

		apol_terule_query_t *teq = apol_terule_query_create();
		if (!teq)
			throw bad_alloc();
		apol_terule_query_set_source_component(pol, teq, APOL_QUERY_SYMBOL_IS_ATTRIBUTE);
		apol_terule_query_set_source_any(pol, teq, 1);

		if (_recommendations.at(require_code_name(SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES)).check(pol, list))
		{
			qpol_policy_build_syn_rule_table(apol_policy_get_qpol(pol));
		}

		for (size_t i = 0; i < apol_vector_get_size(attributes); i++)
		{
			qpol_type_t *cur_attr = NULL;
			cur_attr = static_cast < qpol_type_t * >(apol_vector_get_element(attributes, i));
			const char *name = NULL;
			qpol_type_get_name(apol_policy_get_qpol(pol), cur_attr, &name);
			apol_avrule_query_set_source(pol, avq, name, 0);
			apol_terule_query_set_source(pol, teq, name, 0);

			//search access vector rules
			apol_vector_t *avrules = NULL;
			if (apol_avrule_get_by_query(pol, avq, &avrules))
			{
				throw runtime_error("Error searching access vector rules");
			}
			if (apol_vector_get_size(avrules))
			{
				apol_vector_destroy(&avrules);
				continue;
			}
			apol_vector_destroy(&avrules);

			//search type rules
			apol_vector_t *terules = NULL;
			if (apol_terule_get_by_query(pol, teq, &terules))
			{
				throw runtime_error("Error searching type rules");
			}
			if (apol_vector_get_size(terules))
			{
				apol_vector_destroy(&terules);
				continue;
			}
			apol_vector_destroy(&terules);

			//if available search syntactic rules
			if (_recommendations.at(require_code_name(SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES)).check(pol, list))
			{
				apol_vector_t *syn_avrules = NULL;
				if (apol_syn_avrule_get_by_query(pol, avq, &syn_avrules))
				{
					throw runtime_error("Error searching syntactic access vector rules");
				}
				if (apol_vector_get_size(syn_avrules))
				{
					apol_vector_destroy(&syn_avrules);
					continue;
				}
				apol_vector_destroy(&syn_avrules);

				apol_vector_t *syn_terules = NULL;
				if (apol_syn_terule_get_by_query(pol, teq, &syn_terules))
				{
					throw runtime_error("Error searching syntactic type rules");
				}
				if (apol_vector_get_size(syn_terules))
				{
					apol_vector_destroy(&syn_terules);
					continue;
				}
				apol_vector_destroy(&syn_terules);
			}

			//search constraints
			bool used = false;
			apol_vector_t *constraints = NULL;
			apol_constraint_get_by_query(pol, NULL, &constraints);
			for (size_t j = 0; j < apol_vector_get_size(constraints); j++)
			{
				qpol_constraint_t *cur_constr =
					static_cast < qpol_constraint_t * >(apol_vector_get_element(constraints, j));
				qpol_iterator_t *expr_iter = NULL;
				qpol_constraint_get_expr_iter(apol_policy_get_qpol(pol), cur_constr, &expr_iter);
				for ( /* already initialized */ ; !qpol_iterator_end(expr_iter); qpol_iterator_next(expr_iter))
				{
					qpol_constraint_expr_node_t *node = NULL;
					qpol_iterator_get_item(expr_iter, reinterpret_cast < void **>(&(node)));
					uint32_t node_type = 0;
					qpol_constraint_expr_node_get_expr_type(apol_policy_get_qpol(pol), node, &node_type);
					if (node_type != QPOL_CEXPR_TYPE_NAMES)
						continue;
					uint32_t sym_type = 0;
					qpol_constraint_expr_node_get_sym_type(apol_policy_get_qpol(pol), node, &sym_type);
					if (!(sym_type & QPOL_CEXPR_SYM_TYPE))
						continue;
					qpol_iterator_t *name_iter = NULL;
					qpol_constraint_expr_node_get_names_iter(apol_policy_get_qpol(pol), node, &name_iter);
					for ( /* already initialized */ ; !qpol_iterator_end(name_iter);
					     qpol_iterator_next(name_iter))
					{
						char *expr_name = NULL;
						qpol_iterator_get_item(name_iter, reinterpret_cast < void **>(&expr_name));
						if (string(name) == (expr_name[0] == '-' ? expr_name + 1 : expr_name))
							used = true;
						free(expr_name);
					}
					qpol_iterator_destroy(&name_iter);

				}
				qpol_iterator_destroy(&expr_iter);
			}
			apol_vector_destroy(&constraints);
			if (used)
				continue;

			//search validatetrans
			apol_vector_t *validatetrans;
			apol_validatetrans_get_by_query(pol, NULL, &validatetrans);
			for (size_t j = 0; j < apol_vector_get_size(validatetrans); j++)
			{
				qpol_validatetrans_t *cur_constr =
					static_cast < qpol_validatetrans_t * >(apol_vector_get_element(validatetrans, j));
				qpol_iterator_t *expr_iter = NULL;
				qpol_validatetrans_get_expr_iter(apol_policy_get_qpol(pol), cur_constr, &expr_iter);
				for ( /* already initialized */ ; !qpol_iterator_end(expr_iter); qpol_iterator_next(expr_iter))
				{
					qpol_constraint_expr_node_t *node = NULL;
					qpol_iterator_get_item(expr_iter, reinterpret_cast < void **>(&(node)));
					uint32_t node_type = 0;
					qpol_constraint_expr_node_get_expr_type(apol_policy_get_qpol(pol), node, &node_type);
					if (node_type != QPOL_CEXPR_TYPE_NAMES)
						continue;
					uint32_t sym_type = 0;
					qpol_constraint_expr_node_get_sym_type(apol_policy_get_qpol(pol), node, &sym_type);
					if (!(sym_type & QPOL_CEXPR_SYM_TYPE))
						continue;
					qpol_iterator_t *name_iter = NULL;
					qpol_constraint_expr_node_get_names_iter(apol_policy_get_qpol(pol), node, &name_iter);
					for ( /* already initialized */ ; !qpol_iterator_end(name_iter);
					     qpol_iterator_next(name_iter))
					{
						char *expr_name = NULL;
						qpol_iterator_get_item(name_iter, reinterpret_cast < void **>(&expr_name));
						if (string(name) == (expr_name[0] == '-' ? expr_name + 1 : expr_name))
							used = true;
						free(expr_name);
					}
					qpol_iterator_destroy(&name_iter);

				}
				qpol_iterator_destroy(&expr_iter);
			}
			apol_vector_destroy(&validatetrans);
			if (used)
				continue;

			//if here add result entry
			element attr(cur_attr, NULL, NULL);
			result::entry & cur_result = _results.addEntry(attr);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Attribute is not used in rules or constraints.");
		}

		apol_avrule_query_destroy(&avq);
		apol_terule_query_destroy(&teq);
		apol_vector_destroy(&attributes);
	}
}
