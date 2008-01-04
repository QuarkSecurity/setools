/**
 *  @file
 *  Implementation of the impossible range transitions module.
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

#include "imp_range_trans.hh"
#include "sechecker.hh"
#include "module.hh"
#include "result.hh"

#include <polsearch/polsearch.hh>

#include <apol/policy.h>

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

void *imp_range_trans_init(void)
{
	return static_cast < void *>(new sechk::imp_range_trans_module());
}

namespace sechk
{
	imp_range_trans_module::imp_range_trans_module() throw(std::invalid_argument, std::out_of_range):module("imp_range_trans",
														SECHK_SEV_MED,
														"Find impossible range transitions.",
														"A range transition is possible if and only if all of the following conditions\n"
														"are satisfied:\n"
														"   1) there exist TE rules allowing the range transition to occur\n"
														"   2) there exist RBAC rules allowing the range transition to occur\n"
														"   3) at least one user must be able to transition to the target MLS range")
	{
		requirement req_mls(SECHK_REQUIRE_MLS);
		if (_requirements.insert(make_pair(req_mls.name(), req_mls)).second == false)
		{
			throw out_of_range("Error setting requirements");
		}
	}

	imp_range_trans_module::imp_range_trans_module(const imp_range_trans_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	imp_range_trans_module::~imp_range_trans_module()
	{
		// nothing to do
	}

	void imp_range_trans_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		apol_vector_t *range_trans_rules = NULL;
		apol_range_trans_get_by_query(pol, NULL, &range_trans_rules);
		qpol_policy_t *q = apol_policy_get_qpol(pol);

		for (size_t i = 0; i < apol_vector_get_size(range_trans_rules); i++)
		{
			// gather rule info
			qpol_range_trans_t *cur_rule =
				static_cast < qpol_range_trans_t * >(apol_vector_get_element(range_trans_rules, i));
			const qpol_type_t *source = NULL;
			const char *source_name = NULL;
			qpol_range_trans_get_source_type(q, cur_rule, &source);
			qpol_type_get_name(q, source, &source_name);
			const qpol_type_t *target = NULL;
			const char *target_name = NULL;
			qpol_range_trans_get_target_type(q, cur_rule, &target);
			qpol_type_get_name(q, target, &target_name);
			const qpol_class_t *obj_class = NULL;
			const char *obj_class_name = NULL;
			qpol_range_trans_get_target_class(q, cur_rule, &obj_class);
			qpol_class_get_name(q, obj_class, &obj_class_name);
			const qpol_mls_range_t *qpol_range = NULL;
			qpol_range_trans_get_range(q, cur_rule, &qpol_range);
			apol_mls_range_t *range = apol_mls_range_create_from_qpol_mls_range(pol, qpol_range);
			if (!range)
				throw bad_alloc();

			// 1) there exist TE rules allowing the range transition to occur
			apol_avrule_query_t *avq = apol_avrule_query_create();
			if (!avq)
				throw bad_alloc();
			apol_avrule_query_set_rules(pol, avq, QPOL_RULE_ALLOW);
			apol_avrule_query_set_source(pol, avq, source_name, 1);
			apol_avrule_query_set_target(pol, avq, target_name, 1);
			if (string(obj_class_name) == "process")
			{
				apol_avrule_query_append_class(pol, avq, "file");
				apol_avrule_query_append_perm(pol, avq, "execute");
			}
			else
			{
				apol_avrule_query_append_class(pol, avq, obj_class_name);
				if (validate_permission(q, obj_class, "create"))
				{
					apol_avrule_query_append_perm(pol, avq, "create");
				}
				else
				{
					//other object classes do not make sense; ignore if found
					apol_avrule_query_destroy(&avq);
					continue;
				}
			}
			apol_vector_t *avrules = NULL;
			apol_avrule_get_by_query(pol, avq, &avrules);
			apol_avrule_query_destroy(&avq);
			if (!apol_vector_get_size(avrules))
			{
				// add proof missing av rule
				element rt_elem(cur_rule, NULL, NULL);
				result::entry & rt_entry = _results.addEntry(rt_elem);
				string *missing_rule =
					new string(string("allow ") + source_name + " " + target_name + " : file execute;");
				element missing_elem(missing_rule, std_string_free, std_string_dup);
				rt_entry.addProof(missing_elem, "Missing: ");
			}
			apol_vector_destroy(&avrules);

			// 2) there exist RBAC rules allowing the range transition to occur
			apol_role_query_t *role_query = apol_role_query_create();
			apol_role_query_set_type(pol, role_query, source_name);
			apol_vector_t *source_roles = NULL;
			apol_role_get_by_query(pol, role_query, &source_roles);
			apol_role_query_destroy(&role_query);
			// remove object_r
			const qpol_role_t *object_r = NULL;
			qpol_policy_get_role_by_name(q, "object_r", &object_r);
			size_t idx = 0;
			if (!apol_vector_get_index(source_roles, static_cast < const void *>(object_r), NULL, NULL, &idx))
				apol_vector_remove(source_roles, idx);
			vector < string > role_names;
			if (!apol_vector_get_size(source_roles))
			{
				// add proof source domian has no role
				element rt_elem(cur_rule, NULL, NULL);
				result::entry & rt_entry = _results.addEntry(rt_elem);
				string *missing_role = new string(string("No role associated with type ") + source_name);
				element missing_elem(missing_role, std_string_free, std_string_dup);
				rt_entry.addProof(missing_elem, "");
			}
			else
			{
				for (size_t j = 0; j < apol_vector_get_size(source_roles); j++)
				{
					const char *role_name = NULL;
					const qpol_role_t *role =
						static_cast < const qpol_role_t * >(apol_vector_get_element(source_roles, j));
					qpol_role_get_name(q, role, &role_name);
					role_names.push_back(string(role_name));
				}
			}

			// 3) at least one user must be able to transition to the target MLS range
			polsearch_user_query user_query(POLSEARCH_MATCH_ALL);
			polsearch_test & range_test = user_query.addTest(POLSEARCH_TEST_RANGE);
			polsearch_criterion & range_crit = range_test.addCriterion(POLSEARCH_OP_RANGE_SUPER);
			polsearch_range_parameter *range_param = new polsearch_range_parameter(range);
			range_crit.param(range_param);
			vector < polsearch_result > range_only_results = user_query.run(pol, list);
			vector < polsearch_result > role_results;	// empty if no roles
			if (!range_only_results.size())
			{
				// add proof no user with range
				element rt_elem(cur_rule, NULL, NULL);
				result::entry & rt_entry = _results.addEntry(rt_elem);
				char *rng_str = apol_mls_range_render(pol, range);
				string *missing_rng = new string(string("No user with range ") + rng_str);
				free(rng_str);
				element missing_elem(missing_rng, std_string_free, std_string_dup);
				rt_entry.addProof(missing_elem, "");
			}
			else if (role_names.size())
			{
				polsearch_test & role_test = user_query.addTest(POLSEARCH_TEST_ROLES);
				polsearch_criterion & role_crit = role_test.addCriterion(POLSEARCH_OP_INCLUDE);
				polsearch_string_expression_parameter *role_param =
					new polsearch_string_expression_parameter(role_names);
				role_crit.param(role_param);
				role_results = user_query.run(pol, list);
				if (!role_results.size())
				{
					// add proof no user with range and valid role
					element rt_elem(cur_rule, NULL, NULL);
					result::entry & rt_entry = _results.addEntry(rt_elem);
					char *rng_str = apol_mls_range_render(pol, range);
					string *missing_rng =
						new string(string("No user with range ") + rng_str + " and one of the roles {");
					free(rng_str);
					for (vector < string >::const_iterator j = role_names.begin(); j != role_names.end(); j++)
					{
						*missing_rng += " " + *j;
					}
					*missing_rng += " }";
					element missing_elem(missing_rng, std_string_free, std_string_dup);
					rt_entry.addProof(missing_elem, "");
				}
			}
			// no else

			apol_vector_destroy(&source_roles);
			apol_mls_range_destroy(&range);
		}
		apol_vector_destroy(&range_trans_rules);
	}
}
