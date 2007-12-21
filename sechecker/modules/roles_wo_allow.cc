/**
 *  @file
 *  Implementation of the roles without allow rules utility module.
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

#include "roles_wo_allow.hh"
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

void *roles_wo_allow_init(void)
{
	return static_cast < void *>(new sechk::roles_wo_allow_module());
}

namespace sechk
{
	roles_wo_allow_module::roles_wo_allow_module() throw(std::invalid_argument, std::out_of_range):module("roles_wo_allow",
													      SECHK_SEV_LOW,
													      "Find roles not used in an allow rule.",
													      "A role that is never granted an allow rule in the policy is a dead end role.\n"
													      "This means that all attempts to transtion to or from the role will be denied.")
	{
		//nothing more to do.
	}

	roles_wo_allow_module::roles_wo_allow_module(const roles_wo_allow_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	roles_wo_allow_module::~roles_wo_allow_module()
	{
		//nothing to do.
	}

	void roles_wo_allow_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		// find all roles used in an allow rule
		polsearch_role_query rq(POLSEARCH_MATCH_ALL);
		polsearch_test & rule_test = rq.addTest(POLSEARCH_TEST_ROLEALLOW);
		polsearch_criterion & rule_srctgt = rule_test.addCriterion(POLSEARCH_OP_SRC_TGT);
		polsearch_string_expression_parameter *name = new polsearch_string_expression_parameter("X");
		rule_srctgt.param(name);
		vector < polsearch_result > rq_res;
		rq_res = rq.run(pol, list);

		//get all roles
		apol_vector_t *roles = NULL;
		if (apol_role_get_by_query(pol, NULL, &roles))
			throw bad_alloc();

		// if role is in results remove from list of all roles
		for (vector < polsearch_result >::const_iterator i = rq_res.begin(); i != rq_res.end(); i++)
		{
			size_t j = 0;
			if (!apol_vector_get_index(roles, i->element(), NULL, NULL, &j))
				if (apol_vector_remove(roles, j))
					throw runtime_error("error processing roles");
		}

		// explicitly remove object_r
		const qpol_role_t *object_r = NULL;
		qpol_policy_get_role_by_name(apol_policy_get_qpol(pol), "object_r", &object_r);
		size_t i = 0;
		if (apol_vector_get_index(roles, object_r, NULL, NULL, &i))
			throw runtime_error("could not find object_r");
		apol_vector_remove(roles, i);

		// if any roles remain, add an entry for each
		for (size_t i = 0; i < apol_vector_get_size(roles); i++)
		{
			qpol_role_t *cur_role = static_cast < qpol_role_t * >(apol_vector_get_element(roles, i));
			element role(cur_role, NULL, NULL);
			result::entry & cur_result = _results.addEntry(role);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Role is not used in an allow rule.");
		}

		apol_vector_destroy(&roles);
	}
}
