/**
 *  @file
 *  Implementation of the roles without users module.
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

#include "roles_wo_users.hh"
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

void *roles_wo_users_init(void)
{
	return static_cast < void *>(new sechk::roles_wo_users_module());
}

namespace sechk
{
	roles_wo_users_module::roles_wo_users_module() throw(std::invalid_argument, std::out_of_range):module("roles_wo_users",
													      SECHK_SEV_LOW,
													      "Find roles not assigned to a user.",
													      "Roles not assigned to a user cannot form a valid context.")
	{
		// nothing more to do
	}

	roles_wo_users_module::roles_wo_users_module(const roles_wo_users_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	roles_wo_users_module::~roles_wo_users_module()
	{
		// nothing to do
	}

	void roles_wo_users_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		qpol_iterator_t *role_iter = NULL;
		if (qpol_policy_get_role_iter(apol_policy_get_qpol(pol), &role_iter))
			throw bad_alloc();

		for ( /* already initialized */ ; !qpol_iterator_end(role_iter); qpol_iterator_next(role_iter))
		{
			qpol_role_t *cur_role = NULL;
			if (qpol_iterator_get_item(role_iter, reinterpret_cast < void **>(&cur_role)))
				throw runtime_error("Error accessing policy roles");
			const char *name;
			qpol_role_get_name(apol_policy_get_qpol(pol), cur_role, &name);

			polsearch_user_query uq(POLSEARCH_MATCH_ALL);
			polsearch_test & role_test = uq.addTest(POLSEARCH_TEST_ROLES);
			polsearch_criterion & role_crit = role_test.addCriterion(POLSEARCH_OP_INCLUDE);
			polsearch_string_expression_parameter *role_param = new polsearch_string_expression_parameter(string(name));
			role_crit.param(role_param);

			vector < polsearch_result > res = uq.run(pol, list);
			if (res.size())
				continue;

			element role(cur_role, NULL, NULL);
			result::entry & cur_result = _results.addEntry(role);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Role is not assigned to a user.");
		}
		qpol_iterator_destroy(&role_iter);
	}
}
