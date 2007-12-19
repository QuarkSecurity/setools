/**
 *  @file
 *  Implementation of the domains without roles module.
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

#include "domains_wo_roles.hh"
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

void *domains_wo_roles_init(void)
{
	return static_cast < void *>(new sechk::domains_wo_roles_module());
}

namespace sechk
{
	domains_wo_roles_module::domains_wo_roles_module() throw(std::invalid_argument,
								 std::out_of_range):module("domains_wo_roles", SECHK_SEV_LOW,
											   "Find domains not assigned to a role.",
											   "A domain not assigned to a role cannot form a valid context.\n"
											   "The role \"object_r\" is not considered in this module.")
	{
		_dependencies.push_back("find_domains");
	}

	domains_wo_roles_module::domains_wo_roles_module(const domains_wo_roles_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	domains_wo_roles_module::~domains_wo_roles_module()
	{
		// nothing to do
	}

	void domains_wo_roles_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		const result & domains = _owner->modules().at("find_domains").first->results();
		const qpol_role_t *object_r = NULL;
		qpol_policy_get_role_by_name(apol_policy_get_qpol(pol), "object_r", &object_r);

		for (map < void *, result::entry >::const_iterator i = domains.entries().begin(); i != domains.entries().end(); i++)
		{
			apol_role_query_t *rq = NULL;
			if (!(rq = apol_role_query_create()))
				throw bad_alloc();

			const char *name = NULL;
			qpol_type_get_name(apol_policy_get_qpol(pol), static_cast < qpol_type_t * >(i->first), &name);
			apol_role_query_set_type(pol, rq, name);
			apol_vector_t *roles;
			apol_role_get_by_query(pol, rq, &roles);
			for (size_t j = 0; j < apol_vector_get_size(roles); j++)
			{
				if (apol_vector_get_element(roles, j) == object_r)
				{
					apol_vector_remove(roles, j);
					break;
				}
			}
			size_t size = apol_vector_get_size(roles);
			apol_vector_destroy(&roles);
			apol_role_query_destroy(&rq);
			if (size)
				continue;

			element domain(static_cast < qpol_type_t * >(i->first), NULL, NULL);
			result::entry & cur_result = _results.addEntry(domain);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Domain is not assigned to a role.");

		}
	}
}
