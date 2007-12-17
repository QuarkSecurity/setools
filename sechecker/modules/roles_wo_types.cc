/**
 *  @file
 *  Implementation of the roles without types module.
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

#include "roles_wo_types.hh"
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

void * roles_wo_types_init( void )
{
	return static_cast<void*>(new sechk::roles_wo_types_module());
}

namespace sechk
{
	roles_wo_types_module::roles_wo_types_module() throw(std::invalid_argument, std::out_of_range)
	:module("roles_wo_types",SECHK_SEV_LOW,"Find roles without assigned types.",
	"Roles without types cannot form a valid context.")
	{
		// nothing more to do
	}

	roles_wo_types_module::roles_wo_types_module(const roles_wo_types_module & rhs)
	:module(rhs)
	{
		// nothing more to do
	}

	roles_wo_types_module::~roles_wo_types_module()
	{
		// nothing to do
	}

	void roles_wo_types_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		qpol_iterator_t *role_iter = NULL;
		if (qpol_policy_get_role_iter(apol_policy_get_qpol(pol), &role_iter))
			throw bad_alloc();

		for (/* already initialized */; !qpol_iterator_end(role_iter); qpol_iterator_next(role_iter))
		{
			qpol_role_t *cur_role = NULL;
			if (qpol_iterator_get_item(role_iter, reinterpret_cast<void**>(&cur_role)))
				throw runtime_error("Error accessing policy roles");
			qpol_iterator_t *role_types = NULL;
			if (qpol_role_get_type_iter(apol_policy_get_qpol(pol), cur_role, &role_types))
				throw bad_alloc();
			size_t size = 0;
			qpol_iterator_get_size(role_types, &size);
			qpol_iterator_destroy(&role_types);
			if (size)
				continue;
			element role(cur_role, NULL, NULL);
			result::entry & cur_result = _results.addEntry(role);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Role has no types.");
		}
		qpol_iterator_destroy(&role_iter);
	}
}
