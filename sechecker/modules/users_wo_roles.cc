/**
 *  @file
 *  Implementation of the users without roles module.
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

#include "users_wo_roles.hh"
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

void * users_wo_roles_init( void )
{
	return static_cast<void*>(new sechk::users_wo_roles_module());
}

namespace sechk
{
	users_wo_roles_module::users_wo_roles_module() throw(std::invalid_argument, std::out_of_range)
	:module("users_wo_roles",SECHK_SEV_LOW,"Find users without assigned roles.",
	"Users without roles may appear in the label of a file system object;\n"
	"however, these users cannot login to the system or run any process.  Since these\n"
	"users cannot be used on the system, a policy change is recomended to remove the\n"
	"users or provide some intended access.")
	{
		// nothing more to do
	}

	users_wo_roles_module::users_wo_roles_module(const users_wo_roles_module & rhs)
	:module(rhs)
	{
		// nothing more to do
	}

	users_wo_roles_module::~users_wo_roles_module()
	{
		// nothing to do
	}

	void users_wo_roles_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		qpol_iterator_t *user_iter = NULL;
		if (qpol_policy_get_user_iter(apol_policy_get_qpol(pol), &user_iter))
			throw bad_alloc();

		for (/* already initialized */; !qpol_iterator_end(user_iter); qpol_iterator_next(user_iter))
		{
			qpol_user_t *cur_user = NULL;
			if (qpol_iterator_get_item(user_iter, reinterpret_cast<void**>(&cur_user)))
				throw runtime_error("Error accessing policy users");
			qpol_iterator_t *user_roles = NULL;
			if (qpol_user_get_role_iter(apol_policy_get_qpol(pol), cur_user, &user_roles))
				throw bad_alloc();
			size_t size = 0;
			qpol_iterator_get_size(user_roles, &size);
			qpol_iterator_destroy(&user_roles);
			if (size)
				continue;
			element user(cur_user, NULL, NULL);
			result::entry & cur_result = _results.addEntry(user);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "User has no roles.");
		}
		qpol_iterator_destroy(&user_iter);
	}
}
