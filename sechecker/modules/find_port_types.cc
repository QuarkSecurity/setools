/**
 *  @file
 *  Implementation of the find port types utility module.
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

#include "find_port_types.hh"
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

void *find_port_types_init(void)
{
	return static_cast < void *>(new sechk::find_port_types_module());
}

namespace sechk
{
	find_port_types_module::find_port_types_module() throw(std::invalid_argument, std::out_of_range):module("find_port_types",
														SECHK_SEV_UTIL,
														"Find all types treated as a port type.",
														"A type is considered a port type if either of the following is true:\n"
														"\n"
														"   1) it is used in the context of a a portcon statement\n"
														"   2) it is used in the context of the port initial sid")
	{
		//nothing more to do.
	}

	find_port_types_module::find_port_types_module(const find_port_types_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	find_port_types_module::~find_port_types_module()
	{
		//nothing to do.
	}

	void find_port_types_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		// add entry for the port initial sid
		const qpol_isid_t *port_sid;
		qpol_policy_get_isid_by_name(apol_policy_get_qpol(pol), "port", &port_sid);
		const qpol_context_t *sid_ctx = NULL;
		qpol_isid_get_context(apol_policy_get_qpol(pol), port_sid, &sid_ctx);
		const qpol_type_t *sid_type = NULL;
		qpol_context_get_type(apol_policy_get_qpol(pol), sid_ctx, &sid_type);
		element sid_type_elem(const_cast < qpol_type_t * >(sid_type), NULL, NULL);
		result::entry & sid_res = _results.addEntry(sid_type_elem);
		element sid_elem(const_cast < qpol_isid_t * >(port_sid), NULL, NULL);
		sid_res.addProof(sid_elem, "");

		// add entry for each portcon (note that addEntry returns any previous entry for that type)
		apol_vector_t *portcons;
		apol_portcon_get_by_query(pol, NULL, &portcons);
		for (size_t i = 0; i < apol_vector_get_size(portcons); i++)
		{
			qpol_portcon_t *cur_portcon = NULL;
			cur_portcon = static_cast < qpol_portcon_t * >(apol_vector_get_element(portcons, i));
			const qpol_context_t *port_ctx = NULL;
			qpol_portcon_get_context(apol_policy_get_qpol(pol), cur_portcon, &port_ctx);
			const qpol_type_t *port_type = NULL;
			qpol_context_get_type(apol_policy_get_qpol(pol), port_ctx, &port_type);
			element port_type_elem(const_cast < qpol_type_t * >(port_type), NULL, NULL);
			result::entry & port_res = _results.addEntry(port_type_elem);
			element port_elem(cur_portcon, NULL, NULL);
			port_res.addProof(port_elem, "");
		}
	}
}
