/**
 *  @file
 *  Implementation of the find netif types utility module.
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

#include "find_netif_types.hh"
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

void *find_netif_types_init(void)
{
	return static_cast < void *>(new sechk::find_netif_types_module());
}

namespace sechk
{
	find_netif_types_module::find_netif_types_module() throw(std::invalid_argument,
								 std::out_of_range):module("find_netif_types", SECHK_SEV_UTIL,
											   "Find all types treated as a netif type.",
											   "A type is considered a netif type if either of the following is true:\n"
											   "\n"
											   "   1) it is used in the interface context of a a netifcon statement\n"
											   "   2) it is used in the context of the netif initial sid")
	{
		//nothing more to do.
	}

	find_netif_types_module::find_netif_types_module(const find_netif_types_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	find_netif_types_module::~find_netif_types_module()
	{
		//nothing to do.
	}

	void find_netif_types_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		// add entry for the netif initial sid
		const qpol_isid_t *netif_sid;
		qpol_policy_get_isid_by_name(apol_policy_get_qpol(pol), "netif", &netif_sid);
		const qpol_context_t *sid_ctx = NULL;
		qpol_isid_get_context(apol_policy_get_qpol(pol), netif_sid, &sid_ctx);
		const qpol_type_t *sid_type = NULL;
		qpol_context_get_type(apol_policy_get_qpol(pol), sid_ctx, &sid_type);
		element sid_type_elem(const_cast < qpol_type_t * >(sid_type), NULL, NULL);
		result::entry & sid_res = _results.addEntry(sid_type_elem);
		element sid_elem(const_cast < qpol_isid_t * >(netif_sid), NULL, NULL);
		sid_res.addProof(sid_elem, "");

		// add entry for each netifcon (note that addEntry returns any previous entry for that type)
		apol_vector_t *netifcons;
		apol_netifcon_get_by_query(pol, NULL, &netifcons);
		for (size_t i = 0; i < apol_vector_get_size(netifcons); i++)
		{
			qpol_netifcon_t *cur_netifcon = NULL;
			cur_netifcon = static_cast < qpol_netifcon_t * >(apol_vector_get_element(netifcons, i));
			const qpol_context_t *netif_ctx = NULL;
			qpol_netifcon_get_if_con(apol_policy_get_qpol(pol), cur_netifcon, &netif_ctx);
			const qpol_type_t *netif_type = NULL;
			qpol_context_get_type(apol_policy_get_qpol(pol), netif_ctx, &netif_type);
			element netif_type_elem(const_cast < qpol_type_t * >(netif_type), NULL, NULL);
			result::entry & netif_res = _results.addEntry(netif_type_elem);
			element netif_elem(cur_netifcon, NULL, NULL);
			netif_res.addProof(netif_elem, "");
		}
		apol_vector_destroy(&netifcons);
	}
}
