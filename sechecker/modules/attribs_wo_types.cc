/**
 *  @file
 *  Implementation of the attributes without types module.
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

#include "attribs_wo_types.hh"
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

void * attribs_wo_types_init( void )
{
	return static_cast<void*>(new sechk::attribs_wo_types_module());
}

namespace sechk
{
	attribs_wo_types_module::attribs_wo_types_module() throw(std::invalid_argument, std::out_of_range)
	:module("attribs_wo_types",SECHK_SEV_LOW,"Fnd attributes without assigned types.",
	"Attributes without types can cause type fields in rules to expand to empty\n"
	"sets and thus become unreachable. This makes for misleading policy source files.")
	{
		requirement req_attr_names(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES);
		if (_requirements.insert(make_pair(req_attr_names.name(), req_attr_names)).second == false)
		{
			throw out_of_range("Error setting requirements");
		}
	}

	attribs_wo_types_module::attribs_wo_types_module(const attribs_wo_types_module & rhs)
	:module(rhs)
	{
		// nothing more to do
	}

	attribs_wo_types_module::~attribs_wo_types_module()
	{
		// nothing to do
	}

	void attribs_wo_types_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		qpol_iterator_t *type_iter = NULL;
		if (qpol_policy_get_type_iter(apol_policy_get_qpol(pol), &type_iter))
			throw bad_alloc();

		for (/* already initialized */; !qpol_iterator_end(type_iter); qpol_iterator_next(type_iter))
		{
			qpol_type_t *cur_type = NULL;
			if (qpol_iterator_get_item(type_iter, reinterpret_cast<void**>(&cur_type)))
				throw runtime_error("Error accessing policy types");
			unsigned char isattr = 0;
			qpol_type_get_isattr(apol_policy_get_qpol(pol), cur_type, &isattr);
			if (!isattr)
				continue;
			qpol_iterator_t *attr_types = NULL;
			if (qpol_type_get_type_iter(apol_policy_get_qpol(pol), cur_type, &attr_types))
				throw bad_alloc();
			size_t size = 0;
			qpol_iterator_get_size(attr_types, &size);
			qpol_iterator_destroy(&attr_types);
			if (size)
				continue;
			element attr(cur_type, NULL, NULL);
			result::entry & cur_result = _results.addEntry(attr);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Attribute has no types.");
		}
		qpol_iterator_destroy(&type_iter);
	}
}
