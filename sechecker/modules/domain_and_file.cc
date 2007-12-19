/**
 *  @file
 *  Implementation of the domain and file module.
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

#include "domain_and_file.hh"
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

void *domain_and_file_init(void)
{
	return static_cast < void *>(new sechk::domain_and_file_module());
}

namespace sechk
{
	domain_and_file_module::domain_and_file_module() throw(std::invalid_argument, std::out_of_range):module("domain_and_file",
														SECHK_SEV_LOW,
														"Find all types treated as both a domain and a file type.",
														"See the find_domains and find_file_types modules for details about the\n"
														"heuristics used to determine these types.  It is considered bad security\n"
														"practice to use the same type for a domain and its data objects because it \n"
														"requires that less restrictive access be granted to these types.")
	{
		// no options or requirements
		requirement rec_attr_names(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES);
		if (_recommendations.insert(make_pair(rec_attr_names.name(), rec_attr_names)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
		_dependencies.push_back("find_domains");
		_dependencies.push_back("find_file_types");
	}

	domain_and_file_module::domain_and_file_module(const domain_and_file_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	domain_and_file_module::~domain_and_file_module()
	{
		// nothing to do
	}

	void domain_and_file_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		const result & domains = _owner->modules().at("find_domains").first->results();
		const result & file_types = _owner->modules().at("find_file_types").first->results();

		for (map < void *, result::entry >::const_iterator i = domains.entries().begin(); i != domains.entries().end(); i++)
		{
			element *new_element = NULL;
			try
			{
				// find the same type in the file type results
				new_element =
					new element(file_types.entries().at(const_cast < void *>(i->second.Element().data())).
						    Element());
			}
			catch(out_of_range)
			{
				continue;	// result was only a domain but not a file type
			}
			// add an entry
			result::entry & new_entry = _results.addEntry(*new_element);
			// copy proof from the domain result
			for (map < void *, result::entry::proof >::const_iterator j = i->second.Proof().begin();
			     j != i->second.Proof().end(); j++)
			{
				new_entry.addProof(j->second.Element(), j->second.prefix());
			}
			// copy proof from the file type result
			for (map < void *, result::entry::proof >::const_iterator j =
			     file_types.entries().at(const_cast < void *>(i->second.Element().data())).Proof().begin();
			     j != file_types.entries().at(const_cast < void *>(i->second.Element().data())).Proof().end(); j++)
			{
				new_entry.addProof(j->second.Element(), j->second.prefix());
			}
		}
	}
}
