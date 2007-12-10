/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <polsearch/polsearch.hh>
#include "polsearch_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::invalid_argument;
using std::vector;

polsearch_query::polsearch_query(polsearch_match m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	_match = m;
}

polsearch_query::polsearch_query(const polsearch_query & rhs)
{
	_match = rhs._match;
	_tests = rhs._tests;
}

polsearch_query::~polsearch_query()
{
	// no-op
}

polsearch_match polsearch_query::match() const
{
	return _match;
}

polsearch_match polsearch_query::match(polsearch_match m) throw(std::invalid_argument)
{
	if (m != POLSEARCH_MATCH_ALL && m != POLSEARCH_MATCH_ANY)
		throw invalid_argument("Invalid matching behavior requested.");

	return _match = m;
}

std::vector < polsearch_test_cond > polsearch_get_valid_tests(polsearch_element elem_type)
{
	vector < polsearch_test_cond > v;
	for (int i = POLSEARCH_TEST_NONE; i <= POLSEARCH_TEST_STATE; i++)
		if (validate_test_condition(elem_type, static_cast < polsearch_test_cond > (i)))
			v.push_back(static_cast < polsearch_test_cond > (i));

	return v;
}

polsearch_test & polsearch_query::addTest(polsearch_test_cond test_cond) throw(std::invalid_argument)
{
	return *_tests.insert(_tests.end(), polsearch_test(this, test_cond));
}

std::vector < polsearch_result > polsearch_query::run(const apol_policy_t * policy,
						      sefs_fclist * fclist) const throw(std::bad_alloc, std::runtime_error)
{
	vector < polsearch_result > master_results;
	vector < const void *>Xcandidates = getCandidates(policy);
	//Run each test
	for (vector < polsearch_test >::const_iterator i = _tests.begin(); i != _tests.end(); i++)
	{
		vector < polsearch_result > cur_test_results = i->run(policy, fclist, Xcandidates);
		//Merge current test's results with the master list of results
		for (vector < polsearch_result >::iterator j = cur_test_results.begin(); j != cur_test_results.end(); j++)
		{
			polsearch_result *master_entry = NULL;
			for (vector < polsearch_result >::iterator k = master_results.begin();
			     i != _tests.begin() && k != master_results.end(); k++)
			{
				if (k->element() == j->element())
				{
					master_entry = &(*k);
					break;
				}
			}
			if (master_entry)
			{
				master_entry->merge(*j);
				continue;
			}
			//always merge on first test (otherwise there will never be results)
			if (_match == POLSEARCH_MATCH_ANY || i == _tests.begin())
			{
				master_results.push_back(polsearch_result(*j));
				continue;
			}
		}
		//For each test after the first, prune any results not in current list if match all is set
		if (_match == POLSEARCH_MATCH_ALL && i != _tests.begin())
		{
			for (vector < polsearch_result >::iterator k = master_results.begin(); k != master_results.end(); k++)
			{
				bool found = false;
				for (vector < polsearch_result >::iterator j = cur_test_results.begin();
				     j != cur_test_results.end(); j++)
				{
					if (k->element() == j->element())
					{
						found = true;
						break;
					}
				}
				if (found)
					continue;
				master_results.erase(k);
				k--;
			}
		}
	}

	return master_results;
}

void polsearch_query::update()
{
	for (vector < polsearch_test >::iterator i = _tests.begin(); i != _tests.end(); i++)
	{
		i->_query = this;
		i->update();
	}
}
