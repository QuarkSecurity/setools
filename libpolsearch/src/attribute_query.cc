/**
 * @file
 *
 * Routines to perform complex queries on attributes in a selinux policy.
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
#include <polsearch/query.hh>
#include <polsearch/attribute_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>
#include <apol/type-query.h>

#include <stdexcept>
#include <vector>
#include <string>

using std::vector;
using std::string;
using std::runtime_error;
using std::bad_alloc;

polsearch_attribute_query::polsearch_attribute_query(polsearch_match m) throw(std::invalid_argument):polsearch_query(m)
{
	//nothing more to do
}

polsearch_attribute_query::polsearch_attribute_query(const polsearch_attribute_query & rhs):polsearch_query(rhs)
{
	//nothing more to do
}

polsearch_attribute_query::~polsearch_attribute_query()
{
	//nothing to do
}

std::vector < const void *>polsearch_attribute_query::getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
														    std::
														    runtime_error)
{
	apol_attr_query_t *aq = apol_attr_query_create();
	if (!aq)
		throw bad_alloc();
	apol_vector_t *v = NULL;
	if (apol_attr_get_by_query(policy, aq, &v))
	{
		if (!v)
		{
			throw bad_alloc();
		}
		else
		{
			throw runtime_error("Unable to get all attributeeans");
		}
	}
	vector < const void *>av;
	for (size_t i = 0; i < apol_vector_get_size(v); i++)
	{
		av.push_back(apol_vector_get_element(v, i));
	}
	apol_vector_destroy(&v);
	apol_attr_query_destroy(&aq);

	return av;
}

std::string polsearch_attribute_query::toString() const
{
	//TODO polsearch_attribute_query.toString()
	return "";
}

polsearch_element polsearch_attribute_query::elementType() const
{
	return POLSEARCH_ELEMENT_ATTRIBUTE;
}