/**
 * @file
 *
 * Routines to perform complex queries on types in a selinux policy.
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

polsearch_type_query::polsearch_type_query(polsearch_match m) throw(std::invalid_argument):polsearch_query(m)
{
	//nothing more to do
}

polsearch_type_query::polsearch_type_query(const polsearch_type_query & rhs):polsearch_query(rhs)
{
	//nothing more to do
}

polsearch_type_query::~polsearch_type_query()
{
	//nothing to do
}

std::vector < const void *>polsearch_type_query::getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
													       std::runtime_error)
{
	apol_type_query_t *tq = apol_type_query_create();
	if (!tq)
		throw bad_alloc();
	apol_vector_t *v = NULL;
	if (apol_type_get_by_query(policy, tq, &v))
	{
		if (!v)
		{
			throw bad_alloc();
		}
		else
		{
			throw runtime_error("Unable to get all types");
		}
	}
	vector < const void *>tv;
	for (size_t i = 0; i < apol_vector_get_size(v); i++)
	{
		tv.push_back(apol_vector_get_element(v, i));
	}
	apol_vector_destroy(&v);
	apol_type_query_destroy(&tq);

	return tv;
}

std::string polsearch_type_query::toString() const
{
	//TODO polsearch_type_query.toString()
	return "";
}

polsearch_element polsearch_type_query::elementType() const
{
	return POLSEARCH_ELEMENT_TYPE;
}
