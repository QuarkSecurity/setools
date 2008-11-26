/**
 * @file
 *
 * Routines to create policy element test result proof entries.
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
#include <string>
#include <vector>

using std::vector;
using std::string;

polsearch_proof::polsearch_proof()
{
	throw std::runtime_error("Cannot directly create proof entries.");
}

polsearch_proof::polsearch_proof(polsearch_test_cond test, polsearch_element elem_type, void *elem, const apol_policy_t * p,
				 sefs_fclist * fclist, polsearch_proof_element_free_fn free_fn)
{
	_test_cond = test;
	_element_type = elem_type;
	_element = elem;
	_policy = p;
	_fclist = fclist;
	_free_fn = free_fn;
}

polsearch_proof::polsearch_proof(const polsearch_proof & rhs)
{
	_test_cond = rhs._test_cond;
	_element_type = rhs._element_type;
	_policy = rhs._policy;
	_fclist = rhs._fclist;
	_free_fn = rhs._free_fn;
	if (_free_fn)
		_element = element_copy(_element_type, rhs._element);
	else
		_element = rhs._element;
}

polsearch_proof & polsearch_proof::operator=(const polsearch_proof & rhs)
{
	_test_cond = rhs._test_cond;
	_element_type = rhs._element_type;
	_policy = rhs._policy;
	_fclist = rhs._fclist;
	_free_fn = rhs._free_fn;
	if (_free_fn)
		_element = element_copy(_element_type, rhs._element);
	else
		_element = rhs._element;

	return *this;
}

polsearch_proof::~polsearch_proof()
{
	if (_free_fn)
		_free_fn(_element);
}

string polsearch_proof::toString() const
{
	string tmp;
	//TODO proof to string
	return tmp;
}

polsearch_element polsearch_proof::elementType() const
{
	return _element_type;
}

const void *polsearch_proof::element() const
{
	return _element;
}

polsearch_test_cond polsearch_proof::testCond() const
{
	return _test_cond;
}
