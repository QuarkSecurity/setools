/**
 *  @file
 *  Implements the public interface for sechecker module results.
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

#include "sechecker.hh"

#include <apol/policy.h>

#include <string>
#include <map>
#include <typeinfo>
#include <iostream>
#include <stdexcept>

using std::bad_alloc;
using std::map;
using std::string;
using std::type_info;
using std::invalid_argument;
using std::make_pair;
using std::pair;

namespace sechk
{
	template < typename T > element::element(T * data_, free_fn free_, dup_fn dup_) throw(std::bad_alloc):_type(typeid(data_))
	{
		if (dup_)
			_data = dup_(reinterpret_cast < void *>(data_));
		else
			 _data = reinterpret_cast < void *>(data_);
		if (!_data)
			throw bad_alloc();
		_free = free_;
		_dup = dup_;
	}

	element::element(const element & rhs) throw(std::bad_alloc):_type(rhs._type)
	{
		if (rhs._dup)
			_data = rhs._dup(rhs._data);
		else
			_data = rhs._data;
		if (!_data)
			throw bad_alloc();
		_free = rhs._free;
		_dup = rhs._dup;
	}

	const element & element::operator=(const element & rhs) throw(std::bad_alloc)
	{
		//The following is done because std::type_info::operator=() and std::type_info(const std::type_info&) are private.
		*this = element(rhs);
	}

	element::~element()
	{
		if (_free)
			_free(_data);
	}

	const void *element::data() const
	{
		return _data;
	}

	void *element::data()
	{
		return _data;
	}

	const std::type_info & element::type() const
	{
		return _type;
	}

	std::ostream & element::print(std::ostream & out, apol_policy_t * pol) const
	{
		//TODO print stuff.
		return out;
	}

	result::entry::proof::proof(const element & elem):_element(elem)
	{
		//nothing more to do
	}

	result::entry::proof::proof(const proof & rhs):_element(rhs._element)
	{
		//nothing more to do
	}

	result::entry::proof::~proof()
	{
		//nothing to do
	}

	const element & result::entry::proof::Element() const
	{
		return _element;
	}

	result::entry::entry(const element & elem):_element(elem)
	{
		_proof = map < void *, proof > ();
	}

	result::entry::entry(const entry & rhs):_element(rhs._element)
	{
		_proof = rhs._proof;
	}

	result::entry::~entry()
	{
		//nothing to do
	}

	const element & result::entry::Element() const
	{
		return _element;
	}

	const std::map < void *, result::entry::proof > &result::entry::Proof() const
	{
		return _proof;
	}

	const result::entry::proof & result::entry::addProof(const element & elem) throw(std::invalid_argument)
	{
		proof newproof(elem);

		pair < map < void *, proof >::iterator, bool > retv =
			_proof.insert(make_pair(const_cast < void *>(newproof.Element().data()), newproof));
		if (!retv.second)
		{
			throw invalid_argument("Cannot insert duplicate proof");
		}

		return (*retv.first).second;
	}

	result::result(const std::string & mod_name, output_format out_mode)throw(std::invalid_argument)
	{
		if (mod_name == "")
			throw invalid_argument("Module name may not be empty");

		//default is not valid for a single module result
		if (out_mode <= SECHK_OUTPUT_DEFAULT || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");

		_entries = map < void *, entry > ();
		_output_mode = out_mode;
		_module_name = mod_name;
	}

	result::result(const result & rhs)
	{
		_entries = rhs._entries;
		_output_mode = rhs._output_mode;
		_module_name = rhs._module_name;
	}

	result::~result()
	{
		//nothing to do
	}

	output_format result::outputMode() const
	{
		return _output_mode;
	}

	output_format result::outputMode(output_format out_mode) throw(std::invalid_argument)
	{
		if (out_mode <= SECHK_OUTPUT_NONE || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");

		return _output_mode = out_mode;
	}

	const std::map < void *, result::entry > &result::entries() const
	{
		return _entries;
	}

	const result::entry & result::addEntry(element elem) throw(std::invalid_argument)
	{
		entry newentry(elem);

		pair < map < void *, entry >::iterator, bool > retv =
			_entries.insert(make_pair(const_cast < void *>(newentry.Element().data()), newentry));
		if (!retv.second)
		{
			throw invalid_argument("Cannot insert duplicate result entry");
		}

		return (*retv.first).second;
	}
}
