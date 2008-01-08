/**
 *  @file
 *  Implements the public interface for sechecker module options.
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

#include <string>
#include <vector>
#include <stdexcept>

using std::invalid_argument;
using std::vector;
using std::string;

namespace sechk
{
	option::option(const std::string & name_, const std::string & desc,
		       const std::vector < std::string > &vals) throw(std::invalid_argument)
	{
		if (name_ == "")
			throw invalid_argument("Name may not be empty");
		for (vector < string >::const_iterator i = vals.begin(); i != vals.end(); i++)
		{
			if (*i == "")
				throw invalid_argument("Values may not be empty");
		}
		_name = name_;
		_values = vals;
		_description = desc;
	}

	option::option(const option & rhs)
	{
		_name = rhs._name;
		_values = rhs._values;
		_description = rhs._description;
	}

	option::~option()
	{
		//nothing to do.
	}

	const std::string & option::name() const
	{
		return _name;
	}

	const std::string & option::description() const
	{
		return _description;
	}

	const std::vector < std::string > &option::values() const
	{
		return _values;
	}
	void option::clearValues()
	{
		_values.clear();
	}

	const std::string & option::appendValue(const std::string & value) throw(std::invalid_argument)
	{
		if (value == "")
			throw invalid_argument("Values may not be empty");

		_values.push_back(string(value));

		return _values.back();
	}
}
