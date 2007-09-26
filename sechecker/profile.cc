/**
 *  @file
 *  Implements the public interface for sechecker module profiles.
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
#include <map>
#include <vector>
#include <stdexcept>

using std::invalid_argument;
using std::out_of_range;
using std::pair;
using std::string;
using std::map;
using std::vector;

namespace sechecker
{
	profile::module_specification::module_specification(const std::string & name_,
							    output_format output) throw(std::invalid_argument):_options()
	{
		if (name_ == "")
			throw invalid_argument("Module name may not be empty");
		if (output <= SECHK_OUTPUT_NONE || output > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");
		_name = name_;
		_output_mode = output;
	}

	profile::module_specification::module_specification(const module_specification & rhs)
	{
		_name = rhs._name;
		_output_mode = rhs._output_mode;
		_options = rhs._options;
	}

	profile::module_specification::~module_specification()
	{
		//nothing to do
	}

	output_format profile::module_specification::outputMode() const
	{
		return _output_mode;
	}

	void profile::module_specification::addOption(const std::string & name_,
						      const std::vector < std::string > &vals) throw(std::invalid_argument)
	{
		option opt(name_, "", vals);
		pair < map < string, option >::iterator, bool > retv = _options.insert(make_pair(name_, opt));
		if (!retv.second)
			throw invalid_argument("Cannot insert duplicate option");
	}

	const std::map < std::string, option > &profile::module_specification::options() const
	{
		return _options;
	}

	profile::profile(const std::string & path)throw(std::runtime_error):_mod_specs()
	{
		_version = "";
		_name = "";
		_description = "";

		//TODO port profile parser
	}

	profile::profile(const profile & rhs):_mod_specs(rhs._mod_specs)
	{
		_name = rhs._name;
		_version = rhs._version;
		_description = rhs._description;
	}

	profile::~profile()
	{
		//nothing to do
	}

	const std::vector < std::string > profile::getModuleList() const
	{
		vector < string > v;

		for (map < string, module_specification >::const_iterator i = _mod_specs.begin(); i != _mod_specs.end(); i++)
		{
			v.push_back(i->first);
		}

		return v;
	}

	const std::string & profile::name() const
	{
		return _name;
	}

	const std::string & profile::version() const
	{
		return _version;
	}

	const std::string & profile::description() const
	{
		return _description;
	}

	void profile::apply(sechecker & top) const throw(std::invalid_argument, std::out_of_range)
	{
		for (map < string, module_specification >::const_iterator i = _mod_specs.begin(); i != _mod_specs.end(); i++)
		{
			map < string, pair < module *, void * > >::iterator iter = top.modules().find(i->first);
			if (iter == top.modules().end())
				throw out_of_range("No module named " + i->first + " exists");
			module *mod = iter->second.first;
			mod->outputMode(i->second.outputMode());
			for (map < string, option >::const_iterator j = i->second.options().begin(); j != i->second.options().end();
			     j++)
			{
				mod->setOption(j->first, j->second.values(), true);
			}
		}
	}
}
