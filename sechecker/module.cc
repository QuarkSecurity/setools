/**
 *  @file
 *  Implements the public interface for sechecker modules.
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

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>

using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::map;
using std::pair;
using std::string;
using std::vector;

namespace sechk
{
	module::module(const std::string & name_, severity sev, const std::string & summary_,
		       const std::string & desc) throw(std::invalid_argument):_dependencies(), _requirements(), _recommendations(),
		_options(), _results(name_, SECHK_OUTPUT_SHORT)
	{
		if (name_ == "")
			throw invalid_argument("Module name may not be empty");

		if (sev <= SECHK_SEV_NONE || sev > SECHK_SEV_MAX)
			throw invalid_argument("Invalid module severity");

		_owner = NULL;
		_name = name_;
		_summary = summary_;
		_description = desc;
		_sev = sev;
		_run = false;
	}

	module::module(const module & rhs):_dependencies(rhs._dependencies), _requirements(rhs._requirements),
		_recommendations(rhs._recommendations), _options(rhs._options), _results(rhs._results)
	{
		_owner = rhs._owner;
		_name = rhs._name;
		_summary = rhs._summary;
		_description = rhs._description;
		_sev = rhs._sev;
		_run = rhs._run;
	}

	module::~module()
	{
		//nothing to do
	}

	bool module::verify(apol_policy_t * pol, sefs_fclist * list)
	{
		bool retv = true;
		for (map < string, requirement >::iterator i = _requirements.begin(); i != _requirements.end(); i++)
		{
			if (!(i->second.check(pol, list)))
				retv = false;
		}

		for (map < string, requirement >::iterator i = _recommendations.begin(); i != _recommendations.end(); i++)
		{
			i->second.check(pol, list);
		}

		return retv;
	}

	void module::run(apol_policy_t * pol, sefs_fclist * list) throw(std::invalid_argument, std::runtime_error)
	{
		//only ever run once.
		if (_run)
			return;

		//ensure that it is safe to run.
		//verify that the policy and list meet the requirements
		if (!verify(pol, list))
			throw invalid_argument("Requirements not met for module " + _name);
		//make sure this is not an orphan module
		if (!_owner)
			throw runtime_error("Module " + _name + " has no owner; it cannot be run");
		//check that all dependencies exist and have been run
		for (vector < string >::iterator i = _dependencies.begin(); i != _dependencies.end(); i++)
		{
			map < string, pair < module *, void * > >::const_iterator iter = _owner->modules().find(*i);
			if (iter == _owner->modules().end())
				throw invalid_argument("Module " + *i + " (required by module " + _name + ") does not exist");
			if (!iter->second.first->_run)
				throw runtime_error("Module " + *i + " (required by module " + _name + ") has not been run");
		}
		//check that all options have non-empty values
		for (map < string, option >::iterator i = _options.begin(); i != _options.end(); i++)
		{
			if (i->second.values().empty())
				throw invalid_argument("Option " + i->second.name() + " is not set for module " + _name);
			for (vector < string >::const_iterator j = i->second.values().begin(); j != i->second.values().end(); j++)
			{
				if (*j == "")
					throw invalid_argument("Option " + i->second.name() + " for module " + _name +
							       "has one or more invalid values");
			}
		}

		//call module specific run implementation
		run_internal(pol, list);
	}

	std::ostream & module::help(std::ostream & out) const
	{
		//TODO improve help printout format
		return out;
	}

	const result & module::results() const throw(std::runtime_error)
	{
		if (!_run)
			throw runtime_error("Module " + _name + " has not been run");

		return _results;
	}

	output_format module::outputMode(output_format out_mode) throw(std::invalid_argument)
	{
		return _results.outputMode(out_mode);
	}

	const std::map < std::string, option > &module::options() const
	{
		return _options;
	}

	const option & module::setOption(const std::string & name_, const std::vector < std::string > &values,
					 bool override) throw(std::out_of_range, std::invalid_argument)
	{
		if (values.empty())
			throw invalid_argument("No values given");
		for (vector < string >::const_iterator i = values.begin(); i != values.end(); i++)
			if (*i == "")
				throw invalid_argument("Option values may not be empty");

		map < string, option >::iterator iter = _options.find(name_);
		if (iter == _options.end())
		{
			throw out_of_range("Module " + _name + " has no option " + name_);
		}
		option & opt = iter->second;
		if (override)
			opt.clearValues();
		for (vector < string >::const_iterator i = values.begin(); i != values.end(); i++)
		{
			opt.appendValue(*i);
		}

		return opt;
	}

	const std::vector < std::string > &module::dependencies() const
	{
		return _dependencies;
	}

	const std::map < std::string, requirement > &module::requirements() const
	{
		return _requirements;
	}

	const std::map < std::string, requirement > &module::recommendations() const
	{
		return _recommendations;
	}

	const std::string & module::name() const
	{
		return _name;
	}

	const std::string & module::summary() const
	{
		return _summary;
	}

	const std::string & module::description() const
	{
		return _description;
	}

	severity module::moduleSeverity() const
	{
		return _sev;
	}
}
