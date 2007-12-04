/**
 *  @file
 *  Implements the public interface for reporting sechecker module results.
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
#include <iostream>
#include <stdexcept>

using std::invalid_argument;
using std::out_of_range;
using std::map;
using std::pair;
using std::string;

namespace sechk
{
	report::report(const sechecker * top, output_format out_mode, severity min_sev) throw(std::invalid_argument):_results(),
		_top(top)
	{
		if (!top)
			throw invalid_argument("Report must be associated with a sechecker object");
		if (out_mode <= SECHK_OUTPUT_NONE || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");
		if (min_sev <= SECHK_SEV_NONE || min_sev > SECHK_SEV_MAX)
			throw invalid_argument("Invalid minimum severity requested");
		_output_mode = out_mode;
		_min_sev = min_sev;
	}

	report::report(const report & rhs):_results(rhs._results), _top(rhs._top)
	{
		_output_mode = rhs._output_mode;
		_min_sev = rhs._min_sev;
	}

	report::~report()
	{
		//nothing to do
	}

	std::ostream & report::print(std::ostream & out) const
	{
		//TODO print report
		return out;
	}

	void report::addResults(std::string mod_name) throw(std::out_of_range, std::runtime_error, std::invalid_argument)
	{
		map < string, pair < module *, void * > >::const_iterator i = _top->modules().find(mod_name);
		if (i == _top->modules().end())
			throw out_of_range("No module named " + mod_name + " exists");
		module *mod = i->second.first;
		const result *res = &(mod->results());	//will throw runtime_error if not run
		pair < map < string, const result *>::iterator, bool > retv = _results.insert(make_pair(mod_name, res));
		if (!retv.second)
			throw invalid_argument("Results for " + mod_name + " have already been added");
	}

	output_format report::outputMode() const
	{
		return _output_mode;
	}

	output_format report::outputMode(output_format out_mode) throw(std::invalid_argument)
	{
		if (out_mode <= SECHK_OUTPUT_NONE || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");
		return _output_mode = out_mode;
	}

	severity report::minSev() const
	{
		return _min_sev;
	}

	severity report::minSev(severity min_sev) throw(std::invalid_argument)
	{
		if (min_sev <= SECHK_SEV_NONE || min_sev > SECHK_SEV_MAX)
			throw invalid_argument("Invalid minimum severity requested");
		return _min_sev = min_sev;
	}
}
