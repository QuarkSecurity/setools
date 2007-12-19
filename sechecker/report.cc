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
#include <vector>
#include <iostream>
#include <iomanip>
#include <stdexcept>

using std::invalid_argument;
using std::out_of_range;
using std::map;
using std::pair;
using std::vector;
using std::string;
using std::setw;
using std::left;
using std::endl;

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
		output_format out_mode = _output_mode;
		for (map < string, const result * >::const_iterator i = _results.begin(); i != _results.end(); i++)
		{
			if (_output_mode == SECHK_OUTPUT_DEFAULT)
				out_mode = i->second->outputMode();
			if (_results.size() != 1 && _top->modules().at(i->first).first->moduleSeverity() < _min_sev)
				continue;

			out << setw(30) << left << "Module: " + i->first << "Severity: ";
			switch (_top->modules().at(i->first).first->moduleSeverity())
			{
			case SECHK_SEV_UTIL:
			{
				out << "Utility";
				break;
			}
				case SECHK_SEV_LOW:
			{
				out << "Low";
				break;
			}
			case SECHK_SEV_MED:
			{
				out << "Medium";
				break;
			}
			case SECHK_SEV_HIGH:
			{
				out << "High";
				break;
			}
			case SECHK_SEV_NONE:
			default:
			{
				out << "Error";
				break;
			}
			}
			out << endl << setw(80) << std::setfill('-') << "-" << endl;
			out << std::setfill(' ');
			out << _top->modules().at(i->first).first->summary() << endl;
			if (out_mode > SECHK_OUTPUT_SHORT)
			{
				out << _top->modules().at(i->first).first->description() << endl;
				if (!_top->modules().at(i->first).first->options().empty())
				{
					out << endl << "Options: " << endl;
					for (map < string, option >::const_iterator j =
					     _top->modules().at(i->first).first->options().begin();
					     j != _top->modules().at(i->first).first->options().end(); j++)
					{
						out << "    " << j->first << ":" << endl << "        ";
						for (vector < string >::const_iterator k = j->second.values().begin();
						     k != j->second.values().end(); k++)
						{
							out << *k << " ";
						}
						out << endl;
					}
				}
			}
			out << endl;
			// now that all the heading info has been displayed print the results
			out << "Found " << i->second->entries().size() << " result" << (i->second->entries().size() ==
											1 ? ":" : "s:") << endl;
			int element_count = 0;	// this is for spacing in short output mode
			for (map < void *, result::entry >::const_iterator j = i->second->entries().begin();
			     j != i->second->entries().end(); j++)
			{
				j->second.Element().print(out, _top->policy());
				++element_count;
				element_count %= 4;	//change this to change number per line in short mode
				if (out_mode == SECHK_OUTPUT_VERBOSE)
				{
					out << ":" << endl;
					//print proof
					for (map < void *, result::entry::proof >::const_iterator k = j->second.Proof().begin();
					     k != j->second.Proof().end(); k++)
					{
						out << "    " << k->second.prefix();
						k->second.Element().print(out, _top->policy());
						out << endl;
					}
				}
				// if some kind of rule, add a newline
				else if (j->second.Element().type() == typeid(qpol_avrule_t *) ||
					 j->second.Element().type() == typeid(qpol_terule_t *) ||
					 j->second.Element().type() == typeid(qpol_range_trans_t *) ||
					 j->second.Element().type() == typeid(qpol_role_allow_t *) ||
					 j->second.Element().type() == typeid(qpol_role_trans_t *))
				{
					out << endl;
				}
				// if count per line reached
				else if (!element_count)
				{
					if (++j != i->second->entries().end())	//no comma after last element
						out << "," << endl;
					--j;
				}
				else   // in short mode but only need a comma
				{
					if (++j != i->second->entries().end())
						out << ", ";
					--j;
				}
			}
			if (out_mode != SECHK_OUTPUT_VERBOSE)
				out << endl;
			out << endl;
		}
		out << endl;
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

	const std::map < std::string, const result *>&report::results() const
	{
		return _results;
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
