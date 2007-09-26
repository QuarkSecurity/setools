/**
 *  @file
 *  Implements the public interface for sechecker.
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

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>
#include <dlfcn.h>

using std::map;
using std::pair;
using std::vector;
using std::string;
using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::ios_base;
using std::endl;

namespace sechecker
{
	sechecker::sechecker():_modules(), _profiles()
	{
		_active_profile = "";
		_fclist = NULL;
		_policy = NULL;
	}

	sechecker::sechecker(const sechecker & rhs):_modules(rhs._modules), _profiles(rhs._profiles)
	{
		_active_profile = rhs._active_profile;
		_fclist = rhs._fclist;
		_policy = rhs._policy;
	}
	//! Destructor.
	sechecker::~sechecker()
	{
		//nothing to do
		//Note: this function intentionally does not call close().
	}

	std::ostream & sechecker::listModules(std::ostream & out)
	{
		//TODO list of modules printing
		return out;
	}

	std::ostream & sechecker::listProfiles(std::ostream & out)
	{
		//TODO list of profiles printing
		return out;
	}

	const std::map < std::string, profile > &sechecker::profiles() const
	{
		return _profiles;
	}

	const profile & sechecker::addProfile(const profile & prof) throw(std::invalid_argument)
	{
		pair < map < string, profile >::iterator, bool > retv = _profiles.insert(make_pair(prof.name(), profile(prof)));
		if (!retv.second)
			throw invalid_argument("A profile with name " + prof.name() + " already exists");
		return retv.first->second;
	}

	const std::string & sechecker::activeProfile() const
	{
		return _active_profile;
	}

	const std::string & sechecker::activeProfile(const std::string & prof_name) throw(std::out_of_range, std::invalid_argument)
	{
		//empty string deactivates all profiles
		if (prof_name == "")
			return _active_profile = "";

		map < string, profile >::iterator iter = _profiles.find(prof_name);
		if (iter == _profiles.end())
			throw out_of_range("No profile named " + prof_name + " exists");
		_active_profile = prof_name;
		iter->second.apply(*this);	//can throw invalid_argument or out_of_range
		return _active_profile;
	}

	std::map < std::string, std::pair < module *, void * > >&sechecker::modules()
	{
		return _modules;
	}

	const std::map < std::string, std::pair < module *, void * > >&sechecker::modules() const
	{
		return _modules;
	}

		/**
	 * Load a module. If the module is already loaded this does nothing.
	 * @param name_ The name of the module to load.
	 * @post The module is in the set of loaded modules.
	 * @exception std::ios_base::failure Error loading the module from file.
		 */
	void sechecker::loadModule(std::string name_) throw(std::ios_base::failure)
	{
		//TODO load modules and set its handle
	}

	void sechecker::close()
	{
		for (map < string, pair < module *, void * > >::iterator i = _modules.begin(); i != _modules.end(); i)
		{
			dlclose(i->second.second);
			delete i->second.first;
			_modules.erase(i);
			i--;
		}
	}

	void sechecker::runModules(const std::vector < std::string > &mod_names) throw(std::out_of_range, std::runtime_error)
	{
		for (vector < string >::const_iterator i = mod_names.begin(); i != mod_names.end(); i++)
			runModules(*i);
	}
		/**
	 * Run a single module (and any of its dependencies).
	 * This function will only run a module once including any previous calls
	 * to runModules().
	 * @param mod_name Name of the module to run.
	 * @post The module with name \a mod_name will have a valid and complete result.
	 * @exception std::out_of_range No module with name \a mod_name exists.
	 * @exception std::runtime_error Could not complete running of module \a mod_name
	 * or one of its dependencies.
		 */
	void sechecker::runModules(const std::string & mod_name) throw(std::out_of_range, std::runtime_error)
	{
		map<string, pair<module*, void* > >::iterator iter = _modules.find(mod_name);
		if (iter == _modules.end())
		{
			throw out_of_range("No module with name " + mod_name + " exists");
		}
		module * mod = iter->second.first;
		vector<string> dep_stack;
		dep_stack.push_back(mod->name());
		for (vector<string>::iterator i = dep_stack.begin(); i != dep_stack.end(); i++)
		{
			for (vector<string>::const_iterator j = mod->dependencies().begin(); j != mod->dependencies().end(); j++)
			{
				bool found = false;
				for (vector<string>::iterator k = dep_stack.begin(); k != dep_stack.end(); k++)
					if (*k == *j)
						found = true;
				if (!found)
					dep_stack.push_back(*j);
			}
		}

		for (vector<string>::reverse_iterator i = dep_stack.rend(); i != dep_stack.rbegin(); i--)
		{
			iter = _modules.find(*i);
			if (iter == _modules.end())
			{
				throw out_of_range("No module with name " + *i + " (dependency of " + mod_name + ") exists");
			}
			iter->second.first->run(_policy, _fclist);
		}
	}

	void sechecker::runModules() throw(std::out_of_range, std::runtime_error)
	{
		if (_active_profile == "")
			throw runtime_error("No profile is active");

		vector < string > v = _profiles.find(_active_profile)->second.getModuleList();
		runModules(v);
	}

		/**
	 * Create a report object for the listed modules.
	 * @param mod_names List of the names of the modules to include in the report.
	 * @return A newly created report object. The caller is responsible for calling
	 * delete on the returned object.
	 * @exception std::out_of_range A module in the list does not exist.
	 * @exception std::runtime_error One or more of the list modules has not been run.
		 */
	report *sechecker::createReport(const std::vector < std::string > &mod_names) const throw(std::out_of_range,
												  std::runtime_error)
	{
		//TODO report creation
	}
		/**
	 * Create a report object for a single module.
	 * @param mod_name The name of the module for which to create the report.
	 * @return A newly created report object. The caller is responsible for calling
	 * delete on the returned object.
	 * @exception std::out_of_range No module with name \a mod_name exists.
	 * @exception std::runtime_error The module named \a mod_name has not been run.
		 */
	report *sechecker::createReport(const std::string & mod_name) const throw(std::out_of_range, std::runtime_error)
	{
		//TODO report creation
	}
		/**
	 * Create a report object for all modules specified in the currently active profile.
	 * @return A newly created report object. The caller is responsible for calling
	 * delete on the returned object.
	 * @exception std::out_of_range One or more of the modules specified in the currently active
	 * profile does not exist.
	 * @exception std::runtime_error One or more of the modules specified in the currently active
	 * profile has not been run. This exception is also thrown if there is no active profile.
		 */
	report *sechecker::createReport() const throw(std::out_of_range, std::runtime_error)
	{
		//TODO report creation
	}

	apol_policy_t *sechecker::policy() const
	{
		return _policy;
	}

	apol_policy_t *sechecker::policy(apol_policy_t * pol) throw(std::invalid_argument)
	{
		if (pol && _fclist)
		{
			if ((apol_policy_is_mls(pol) > 0 && !_fclist->isMLS()) ||
			    (apol_policy_is_mls(pol) == 0 && _fclist->isMLS()))
				throw invalid_argument("Policy and file contexts list differ in MLS use");
		}
		if (_fclist)
			_fclist->associatePolicy(pol);
		return _policy = pol;
	}

	sefs_fclist *sechecker::fclist() const
	{
		return _fclist;
	}

	sefs_fclist *sechecker::fclist(sefs_fclist * list) throw(std::invalid_argument)
	{
		if (list && _policy)
		{
			if ((apol_policy_is_mls(_policy) > 0 && !list->isMLS()) ||
			    (apol_policy_is_mls(_policy) == 0 && list->isMLS()))
				throw invalid_argument("Policy and file contexts list differ in MLS use");
		}
		if (list)
			list->associatePolicy(_policy);
		return _fclist = list;
	}
}
