/**
 *  @file
 *  Implements the public interface for sechecker.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2008 Tresys Technology, LLC
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

#include <apol/util.h>

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <dlfcn.h>
#include <cassert>

using std::map;
using std::pair;
using std::make_pair;
using std::vector;
using std::string;
using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::ios_base;
using std::setw;
using std::endl;

namespace sechk
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
	sechecker::~sechecker()
	{
		//nothing to do
		//Note: this function intentionally does not call close().
	}

	std::ostream & sechecker::listProfiles(std::ostream & out)
	{
		for (map < string, profile >::const_iterator i = _profiles.begin(); i != _profiles.end(); i++)
		{
			out << setw(20) << i->first << "    " << i->second.description() << endl;
		}
		return out;
	}

	std::ostream & sechecker::listModules(std::ostream & out)
	{
		for (map < string, pair < module *, void * > >::const_iterator i = _modules.begin(); i != _modules.end(); i++)
		{
			out << setw(20) << i->first << "    " << i->second.first->summary() << endl;
		}
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

	void sechecker::loadModule(std::string name_) throw(std::ios_base::failure)
	{
		map < string, pair < module *, void * > >::iterator iter = _modules.find(name_);
		if (iter != _modules.end())
			return;	       //already loaded
		string path = "sechecker/" + name_ + ".so";
		char *found_path = apol_file_find_path(path.c_str());
		if (!found_path)
			throw std::ios_base::failure("Cannot find module " + name_);
		void *handle = dlopen(found_path, RTLD_LAZY | RTLD_GLOBAL);
		free(found_path);
		if (!handle)
		{
			throw std::ios_base::failure("Could not load module " + name_ + ": " + dlerror());
		}
		string init_name = name_ + "_init";
		module_init_fn init_fn = reinterpret_cast < module_init_fn > (dlsym(handle, init_name.c_str()));
		if (!init_fn)
		{
			//grab dlerror message first as dlclose is permitted to change it.
			string message = "Could not initialize module " + name_ + ": " + dlerror();
			dlclose(handle);
			handle = NULL;
			throw std::ios_base::failure(message);
		}
		module *mod = init_fn();
		if (!mod)
		{
			//grab dlerror message first as dlclose is permitted to change it.
			string message = "Initializing module " + name_ + " failed: " + dlerror();
			dlclose(handle);
			handle = NULL;
			throw std::ios_base::failure(message);
		}
		//take ownership of the module
		mod->_owner = this;
		//insert it
		pair < string, pair < module *, void * > >entry = make_pair(name_, make_pair(mod, handle));
		pair < map < string, pair < module *, void * > >::iterator, bool > retv = _modules.insert(entry);
		//this is an assertion as we already check for the case of duplicate load; thus the only failure is oom
		assert(retv.second);
	}

	void sechecker::close()
	{
		while (!_modules.empty())
		{
			delete _modules.begin()->second.first;
			dlclose(_modules.begin()->second.second);
			_modules.erase(_modules.begin());
		}
	}

	void sechecker::runModules(const std::vector < std::string > &mod_names) throw(std::out_of_range, std::runtime_error,
										       std::invalid_argument)
	{
		for (vector < string >::const_iterator i = mod_names.begin(); i != mod_names.end(); i++)
			runModules(*i);
	}

	void sechecker::runModules(const std::string & mod_name) throw(std::out_of_range, std::runtime_error, std::invalid_argument)
	{
		map < string, pair < module *, void * > >::iterator iter = _modules.find(mod_name);
		if (iter == _modules.end())
		{
			throw out_of_range("No module with name " + mod_name + " exists");
		}
		module *mod = iter->second.first;
		vector < string > dep_stack;
		dep_stack.push_back(mod->name());
//              for (vector < string >::iterator i = dep_stack.begin(); i != dep_stack.end(); i++)
		for (size_t i = 0; i < dep_stack.size(); i++)
		{
			module *tmp = _modules.at(*(dep_stack.begin() + i)).first;
			for (vector < string >::const_iterator j = tmp->dependencies().begin(); j != tmp->dependencies().end(); j++)
			{
				bool found = false;
				for (vector < string >::iterator k = dep_stack.begin(); k != dep_stack.end(); k++)
					if (*k == *j)
						found = true;
				if (!found)
					dep_stack.push_back(*j);
			}
		}

		for (vector < string >::reverse_iterator i = dep_stack.rbegin(); i != dep_stack.rend(); i++)
		{
			module *cur_mod = NULL;
			try
			{
				cur_mod = (_modules.at(*i)).first;
			}
			catch(out_of_range)
			{
				throw out_of_range("No module with name " + *i + " (dependency of " + mod_name + ") exists");
			}
			cur_mod->run(_policy, _fclist);
		}
	}

	void sechecker::runModules() throw(std::out_of_range, std::runtime_error, std::invalid_argument)
	{
		if (_active_profile == "")
			throw runtime_error("No profile is active");

		vector < string > v = _profiles.find(_active_profile)->second.getModuleList();
		runModules(v);
	}

	report *sechecker::createReport(const std::vector < std::string > &mod_names) const throw(std::out_of_range,
												  std::runtime_error)
	{
		report *rpt = new report(this);
		for (vector < string >::const_iterator i = mod_names.begin(); i != mod_names.end(); i++)
		{
			rpt->addResults(*i);
		}

		return rpt;
	}

	report *sechecker::createReport(const std::string & mod_name)const throw(std::out_of_range, std::runtime_error)
	{
		report *rpt = new report(this);
		rpt->addResults(mod_name);

		return rpt;
	}

	report *sechecker::createReport() const throw(std::out_of_range, std::runtime_error)
	{
		if (_active_profile == "")
			throw runtime_error("No active profile");
		map < string, profile >::const_iterator iter = _profiles.find(_active_profile);
		vector < string > list = iter->second.getModuleList();
		return createReport(list);
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
