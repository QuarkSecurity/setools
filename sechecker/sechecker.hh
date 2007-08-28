/**
 *  @file
 *  Defines the public interface for sechecker.
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

#ifndef SECHECKER_HH
#define SECHECKER_HH

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>

/**
 * The sechecker namespace includes all classes used by the sechecker tool.
 */
namespace sechecker
{
	//forward declarations
	class module;
	class report;
	class profile;

	/**
	 * Top level class for sechecker.
	 */
	class sechecker
	{
	      public:
		//! Create a sechecker object.
		sechecker();
		/**
		 * Copy a sechecker object.
		 * @param rhs Sechecker object to copy.
		 */
		sechecker(const sechecker & rhs);
		//! Destructor.
		~sechecker();

		/**
		 * Output a list of all modules currently loaded and their brief descriptions.
		 * @param out The stream to which to write output.
		 * @return \a out after writing.
		 */
		 std::ostream & list_modules(std::ostream & out);
		/**
		 * Output a list of all profiles currently loaded and their brief descriptions.
		 * @param out The stream to which to write output.
		 * @return \a out after writing.
		 */
		 std::ostream & list_profiles(std::ostream & out);

		/**
		 * Get the set of known profiles, keyed by name.
		 * @return The set of konown profiles.
		 */
		const std::map < std::string, profile > &profiles() const;
		/**
		 * Add a profile to the set of known profiles.
		 * @param prof The profile to add. (It will be duplicated.)
		 * @return The profile added.
		 */
		const profile & addProfile(const profile & prof);

		/**
		 * Get the name of the currently active profile.
		 * @return The name of the currently active profile,
		 * or empty string if no profile is active.
		 */
		const std::string & activeProfile() const;
		/**
		 * Set the currently active profile. Only one profile is active.
		 * @param prof_name The name of the profile to set as active.
		 * Set to empty string to deacitivate all profiles.
		 * @return The name of the profile set as active or empty string if no
		 * profile is active.
		 */
		const std::string & activeProfile(const std::string & prof_name) throw(std::out_of_range);

		/**
		 * Get the set of loaded modules.
		 * @return The set of loaded modules.
		 */
		 std::map < std::string, module * >&modules();
		/**
		 * Get the set of loaded modules.
		 * @return The set of loaded modules.
		 */
		const std::map < std::string, module * >&modules() const;

		/**
		 * Run a list of modules. All listed modules will be run only once
		 * including any previous calls to runModules().
		 * @param mod_names List of the names of the modules to run.
		 * @post All modules listed in \a mod_names have a valid and complete result.
		 * @exception std::out_of_range A module in the list does not exist.
		 * @exception std::runtime_error Could not complete running of all listed modules.
		 */
		void runModules(const std::vector < std::string > &mod_names) throw(std::out_of_range, std::runtime_error);
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
		void runModules(const std::string & mod_name) throw(std::out_of_range, std::runtime_error);
		/**
		 * Run all modules in the currently active profile. All modules specified
		 * in the profile will be run only once including any previous calls to runModules().
		 * @post All modules in the currently active profile will have valid and complete results.
		 * @exception std::out_of_range One or more modules specified in the currently active
		 * profile does not exist.
		 * @exception std::runtime_error Could not complete running of all specified modules.
		 * This exception is also thrown if there is no active profile.
		 */
		void runModules() throw(std::out_of_range, std::runtime_error);

		/**
		 * Create a report object for the listed modules.
		 * @param mod_names List of the names of the modules to include in the report.
		 * @return A newly created report object. The caller is responsible for calling
		 * delete on the returned object.
		 * @exception std::out_of_range A module in the list does not exist.
		 * @exception std::runtime_error One or more of the list modules has not been run.
		 */
		report *createReport(const std::vector < std::string > &mod_names) const throw(std::out_of_range,
											       std::runtime_error);
		/**
		 * Create a report object for a single module.
		 * @param mod_name The name of the module for which to create the report.
		 * @return A newly created report object. The caller is responsible for calling
		 * delete on the returned object.
		 * @exception std::out_of_range No module with name \a mod_name exists.
		 * @exception std::runtime_error The module named \a mod_name has not been run.
		 */
		report *createReport(const std::string & mod_name) const throw(std::out_of_range, std::runtime_error);
		/**
		 * Create a report object for all modules specified in the currently active profile.
		 * @return A newly created report object. The caller is responsible for calling
		 * delete on the returned object.
		 * @exception std::out_of_range One or more of the modules specified in the currently active
		 * profile does not exist.
		 * @exception std::runtime_error One or more of the modules specified in the currently active
		 * profile has not been run. This exception is also thrown if there is no active profile.
		 */
		report *createReport() const throw(std::out_of_range, std::runtime_error);

		/**
		 * Get the policy used when running modules.
		 * @return The policy used when running modules.
		 */
		apol_policy_t *policy() const;
		/**
		 * Set the policy used when running modules.
		 * @param pol The policy to set. The sechecker object does not take
		 * ownership of \a pol, but the caller should not destroy \a pol
		 * until the sechecker object and all associated results are destroyed.
		 * If a file contexts list is set, \a pol will be associated with it.
		 * @return The policy set.
		 * @exception std::invalid_argument The provided fclist and policy are not compatiple.
		 */
		apol_policy_t *policy(apol_policy_t * pol);

		/**
		 * Get the file contexts list used when running modules.
		 * @return The file contexts list used when running modules.
		 */
		sefs_fclist *fclist() const;
		/**
		 * Set the file contexts list to use when running modules.
		 * @param list The file contexts list to set. The sechecker object
		 * does not take ownership of \a list, but the caller should not
		 * destroy \a list until the sechecker object and all associated
		 * results are destroyed. If a policy is set, it will be associated
		 * with \a list.
		 * @return The file contexts list set.
		 * @exception std::invalid_argument The provided fclist and policy are not compatiple.
		 */
		sefs_fclist *fclist(sefs_fclist * list) throw(std::invalid_argument);

	      private:
		/**
		 * Add a module to the set of loaded modules.
		 * @param mod The module to add.
		 * @return The module added.
		 * @exception std::invalid_argument A module with the same name already exists.
		 */
		const module & addModule(const module & mod) throw(std::invalid_argument);

		 std::map < std::string, module * >_modules;	//!< The set of loaded modules.
		 std::map < std::string, profile > _profiles;	//!< The set of known profiles.
		 std::string _active_profile;	//!< The name of the currently active profile.
		sefs_fclist *_fclist;  //!< The file contexts list to use when running modules.
		apol_policy_t *_policy;	//!< The policy ot use when running modules.
	};
}

//include the rest of the sechecker namespace
#include "module.hh"
#include "requirement.hh"
#include "option.hh"
#include "profile.hh"
#include "result.hh"

#endif				       /* SECHECKER_HH */
