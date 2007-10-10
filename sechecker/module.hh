/**
 *  @file
 *  Defines the public interface for sechecker modules.
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

#ifndef SECHECKER_MODULE_HH
#define SECHECKER_MODULE_HH

#include "result.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>

namespace sechk
{
	//forward declarations
	class requirement;
	class option;
	class sechecker;
	class element;

	//! Values to indicate the severity of module results.
	enum severity
	{
		SECHK_SEV_NONE = 0,    //!< Only used for error checking.
		SECHK_SEV_UTIL,	       //!< Results for this module are used for collecting data used by other modules. They have no security significance.
		SECHK_SEV_LOW,	       //!< Results for this module indicate a flaw in the policy that does not affet the manner in which the policy is enforced, but is considered to be improper.
		SECHK_SEV_MED,	       //!< Results for this module indicate a flaw in the policy that change the manner in which the policy is enforced; however, it does not present an identifiable security risk.
		SECHK_SEV_HIGH,	       //!< Results for this module indicate a flaw in the policy that presents an identifiable security risk.
		SECHK_SEV_MAX = SECHK_SEV_HIGH	//!< The maximum severity value.
	};

	/**
	 * A modular check to perform on a policy and (optionally) a file context list.
	 * Each module represents a single distinct check; however, one module may request
	 * the results of another to reduce reduntant checking.
	 */
	class module
	{
	      public:
		/** Create a module.
		 * @param name_ The name of the module.
		 * @param sev The severity of the module.
		 * @param summary_ A brief summary of what the module checks.
		 * @param desc A detailed description of the steps performed by the module check.
		 * @exception std::invalid_argument The name provided is empty or invalid severity specified.
		 */
		module(const std::string & name_, severity sev, const std::string & summary_,
		       const std::string & desc) throw(std::invalid_argument);
		/**
		 * Copy a module.
		 * @param rhs The module to copy.
		 */
		 module(const module & rhs);
		//! Destructor.
		 virtual ~module();

		/**
		 * Verify that the given policy and file context list satisfy all requirements.
		 * @param pol The policy to be used.
		 * @param list The file context list to use if needed.
		 * @return Returns \a true if all requirements are satisfied, and \a false otherwise.
		 * @post All of this module's requirements and recommendations will be updated.
		 */
		bool verify(apol_policy_t * pol, sefs_fclist * list = NULL);

		/**
		 * Run the module and populate its results.
		 * @param pol The policy on which to perform the check.
		 * @param list the file context list to use for context data if needed.
		 * @exception std::invalid_argument The provided policy and file context list
		 * do not meet the module's requirements.
		 * @exception std::runtime_error Could not complete running of the module.
		 */
		void run(apol_policy_t * pol, sefs_fclist * list) throw(std::invalid_argument, std::runtime_error);

		/**
		 * Print a module's help text to an output stream.
		 * This text includes the module's name, severity, description,
		 * and list of dependencies, as well as the  name and description
		 * of each of its requirements, recommendations, and options.
		 * @param out The stream to which to write the help text.
		 * @return The stream after writing.
		 */
		 std::ostream & help(std::ostream & out) const;

		/**
		 * Get the results of the module's check.
		 * @return The results populated by run().
		 * @exception std::runtime_error The module has not yet been run.
		 */
		const result & results() const throw(std::runtime_error);
		/**
		 * Set the output mode for the results.
		 * @param out_mode The desired amount of output when reporting the results.
		 * @return The output mode set.
		 * @exception std::invalid_argument Invalid output mode requested.
		 */
		output_format outputMode(output_format out_mode) throw(std::invalid_argument);

		/**
		 * Get the set of configurable options for the module.
		 * @return The set of options indexed by name.
		 */
		const std::map < std::string, option > &options() const;
		/**
		 * Set the value of an option.
		 * @param name_ The name of the option to set.
		 * @param values The list of values for the option.
		 * This list may <b>not</b> be empty.
		 * @param override Discard previous values if \a true, otherwise
		 * append additional values.
		 * @return The option set.
		 * @exception std::out_of_range No option with name \a name exists.
		 * @exception std::invalid_argument One or more of the \a values
		 * specified is invalid, or \a values is empty.
		 */
		const option & setOption(const std::string & name_, const std::vector < std::string > &values,
					 bool override) throw(std::out_of_range, std::invalid_argument);

		/**
		 * Get the list of module dependencies.
		 * @return The list of module dependencies.
		 */
		const std::vector < std::string > &dependencies() const;

		/**
		 * Get the set of requirements that a policy (or associated file
		 * context list) must meet to run the module.
		 * @return The set of requirements.
		 */
		const std::map < std::string, requirement > &requirements() const;

		/**
		 * Get the set of recommended features that a policy (or
		 * associated file context list) should meet to obtain the most
		 * complete set of results possible for the module.
		 * @return The set of recommendations.
		 */
		const std::map < std::string, requirement > &recommendations() const;

		/**
		 * Get the name of the module.
		 * @return The module name.
		 */
		const std::string & name() const;
		/**
		 * Get the brief summary of the module.
		 * @return The module summary.
		 */
		const std::string & summary() const;
		/**
		 * Get the description of the module.
		 * @return The module description.
		 */
		const std::string & description() const;
		/**
		 * Get the severity of the module.
		 * @return The module severity.
		 */
		severity moduleSeverity() const;

		friend class sechecker;

	      protected:
		const sechecker *_owner;	//!< The sechecker object that owns this module.
		 std::string _name;    //!< The name of the module. This name is a unique idenifier for the module.
		 std::string _summary; //!< A brief summary of what the module does.
		 std::string _description;	//!< A detailed description of the check performed by run();
		severity _sev;	       //!< The severity level of this module's results.
		 std::vector < std::string > _dependencies;	//!< The list of the names of all modules from which this module will request results.
		 std::map < std::string, requirement > _requirements;	//!< The set of all features required to call run().
		 std::map < std::string, requirement > _recommendations;	//!< The set of all features that are recommended for more complete results but not required to call run().
		 std::map < std::string, option > _options;	//!< The configurable options available to this module.
		bool _run;	       //!< Set once the module has run so that it need only run once.
		result _results;       //!< The results generated by run().

		/**
		 * Function called by run() to perform module specific checking.
		 * @param pol The policy used.
		 * @param list The file context list to use.
		 */
		virtual void run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error) = 0;
	};

	/**
	 * Function to get an initialized module.
	 * @return A fully initialized module.
	 */
	typedef module *(*module_init_fn) (void);
}

#endif				       /* SECHECKER_MODULE_HH */
