/**
 *  @file
 *  Defines the public interface for sechecker module profiles.
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

#ifndef SECHECKER_PROFILE_HH
#define SECHECKER_PROFILE_HH

#include "option.hh"

#include <string>
#include <map>
#include <vector>
#include <stdexcept>

namespace sechk
{
	//forward declaration
	class sechecker;

	//! Values to specify the desired amount of module output in a report.
	enum output_format
	{
		SECHK_OUTPUT_NONE = 0, //!< Only for error checking
		SECHK_OUTPUT_DEFAULT,  //!< Only used by report, do not globally override individual module ouput values.
		SECHK_OUTPUT_QUIET,    //!< Do not report output for the module.
		SECHK_OUTPUT_SHORT,    //!< Output a list of result entries but not the proof.
		SECHK_OUTPUT_VERBOSE,  //!< Output as much information as possible.
		SECHK_OUTPUT_MAX = SECHK_OUTPUT_VERBOSE	//!< The maximum output format value.
	};

	//! Sechecker profile representing a set of modules to run and all associated options
	class profile
	{
	      public:

		//! Specification of output and options for a single module listed in the profile.
		class module_specification
		{
		      public:
			/**
			 * Create a module specification entry for a profile. This entry indicates
			 * that the module named should be run with the supplied options and
			 * should be included in the report with the given output format.
			 * @param name_ The name of the module.
			 * @param output The level of output for this module in the report.
			 * @exception std::invalid_argument Empty name or invalid output mode requested.
			 */
			module_specification(const std::string & name_, output_format output) throw(std::invalid_argument);
			/**
			 * Copy a module specification entry.
			 * @param rhs The module specification entry to copy.
			 */
			 module_specification(const module_specification & rhs);
			//! Destructor.
			~module_specification();

			/**
			 * Get the name of the specified module.
			 * @return The name of the specified module.
			 */
			const std::string & name () const;

			/**
 			 * Get the output format for the specified module.
 			 * @return The level of output for the specified module.
 			 */
			output_format outputMode() const;

			/**
			 * Add an option to the module specification. This option will override
			 * any defaults set by the module.
			 * @param name_ Name of the option.
			 * @param vals Values to assign to the option.
			 * @exception std::invalid_argument One or more of \a name_ or vals is an empty string.
			 */
			void addOption(const std::string & name_,
				       const std::vector < std::string > &vals) throw(std::invalid_argument);
			/**
			 * Get the set of options for the specified module.
			 * @return The set of options for the specified module.
			 */
			const std::map < std::string, option > &options() const;

		      private:
			 std::string _name;	//!< The name of the module.
			output_format _output_mode;	//!< The amount of desired output for the module.
			 std::map < std::string, option > _options;	//!< The options specified for the module.
		};

		/**
		 * Create a profile.
		 * @param path Path of the profile to parse.
		 * @exception std::runtime_error Error parsing the profile.
		 */
		 profile(const std::string & path) throw(std::runtime_error);
		 /**
		  * Copy a profile.
		  * @param rhs The profile to copy.
		  */
		 profile(const profile & rhs);
		//! Destructor.
		~profile();

		/**
		 * Get the name of the profile.
		 * @return The name of the profile.
		 */
		const std::string & name() const;

		/**
		 * Get the version of sechecker required for the profile.
		 * @return The version of sechecker required for the profile.
		 */
		const std::string & version() const;

		/**
		 * Get the description of the profile.
		 * @return The description of the profile.
		 */
		const std::string & description() const;

		/**
		 * Get a list of all modules specified in the profile.
		 * @return A list of all modules specified in the profile.
		 */
		const std::vector < std::string > getModuleList() const;
		/**
		 * Apply the options and selections to all modules specified in the profile.
		 * @pre All modules specified are loaded.
		 * @param top The sechecker object containing the modules
		 * specified in the profile.
		 * @post All options for the specified modules are overridden by
		 * those in the profile.
		 * @exception std::invalid_argument One or more of the values given
		 * for output or options is invalid.
		 * @exception std::out_of_range One or more of the modules specified
		 * or options given for a module does not exist.
		 */
		void apply(sechecker & top) const throw(std::invalid_argument, std::out_of_range);

	      private:
		 std::string _version; //!< Expected minimum version of sechecker.
		 std::string _name;    //!< The name of the profile.
		 std::string _description;	//!< Description of the checks performed.
		 std::map < std::string, module_specification > _mod_specs;	//!< Set of modules specified by the profile.
	};
}

#endif				       /* SECHECKER_PROFILE_HH */
