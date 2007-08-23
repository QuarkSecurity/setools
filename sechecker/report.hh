/**
 *  @file
 *  Defines the public interface for reporting sechecker module results.
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

#ifndef SECHECKER_REPORT_HH
#define SECHECKER_REPORT_HH

#include "result.hh"
#include "module.hh"
#include "profile.hh"

#include <string>
#include <map>
#include <iostream>
#include <stdexcept>

namespace sechecker
{
	//forward declaration
	class sechecker;

	//! Report generator class for reporting results from multiple modules.
	class report
	{
	      public:
		/**
		 * Create a report object for a sechecker object.
		 * @param top The top level sechecker object containing the results to report.
		 * @param out_mode The level of output to use for all modules. If \a out_mode is
		 * SECHK_OUTPUT_DEFAULT, use each module's output mode instead.
		 * @param min_sev The minimum severity of a module to report its results. Output
		 * for all modules in the report with severity less than this value will be supressed.
		 */
		report(const sechecker * top, output_format out_mode = SECHK_OUTPUT_DEFAULT, severity min_sev = SECHK_SEV_LOW);
		/**
		 * Copy a report.
		 * @param rhs The report to copy.
		 */
		 report(const report & rhs);
		//! Destructor.
		~report();

		/**
		 * Print the report.
		 * @param out The stream to which to write the output.
		 * @return The stream after writing.
		 */
		 std::ostream & print(std::ostream & out) const;

		/**
		 * Add the resuts of a module to the report.
		 * @param mod_name The name of the module with results to add.
		 * @exception std::out_of_range No module with name \a mod_name exists.
		 * @exception std::runtime_error Module \a mod_name has not been run.
		 */
		void addResults(std::string mod_name) throw(std::out_of_range, std::runtime_error);

		/**
		 * Get the preferred level of output for the report.
		 * @return The preferred level of output for the report.
		 */
		output_format outputMode() const;
		/**
		 * Set the preferred level of output for the report.
		 * @param out_mode The level of output to use for all modules. If \a out_mode is
		 * SECHK_OUTPUT_DEFAULT, use each module's output mode instead.
		 * @return The level of output set.
		 */
		output_format outputMode(output_format out_mode);

		/**
		 * Get the minimum severity of a module to report its results.
		 * @return The minimum severity of a module to report its results.
		 */
		severity minSev() const;
		/**
		 * Get the minimum severity of a module to report its results.
		 * @param min_sev The severity level to set.
		 * @return The severity level set.
		 */
		severity minSev(severity min_sev);

	      private:
		 std::map < std::string, const result *>_results;	//!< The set of results to include in the report.
		output_format _output_mode;	//!< The level of output to use for the report.
		severity _min_sev;     //!< The minimum severity a module must have to appear in the report.
		//std::string _style_sheet; //!< The style sheet to use for the report. TODO add this later.
		const sechecker *_top; //!< The sechecker object containing the modules with results to report.
	};
}

#endif				       /* SECHECKER_REPORT_HH */
