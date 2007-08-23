/**
 *  @file
 *  Defines the public interface for sechecker module options.
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

#ifndef SECHECKER_OPTION_HH
#define SECHECKER_OPTION_HH

#include <string>
#include <vector>
#include <stdexcept>

namespace sechecker
{
	//! Optional parameter for a sechecker module.
	class option
	{
	      public:
		/**
		 * Create a module option object.
		 * @param name_ The name of the option.
		 * @param desc The description of the option.
		 * @param vals The initial value(s) of the option.
		 * @exception std::invalid_argument Name or one or more of the provided value strings was empty.
		 */
		option(const std::string & name_, const std::string & desc, const std::vector < std::string > &vals =
		       std::vector < std::string > ())throw(std::invalid_argument);
		/**
		 * Copy a module option object.
		 * @param rhs The option to copy.
		 */
		 option(const option & rhs);
		//! Destructor.
		~option();

		/**
		 * Get the name of the option.
		 * @return The name of the option.
		 */
		const std::string & name() const;
		/**
		 * Get the description of the option.
		 * @return The description of the option.
		 */
		const std::string & description() const;
		/**
		 * Get the current values for the option.
		 * @return The current values for the option.
		 */
		const std::vector < std::string > &values() const;
		/**
		 * Clear all values for the option.
		 * Note: it is invalid to run a module if one or more options
		 * has no value.
		 */
		void clearValues();
		/**
		 * Append a value for an option.
		 * @param value The value to append.
		 * @return The value appended.
		 * @exception std::invalid_argument \a value is an empty string.
		 */
		const std::string & appendValue(const std::string & value) throw(std::invalid_argument);

	      private:
		 std::string _name;    //!< The name of the option.
		 std::vector < std::string > _values;	//!< The values associated with the option.
		 std::string _description;	//!< A brief description of the option including possible values and their effect.
	};
}

#endif				       /* SECHECKER_OPTION_HH */
