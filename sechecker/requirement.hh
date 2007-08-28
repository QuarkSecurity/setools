/**
 *  @file
 *  Defines the public interface for sechecker module requirements.
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

#ifndef SECHECKER_REQUIREMENT_HH
#define SECHECKER_REQUIREMENT_HH

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <string>
#include <stdexcept>

namespace sechecker
{
	//! Values to represent a requirement type.
	enum require_code
	{
		SECHK_REQUIRE_NONE = 0,	//!< Only used for error checking.
		SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES,	//!< Require that the policy has attribute names.
		SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES,	//!< Require that the policy has syntactic rules.
		SECHK_REQUIRE_POLICY_CAPABILITY_LINE_NUMBERS,	//!< Require that the policy has line numbers.
		SECHK_REQUIRE_POLICY_CAPABILITY_CONDITIONALS,	//!< Require that the policy has support for booleans and conditional policy.
		SECHK_REQUIRE_POLICY_CAPABILITY_MODULES,	//!< Require that the policy has support for loadable modules.
		SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW,	//!< Require that the policy has support for neverallow rules.
		SECHK_REQUIRE_SELINUX_SYSTEM,	//!< Require a selinux system to run.
		SECHK_REQUIRE_FCLIST,  //!< Require a valid file context list to run.
		SECHK_REQUIRE_DEFAULT_CONTEXTS,	//!< Require the default_contexts file (the file specifying default contexts for users).
		SECHK_REQUIRE_MLS,     //!< Require MLS for both the policy and file context list (if present).
		SECHK_REQUIRE_MAX = SECHK_REQUIRE_MLS	//!< The maximum value for a requirement code;
	};

	//! Object to tract the requirements to run a module. This class is also used for reccommendations.
	class requirement
	{
	      public:
		/**
		 * Create a requirement.
		 * @param code The requirement type code (any value other than SECHK_REQUIRE_NONE).
		 * @exception std::invalid_argument The given code is invalid.
		 */
		requirement(require_code code) throw(std::invalid_argument);
		/**
		 * Copy a requirement.
		 * @param rhs The requirement to copy.
		 */
		requirement(const requirement & rhs);
		//! Destructor.
		~requirement();

		/**
		 * Get the name of the requirement.
		 * @return The requirement's name.
		 */
		const std::string name() const;
		/**
		 * Get a description of the requirement.
		 * @return A description of the requirement.
		 */
		const std::string description() const;
		/**
		 * Determine if this requirement has been satisfied.
		 * @pre check() has already been called.
		 * @return If the policy and file context list (if needed) meet the requirement,
		 * return \a true, otherwise, return \a false.
		 */
		bool satisfied() const;

		/**
		 * Check the requirement.
		 * If the policy and file context list (if needed) satisfy the requirement,
		 * update the \a _satisfied field.
		 * @param pol The policy to check.
		 * @param list The file context list to check.
		 * (Only used for SECHK_REQUIRE_FCLIST and SECHK_REQUIRE_MLS.)
		 * @return If the requirement is satisfied, return \a true, otherwise return \a false.
		 */
		bool check(apol_policy_t * pol, sefs_fclist * list);
	      private:
		 bool _satisfied;      //!< Set to true when the requirement is satisfied.
		require_code _code;    //!< The code indicating the type of requirement.
	};

	/**
	 * Get the name associated with a requirement of type \a code.
	 * @return The name associated with a requirement of type \a code.
	 */
	const std::string require_code_name(require_code code);
	/**
	 * Get a description of what requiring \a code means.
	 * @return A description of requiring \a code.
	 */
	const std::string require_code_description(require_code code);
}

#endif				       /* SECHECKER_REQUIREMENT_HH */
