/**
 *  @file
 *  Implements the public interface for sechecker module requirements.
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

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <string>
#include <stdexcept>

#include <sys/stat.h>

using std::invalid_argument;

namespace sechk
{
	requirement::requirement(require_code code) throw(std::invalid_argument)
	{
		if (code <= SECHK_REQUIRE_NONE || code > SECHK_REQUIRE_MAX)
			throw invalid_argument("Invalid requirement requested");
		_satisfied = false;
		_code = code;
	}

	requirement::requirement(const requirement & rhs)
	{
		_satisfied = rhs._satisfied;
		_code = rhs._code;
	}

	requirement::~requirement()
	{
		//nothing to do
	}

	const std::string requirement::name() const
	{
		return require_code_name(_code);
	}

	const std::string requirement::description() const
	{
		return require_code_description(_code);
	}

	bool requirement::satisfied() const
	{
		return _satisfied;
	}

	bool requirement::check(apol_policy_t * pol, sefs_fclist * list)
	{
		switch (_code)
		{
		case SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES:	// Require that the policy has attribute names.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_ATTRIB_NAMES))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES:	// Require that the policy has syntactic rules.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_SYN_RULES))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_LINE_NUMBERS:	// Require that the policy has line numbers.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_LINE_NUMBERS))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_CONDITIONALS:	// Require that the policy has support for booleans and conditional policy.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_CONDITIONALS))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_MODULES:	// Require that the policy has support for loadable modules.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_MODULES))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW:	// Require that the policy has support for neverallow rules.
		{
			if (!qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_NEVERALLOW))
				_satisfied = false;
			else
				_satisfied = true;
			break;
		}
		case SECHK_REQUIRE_SELINUX_SYSTEM:	// Require a selinux system to run.
		{
			_satisfied = is_selinux_enabled();
			break;
		}
		case SECHK_REQUIRE_FCLIST:	// Require a valid file context list to run.
		{
			_satisfied = (list != NULL);
			break;
		}
		case SECHK_REQUIRE_DEFAULT_CONTEXTS:	// Require the default_contexts file (the file specifying default contexts for users).
		{
			struct stat stat_buf;
			_satisfied = (stat(selinux_default_context_path(), &stat_buf) < 0);
			break;
		}
		case SECHK_REQUIRE_MLS:	// Require MLS for both the policy and file context list (if present).
		{
			bool pol_ok = false, fc_ok = false;
			if (qpol_policy_has_capability(apol_policy_get_qpol(pol), QPOL_CAP_MLS))
				pol_ok = false;
			if (!list || list->isMLS())
				fc_ok = true;
			_satisfied = (pol_ok && fc_ok);
			break;
		}
		case SECHK_REQUIRE_NONE:	// Only used for error checking.
		default:
		{
			return false;
		}
		}
		return _satisfied;
	}

	const std::string require_code_name(require_code code)
	{
		switch (code)
		{
		case SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES:	// Require that the policy has attribute names.
		{
			return "Attribute_Names";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES:	// Require that the policy has syntactic rules.
		{
			return "Syntactic_Rules";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_LINE_NUMBERS:	// Require that the policy has line numbers.
		{
			return "Line_Numbers";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_CONDITIONALS:	// Require that the policy has support for booleans and conditional policy.
		{
			return "Conditional_Policy";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_MODULES:	// Require that the policy has support for loadable modules.
		{
			return "Modular_Policy";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW:	// Require that the policy has support for neverallow rules.
		{
			return "Neverallow_Rules";
		}
		case SECHK_REQUIRE_SELINUX_SYSTEM:	// Require a selinux system to run.
		{
			return "Selinux_System";
		}
		case SECHK_REQUIRE_FCLIST:	// Require a valid file context list to run.
		{
			return "File_Contexts";
		}
		case SECHK_REQUIRE_DEFAULT_CONTEXTS:	// Require the default_contexts file (the file specifying default contexts for users).
		{
			return "Default_Contexts";
		}
		case SECHK_REQUIRE_MLS:	// Require MLS for both the policy and file context list (if present).
		{
			return "MLS";
		}
		case SECHK_REQUIRE_NONE:	// Only used for error checking.
		default:
		{
			return "";
		}
		}
	}

	const std::string require_code_description(require_code code)
	{
		switch (code)
		{
		case SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES:	// Require that the policy has attribute names.
		{
			return "Policy must store the names of attributes";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_SYN_RULES:	// Require that the policy has syntactic rules.
		{
			return "Policy must store syntactic rules";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_LINE_NUMBERS:	// Require that the policy has line numbers.
		{
			return "Policy must store line numbers";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_CONDITIONALS:	// Require that the policy has support for booleans and conditional policy.
		{
			return "Policy must support conditional policy";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_MODULES:	// Require that the policy has support for loadable modules.
		{
			return "Policy must support loadable modules";
		}
		case SECHK_REQUIRE_POLICY_CAPABILITY_NEVERALLOW:	// Require that the policy has support for neverallow rules.
		{
			return "Policy must store neverallow rules";
		}
		case SECHK_REQUIRE_SELINUX_SYSTEM:	// Require a selinux system to run.
		{
			return "System must have runtime SELinux support";
		}
		case SECHK_REQUIRE_FCLIST:	// Require a valid file context list to run.
		{
			return "A valid file_contexts file is required";
		}
		case SECHK_REQUIRE_DEFAULT_CONTEXTS:	// Require the default_contexts file (the file specifying default contexts for users).
		{
			return "The default_contexts file is required";
		}
		case SECHK_REQUIRE_MLS:	// Require MLS for both the policy and file context list (if present).
		{
			return "MLS support is required";
		}
		case SECHK_REQUIRE_NONE:	// Only used for error checking.
		default:
		{
			return "";
		}
		}
	}
}
