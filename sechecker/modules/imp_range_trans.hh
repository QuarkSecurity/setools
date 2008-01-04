/**
 *  @file
 *  Defines the interface for the impossible range transitions module.
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

#ifndef SECHECKER_MODULE_IMP_RANGE_TRANS
#define SECHECKER_MODULE_IMP_RANGE_TRANS

#include "sechecker.hh"
#include "module.hh"

#include <vector>
#include <string>
#include <stdexcept>

extern "C"
{
	/**
	 * Initialization function for this module.
	 * This is exported as a C function so dlsym can find it.
	 * @return A fully initialized module object.
	 */
	void *imp_range_trans_init(void);
}

namespace sechk
{
	class imp_range_trans_module:public module
	{
	      public:
		/**
		 * Create a impossible range transitions module.
		 * Module will be initialized with default options.
		 * @exception std::invalid_argument Error setting default properties of the module.
		 * @exception std::out_of_range Error setting default options, requirements, or recommendations.
		 */
		imp_range_trans_module() throw(std::invalid_argument, std::out_of_range);

		/**
			 * Copy a impossible range transitions module.
			 * @param rhs The module to copy.
		 */
		imp_range_trans_module(const imp_range_trans_module & rhs);

		//! Destructor.
		 virtual ~imp_range_trans_module();

		/**
			 * Function called by run() to perform module specific checking.
			 * @param pol The policy used.
			 * @param list The file context list to use.
		 */
		virtual void run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error);

	};
}

#endif				       /* SECHECKER_MODULE_IMP_RANGE_TRANS */
