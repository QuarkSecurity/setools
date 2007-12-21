/**
 *  @file
 *  Implementation of the types without allow rules utility module.
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

#include "types_wo_allow.hh"
#include "sechecker.hh"
#include "module.hh"
#include "result.hh"

#include <polsearch/polsearch.hh>

#include <apol/policy.h>

#include <vector>
#include <string>
#include <map>
#include <stdexcept>

using std::vector;
using std::string;
using std::map;
using std::pair;
using std::make_pair;
using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::bad_alloc;

void *types_wo_allow_init(void)
{
	return static_cast < void *>(new sechk::types_wo_allow_module());
}

namespace sechk
{
	types_wo_allow_module::types_wo_allow_module() throw(std::invalid_argument, std::out_of_range):module("types_wo_allow",
													      SECHK_SEV_LOW,
													      "Find types not used in an allow rule.",
													      "A type that is never granted an allow rule in the policy is a dead type.\n"
													      "This means that all attempted access to the type will be denied including\n"
													      "attempts to relabel to a (usable) type.  The type may need to be removed from\n"
													      "the policy or some intended access should be granted to the type.")
	{
		//nothing more to do.
	}

	types_wo_allow_module::types_wo_allow_module(const types_wo_allow_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	types_wo_allow_module::~types_wo_allow_module()
	{
		//nothing to do.
	}

	void types_wo_allow_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		// find all types used in an allow rule
		polsearch_type_query tq(POLSEARCH_MATCH_ALL);
		polsearch_test & av_test = tq.addTest(POLSEARCH_TEST_AVRULE);
		polsearch_criterion & av_type = av_test.addCriterion(POLSEARCH_OP_RULE_TYPE);
		polsearch_number_parameter *av_type_val = new polsearch_number_parameter(QPOL_RULE_ALLOW);
		av_type.param(av_type_val);
		polsearch_criterion & av_src = av_test.addCriterion(POLSEARCH_OP_SRC_TGT);
		polsearch_string_expression_parameter *av_src_name = new polsearch_string_expression_parameter("X");
		av_src.param(av_src_name);
		vector < polsearch_result > tq_res;
		tq_res = tq.run(pol, list);

		//get all types
		apol_vector_t *types = NULL;
		if (apol_type_get_by_query(pol, NULL, &types))
			throw bad_alloc();

		// if type is in results remove from list of all types
		for (vector < polsearch_result >::const_iterator i = tq_res.begin(); i != tq_res.end(); i++)
		{
			size_t j = 0;
			if (!apol_vector_get_index(types, i->element(), NULL, NULL, &j))
				if (apol_vector_remove(types, j))
					throw runtime_error("error processing types");
		}

		// if any types remain, add an entry for each
		for (size_t i = 0; i < apol_vector_get_size(types); i++)
		{
			qpol_type_t *cur_type = static_cast < qpol_type_t * >(apol_vector_get_element(types, i));
			element type(cur_type, NULL, NULL);
			result::entry & cur_result = _results.addEntry(type);
			void *x = NULL;
			element nothing(x, NULL, NULL);
			cur_result.addProof(nothing, "Type is not used in an allow rule.");
		}

		apol_vector_destroy(&types);
	}
}
