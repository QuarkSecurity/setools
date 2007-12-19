/**
 *  @file
 *  Implementation of the find file types utility module.
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

#include "find_file_types.hh"
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

void *find_file_types_init(void)
{
	return static_cast < void *>(new sechk::find_file_types_module());
}

namespace sechk
{
	find_file_types_module::find_file_types_module() throw(std::invalid_argument, std::out_of_range):module("find_file_types",
														SECHK_SEV_UTIL,
														"Find all types treated as a file type.",
														"A type is considered a file type if any of the following is true:"
														"\n"
														"   1) it has an attribute associated with file types\n"
														"   2) it is the source of a rule to allow filesystem associate permission\n"
														"   3) it is the default type of a type transition rule with an object class\n"
														"      other than process\n"
														"   4) it is specified in a context in the file_contexts file")
	{
		vector < string > file_type_attribute_names;
		file_type_attribute_names.push_back("file_type");
		option ft_attr_opt("file_type_attribute", "Names of attributes indicating a file type.", file_type_attribute_names);
		if (_options.insert(make_pair(ft_attr_opt.name(), ft_attr_opt)).second == false)
		{
			throw out_of_range("Error setting default options");
		}
		requirement rec_attr_names(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES);
		if (_recommendations.insert(make_pair(rec_attr_names.name(), rec_attr_names)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
		requirement rec_fclist(SECHK_REQUIRE_FCLIST);
		if (_recommendations.insert(make_pair(rec_fclist.name(), rec_fclist)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
	}
	find_file_types_module::find_file_types_module(const find_file_types_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	find_file_types_module::~find_file_types_module()
	{
		// nothing to do
	}

	void find_file_types_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		polsearch_type_query tq(POLSEARCH_MATCH_ANY);
		//"   1) it has an attribute associated with file types\n"
		if (_recommendations.at(require_code_name(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES)).check(pol, list))
		{
			polsearch_test & attr_test = tq.addTest(POLSEARCH_TEST_ATTRIBUTES);
			polsearch_criterion & attr_crit = attr_test.addCriterion(POLSEARCH_OP_INCLUDE);
			polsearch_string_expression_parameter *attr_names =
				new polsearch_string_expression_parameter(_options.at("file_type_attribute").values());
			attr_crit.param(attr_names);
		}

		//"   2) it is the source of a rule to allow filesystem associate permission\n"
		polsearch_test & av_test = tq.addTest(POLSEARCH_TEST_AVRULE);
		polsearch_criterion & av_type = av_test.addCriterion(POLSEARCH_OP_RULE_TYPE);
		polsearch_number_parameter *av_type_val = new polsearch_number_parameter(QPOL_RULE_ALLOW);
		av_type.param(av_type_val);
		polsearch_criterion & av_src = av_test.addCriterion(POLSEARCH_OP_SOURCE);
		polsearch_string_expression_parameter *av_src_name = new polsearch_string_expression_parameter("X");
		av_src.param(av_src_name);
		polsearch_criterion & av_obj = av_test.addCriterion(POLSEARCH_OP_CLASS);
		polsearch_string_expression_parameter *av_obj_name = new polsearch_string_expression_parameter("filesystem");
		av_obj.param(av_obj_name);
		polsearch_criterion & av_perm = av_test.addCriterion(POLSEARCH_OP_PERM);
		polsearch_string_expression_parameter *av_perm_name = new polsearch_string_expression_parameter("associate");
		av_perm.param(av_perm_name);

		//"   3) it is the default type of a type transition rule with an object class\n"
		//"      other than process\n"
		polsearch_test & tt_test = tq.addTest(POLSEARCH_TEST_TERULE);
		polsearch_criterion & tt_type = tt_test.addCriterion(POLSEARCH_OP_RULE_TYPE);
		polsearch_number_parameter *tt_type_val = new polsearch_number_parameter(QPOL_RULE_TYPE_TRANS);
		tt_type.param(tt_type_val);
		polsearch_criterion & tt_dflt = tt_test.addCriterion(POLSEARCH_OP_DEFAULT);
		polsearch_string_expression_parameter *tt_dflt_name = new polsearch_string_expression_parameter("X");
		tt_dflt.param(tt_dflt_name);
		polsearch_criterion & tt_obj = tt_test.addCriterion(POLSEARCH_OP_CLASS, true);
		polsearch_string_expression_parameter *tt_obj_name = new polsearch_string_expression_parameter("process");
		tt_obj.param(tt_obj_name);
		//"   4) it is specified in a context in the file_contexts file")
		if (_recommendations.at(require_code_name(SECHK_REQUIRE_FCLIST)).check(pol, list))
		{
			polsearch_test & fc_test = tq.addTest(POLSEARCH_TEST_FCENTRY);
			polsearch_criterion & fc_type = fc_test.addCriterion(POLSEARCH_OP_TYPE);
			polsearch_string_expression_parameter *fc_type_name = new polsearch_string_expression_parameter("X");
			fc_type.param(fc_type_name);
		}

		// run the query
		vector < polsearch_result > tq_res;
		tq_res = tq.run(pol, list);

		// assemble the results
		for (vector < polsearch_result >::iterator i = tq_res.begin(); i != tq_res.end(); i++)
		{
			element res_type(static_cast < qpol_type_t * >(const_cast < void *>(i->element())), NULL, NULL);
			result::entry & cur_entry = _results.addEntry(res_type);
			for (vector < polsearch_proof >::const_iterator j = i->proof().begin(); j != i->proof().end(); j++)
			{
				element *proof_elem = NULL;
				string prefix = "";
				switch (j->elementType())
				{
				case POLSEARCH_ELEMENT_ATTRIBUTE:
				{
					proof_elem =
						new element(static_cast < qpol_type_t * >(const_cast < void *>(j->element())), NULL,
							    NULL);
					prefix = "has attribute ";
					break;
				}
				case POLSEARCH_ELEMENT_FC_ENTRY:
				{
					proof_elem =
						new element(new
							    sefs_entry(static_cast <
								       sefs_entry * >(const_cast < void *>(j->element()))), NULL,
							    NULL);
					prefix = "is in the file_contexts entry ";
					break;
				}
				case POLSEARCH_ELEMENT_AVRULE:
				{
					proof_elem =
						new element(static_cast < qpol_avrule_t * >(const_cast < void *>(j->element())),
							    NULL, NULL);
					break;
				}
				case POLSEARCH_ELEMENT_TERULE:
				{
					proof_elem =
						new element(static_cast < qpol_terule_t * >(const_cast < void *>(j->element())),
							    NULL, NULL);
					break;
				}
				default:
				{
					throw runtime_error("Unexpected proof type from query");
				}
				}
				cur_entry.addProof(*proof_elem, prefix);
				delete proof_elem;
			}
		}
	}
}
