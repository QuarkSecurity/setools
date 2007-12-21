/**
 *  @file
 *  Implementation of the find domains utility module.
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

#include "find_domains.hh"
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

void *find_domains_init(void)
{
	return static_cast < void *>(new sechk::find_domains_module());
}

namespace sechk
{
	find_domains_module::find_domains_module() throw(std::invalid_argument, std::out_of_range):module("find_domains",
													  SECHK_SEV_UTIL,
													  "Find types treated as a domain.",
													  "A type is considered a domain if any of the following is true:\n"
													  "\n"
													  "   1) it has an attribute associated with domains\n"
													  "   2) it is the source of an AV rule for object class other than filesystem\n"
													  "   3) it is the default type in a type_transition rule for object class process \n"
													  "   4) it is associated with a role other than object_r")
	{
		vector < string > domain_attribute_names;
		domain_attribute_names.push_back("domain");
		option dom_attr_opt("domain_attribute", "Names of attributes indicating a domain.", domain_attribute_names);
		if (_options.insert(make_pair(dom_attr_opt.name(), dom_attr_opt)).second == false)
		{
			throw out_of_range("Error setting default options");
		}
		requirement rec_attr_names(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES);
		if (_recommendations.insert(make_pair(rec_attr_names.name(), rec_attr_names)).second == false)
		{
			throw out_of_range("Error setting recommendations");
		}
	}

	find_domains_module::find_domains_module(const find_domains_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	find_domains_module::~find_domains_module()
	{
		//nothing to do.
	}

	void find_domains_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		polsearch_type_query tq(POLSEARCH_MATCH_ANY);
		// if attribute names are available test them
		//"   1) it has an attribute associated with domains\n"
		if (_recommendations.at(require_code_name(SECHK_REQUIRE_POLICY_CAPABILITY_ATTRIBUTE_NAMES)).check(pol, list))
		{
			polsearch_test & attr_test = tq.addTest(POLSEARCH_TEST_ATTRIBUTES);
			polsearch_criterion & attr_crit = attr_test.addCriterion(POLSEARCH_OP_INCLUDE);
			polsearch_string_expression_parameter *attr_names =
				new polsearch_string_expression_parameter(_options.at("domain_attribute").values());
			attr_crit.param(attr_names);
		}

		//"   2) it is the source of an AV rule for object class other than filesystem\n"
		polsearch_test & av_test = tq.addTest(POLSEARCH_TEST_AVRULE);
		//do not include neverallow rules
		polsearch_criterion & av_type = av_test.addCriterion(POLSEARCH_OP_RULE_TYPE, true);
		polsearch_number_parameter *av_type_val = new polsearch_number_parameter(QPOL_RULE_NEVERALLOW);
		av_type.param(av_type_val);
		polsearch_criterion & av_src = av_test.addCriterion(POLSEARCH_OP_SOURCE);
		polsearch_string_expression_parameter *av_src_name = new polsearch_string_expression_parameter("X");
		av_src.param(av_src_name);
		polsearch_criterion & av_obj = av_test.addCriterion(POLSEARCH_OP_CLASS, true);
		polsearch_string_expression_parameter *av_obj_name = new polsearch_string_expression_parameter("filesystem");
		av_obj.param(av_obj_name);

		//"   3) it is the default type in a type_transition rule for object class process \n"
		polsearch_test & tt_test = tq.addTest(POLSEARCH_TEST_TERULE);
		polsearch_criterion & tt_type = tt_test.addCriterion(POLSEARCH_OP_RULE_TYPE);
		polsearch_number_parameter *tt_type_val = new polsearch_number_parameter(QPOL_RULE_TYPE_TRANS);
		tt_type.param(tt_type_val);
		polsearch_criterion & tt_dflt = tt_test.addCriterion(POLSEARCH_OP_DEFAULT);
		polsearch_string_expression_parameter *tt_dflt_name = new polsearch_string_expression_parameter("X");
		tt_dflt.param(tt_dflt_name);
		polsearch_criterion & tt_obj = tt_test.addCriterion(POLSEARCH_OP_CLASS);
		polsearch_string_expression_parameter *tt_obj_name = new polsearch_string_expression_parameter("process");
		tt_obj.param(tt_obj_name);

		//"   4) it is associated with a role other than object_r\n")
		polsearch_test & role_test = tq.addTest(POLSEARCH_TEST_ROLES);
		polsearch_criterion & role_set = role_test.addCriterion(POLSEARCH_OP_INCLUDE);
		// construct list of roles that are not object_r
		vector < string > roles;
		apol_role_query_t *rq = apol_role_query_create();
		if (!rq)
		{
			throw bad_alloc();
		}
		apol_vector_t *v = NULL;
		if (apol_role_get_by_query(pol, rq, &v) < 0)
		{
			throw bad_alloc();
		}
		for (size_t i = 0; i < apol_vector_get_size(v); i++)
		{
			const char *tmp = NULL;
			qpol_role_get_name(apol_policy_get_qpol(pol), static_cast < qpol_role_t * >(apol_vector_get_element(v, i)),
					   &tmp);
			if (string(tmp) != "object_r")
			{
				roles.push_back(tmp);
			}
		}
		apol_vector_destroy(&v);
		apol_role_query_destroy(&rq);
		polsearch_string_expression_parameter *role_name = new polsearch_string_expression_parameter(roles);
		role_set.param(role_name);

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
				case POLSEARCH_ELEMENT_ROLE:
				{
					proof_elem =
						new element(static_cast < qpol_role_t * >(const_cast < void *>(j->element())), NULL,
							    NULL);
					prefix = "is assigned to role ";
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
