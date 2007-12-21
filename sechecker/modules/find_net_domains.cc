/**
 *  @file
 *  Implementation of the find network domains utility module.
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

#include "find_net_domains.hh"
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

void *find_net_domains_init(void)
{
	return static_cast < void *>(new sechk::find_net_domains_module());
}

namespace sechk
{
	find_net_domains_module::find_net_domains_module() throw(std::invalid_argument,
								 std::out_of_range):module("find_net_domains", SECHK_SEV_UTIL,
											   "Find types treated as a network domain.",
											   "A type is considered a network domain if it is the source of an allow rule\n"
											   "for a network object.")
	{
		vector < string > net_obj_names;
		net_obj_names.push_back("netif");
		net_obj_names.push_back("node");
		net_obj_names.push_back("tcp_socket");
		net_obj_names.push_back("udp_socket");
		net_obj_names.push_back("association");
		option net_obj_opt("net_obj", "Names of network object classes.", net_obj_names);
		if (_options.insert(make_pair(net_obj_opt.name(), net_obj_opt)).second == false)
		{
			throw out_of_range("Error setting default options");
		}
	}

	find_net_domains_module::find_net_domains_module(const find_net_domains_module & rhs):module(rhs)
	{
		//nothing more to do.
	}

	find_net_domains_module::~find_net_domains_module()
	{
		//nothing to do.
	}

	void find_net_domains_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		polsearch_type_query tq(POLSEARCH_MATCH_ANY);
		polsearch_test & av_test = tq.addTest(POLSEARCH_TEST_AVRULE);
		polsearch_criterion & av_type = av_test.addCriterion(POLSEARCH_OP_RULE_TYPE);
		polsearch_number_parameter *av_type_val = new polsearch_number_parameter(QPOL_RULE_ALLOW);
		av_type.param(av_type_val);
		polsearch_criterion & av_src = av_test.addCriterion(POLSEARCH_OP_SOURCE);
		polsearch_string_expression_parameter *av_src_name = new polsearch_string_expression_parameter("X");
		av_src.param(av_src_name);
		polsearch_criterion & av_obj = av_test.addCriterion(POLSEARCH_OP_CLASS);
		polsearch_string_expression_parameter *av_obj_name =
			new polsearch_string_expression_parameter(_options.at("net_obj").values());
		av_obj.param(av_obj_name);

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
				proof_elem =
					new element(static_cast < qpol_avrule_t * >(const_cast < void *>(j->element())), NULL,
						    NULL);
				cur_entry.addProof(*proof_elem, prefix);
				delete proof_elem;
			}
		}
	}
}
