/**
 *  @file
 *  Implementation of the spurious audit rules module.
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

#include "spurious_audit.hh"
#include "sechecker.hh"
#include "module.hh"
#include "result.hh"

#include <polsearch/polsearch.hh>

#include <apol/policy.h>
#include <apol/util.h>

#include <vector>
#include <string>
#include <set>
#include <map>
#include <stdexcept>
#include <cassert>

using std::vector;
using std::string;
using std::set;
using std::map;
using std::pair;
using std::make_pair;
using std::invalid_argument;
using std::runtime_error;
using std::out_of_range;
using std::bad_alloc;

void *spurious_audit_init(void)
{
	return static_cast < void *>(new sechk::spurious_audit_module());
}

namespace sechk
{
	spurious_audit_module::spurious_audit_module() throw(std::invalid_argument, std::out_of_range):module("spurious_audit",
													      SECHK_SEV_LOW,
													      "Find audit rules with no effect.",
													      "This happens when either of the following exist:\n"
													      "\n"
													      "   1) an allow rule with the same key and permissions as a dontaudit rule\n"
													      "   2) an auditallow rule without an allow rule with the same key and\n"
													      "      permission combination.")
	{
		// nothing more to do
	}

	spurious_audit_module::spurious_audit_module(const spurious_audit_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	spurious_audit_module::~spurious_audit_module()
	{
		// nothing to do
	}

	/**
	 * Find the intersection of the permissions for an audit rule and an allow rule.
	 * Rules are assumed to have the same key. Intersecting permissions will be
	 * added to the set \a perms.
	 * @param pol The policy from which the rules come.
	 * @param audit The audit rule.
	 * @param allow The allow rule.
	 * @param perms The set of permissions to which to add any common permissions.
	 * @return If any permissions intersected, return \a true; return \a flase otherwise.
	 */
	static bool perm_intersect(const apol_policy_t * pol, const qpol_avrule_t * audit, const qpol_avrule_t * allow,
				   set < string > &perms)
	{
		qpol_iterator_t *audit_perm_iter = NULL;
		if (qpol_avrule_get_perm_iter(apol_policy_get_qpol(pol), audit, &audit_perm_iter))
			throw bad_alloc();
		apol_vector_t *audit_perm_vector = apol_vector_create_from_iter(audit_perm_iter, free);
		qpol_iterator_destroy(&audit_perm_iter);
		if (!audit_perm_vector)
			throw bad_alloc();

		qpol_iterator_t *allow_perm_iter = NULL;
		if (qpol_avrule_get_perm_iter(apol_policy_get_qpol(pol), allow, &allow_perm_iter))
			throw bad_alloc();
		apol_vector_t *allow_perm_vector = apol_vector_create_from_iter(allow_perm_iter, free);
		qpol_iterator_destroy(&allow_perm_iter);
		if (!allow_perm_vector)
		{
			apol_vector_destroy(&audit_perm_vector);
			throw bad_alloc();
		}

		apol_vector_t *intersection =
			apol_vector_create_from_intersection(audit_perm_vector, allow_perm_vector, apol_str_strcmp, NULL);
		if (!intersection)
		{
			apol_vector_destroy(&audit_perm_vector);
			apol_vector_destroy(&allow_perm_vector);
			throw bad_alloc();
		}

		bool retv = (apol_vector_get_size(intersection) > 0);
		for (size_t i = 0; i < apol_vector_get_size(intersection); i++)
			perms.insert(string(static_cast < char *>(apol_vector_get_element(intersection, i))));

		apol_vector_destroy(&audit_perm_vector);
		apol_vector_destroy(&allow_perm_vector);
		apol_vector_destroy(&intersection);
		return retv;
	}

	/**
	 * Prune the set of permissions to include only those not in the allow rule.
	 * @param pol The policy from which the rule comes.
	 * @param allow The allow rule to use to prune \a perms.
	 * @param perms The set of permissions to prune.
	 */
	static void perm_unique(const apol_policy_t * pol, const qpol_avrule_t * allow, set < string > &perms)
	{
		if (perms.empty())
			return;
		qpol_iterator_t *perm_iter = NULL;
		if (qpol_avrule_get_perm_iter(apol_policy_get_qpol(pol), allow, &perm_iter))
			throw bad_alloc();
		for ( /* already initialized */ ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter))
		{
			char *perm = NULL;
			qpol_iterator_get_item(perm_iter, reinterpret_cast < void **>(&perm));
			perms.erase(perm);
			free(perm);
		}
		qpol_iterator_destroy(&perm_iter);
	}

	void spurious_audit_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		apol_avrule_query *query = apol_avrule_query_create();
		// get all allow rules
		apol_vector_t *allow_rules = NULL;
		apol_avrule_query_set_rules(pol, query, QPOL_RULE_ALLOW);
		if (apol_avrule_get_by_query(pol, query, &allow_rules))
		{
			apol_avrule_query_destroy(&query);
			throw runtime_error("Could not get allow rules");
		}
		// get all dontaudit rules
		apol_vector_t *dontaudit_rules = NULL;
		apol_avrule_query_set_rules(pol, query, QPOL_RULE_DONTAUDIT);
		if (apol_avrule_get_by_query(pol, query, &dontaudit_rules))
		{
			apol_avrule_query_destroy(&query);
			throw runtime_error("Could not get dontaudit rules");
		}
		// get all auditallow rules
		apol_vector_t *auditallow_rules = NULL;
		apol_avrule_query_set_rules(pol, query, QPOL_RULE_AUDITALLOW);
		if (apol_avrule_get_by_query(pol, query, &auditallow_rules))
		{
			apol_avrule_query_destroy(&query);
			throw runtime_error("Could not get auditallow rules");
		}
		apol_avrule_query_destroy(&query);

		//"   1) an allow rule with the same key and permissions as a dontaudit rule"

		for (size_t i = 0; i < apol_vector_get_size(dontaudit_rules); i++)
		{
			set < string > common_perms;
			common_perms.clear();
			qpol_avrule_t *audit = static_cast < qpol_avrule_t * >(apol_vector_get_element(dontaudit_rules, i));
			for (size_t j = 0; j < apol_vector_get_size(allow_rules); j++)
			{
				qpol_avrule_t *allow = static_cast < qpol_avrule_t * >(apol_vector_get_element(allow_rules, j));
				if (avrule_key_match(pol, audit, allow))
				{
					if (perm_intersect(pol, audit, allow, common_perms))
					{
						element audit_elem(audit, NULL, NULL);
						result::entry & audit_entry = _results.addEntry(audit_elem);
						element allow_elem(allow, NULL, NULL);
						audit_entry.addProof(allow_elem, "");
					}
				}
			}
			if (!common_perms.empty())
			{
				string str = "spurious permissions: { ";
				for (set < string >::const_iterator j = common_perms.begin(); j != common_perms.end(); j++)
				{
					str += (*j + " ");
				}
				str += "}";
				element audit_elem(audit, NULL, NULL);
				result::entry & audit_entry = _results.addEntry(audit_elem);
				assert(!audit_entry.Proof().empty());
				void *x = NULL;
				element proof_elem(x, NULL, NULL);
				audit_entry.addProof(proof_elem, str);
			}
		}

		//"   2) an auditallow rule without an allow rule with the same key and permission combination."
		for (size_t i = 0; i < apol_vector_get_size(auditallow_rules); i++)
		{
			set < string > audit_perms;
			qpol_avrule_t *audit = static_cast < qpol_avrule_t * >(apol_vector_get_element(auditallow_rules, i));
			qpol_iterator_t *perm_iter = NULL;
			if (qpol_avrule_get_perm_iter(apol_policy_get_qpol(pol), audit, &perm_iter))
				throw bad_alloc();
			for ( /* already initialized */ ; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter))
			{
				char *perm = NULL;
				qpol_iterator_get_item(perm_iter, reinterpret_cast < void **>(&perm));
				if (!((audit_perms.insert(string(perm))).second))
					throw runtime_error("Error collecting audit permissions");
				free(perm);
			}
			qpol_iterator_destroy(&perm_iter);

			for (size_t j = 0; j < apol_vector_get_size(allow_rules); j++)
			{
				qpol_avrule_t *allow = static_cast < qpol_avrule_t * >(apol_vector_get_element(allow_rules, j));
				if (avrule_key_match(pol, audit, allow))
				{
					perm_unique(pol, allow, audit_perms);
				}
			}
			if (!audit_perms.empty())
			{
				string str = "spurious permissions: { ";
				for (set < string >::const_iterator j = audit_perms.begin(); j != audit_perms.end(); j++)
				{
					str += (*j + " ");
				}
				str += "}";
				element audit_elem(audit, NULL, NULL);
				result::entry & audit_entry = _results.addEntry(audit_elem);
				void *x = NULL;
				element proof_elem(x, NULL, NULL);
				audit_entry.addProof(proof_elem, str);
			}
		}

		apol_vector_destroy(&allow_rules);
		apol_vector_destroy(&auditallow_rules);
		apol_vector_destroy(&dontaudit_rules);
	}
}
