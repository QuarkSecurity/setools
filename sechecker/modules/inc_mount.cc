/**
 *  @file
 *  Implementation of the incomplete mount permissions module.
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

#include "inc_mount.hh"
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

void *inc_mount_init(void)
{
	return static_cast < void *>(new sechk::inc_mount_module());
}

namespace sechk
{
	inc_mount_module::inc_mount_module() throw(std::invalid_argument, std::out_of_range):module("inc_mount", SECHK_SEV_MED,
												    "Find domains that have incomplete mount permissions.",
												    "In order for a mount operation to be allowed by the policy the following rules\n"
												    "must be present: \n"
												    "\n"
												    "   1) allow somedomain_d sometype_t : filesystem  { mount };\n"
												    "   2) allow somedomain_d sometype_t : dir { mounton };\n"
												    "\n"
												    "This module finds domains that have only one of the rules listed above.")
	{
		// nothing more to do
	}

	inc_mount_module::inc_mount_module(const inc_mount_module & rhs):module(rhs)
	{
		// nothing more to do
	}

	inc_mount_module::~inc_mount_module()
	{
		// nothing to do
	}

	/**
	 * Given a type return a vector of all types to which it expands.
	 * @param qp The policy from which the type comes.
	 * @param type The type to expand.
	 * @return A vector of types.
	 */
	static vector < const qpol_type_t *>expand_type(const qpol_policy_t * qp, const qpol_type_t * type)
	{
		unsigned char is_attr = 0;
		qpol_type_get_isattr(qp, type, &is_attr);
		vector < const qpol_type_t *>expanded;
		if (!is_attr)
		{
			expanded.push_back(type);
			return expanded;
		}
		else
		{
			qpol_iterator_t *iter;
			if (qpol_type_get_type_iter(qp, type, &iter))
				throw bad_alloc();
			for ( /* already initialized */ ; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				const qpol_type_t *t = NULL;
				qpol_iterator_get_item(iter, reinterpret_cast < void **>(const_cast < qpol_type_t ** >(&t)));
				expanded.push_back(t);
			}
			qpol_iterator_destroy(&iter);
			return expanded;
		}
	}

	void inc_mount_module::run_internal(apol_policy_t * pol, sefs_fclist * list) throw(std::runtime_error)
	{
		qpol_policy_t *q = apol_policy_get_qpol(pol);

		apol_avrule_query_t *mount_avrule_query = NULL;
		if (!(mount_avrule_query = apol_avrule_query_create()))
			throw bad_alloc();
		apol_avrule_query_t *mounton_avrule_query = NULL;
		if (!(mounton_avrule_query = apol_avrule_query_create()))
		{
			apol_avrule_query_destroy(&mount_avrule_query);
			throw bad_alloc();
		}

		apol_vector_t *mount_vector = NULL;
		/* Get avrules for filesystem mount */
		apol_avrule_query_set_rules(pol, mount_avrule_query, QPOL_RULE_ALLOW);
		apol_avrule_query_append_class(pol, mount_avrule_query, "filesystem");
		apol_avrule_query_append_perm(pol, mount_avrule_query, "mount");
		apol_avrule_get_by_query(pol, mount_avrule_query, &mount_vector);
		apol_avrule_query_destroy(&mount_avrule_query);
		if (!mount_vector)
		{
			apol_avrule_query_destroy(&mount_avrule_query);
			throw bad_alloc();
		}

		apol_vector_t *mounton_vector = NULL;
		/* Get avrules for dir mounton */
		apol_avrule_query_set_rules(pol, mounton_avrule_query, QPOL_RULE_ALLOW);
		apol_avrule_query_append_class(pol, mounton_avrule_query, "dir");
		apol_avrule_query_append_perm(pol, mounton_avrule_query, "mounton");
		apol_avrule_get_by_query(pol, mounton_avrule_query, &mounton_vector);
		apol_avrule_query_destroy(&mounton_avrule_query);
		if (!mounton_vector)
		{
			apol_vector_destroy(&mount_vector);
			throw bad_alloc();
		}

		// find mount w/o mounton
		for (size_t i = 0; i < apol_vector_get_size(mount_vector); i++)
		{
			const qpol_avrule_t *mount_rule = NULL;
			const qpol_type_t *mount_source = NULL;
			const qpol_type_t *mount_target = NULL;
			mount_rule = static_cast < const qpol_avrule_t *>(apol_vector_get_element(mount_vector, i));
			qpol_avrule_get_source_type(q, mount_rule, &mount_source);
			qpol_avrule_get_target_type(q, mount_rule, &mount_target);
			bool match = false;
			vector < const qpol_type_t *>mount_source_types = expand_type(q, mount_source);
			vector < const qpol_type_t *>mount_target_types = expand_type(q, mount_target);
			for (vector < const qpol_type_t * >::const_iterator j = mount_source_types.begin();
			     j != mount_source_types.end(); j++)
			{
				for (vector < const qpol_type_t * >::const_iterator k = mount_target_types.begin();
				     k != mount_target_types.end(); k++)
				{
					match = false;
					for (size_t l = 0; l < apol_vector_get_size(mounton_vector); l++)
					{
						const qpol_avrule_t *mounton_rule = NULL;
						const qpol_type_t *mounton_source = NULL;
						const qpol_type_t *mounton_target = NULL;
						mounton_rule =
							static_cast <
							const qpol_avrule_t *>(apol_vector_get_element(mounton_vector, l));
						qpol_avrule_get_source_type(q, mounton_rule, &mounton_source);
						qpol_avrule_get_target_type(q, mounton_rule, &mounton_target);

						/* Check to see if they match */
						if (semantic_type_match(q, *j, mounton_source) &&
						    semantic_type_match(q, *k, mounton_target))
						{
							match = true;
							break;
						}
					}
					if (!match)
					{
						element dom_elem(const_cast < qpol_type_t * >(*j), NULL, NULL);
						result::entry & dom_entry = _results.addEntry(dom_elem);
						const char *src_name = NULL;
						const char *tgt_name = NULL;
						qpol_type_get_name(q, *j, &src_name);
						qpol_type_get_name(q, *k, &tgt_name);
						string *missing_rule =
							new string(string("allow ") + src_name + " " + tgt_name +
								   " : dir mounton;");
						element missing_elem(missing_rule, std_string_free, std_string_dup);
						dom_entry.addProof(missing_elem, "Missing: ");
						delete missing_rule;
						missing_rule = NULL;
						try
						{
							element rule_elem(const_cast < qpol_avrule_t * >(mount_rule), NULL, NULL);
							dom_entry.addProof(rule_elem, "Have: ");
						}
						catch(invalid_argument x)
						{
							// ignore duplicate add if multiple types in an attribute are missing
						}
					}
				}
			}
		}

		// find mounon w/o mount
		for (size_t i = 0; i < apol_vector_get_size(mounton_vector); i++)
		{
			const qpol_avrule_t *mounton_rule = NULL;
			const qpol_type_t *mounton_source = NULL;
			const qpol_type_t *mounton_target = NULL;
			mounton_rule = static_cast < const qpol_avrule_t *>(apol_vector_get_element(mounton_vector, i));
			qpol_avrule_get_source_type(q, mounton_rule, &mounton_source);
			qpol_avrule_get_target_type(q, mounton_rule, &mounton_target);
			bool match = false;
			vector < const qpol_type_t *>mounton_source_types = expand_type(q, mounton_source);
			vector < const qpol_type_t *>mounton_target_types = expand_type(q, mounton_target);
			for (vector < const qpol_type_t * >::const_iterator j = mounton_source_types.begin();
			     j != mounton_source_types.end(); j++)
			{
				for (vector < const qpol_type_t * >::const_iterator k = mounton_target_types.begin();
				     k != mounton_target_types.end(); k++)
				{
					match = false;
					for (size_t l = 0; l < apol_vector_get_size(mount_vector); l++)
					{
						const qpol_avrule_t *mount_rule = NULL;
						const qpol_type_t *mount_source = NULL;
						const qpol_type_t *mount_target = NULL;
						mount_rule =
							static_cast <
							const qpol_avrule_t *>(apol_vector_get_element(mount_vector, l));
						qpol_avrule_get_source_type(q, mount_rule, &mount_source);
						qpol_avrule_get_target_type(q, mount_rule, &mount_target);

						/* Check to see if they match */
						if (semantic_type_match(q, *j, mount_source) &&
						    semantic_type_match(q, *k, mount_target))
						{
							match = true;
							break;
						}
					}
					if (!match)
					{
						element dom_elem(const_cast < qpol_type_t * >(*j), NULL, NULL);
						result::entry & dom_entry = _results.addEntry(dom_elem);
						const char *src_name = NULL;
						const char *tgt_name = NULL;
						qpol_type_get_name(q, *j, &src_name);
						qpol_type_get_name(q, *k, &tgt_name);
						string *missing_rule =
							new string(string("allow ") + src_name + " " + tgt_name +
								   " : filesystem mount;");
						element missing_elem(missing_rule, std_string_free, std_string_dup);
						dom_entry.addProof(missing_elem, "Missing: ");
						delete missing_rule;
						try
						{
							element rule_elem(const_cast < qpol_avrule_t * >(mounton_rule), NULL, NULL);
							dom_entry.addProof(rule_elem, "Have: ");
						}
						catch(invalid_argument x)
						{
							// ignore duplicate add if multiple types in an attribute are missing
						}
					}
				}
			}
		}

		apol_vector_destroy(&mount_vector);
		apol_vector_destroy(&mounton_vector);
	}
}
