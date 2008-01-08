/**
 *  @file
 *  Defines a common utility interface for sechecker.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2008 Tresys Technology, LLC
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

#include <config.h>

#include "util.hh"

#include <apol/policy.h>
#include <apol/util.h>

#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <stdexcept>
#include <cassert>

#define COPYRIGHT_INFO "Copyright (C) 2005-2008 Tresys Technology, LLC"

using std::cout;
using std::endl;
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

namespace sechk
{
	void print_copyright(void)
	{
		cout << "sechecker " << SECHECKER_VERSION << endl;
		cout << COPYRIGHT_INFO << endl;
	}

	bool semantic_type_match(const qpol_policy_t * policy, const qpol_type_t * first_type, const qpol_type_t * second_type)
	{
		unsigned char first_type_is_attr = 0;
		unsigned char second_type_is_attr = 0;
		qpol_type_get_isattr(policy, first_type, &first_type_is_attr);
		qpol_type_get_isattr(policy, second_type, &second_type_is_attr);

		if (!first_type_is_attr && !second_type_is_attr)
		{
			return (first_type == second_type);
		}
		else
		{
			vector < const qpol_type_t *>first_type_types;
			vector < const qpol_type_t *>second_type_types;
			qpol_iterator_t *iter = NULL;
			if (first_type_is_attr)
			{
				qpol_type_get_type_iter(policy, first_type, &iter);
				for ( /* already initialized */ ; !qpol_iterator_end(iter); qpol_iterator_next(iter))
				{
					qpol_type_t *tmp = NULL;
					qpol_iterator_get_item(iter, reinterpret_cast < void **>(&tmp));
					first_type_types.push_back(tmp);
				}
				qpol_iterator_destroy(&iter);
			}
			else
			{
				first_type_types.push_back(first_type);
			}
			if (second_type_is_attr)
			{
				qpol_type_get_type_iter(policy, second_type, &iter);
				for ( /* already initialized */ ; !qpol_iterator_end(iter); qpol_iterator_next(iter))
				{
					qpol_type_t *tmp = NULL;
					qpol_iterator_get_item(iter, reinterpret_cast < void **>(&tmp));
					second_type_types.push_back(tmp);
				}
				qpol_iterator_destroy(&iter);
			}
			else
			{
				second_type_types.push_back(second_type);
			}
			for (vector < const qpol_type_t * >::iterator i = first_type_types.begin(); i != first_type_types.end();
			     i++)
			{
				for (vector < const qpol_type_t * >::iterator j = second_type_types.begin();
				     j != second_type_types.end(); j++)
				{
					if (*i == *j)
						return true;
				}
			}
			return false;
		}
	}

	bool avrule_key_match(const apol_policy_t * pol, const qpol_avrule_t * first, const qpol_avrule_t * second)
	{
		const qpol_policy_t *qp = apol_policy_get_qpol(pol);
		const qpol_class_t *first_obj = NULL;
		const qpol_class_t *second_obj = NULL;
		qpol_avrule_get_object_class(qp, first, &first_obj);
		qpol_avrule_get_object_class(qp, second, &second_obj);
		if (first_obj != second_obj)
			return false;

		const qpol_type_t *first_src = NULL;
		const qpol_type_t *second_src = NULL;
		qpol_avrule_get_source_type(qp, first, &first_src);
		qpol_avrule_get_source_type(qp, second, &second_src);
		if (!semantic_type_match(qp, first_src, second_src))
			return false;

		const qpol_type_t *first_tgt = NULL;
		const qpol_type_t *second_tgt = NULL;
		qpol_avrule_get_target_type(qp, first, &first_tgt);
		qpol_avrule_get_target_type(qp, second, &second_tgt);
		return semantic_type_match(qp, first_tgt, second_tgt);
	}

	bool terule_key_match(const apol_policy_t * pol, const qpol_terule_t * first, const qpol_terule_t * second)
	{
		const qpol_policy_t *qp = apol_policy_get_qpol(pol);
		const qpol_class_t *first_obj = NULL;
		const qpol_class_t *second_obj = NULL;
		qpol_terule_get_object_class(qp, first, &first_obj);
		qpol_terule_get_object_class(qp, second, &second_obj);
		if (first_obj != second_obj)
			return false;

		const qpol_type_t *first_src = NULL;
		const qpol_type_t *second_src = NULL;
		qpol_terule_get_source_type(qp, first, &first_src);
		qpol_terule_get_source_type(qp, second, &second_src);
		if (!semantic_type_match(qp, first_src, second_src))
			return false;

		const qpol_type_t *first_tgt = NULL;
		const qpol_type_t *second_tgt = NULL;
		qpol_terule_get_target_type(qp, first, &first_tgt);
		qpol_terule_get_target_type(qp, second, &second_tgt);
		return semantic_type_match(qp, first_tgt, second_tgt);
	}

	void *std_string_dup(void *str)
	{
		return reinterpret_cast < void *>(new string(*(reinterpret_cast < string * >(str))));
	}

	void std_string_free(void *str)
	{
		delete reinterpret_cast < string * >(str);
	}

	bool validate_permission(const qpol_policy_t * q, const qpol_class_t * obj_class, const char *perm)
	{
		bool valid = false;

		if (!q || !obj_class || !perm)
			return false;

		qpol_iterator_t *iter = NULL;
		qpol_class_get_perm_iter(q, obj_class, &iter);
		for ( /* already initialized */ ; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			char *cur_perm = NULL;
			qpol_iterator_get_item(iter, reinterpret_cast < void **>(&cur_perm));
			if (string(cur_perm) == perm)
			{
				valid = true;
				break;
			}
		}
		qpol_iterator_destroy(&iter);

		const qpol_common_t *common = NULL;
		qpol_class_get_common(q, obj_class, &common);
		if (common)
		{
			qpol_common_get_perm_iter(q, common, &iter);
			for ( /* already initialized */ ; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				char *cur_perm = NULL;
				qpol_iterator_get_item(iter, reinterpret_cast < void **>(&cur_perm));
				if (string(cur_perm) == perm)
				{
					valid = true;
					break;
				}
			}
			qpol_iterator_destroy(&iter);
		}

		return valid;
	}
}
