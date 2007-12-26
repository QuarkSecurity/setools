/**
 *  @file
 *  Implements the public interface for sechecker module results.
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

#include <apol/policy.h>

#include <string>
#include <map>
#include <typeinfo>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <cstdlib>

using std::bad_alloc;
using std::map;
using std::string;
using std::type_info;
using std::invalid_argument;
using std::make_pair;
using std::pair;

namespace sechk
{
	element::element(const element & rhs) throw(std::bad_alloc):_type(rhs._type)
	{
		if (rhs._dup)
			_data = rhs._dup(rhs._data);
		else
			_data = rhs._data;
		if (!_data && _type != typeid(void *))
			throw bad_alloc();
		_free = rhs._free;
		_dup = rhs._dup;
	}

	const element & element::operator=(const element & rhs) throw(std::bad_alloc)
	{
		//The following is done because std::type_info::operator=() and std::type_info(const std::type_info&) are private.
		*this = element(rhs);
		return *this;
	}

	element::~element()
	{
		if (_free)
			_free(_data);
	}

	const void *element::data() const
	{
		return _data;
	}

	void *element::data()
	{
		return _data;
	}

	const std::type_info & element::type() const
	{
		return _type;
	}

	std::ostream & element::print(std::ostream & out, apol_policy_t * pol) const
	{
		const char *name = NULL;
		char *rule = NULL;
		if (_type == typeid(qpol_avrule_t *))
		{
			out << (rule = apol_avrule_render(pol, static_cast < qpol_avrule_t * >(_data)));
			const qpol_cond_t *cond = NULL;
			qpol_avrule_get_cond(apol_policy_get_qpol(pol), static_cast < qpol_avrule_t * >(_data), &cond);
			if (cond)
			{
				char *cond_str = apol_cond_expr_render(pol, cond);
				out << " [ " << cond_str << " ]";
				free(cond_str);
			}
		}
		else if (_type == typeid(qpol_bool_t *))
		{
			qpol_bool_get_name(apol_policy_get_qpol(pol), static_cast < qpol_bool_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_cat_t *))
		{
			qpol_cat_get_name(apol_policy_get_qpol(pol), static_cast < qpol_cat_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_class_t *))
		{
			qpol_class_get_name(apol_policy_get_qpol(pol), static_cast < qpol_class_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_common_t *))
		{
			qpol_common_get_name(apol_policy_get_qpol(pol), static_cast < qpol_common_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_fs_use_t *))
		{
			out << (rule = apol_fs_use_render(pol, static_cast < qpol_fs_use_t * >(_data)));
		}
		else if (_type == typeid(qpol_genfscon_t *))
		{
			out << (rule = apol_genfscon_render(pol, static_cast < qpol_genfscon_t * >(_data)));
		}
		else if (_type == typeid(qpol_isid_t *))
		{
			qpol_isid_get_name(apol_policy_get_qpol(pol), static_cast < qpol_isid_t * >(_data), &name);
			const qpol_context_t *qctx = NULL;
			qpol_isid_get_context(apol_policy_get_qpol(pol), static_cast < qpol_isid_t * >(_data), &qctx);
			apol_context_t *ctx = apol_context_create_from_qpol_context(pol, qctx);
			rule = apol_context_render(pol, ctx);
			apol_context_destroy(&ctx);
			out << "sid " << name << " " << rule;
		}
		else if (_type == typeid(qpol_level_t *))
		{
			qpol_level_get_name(apol_policy_get_qpol(pol), static_cast < qpol_level_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_netifcon_t *))
		{
			out << (rule = apol_netifcon_render(pol, static_cast < qpol_netifcon_t * >(_data)));
		}
		else if (_type == typeid(qpol_nodecon_t *))
		{
			out << (rule = apol_nodecon_render(pol, static_cast < qpol_nodecon_t * >(_data)));
		}
		else if (_type == typeid(qpol_portcon_t *))
		{
			out << (rule = apol_portcon_render(pol, static_cast < qpol_portcon_t * >(_data)));
		}
		else if (_type == typeid(qpol_range_trans_t *))
		{
			out << (rule = apol_range_trans_render(pol, static_cast < qpol_range_trans_t * >(_data)));
		}
		else if (_type == typeid(qpol_role_allow_t *))
		{
			out << (rule = apol_role_allow_render(pol, static_cast < qpol_role_allow_t * >(_data)));
		}
		else if (_type == typeid(qpol_role_t *))
		{
			qpol_role_get_name(apol_policy_get_qpol(pol), static_cast < qpol_role_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_role_trans_t *))
		{
			out << (rule = apol_role_trans_render(pol, static_cast < qpol_role_trans_t * >(_data)));
		}
		else if (_type == typeid(qpol_terule_t *))
		{
			out << (rule = apol_terule_render(pol, static_cast < qpol_terule_t * >(_data)));
			const qpol_cond_t *cond = NULL;
			qpol_terule_get_cond(apol_policy_get_qpol(pol), static_cast < qpol_terule_t * >(_data), &cond);
			if (cond)
			{
				char *cond_str = apol_cond_expr_render(pol, cond);
				out << " [ " << cond_str << " ]";
				free(cond_str);
			}
		}
		else if (_type == typeid(qpol_type_t *))
		{
			qpol_type_get_name(apol_policy_get_qpol(pol), static_cast < qpol_type_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(qpol_user_t *))
		{
			qpol_user_get_name(apol_policy_get_qpol(pol), static_cast < qpol_user_t * >(_data), &name);
			out << name;
		}
		else if (_type == typeid(std::string *))
		{
			out << static_cast < string * >(_data);
		}
		else if (_type == typeid(sefs_entry *))
		{
			out << (rule = static_cast < sefs_entry * >(_data)->toString());
		}
		//special case for nothing to print
		else if (_type == typeid(void *) && _data == NULL)
		{
			return out;
		}
		else
		{
			out << _type.name() << ":" << std::showbase << std::setbase(16) << _data;
		}
		free(rule);
		return out;
	}

      result::entry::proof::proof(const element & elem, const std::string prefix_):_element(elem), _prefix(prefix_)
	{
		//nothing more to do
	}

	result::entry::proof::proof(const proof & rhs):_element(rhs._element), _prefix(rhs._prefix)
	{
		//nothing more to do
	}

	result::entry::proof::~proof()
	{
		//nothing to do
	}

	const element & result::entry::proof::Element() const
	{
		return _element;
	}

	const std::string & result::entry::proof::prefix() const
	{
		return _prefix;
	}

	result::entry::entry(const element & elem):_element(elem)
	{
		_proof = map < void *, proof > ();
	}

	result::entry::entry(const entry & rhs):_element(rhs._element)
	{
		_proof = rhs._proof;
	}

	result::entry::~entry()
	{
		//nothing to do
	}

	const element & result::entry::Element() const
	{
		return _element;
	}

	const std::map < void *, result::entry::proof > &result::entry::Proof() const
	{
		return _proof;
	}

	result::entry::proof & result::entry::addProof(const element & elem, const std::string prefix_)throw(std::invalid_argument)
	{
		proof newproof(elem, prefix_);

		pair < map < void *, proof >::iterator, bool > retv =
			_proof.insert(make_pair(const_cast < void *>(newproof.Element().data()), newproof));
		if (!retv.second)
		{
			throw invalid_argument("Cannot insert duplicate proof");
		}

		return (*retv.first).second;
	}

	result::result(const std::string & mod_name, output_format out_mode)throw(std::invalid_argument)
	{
		if (mod_name == "")
			throw invalid_argument("Module name may not be empty");

		//default is not valid for a single module result
		if (out_mode <= SECHK_OUTPUT_DEFAULT || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");

		_entries = map < void *, entry > ();
		_output_mode = out_mode;
		_module_name = mod_name;
	}

	result::result(const result & rhs)
	{
		_entries = rhs._entries;
		_output_mode = rhs._output_mode;
		_module_name = rhs._module_name;
	}

	result::~result()
	{
		//nothing to do
	}

	output_format result::outputMode() const
	{
		return _output_mode;
	}

	output_format result::outputMode(output_format out_mode) throw(std::invalid_argument)
	{
		if (out_mode <= SECHK_OUTPUT_NONE || out_mode > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");

		return _output_mode = out_mode;
	}

	const std::map < void *, result::entry > &result::entries() const
	{
		return _entries;
	}

	result::entry & result::addEntry(const element & elem)throw(std::invalid_argument)
	{
		entry newentry(elem);

		if (_entries.find(const_cast < void *>(elem.data())) != _entries.end())
			return _entries.find(const_cast < void *>(elem.data()))->second;

		pair < map < void *, entry >::iterator, bool > retv =
			_entries.insert(make_pair(const_cast < void *>(newentry.Element().data()), newentry));
		if (!retv.second)
		{
			throw invalid_argument("Invalid attempt to insert duplicate result entry");
		}

		return (*retv.first).second;
	}
}
