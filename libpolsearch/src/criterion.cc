/**
 * @file
 *
 * Routines to handle tests' criteria.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <polsearch/polsearch.hh>
#include "polsearch_internal.hh"

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <string>
#include <vector>
#include <stdexcept>

#include <stdint.h>
#include <cassert>
#include <cstdlib>

using std::runtime_error;
using std::invalid_argument;
using std::bad_alloc;
using std::vector;
using std::string;

polsearch_criterion::polsearch_criterion()
{
	throw std::runtime_error("Cannot directly create criteria.");
}

polsearch_criterion::polsearch_criterion(const polsearch_test * Test, polsearch_op opr, bool neg) throw(std::invalid_argument)
{
	if (!validate_operator(Test->elementType(), Test->testCond(), opr))
		throw invalid_argument("Invalid operator for the given test.");

	_op = opr;
	_negated = neg;
	_test = Test;
	_param = NULL;
}

polsearch_criterion::polsearch_criterion(const polsearch_criterion & rhs)
{
	_op = rhs._op;
	_negated = rhs._negated;
	_test = rhs._test;
	if (rhs._param)
		_param = rhs._param->clone();
	else
		_param = NULL;
}

polsearch_criterion::~polsearch_criterion()
{
	delete _param;
}

polsearch_op polsearch_criterion::op() const
{
	return _op;
}

polsearch_op polsearch_criterion::op(polsearch_op opr)
{
	return _op = opr;
}

bool polsearch_criterion::negated() const
{
	return _negated;
}

bool polsearch_criterion::negated(bool neg)
{
	return _negated = neg;
}

const polsearch_test *polsearch_criterion::test() const
{
	return _test;
}

const polsearch_parameter *polsearch_criterion::param() const
{
	return _param;
}

polsearch_parameter *polsearch_criterion::param()
{
	return _param;
}

polsearch_parameter *polsearch_criterion::param(polsearch_parameter * p) throw(std::invalid_argument)
{
	if (!p || !validate_parameter_type(_test->elementType(), _test->testCond(), _op, p->paramType()))
		throw invalid_argument("Invalid parameter");

	delete _param;
	return _param = p;
}

polsearch_param_type polsearch_get_valid_param_type(polsearch_element elem_type, polsearch_test_cond cond, polsearch_op opr)
{
	for (int i = POLSEARCH_PARAM_TYPE_REGEX; i <= POLSEARCH_PARAM_TYPE_RANGE; i++)
	{
		if (validate_parameter_type(elem_type, cond, opr, static_cast < polsearch_param_type > (i)))
			return static_cast < polsearch_param_type > (i);
	}

	//should not get here
	assert(0);
	return POLSEARCH_PARAM_TYPE_NONE;
}

std::string polsearch_criterion::toString() const
{
	//TODO crit to string
	return "";
}

//! Union of posible input to the parameter's match function.
union match_input
{
	bool bval;		       //!< State of a policy boolean.
	std::string * str;	       //!< Name of a policy symbol.
	uint32_t nval;		       //!< Generic numberic value.
	const apol_mls_level_t *lvl;   //!< User's default level.
	const apol_mls_range_t *rng;   //!< Range of user, context, or range_transition rule.
	std::vector < std::string > *list;	//!< List of type names expanded from an attribute.
};

//! Value to determine which type of matching is needed for the given input.
enum match_type
{
	MATCH_BOOL,		       //!< Input should be matched as a boolean value.
	MATCH_STRING,		       //!< Input should be matched as a string.
	MATCH_NUM,		       //!< Input should be matched as a numeric value (uint32_t).
	MATCH_LEVEL,		       //!< Input should be matched as a MLS level (apol_mls_level_t*).
	MATCH_RANGE,		       //!< Input should be matched as a MLS range (apol_mls_range_t*).
	MATCH_LIST		       //!< Input should be matched as an expanded list of symbol names.
};

//not normally defined by STL will not be exported
/**
 * Add the elements from \a rhs to \a lhs.
 * @param lhs Vector to which to add strings
 * @param rhs Vector containing strings to add.
 * @return A reference to \a lhs with the elements added.
 */
static vector < string > &operator+=(vector < string > &lhs, const vector < string > &rhs)
{
	for (size_t i = 0; i < rhs.size(); i++)
	{
		lhs.push_back(string(rhs[i]));
	}
	return lhs;
}

/**
 * Given a qpol_type_t expand into a list of all names that can be matched.
 * For a type, this means its primary and all aliases; for an attribute,
 * this means the attribute name and the primary name and aliases for all
 * types to which it expands.
 * @param policy The policy from which the type comes.
 * @param type The qpol type to expand.
 * @return A vector of all type names to match.
 * @exception std::bad_alloc Out of memory.
 */
static vector < string > expand_semantic_type(const apol_policy_t * policy, const qpol_type_t * type) throw(std::bad_alloc)
{
	vector < string > names;
	unsigned char isattr;
	const qpol_policy_t *qp = apol_policy_get_qpol(policy);

	qpol_type_get_isattr(qp, type, &isattr);
	if (isattr)
	{
		names += get_all_names(type, POLSEARCH_ELEMENT_ATTRIBUTE, policy);
		qpol_iterator_t *iter = NULL;
		if (qpol_type_get_type_iter(qp, type, &iter))
			throw bad_alloc();
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *itype = NULL;
			qpol_iterator_get_item(iter, &itype);
			names += get_all_names(itype, POLSEARCH_ELEMENT_TYPE, policy);
		}
		qpol_iterator_destroy(&iter);
	}
	else
	{
		names = get_all_names(type, POLSEARCH_ELEMENT_TYPE, policy);
	}

	return names;
}

/**
 * Determine the correct version of the parameter match function to call
 * and initialize its input appropriately.
 * @param policy The policy from which \a candidate comes.
 * @param candidate The policy to compare.
 * @param candidate_type The type of policy element repesented by \a candidate.
 * @param opr The comparison operator for the criterion.
 * @param input Union of possible match input to initialize.
 * @return Value indicating which version of the match function to call.
 * @exception std::runtime_error Conflicting candidate type and operator.
 * @exception std::bad_alloc Out of memory.
 */
enum match_type determine_match_type(const apol_policy_t * policy, const void *candidate, polsearch_element candidate_type,
				     polsearch_op opr, union match_input &input) throw(std::runtime_error, std::bad_alloc)
{
	qpol_policy_t *qp = apol_policy_get_qpol(policy);
	qpol_iterator_t *iter = NULL;

	switch (opr)
	{
	case POLSEARCH_OP_IS:
	{
		if (candidate_type == POLSEARCH_ELEMENT_STRING)
		{
			input.str = new string(static_cast < const char *>(candidate));
			return MATCH_STRING;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_BOOL_STATE)
		{
			input.bval = candidate == 0 ? false : true;
			return MATCH_BOOL;
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
	}
	case POLSEARCH_OP_MATCH_REGEX:
	{
		if (candidate_type == POLSEARCH_ELEMENT_STRING)
		{
			input.str = new string(static_cast < const char *>(candidate));
			return MATCH_STRING;
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
	}
	case POLSEARCH_OP_RULE_TYPE:
	{
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
		{
			qpol_avrule_get_rule_type(qp, static_cast < const qpol_avrule_t * >(candidate), &input.nval);
		}
		else if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			qpol_terule_get_rule_type(qp, static_cast < const qpol_terule_t * >(candidate), &input.nval);
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
		return MATCH_NUM;
	}
	case POLSEARCH_OP_INCLUDE:
	{
		if (candidate_type == POLSEARCH_ELEMENT_TYPE || candidate_type == POLSEARCH_ELEMENT_ATTRIBUTE ||
		    candidate_type == POLSEARCH_ELEMENT_ROLE || candidate_type == POLSEARCH_ELEMENT_USER ||
		    candidate_type == POLSEARCH_ELEMENT_COMMON || candidate_type == POLSEARCH_ELEMENT_CATEGORY)
		{
			input.list = new vector < string > (get_all_names(candidate, candidate_type, policy));
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_PERMISSION)
		{
			input.str = new string(static_cast < const char *>(candidate));
			return MATCH_STRING;
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
	}
	case POLSEARCH_OP_SOURCE:
	{
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE || candidate_type == POLSEARCH_ELEMENT_TERULE ||
		    candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
		{
			const qpol_type_t *src = NULL;
			if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
				qpol_avrule_get_source_type(qp, static_cast < const qpol_avrule_t * >(candidate), &src);
			if (candidate_type == POLSEARCH_ELEMENT_TERULE)
				qpol_terule_get_source_type(qp, static_cast < const qpol_terule_t * >(candidate), &src);
			if (candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
				qpol_range_trans_get_source_type(qp, static_cast < const qpol_range_trans_t * >(candidate), &src);
			input.list = new vector < string > (expand_semantic_type(policy, src));
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_ROLE_ALLOW || candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
		{
			const qpol_role_t *src = NULL;
			if (candidate_type == POLSEARCH_ELEMENT_ROLE_ALLOW)
				qpol_role_allow_get_source_role(qp, static_cast < const qpol_role_allow_t * >(candidate), &src);
			if (candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
				qpol_role_trans_get_source_role(qp, static_cast < const qpol_role_trans_t * >(candidate), &src);
			const char *name;
			qpol_role_get_name(qp, src, &name);
			input.str = new string(name);
			return MATCH_STRING;
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
	}
	case POLSEARCH_OP_TARGET:
	{
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE || candidate_type == POLSEARCH_ELEMENT_TERULE ||
		    candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS || candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
		{
			const qpol_type_t *tgt = NULL;
			if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
				qpol_avrule_get_target_type(qp, static_cast < const qpol_avrule_t * >(candidate), &tgt);
			if (candidate_type == POLSEARCH_ELEMENT_TERULE)
				qpol_terule_get_target_type(qp, static_cast < const qpol_terule_t * >(candidate), &tgt);
			if (candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
				qpol_range_trans_get_target_type(qp, static_cast < const qpol_range_trans_t * >(candidate), &tgt);
			if (candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
				qpol_role_trans_get_target_type(qp, static_cast < const qpol_role_trans_t * >(candidate), &tgt);
			input.list = new vector < string > (expand_semantic_type(policy, tgt));
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_ROLE_ALLOW)
		{
			const qpol_role_t *tgt = NULL;
			qpol_role_allow_get_target_role(qp, static_cast < const qpol_role_allow_t * >(candidate), &tgt);
			const char *name;
			qpol_role_get_name(qp, tgt, &name);
			input.str = new string(name);
			return MATCH_STRING;
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
	}
	case POLSEARCH_OP_CLASS:
	{
		const qpol_class_t *cls = NULL;
		const char *name;
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
		{
			qpol_avrule_get_object_class(qp, static_cast < const qpol_avrule_t * >(candidate), &cls);
			qpol_class_get_name(qp, cls, &name);
		}
		else if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			qpol_terule_get_object_class(qp, static_cast < const qpol_terule_t * >(candidate), &cls);
			qpol_class_get_name(qp, cls, &name);
		}
		else if (candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
		{
			qpol_range_trans_get_target_class(qp, static_cast < const qpol_range_trans_t * >(candidate), &cls);
			qpol_class_get_name(qp, cls, &name);
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
		input.str = new string(name);
		return MATCH_STRING;
	}
	case POLSEARCH_OP_PERM:
	{
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
		{
			qpol_avrule_get_perm_iter(qp, static_cast < const qpol_avrule_t * >(candidate), &iter);
			input.list = new vector < string > ();
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				void *name;
				qpol_iterator_get_item(iter, &name);
				input.list->push_back(string(static_cast < char *>(name)));
				free(name);
			}
			qpol_iterator_destroy(&iter);
		}
		else
		{
			throw runtime_error("Incompatible comparison.");
		}
		return MATCH_LIST;
	}
	case POLSEARCH_OP_DEFAULT:
	{
		if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			const qpol_type_t *type;
			qpol_terule_get_default_type(qp, static_cast < const qpol_terule_t * >(candidate), &type);
			input.list = new vector < string > (get_all_names(type, POLSEARCH_ELEMENT_TYPE, policy));
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
		{
			const qpol_role_t *dflt = NULL;
			qpol_role_trans_get_default_role(qp, static_cast < const qpol_role_trans_t * >(candidate), &dflt);
			const char *name;
			qpol_role_get_name(qp, dflt, &name);
			input.str = new string(name);
			return MATCH_STRING;
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
	}
	case POLSEARCH_OP_SRC_TGT:
	{
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE || candidate_type == POLSEARCH_ELEMENT_TERULE ||
		    candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
		{
			const qpol_type_t *src = NULL;
			const qpol_type_t *tgt = NULL;
			if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
			{
				qpol_avrule_get_source_type(qp, static_cast < const qpol_avrule_t * >(candidate), &src);
				qpol_avrule_get_target_type(qp, static_cast < const qpol_avrule_t * >(candidate), &tgt);
			}
			else if (candidate_type == POLSEARCH_ELEMENT_TERULE)
			{
				qpol_terule_get_source_type(qp, static_cast < const qpol_terule_t * >(candidate), &src);
				qpol_terule_get_target_type(qp, static_cast < const qpol_terule_t * >(candidate), &tgt);
			}
			else if (candidate_type == POLSEARCH_ELEMENT_RANGE_TRANS)
			{
			}
			input.list = new vector < string > (expand_semantic_type(policy, src));
			*input.list += expand_semantic_type(policy, tgt);
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_ROLE_ALLOW)
		{
			const qpol_role_t *src = NULL;
			const qpol_role_t *tgt = NULL;
			const char *sname;
			const char *tname;
			qpol_role_allow_get_source_role(qp, static_cast < const qpol_role_allow_t * >(candidate), &src);
			qpol_role_allow_get_target_role(qp, static_cast < const qpol_role_allow_t * >(candidate), &tgt);
			qpol_role_get_name(qp, src, &sname);
			qpol_role_get_name(qp, tgt, &tname);
			input.list = new vector < string > ();
			(*input.list).push_back(string(sname));
			(*input.list).push_back(string(tname));
			return MATCH_LIST;
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
	}
	case POLSEARCH_OP_SRC_TGT_DFLT:
	{
		const qpol_type_t *src = NULL;
		const qpol_type_t *tgt = NULL;
		const qpol_type_t *dflt = NULL;
		if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			qpol_terule_get_source_type(qp, static_cast < const qpol_terule_t * >(candidate), &src);
			qpol_terule_get_target_type(qp, static_cast < const qpol_terule_t * >(candidate), &tgt);
			qpol_terule_get_default_type(qp, static_cast < const qpol_terule_t * >(candidate), &dflt);
			input.list = new vector < string > (expand_semantic_type(policy, src));
			*input.list += expand_semantic_type(policy, tgt);
			*input.list += get_all_names(dflt, POLSEARCH_ELEMENT_TYPE, policy);
			return MATCH_LIST;
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
	}
	case POLSEARCH_OP_SRC_DFLT:
	{
		if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			const qpol_type_t *src = NULL;
			const qpol_type_t *dflt = NULL;
			qpol_terule_get_source_type(qp, static_cast < const qpol_terule_t * >(candidate), &src);
			qpol_terule_get_default_type(qp, static_cast < const qpol_terule_t * >(candidate), &dflt);
			input.list = new vector < string > (expand_semantic_type(policy, src));
			*input.list += get_all_names(dflt, POLSEARCH_ELEMENT_TYPE, policy);
			return MATCH_LIST;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_ROLE_TRANS)
		{
			const qpol_role_t *src = NULL;
			const qpol_role_t *dflt = NULL;
			const char *sname;
			const char *dname;
			qpol_role_trans_get_source_role(qp, static_cast < const qpol_role_trans_t * >(candidate), &src);
			qpol_role_trans_get_default_role(qp, static_cast < const qpol_role_trans_t * >(candidate), &dflt);
			qpol_role_get_name(qp, src, &sname);
			qpol_role_get_name(qp, dflt, &dname);
			input.list = new vector < string > ();
			(*input.list).push_back(string(sname));
			(*input.list).push_back(string(dname));
			return MATCH_LIST;
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
	}
	case POLSEARCH_OP_IN_COND:
	{
		const qpol_cond_t *cond;
		if (candidate_type == POLSEARCH_ELEMENT_AVRULE)
		{
			qpol_avrule_get_cond(qp, static_cast < const qpol_avrule_t * >(candidate), &cond);
		}
		else if (candidate_type == POLSEARCH_ELEMENT_TERULE)
		{
			qpol_terule_get_cond(qp, static_cast < const qpol_terule_t * >(candidate), &cond);
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
		input.list = new vector < string > ();
		qpol_cond_get_expr_node_iter(qp, cond, &iter);
		if (!iter)
			throw bad_alloc();
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
		{
			void *node;
			qpol_iterator_get_item(iter, &node);
			uint32_t type;
			qpol_cond_expr_node_get_expr_type(qp, static_cast < const qpol_cond_expr_node_t * >(node), &type);
			if (type == QPOL_COND_EXPR_BOOL)
			{
				qpol_bool_t *b;
				qpol_cond_expr_node_get_bool(qp, static_cast < const qpol_cond_expr_node_t * >(node), &b);
				const char *name;
				qpol_bool_get_name(qp, b, &name);
				input.list->push_back(string(name));
			}
		}
		qpol_iterator_destroy(&iter);
		return MATCH_LIST;
	}
	case POLSEARCH_OP_LEVEL_EXACT:
	case POLSEARCH_OP_LEVEL_DOM:
	case POLSEARCH_OP_LEVEL_DOMBY:
	{
		if (candidate_type == POLSEARCH_ELEMENT_LEVEL)
		{
			input.lvl =
				apol_mls_level_create_from_qpol_level_datum(policy,
									    static_cast < const qpol_level_t * >(candidate));
			if (!input.lvl)
				throw bad_alloc();
			return MATCH_LEVEL;
		}
		else if (candidate_type == POLSEARCH_ELEMENT_MLS_LEVEL)
		{
			input.lvl = static_cast < const apol_mls_level_t *>(candidate);
			return MATCH_LEVEL;
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
	}
	case POLSEARCH_OP_RANGE_EXACT:
	case POLSEARCH_OP_RANGE_SUPER:
	case POLSEARCH_OP_RANGE_SUB:
	{
		if (candidate_type == POLSEARCH_ELEMENT_FC_ENTRY)
		{
			const apol_context_t *ctx = static_cast < const sefs_entry * >(candidate)->context();
			input.rng = apol_context_get_range(ctx);
		}
		else
		{
			input.rng = static_cast < const apol_mls_range_t *>(candidate);
		}
		return MATCH_RANGE;
	}
	case POLSEARCH_OP_USER:
	{
		if (candidate_type == POLSEARCH_ELEMENT_FC_ENTRY)
		{
			const qpol_user_t *user;
			const apol_context_t *ctx = static_cast < const sefs_entry * >(candidate)->context();
			const char *name = apol_context_get_user(ctx);
			qpol_policy_get_user_by_name(qp, name, &user);
			input.list = new vector < string > (get_all_names(user, POLSEARCH_ELEMENT_USER, policy));
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
		return MATCH_LIST;
	}
	case POLSEARCH_OP_ROLE:
	{
		if (candidate_type == POLSEARCH_ELEMENT_FC_ENTRY)
		{
			const qpol_role_t *role;
			const apol_context_t *ctx = static_cast < const sefs_entry * >(candidate)->context();
			const char *name = apol_context_get_role(ctx);
			qpol_policy_get_role_by_name(qp, name, &role);
			input.list = new vector < string > (get_all_names(role, POLSEARCH_ELEMENT_ROLE, policy));
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
		return MATCH_LIST;
	}
	case POLSEARCH_OP_TYPE:
	{
		if (candidate_type == POLSEARCH_ELEMENT_FC_ENTRY)
		{
			const qpol_type_t *type;
			const apol_context_t *ctx = static_cast < const sefs_entry * >(candidate)->context();
			const char *name = apol_context_get_type(ctx);
			qpol_policy_get_type_by_name(qp, name, &type);
			input.list = new vector < string > (get_all_names(type, POLSEARCH_ELEMENT_TYPE, policy));
		}
		else
		{
			throw runtime_error("Incompatible comparison");
		}
		return MATCH_LIST;
	}
	case POLSEARCH_OP_NONE:
	default:
	{
		assert(0);
		throw runtime_error("Impossible case reached");
	}
	}
}

void polsearch_criterion::check(const apol_policy_t * policy, std::vector < const void *>&test_candidates,
				const std::vector < std::string > &Xnames) const throw(std::runtime_error, std::bad_alloc)
{
	if (!_test)
		throw runtime_error("Cannot check criteria until associated with a test.");

	polsearch_element candidate_type = determine_candidate_type(_test->testCond());
	for (size_t i = 0; i < test_candidates.size(); i++)
	{
		bool match = false;
		union match_input input;
		enum match_type which = determine_match_type(policy, test_candidates[i], candidate_type, _op, input);

		switch (which)
		{
		case MATCH_BOOL:
		{
			match = _param->match(input.bval);
			break;
		}
		case MATCH_STRING:
		{
			match = _param->match(*(input.str), Xnames);
			delete input.str;
			break;
		}
		case MATCH_NUM:
		{
			match = _param->match(input.nval);
			break;
		}
		case MATCH_LEVEL:
		{
			int method;
			if (_op == POLSEARCH_OP_LEVEL_EXACT)
				method = APOL_MLS_EQ;
			else if (_op == POLSEARCH_OP_LEVEL_DOM)
				method = APOL_MLS_DOM;
			else if (_op == POLSEARCH_OP_LEVEL_DOMBY)
				method = APOL_MLS_DOMBY;
			else
			{
				assert(0);
				throw runtime_error("Impossible case reached.");
			}
			match = _param->match(policy, input.lvl, method);
			break;
		}
		case MATCH_RANGE:
		{
			unsigned int method;
			if (_op == POLSEARCH_OP_RANGE_EXACT)
				method = APOL_QUERY_EXACT;
			else if (_op == POLSEARCH_OP_RANGE_SUB)
				method = APOL_QUERY_SUB;
			else if (_op == POLSEARCH_OP_RANGE_SUPER)
				method = APOL_QUERY_SUPER;
			else
			{
				assert(0);
				throw runtime_error("Impossible case reached.");
			}
			match = _param->match(policy, input.rng, method);
			break;
		}
		case MATCH_LIST:
		{
			match = _param->match(*(input.list), Xnames);
			delete input.list;
			break;
		}
		default:
		{
			assert(0);
			throw runtime_error("Impossible case reached.");
		}
		}

		if (_negated)
			match = !match;

		if (!match)
		{
			if (candidate_type == POLSEARCH_ELEMENT_MLS_LEVEL)	//the following odd cast handles freeing the memory temporarily used for the level
				apol_mls_level_destroy((reinterpret_cast <
							apol_mls_level_t ** >(const_cast < void **>(&(test_candidates[i])))));
			if (candidate_type == POLSEARCH_ELEMENT_MLS_RANGE)	//the following odd cast handles freeing the memory temporarily used for the level
				apol_mls_range_destroy((reinterpret_cast <
							apol_mls_range_t ** >(const_cast < void **>(&(test_candidates[i])))));
			test_candidates.erase(test_candidates.begin() + i);
			i--;
		}
	}
}

bool polsearch_criterion::operator==(const polsearch_criterion & rhs) const
{
	if (_op != rhs._op)
		return false;
	if (_negated != rhs._negated)
		return false;
	if (_test != rhs._test)
		return false;
	if (_param && !rhs._param)
		return false;
	if (!_param && rhs._param)
		return false;
	if ((_param && rhs._param) &&
	    (_param->paramType() != rhs._param->paramType() || _param->toString() != rhs._param->toString()))
		return false;
	return true;
}

bool polsearch_criterion::operator!=(const polsearch_criterion & rhs) const
{
	return !(*this == rhs);
}
