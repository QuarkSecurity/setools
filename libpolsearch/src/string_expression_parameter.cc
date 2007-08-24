/**
 * @file
 *
 * A parameter object for use in polsearch_criterion to check string
 * expressions representing symbol names.
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

#include <string>
#include <vector>
#include <stdexcept>
#include <typeinfo>

#include <stdint.h>

#include <polsearch/polsearch.hh>
#include <polsearch/parameter.hh>
#include <polsearch/string_expression_parameter.hh>

#include <apol/policy.h>
#include <apol/policy-query.h>

using std::vector;
using std::string;

polsearch_string_expression_parameter::polsearch_string_expression_parameter(const std::string & expr) throw(std::
													     invalid_argument):polsearch_parameter
	()
{
	if (expr == "")
	{
		throw std::invalid_argument("String expression cannot be empty.");
	}
	_expression.push_back(expr);
}

polsearch_string_expression_parameter::polsearch_string_expression_parameter(const std::vector < std::string >
									     &expr) throw(std::
											  invalid_argument):polsearch_parameter()
{
	for (vector < string >::const_iterator i = expr.begin(); i != expr.end(); i++)
	{
		if (*i == "")
		{
			throw std::invalid_argument("String expression cannot be empty.");
		}
		_expression.push_back(*i);
	}
}

polsearch_string_expression_parameter::
polsearch_string_expression_parameter(const polsearch_string_expression_parameter & rhs):polsearch_parameter(rhs)
{
	_expression = rhs._expression;
}

polsearch_string_expression_parameter::~polsearch_string_expression_parameter()
{
	//nothign to do
}

static bool exists(const vector < string > &v, const string & s)
{
	for (vector < string >::const_iterator i = v.begin(); i != v.end(); i++)
	{
		if (*i == s)
		{
			return true;
		}
	}
	return false;
}

bool polsearch_string_expression_parameter::match(const std::string & str,
						  const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	if (str == "")
	{
		throw std::invalid_argument("String to match can not be empty.");
	}
	if (str == "X")
	{
		for (vector < string >::const_iterator i = Xnames.begin(); i != Xnames.end(); i++)
		{
			if (*i == "")
			{
				throw std::invalid_argument("String to match can not be empty.");
			}
			if (exists(_expression, *i))
			{
				return true;
			}
		}
		return false;
	}
	else
	{
		return exists(_expression, str);
	}
}

bool polsearch_string_expression_parameter::match(const std::vector < std::string > &test_list,
						  const std::vector < std::string > &Xnames) const throw(std::invalid_argument)
{
	for (vector < string >::const_iterator i = test_list.begin(); i != test_list.end(); i++)
	{
		if (match(*i, Xnames))
			return true;
	}
	return false;
}

const std::type_info & polsearch_string_expression_parameter::paramType() const
{
	return typeid(*this);
}

std::string polsearch_string_expression_parameter::toString() const
{
	//TODO polsearch_string_expression_parameter::toString()
	return "";
}

polsearch_parameter *polsearch_string_expression_parameter::clone() const throw(std::bad_alloc)
{
	return dynamic_cast < polsearch_parameter * >(new polsearch_string_expression_parameter(*this));
}
