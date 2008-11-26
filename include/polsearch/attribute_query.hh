/**
 * @file
 *
 * Routines to perform complex queries on attributes in a selinux policy.
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

#ifndef POLSEARCH_ATTRIBUTE_QUERY_HH
#define POLSEARCH_ATTRIBUTE_QUERY_HH

#include <polsearch/polsearch.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

/**
 * Query for attributes.
 */
class polsearch_attribute_query:public polsearch_query
{
      public:
	/**
	 * Create a query for attributes.
	 * @param m Set the matching behavior of the query, must be
	 * either POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY.
	 * @exception std::invalid_argument Invalid matching behavior requested.
	 */
	polsearch_attribute_query(polsearch_match m = POLSEARCH_MATCH_ALL) throw(std::invalid_argument);
	/**
		 * Copy constructor
		 * @param rhs The query to copy.
	 */
	polsearch_attribute_query(const polsearch_attribute_query & rhs);
	//! Destructor.
	~polsearch_attribute_query();

	/**
		 * Get a string repersenting the query.
		 * @return A string representing the query.
	 */
	virtual std::string toString() const;

	/**
		 * Get the type of element queried.
		 * @return Always returns POLSEARCH_ELEMENT_ATTRIBUTE.
	 */
	virtual polsearch_element elementType() const;

      protected:
	/**
	 * Get all conditional attributes.
	 * to pass to tests when calling \a polsearch_test::run().
	 * @param policy The policy from which to get the attributes.
	 * @return A vector of all attributes.
	 * @exception std::bad_alloc Out of memory.
	 * @exception std::runtime_error Unable to get the attributes from the poliy.
	 */
	 virtual std::vector < const void *>getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
												    std::runtime_error);

};

#endif				       /* POLSEARCH_ATTRIBUTE_QUERY_HH */
