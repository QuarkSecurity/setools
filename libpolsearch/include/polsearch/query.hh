/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
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

#ifndef POLSEARCH_QUERY_HH
#define POLSEARCH_QUERY_HH

#include <polsearch/polsearch.hh>

#include <sefs/fclist.hh>

#include <apol/policy.h>

#include <stdexcept>
#include <vector>
#include <string>

/**
 * Abstract query class for multiple test queries for policy elements.
 */
class polsearch_query
{
      public:
	//! Destructor.
	virtual ~polsearch_query();

	/**
	 * Get the matching behavior of the query.
	 * @return The current matching behavior of the query.
	 */
	polsearch_match match() const;
	/**
	 * Set the matching behavior of the query.
	 * @param m One of POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY to set.
	 * @return The behavior set.
	 * @exception std::invalid_argument Invalid matching behavior requested.
	 */
	polsearch_match match(polsearch_match m) throw(std::invalid_argument);

	/**
	 * Add a test to the query.
	 * @param test_cond The condition to be tested.
	 * @return A reference to the newly created and added test. This reference
	 * is only valid until the next call to addTest().
	 * @exception std::invalid_argument Given condition is not valid for
	 * the element type queried.
	 */
	 polsearch_test & addTest(polsearch_test_cond test_cond) throw(std::invalid_argument);

	/**
	 * Run the query.
	 * @param policy The policy containing the elements to match. If the query
	 * includes tests that check rules, all rules should be loaded for this policy.
	 * @param fclist A file_contexts list to optionally use for tests that
	 * match file_context entries. It is an error to not provide \a fclist
	 * if a test matches file_context entries.
	 * @return A vector of results containing one entry per element that matches
	 * the query.
	 * @exception std::bad_alloc Out of memory.
	 * @exception std::runtime_error Error running tests.
	 */
	 std::vector < polsearch_result > run(const apol_policy_t * policy, sefs_fclist * fclist =
					      NULL) const throw(std::bad_alloc, std::runtime_error);

	/**
	 * Get a string repersenting the query.
	 * @return A string representing the query.
	 */
	virtual std::string toString() const = 0;

	/**
	 * Get the type of element queried.
	 * @return The type of element queried.
	 */
	virtual polsearch_element elementType() const = 0;

      protected:
	/**
	 * Base class constructor.
	 * @param m Set the matching behavior of the query, must be
	 * either POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY.
	 * @exception std::invalid_argument Invalid matching behavior requested.
	 */
	 polsearch_query(polsearch_match m = POLSEARCH_MATCH_ALL) throw(std::invalid_argument);
	/**
	 * Base class copy constructor
	 * @param rhs The query to copy.
	 */
	 polsearch_query(const polsearch_query & rhs);

	/**
	 * Get all candidates of the appropriate element type
	 * to pass to tests when calling \a polsearch_test::run().
	 * @param policy The policy from which to get the elements.
	 * @return A vector of all elements of the appropriate type.
	 * @exception std::bad_alloc Out of memory.
	 * @exception std::runtime_error Unable to get the elements from the policy.
	 */
	virtual std::vector < const void *>getCandidates(const apol_policy_t * policy) const throw(std::bad_alloc,
												   std::runtime_error) = 0;

	 std::vector < polsearch_test > _tests;	/*!< The set of tests used by the query to determine which elements match. */

      private:

	/**
	 * Update internal state data. Called when adding tests or copying the query.
	 */
	void update();

	polsearch_match _match;	       /*!< The matching behavior used for determining if an element matches with multiple tests. */
};

/**
 * Get a list of the valid types of tests to perform for the element
 * type specified.
 * @param elem_type The type of element queried.
 * @return A vector containing all valid tests for the specified element type.
 */
std::vector < polsearch_test_cond > polsearch_get_valid_tests(polsearch_element elem_type);

#endif				       /* POLSEARCH_QUERY_HH */
