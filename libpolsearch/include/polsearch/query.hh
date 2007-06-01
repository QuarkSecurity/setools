/**
 * @file
 *
 * Routines to perform complex queries on a selinux policy.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef POLSEARCH_QUERY_H
#define POLSEARCH_QUERY_H

#include "polsearch.hh"
#include "test.hh"

#ifdef __cplusplus
extern "C"
{
#endif

#include <apol/policy.h>
#include <apol/vector.h>

#include <sefs/fclist.h>

	/** Value to indicate the overall matching behavior of the query */
	typedef enum polsearch_match
	{
		POLSEARCH_MATCH_ALL = 0,	/*!< Returned symbols must match all tests. */
		POLSEARCH_MATCH_ANY    /*!< Returned symbols must match at least one test. */
	} polsearch_match_e;

}

/**
 * Abstract query class for multiple test queries for policy elements.
 */
class polsearch_query
{
	public:
	/**
	 * Base class constructor.
	 * @param m Set the matching behavior of the query, must be
	 * either POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY.
	 */
	virtual polsearch_query(polsearch_match_e m = POLSEARCH_MATCH_ALL);
	/**
	 * Base class copy constructor
	 */
	virtual polsearch_query(const polsearch_query& pq);
	//! Destructor.
	virtual ~polsearch_query();

	/**
	 * Get the matching behavior of the query.
	 * @return The current matching behavior of the query.
	 */
	polsearch_match_e match() const;
	/**
	 * Set the matching behavior of the query.
	 * @param m One of POLSEARCH_MATCH_ALL or POLSEARCH_MATCH_ANY to set.
	 * @return The behavior set.
	 */
	polsearch_match_e match(polsearch_match_e m);
/**
	* Get a list of the valid types of tests to perform for the symbol
	* type specified by the query.
	* @return A vector (of type polsearch_test_cond_e) containing all valid
	* tests for the specified symbol type. The caller is responsible for
	* calling apol_vector_destroy() on the returned vector.
	*/
	virtual apol_vector_t *getValidTests() const = 0;
	/**
	 * Get the vector of tests performed by the query.
	 * @return The vector of tests. The caller is free to modify this vector,
	 * but should not destroy it.
	 */
	apol_vector_t *tests();
	/**
		* Run the query.
		* @param policy The policy containing the elements to match.
		* @param fclist A file_contexts list to optionally use for tests that
		* match file_context entries. It is an error to not provide \a fclist
		* if a test matches file_context entries.
		* @return A vector of results (polsearch_result), or NULL on
		* error. The caller is responsible for calling apol_vector_destroy()
		* on the returned vector.
		*/
	virtual apol_vector_t *run(const apol_policy_t * policy, const sefs_fclist_t * fclist = NULL) const = 0;

	protected:
	polsearch_match_e _match;      /*!< The matching behavior used for determining if an element matches with multiple tests. */
	apol_vector_t * _tests;       /*!< The set of tests used by the query to determine which elements match. */

	private:
};

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SWIG

	/** This typedef may safely be used in C to represent the class polsearch_query */
	typedef struct polsearch_query polsearch_query_t;

	/**
	 * Get the symbol matching behavior from a symbol query.
	 * @see polsearch_query::match()
	 */
	extern polsearch_match_e polsearch_query_get_match(const polsearch_symbol_query_t * sq);
	/**
	 * Set the symbol matching behavior from a symbol query.
	 * @see polsearch_query::match(polsearch_match_e)
	 */
	extern polsearch_match_e polsearch_query_set_match(polsearch_symbol_query_t * sq, polsearch_match_e m);
	/**
	 * Get the vector of tests run by a symbol query.
	 * @see polsearch_query::tests()
	 */
	extern apol_vector_t *polsearch_query_get_tests(polsearch_symbol_query_t * sq);

#endif

#ifdef __cplusplus
}
#endif

#endif /* POLSEARCH_QUERY_H */