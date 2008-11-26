/**
 * @file
 *
 * Declarations for performing conditional expression simplification.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007-2008 Tresys Technology, LLC
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

#ifndef APOL_COND_SIMPLIFY_H
#define APOL_COND_SIMPLIFY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include "policy.h"
#include "vector.h"

	typedef struct apol_cond_minterm apol_cond_minterm_t;

/**
 * Given an arbitrary qpol conditional expression, calculate and
 * return a simplified expression.  The expression is in canonical
 * form as a sum of products.
 *
 * @param p Policy from which the expression originated.
 * @param cond Expression to simplify.
 *
 * @return A newly allocated vector of minterms (of type
 * apol_cond_minterm *).  The caller must call apol_vector_destroy()
 * afterwards.
 */
	extern apol_vector_t *apol_cond_simplify(const apol_policy_t * p, const qpol_cond_t * cond);

/**
 * Given a minterm, return a vector of all variables (of type
 * qpol_bool_t *) in the minterm that are uncomplemented.  The
 * returned vector is unsorted and may be empty.
 *
 * @param minterm Minterm from which to extract.
 *
 * @return Vector of uncomplemented booleans.  Do not free or
 * otherwise modify this vector.
 */
	extern const apol_vector_t *apol_cond_minterm_get_variables(const apol_cond_minterm_t * minterm);

/**
 * Given a minterm, return a vector of all variables (of type
 * qpol_bool_t *) in the minterm that are complemented.  The returned
 * vector is unsorted and may be empty.
 *
 * @param minterm Minterm from which to extract.
 *
 * @return Vector of complemented booleans.  Do not free or otherwise
 * modify this vector.
 */
	extern const apol_vector_t *apol_cond_minterm_get_comp_variables(const apol_cond_minterm_t * minterm);

#ifdef	__cplusplus
}
#endif

#endif
