/**
 *  @file
 *  Defines a common utility interface for sechecker.
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

#ifndef SECHECKER_UTIL_HH
#define SECHECKER_UTIL_HH

#include <apol/policy.h>

namespace sechk
{
	/**
	 * Print copyright information to stdout.
	 */
	void print_copyright(void);

	/**
	 * Determine if two types semantically match.
	 * This is true if either they are the same type or
	 * has at least one type with the other if one is an attribute.
	 * @param policy The policy from which the types come.
	 * @param first_type The first type.
	 * @param second_type The second type.
	 * @return If the types match, return \a true, return \a false otherwise.
	 */
	bool semantic_type_match(const qpol_policy_t * policy, const qpol_type_t * first_type, const qpol_type_t * second_type);

	/**
	 * Determine if the key for two av rules matches.
	 * Comparison is semantic; all attributes are expanded. Type fields
	 * are considered a match if the type sets have a non-null intersection.
	 * @param pol The policy from which the rules come.
	 * @param first The first rule to compare.
	 * @param second The second rule to compare.
	 * @return If the source type(s), target type(s), and object class match, return \a true;
	 * return \a false otherwise.
	 */
	bool avrule_key_match(const apol_policy_t * pol, const qpol_avrule_t * first, const qpol_avrule_t * second);

	/**
	 * Determine if the key for two type rules matches.
	 * Comparison is semantic; all attributes are expanded. Type fields
	 * are considered a match if the type sets have a non-null intersection.
	 * @param pol The policy from which the rules come.
	 * @param first The first rule to compare.
	 * @param second The second rule to compare.
	 * @return If the source type(s), target type(s), and object class match, return \a true;
	 * return \a false otherwise.
	 */
	bool terule_key_match(const apol_policy_t * pol, const qpol_terule_t * first, const qpol_terule_t * second);

	/**
	 * Duplication callback for use in elements for std::string.
	 * @param str The string to duplicate as a void pointer.
	 * @return A newly allocated copy of the string as a void pointer.
	 * The caller is responsible for calling std_string_free() on the returned pointer.
	 */
	void *std_string_dup(void *str);

	/**
	 * Deallocation callback for use in elements for std::string.
	 * @param str The string to deallocate as a void pointer.
	 */
	void std_string_free(void *str);

	/**
	 * Determine if a permission is valid for class.
	 * @param q The policy from which the class comes.
	 * @param obj_class The class to check.
	 * @param perm The permission for which to check.
	 * @return If \a perm is valid for \a obj_class, return \a true; otherwise, return \a false.
	 */
	bool validate_permission(const qpol_policy_t * q, const qpol_class_t * obj_class, const char *perm);
}

#endif				       /* SECHECKER_UTIL_HH */
