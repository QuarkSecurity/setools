/**
 * @file relabel-analysis.c
 * Implementation of the direct relabelling analysis.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include "policy-query.h"

#include <errno.h>
#include <string.h>

/* defines for mode */
#define APOL_RELABEL_MODE_OBJ	0x01
#define APOL_RELABEL_MODE_SUBJ	0x02

struct apol_relabel_analysis {
	unsigned int mode, direction;
	char *type, *result;
	apol_vector_t *classes, *subjects;
	regex_t *result_regex;
};


/**
 * Results are in the form of a list of apol_relabel_result_t nodes.
 * For subject mode analysis, there is exactly one node, of which the
 * to, from, and both vectors are used; the type field is ignored.
 * For object mode analysis, there are multiple nodes such that within
 * each node,
 *
 * to_1(T) = to_2(T) = ... = to_m(T) = target type
 * from_1(T) = from_2(T) = ... = from_n(T) = type
 * to_i(S) = from_i(S) for all 1 <= i <= m
 * m = n
 */
struct apol_relabel_result {
	/** vector of qpol_rule_t pointers */
	apol_vector_t *to;
	/** vector of qpol_rule_t pointers */
	apol_vector_t *from;
	/** vector of qpol_rule_t pointers */
	apol_vector_t *both;
	/** private field, used when building results for object mode
	 * analysis */
	qpol_type_t *type;
};

#define PERM_RELABELTO "relabelto"
#define PERM_RELABELFROM "relabelfrom"

/******************** actual analysis rountines ********************/

/**
 * Given an avrule, determine which relabel direction it has (to,
 * from, or both).
 *
 * @param p Policy containing avrule.
 * @param avrule Rule to examine.
 *
 * @return One of APOL_RELABEL_DIR_TO, APOL_RELABEL_DIR_FROM,
 * APOL_RELABEL_DIR_BOTH, or < 0 if direction could not be determined.
 */
static int relabel_analysis_get_direction(apol_policy_t *p,
                                          qpol_avrule_t *avrule)
{
	qpol_iterator_t *iter;
	int to = 0, from = 0, retval = -1;

	if (qpol_avrule_get_perm_iter(p->qh, p->p, avrule, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *perm;
		if (qpol_iterator_get_item(iter, (void **) &perm) < 0) {
			goto cleanup;
		}
		if (strcmp(perm, PERM_RELABELTO) == 0) {
			to = 1;
		}
		else if (strcmp(perm, PERM_RELABELFROM) == 0) {
			from = 1;
		}
	}
	if (to && from) {
		retval = APOL_RELABEL_DIR_BOTH;
	}
	else if (to) {
		retval = APOL_RELABEL_DIR_TO;
	}
	else if (from) {
		retval = APOL_RELABEL_DIR_FROM;
	}
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Given a qpol_type_t pointer, find and return the first
 * apol_relabel_result_t node within vector v that matches the type.
 * If there does not exist a node with that type, then allocate a new
 * one, append it to the vector, and return it.  The caller is
 * expected to eventually call apol_vector_destroy() upon the vector
 * with the parameter apoL_relabel_result_free(); the caller should
 * not free the individual nodes.
 *
 * @param p Policy, used for error handling.
 * @param v A vector of apol_relabel_result_t nodes.
 * @param type Target type to find.
 *
 * @return An apol_relabel_result_t node from which to append results,
 * or NULL upon error.
 */
static apol_relabel_result_t *relabel_result_get_node(apol_policy_t *p,
						      apol_vector_t *v,
						      qpol_type_t *type)
{
	apol_relabel_result_t *result;
	size_t i;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		result = (apol_relabel_result_t *) apol_vector_get_element(v, i);
		if (result->type == type) {
			return result;
		}
	}
	/* make a new result node */
	if ((result = calloc(1, sizeof(*result))) == NULL ||
	    (result->to = apol_vector_create()) == NULL ||
	    (result->from = apol_vector_create()) == NULL ||
	    (result->both = apol_vector_create()) == NULL ||
	    apol_vector_append(v, result) < 0) {
		apol_relabel_result_free(result);
		ERR(p, "Out of memory!");
		return NULL;
	}
	result->type = type;
	return result;
}

/**
 * Given an avrule, possbily append it to the result object onto the
 * appropriate rules vector.  The decision to actually append or not
 * is dependent upon the filtering options stored within the relabel
 * analysis object.
 *
 * @param p Policy containing avrule.
 * @param r Relabel analysis query object, containing filtering options.
 * @param avrule AV rule to add.
 * @param result Pointer to the result object being built.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_avrule_to_result(apol_policy_t *p,
				   apol_relabel_analysis_t *r,
				   qpol_avrule_t *avrule,
				   apol_relabel_result_t *result)
{
	qpol_type_t *target;
	int retval = -1, dir, compval;
	if ((dir = relabel_analysis_get_direction(p, avrule)) < 0) {
		goto cleanup;
	}
	if (qpol_avrule_get_target_type(p->qh, p->p, avrule, &target) < 0) {
		goto cleanup;
	}
	compval = apol_compare_type(p, target, r->result, APOL_QUERY_REGEX, &r->result_regex);
	if (compval < 0) {
		goto cleanup;
	}
	else if (compval == 0) {
		retval = 0;
		goto cleanup;
	}
	switch (dir) {
	case APOL_RELABEL_DIR_TO:
		if ((apol_vector_append(result->to, avrule)) < 0) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
		break;
	case APOL_RELABEL_DIR_FROM:
		if ((apol_vector_append(result->from, avrule)) < 0) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
		break;
	case APOL_RELABEL_DIR_BOTH:
		if ((apol_vector_append(result->both, avrule)) < 0) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
		break;
	}

	retval = 0;
 cleanup:
	return retval;
}

/**
 * Given a vector of strings representing type names, allocate and
 * return a vector of qpol_type_t pointers into the given policy for
 * those types.  If a type name is really an alias, obtain and store
 * its primary instead.
 *
 * @param p Policy to which look up types
 * @param v Vector of strings.
 *
 * @return A newly allocated apol_vector_t, which the caller must free
 * with apol_vector_destroy(), passing NULL as the second parameter.
 * If a type name was not found or upon other error return NULL.
 */
static apol_vector_t *relabel_analysis_get_type_vector(apol_policy_t *p,
						       apol_vector_t *v)
{
	apol_vector_t *types = NULL;
	size_t i;
	int retval = -1;

	if ((types = apol_vector_create_with_capacity(apol_vector_get_size(v))) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		char *s = (char *) apol_vector_get_element(v, i);
		qpol_type_t *type;
		if (apol_query_get_type(p, s, &type) < 0 ||
		    apol_vector_append(types, type)) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval == -1) {
		apol_vector_destroy(&types, NULL);
		return NULL;
	}
	return types;
}

/**
 * Given a type, see if it is an element within a vector of
 * qpol_type_t pointers.  If the type is really an attribute, also
 * check if any of the attribute's types are a member of v.  If v is
 * NULL then the comparison always succeeds.
 *
 * @param p Policy to which look up types.
 * @param v Target vector of qpol_type_t pointers.
 * @param type Source type to find.
 *
 * @return 1 if type is a member of v, 0 if not, < 0 on error.
 */
static int relabel_analysis_compare_type_to_vector(apol_policy_t *p,
						   apol_vector_t *v,
						   qpol_type_t *type)
{
	size_t i;
	unsigned char isattr;
	qpol_iterator_t *iter = NULL;
	int retval = -1;
	if (v == NULL || apol_vector_get_index(v, type, NULL, NULL, &i) == 0) {
		retval = 1;  /* found it */
		goto cleanup;
	}
	if (qpol_type_get_isattr(p->qh, p->p, type, &isattr) < 0) {
		goto cleanup;
	}
	if (!isattr) {	/* not an attribute, so comparison failed */
		retval = 0;
		goto cleanup;
	}
	if (qpol_type_get_type_iter(p->qh, p->p, type, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_type_t *t;
		if (qpol_iterator_get_item(iter, (void **) &t) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_index(v, t, NULL, NULL, &i) == 0) {
			retval = 1;
			goto cleanup;
		}
	}
	retval = 0;  /* no matches */
 cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Search through sets av and bv, finding pairs of avrules that
 * satisfy a relabel and adding those pairs to result vector v.
 *
 * @param p Policy containing avrules.
 * @param r Relabel analysis query object.
 * @param v Vector of apol_relabel_result_t nodes.
 * @param av Vector of qpol_avrule_t pointers.
 * @param bv Vector of qpol_avrule_t pointers.
 * @param subjects_v Vector of permitted qpol_type_t subjects, or NULL
 * to allow all types.
 *
 * @return 0 on success, < 0 upon error.
 */
static int relabel_analysis_matchup(apol_policy_t *p,
				    apol_relabel_analysis_t *r,
				    apol_vector_t *v,
				    apol_vector_t *av,
				    apol_vector_t *bv,
				    apol_vector_t *subjects_v)
{
	qpol_avrule_t *a_avrule, *b_avrule;
	qpol_type_t *a_source, *a_target, *b_source, *b_target, *start_type;
	qpol_class_t *a_class, *b_class;
	apol_relabel_result_t *result = NULL;
	size_t i, j;
	int compval, retval = -1;

	if (apol_query_get_type(p, r->type, &start_type) < 0) {
		goto cleanup;
	}
        for (i = 0; i < apol_vector_get_size(av); i++) {
		a_avrule = apol_vector_get_element(av, i);
		if (qpol_avrule_get_source_type(p->qh, p->p, a_avrule, &a_source) < 0 ||
		    qpol_avrule_get_target_type(p->qh, p->p, a_avrule, &a_target) < 0 ||
		    qpol_avrule_get_object_class(p->qh, p->p, a_avrule, &a_class) < 0) {
			goto cleanup;
		}
		compval = relabel_analysis_compare_type_to_vector(p, subjects_v, a_source);
		if (compval < 0) {
			goto cleanup;
		}
		else if (compval == 0) {
			continue;
		}

		/* check if there exists a B s.t. B(s) = source and
		   B(t) != r->type and B(o) = A(o) */
		for (j = 0; j < apol_vector_get_size(bv); j++) {
			b_avrule = apol_vector_get_element(bv, j);
			if (qpol_avrule_get_source_type(p->qh, p->p, b_avrule, &b_source) < 0 ||
			    qpol_avrule_get_target_type(p->qh, p->p, b_avrule, &b_target) < 0 ||
			    qpol_avrule_get_object_class(p->qh, p->p, b_avrule, &b_class) < 0) {
				goto cleanup;
			}
			if (a_source != b_source ||
			    b_target == start_type ||
			    a_class != b_class) {
				continue;
			}

			/* exclude B if B(t) does not match search criteria */
			compval = apol_compare_type(p, b_target, r->result, APOL_QUERY_REGEX, &r->result_regex);
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}

			/* add the pairing (A, B) to results v, at an
			 * existing relabel_results_t if possible */
			if ((result = relabel_result_get_node(p, v, b_target)) == NULL) {
				goto cleanup;
			}
			if (apol_vector_append(result->to, a_avrule) < 0 ||
			    apol_vector_append(result->from, b_avrule) < 0) {
				ERR(p, "Out of memory");
				goto cleanup;
			}
		}
	}

	retval = 0;
 cleanup:
	return retval;
}

/**
 * Get a list of allow rules, whose target type matches r->type and
 * whose permission is <i>opposite</i> of the direction given (e.g.,
 * relabelfrom if given DIR_TO).  Only include rules whose class is a
 * member of r->classes and whose source is a member of subjects_v.
 *
 * @param p Policy to which look up rules.
 * @param r Structure containing parameters for subject relabel analysis.
 * @param v Target vector to which append discovered rules.
 * @param direction Relabelling direction to search.
 * @param subjects_v If not NULL, then a vector of qpol_type_t pointers.
 *
 * @return 0 on success, < 0 on error.
 */
static int relabel_analysis_object(apol_policy_t *p,
				   apol_relabel_analysis_t *r,
				   apol_vector_t *v,
				   unsigned int direction,
				   apol_vector_t *subjects_v)
{
	apol_avrule_query_t *a = NULL, *b = NULL;
	apol_vector_t *a_rules = NULL, *b_rules = NULL;
	char *perm1, *perm2;
	size_t i;
	int retval = -1;

	if (direction == APOL_RELABEL_DIR_TO) {
		perm1 = PERM_RELABELFROM;
		perm2 = PERM_RELABELTO;
	}
	else {
		perm1 = PERM_RELABELTO;
		perm2 = PERM_RELABELFROM;
	}

	if ((a = apol_avrule_query_create()) == NULL) {
	    ERR(p, "Out of memory!");
	    goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, a, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_set_target(p, a, r->type, 1) < 0 ||
	    apol_avrule_query_append_perm(p, a, perm1) < 0) {
		goto cleanup;
	}
	for (i = 0; r->classes != NULL && i < apol_vector_get_size(r->classes); i++) {
		if (apol_avrule_query_append_class(p, a, apol_vector_get_element(r->classes, i)) < 0) {
			goto cleanup;
		}
	}
	if (apol_get_avrule_by_query(p, a, &a_rules) < 0) {
		goto cleanup;
	}

	if ((b = apol_avrule_query_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, b, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_append_perm(p, b, perm2) < 0) {
		goto cleanup;
	}
	for (i = 0; r->classes != NULL && i < apol_vector_get_size(r->classes); i++) {
		if (apol_avrule_query_append_class(p, b, apol_vector_get_element(r->classes, i)) < 0) {
			goto cleanup;
		}
	}
	if (apol_get_avrule_by_query(p, b, &b_rules) < 0) {
		goto cleanup;
	}

	if (relabel_analysis_matchup(p, r, v, a_rules, b_rules, subjects_v) < 0) {
		goto cleanup;
	}
	retval = 0;
 cleanup:
	apol_avrule_query_destroy(&a);
	apol_vector_destroy(&a_rules, NULL);
	apol_avrule_query_destroy(&b);
	apol_vector_destroy(&b_rules, NULL);
	return retval;
}


/**
 * Get a list of all allow rules, whose source type matches r->type
 * and whose permission list has either "relabelto" or "relabelfrom".
 * Only include rules whose class is a member of r->classes.  Add
 * instances of those to the result vector.
 *
 * @param p Policy to which look up rules.
 * @param r Structure containing parameters for subject relabel analysis.
 * @param v Target vector to which append discovered rules.
 *
 * @return 0 on success, < 0 on error.
 */
static int relabel_analysis_subject(apol_policy_t *p,
				    apol_relabel_analysis_t *r,
				    apol_vector_t *v)
{
	apol_avrule_query_t *a = NULL;
	apol_vector_t *avrules_v = NULL;
	qpol_avrule_t *avrule;
        apol_relabel_result_t *result = NULL;
	size_t i;
	int retval = -1;

	if ((a = apol_avrule_query_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, a, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_set_source(p, a, r->type, 1) < 0 ||
	    apol_avrule_query_append_perm(p, a, PERM_RELABELTO) < 0 ||
	    apol_avrule_query_append_perm(p, a, PERM_RELABELFROM) < 0) {
		goto cleanup;
	}
	for (i = 0; r->classes != NULL && i < apol_vector_get_size(r->classes); i++) {
		if (apol_avrule_query_append_class(p, a, apol_vector_get_element(r->classes, i)) < 0) {
			goto cleanup;
		}
	}
	if (apol_get_avrule_by_query(p, a, &avrules_v) < 0) {
		goto cleanup;
	}

	if ((result = relabel_result_get_node(p, v, NULL)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(avrules_v); i++) {
		avrule = (qpol_avrule_t *) apol_vector_get_element(avrules_v, i);
		if (append_avrule_to_result(p, r, avrule, result) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	apol_avrule_query_destroy(&a);
	apol_vector_destroy(&avrules_v, NULL);
	return retval;
}

/******************** public functions below ********************/

int apol_relabel_analysis_do(apol_policy_t *p,
			     apol_relabel_analysis_t *r,
			     apol_vector_t **v)
{
	apol_vector_t *subjects_v = NULL;
	qpol_type_t *start_type;
	int retval = -1;
	*v = NULL;

	if (r->mode == 0 || r->type == NULL) {
		ERR(p, strerror(EINVAL));
		goto cleanup;
	}
	if (apol_query_get_type(p, r->type, &start_type) < 0) {
		goto cleanup;
	}

	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}

	if (r->mode == APOL_RELABEL_MODE_OBJ) {
		if (r->subjects != NULL &&
		    (subjects_v = relabel_analysis_get_type_vector(p, r->subjects)) == NULL) {
			goto cleanup;
		}
		if ((r->direction & APOL_RELABEL_DIR_TO) &&
		    relabel_analysis_object(p, r, *v, APOL_RELABEL_DIR_TO, subjects_v) < 0) {
			goto cleanup;
		}
		if ((r->direction & APOL_RELABEL_DIR_FROM) &&
		    relabel_analysis_object(p, r, *v, APOL_RELABEL_DIR_FROM, subjects_v) < 0) {
			goto cleanup;
		}
	}
	else {
		if (relabel_analysis_subject(p, r, *v) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	apol_vector_destroy(&subjects_v, NULL);
	if (retval != 0) {
		apol_vector_destroy(v, apol_relabel_result_free);
	}
	return retval;
}

apol_relabel_analysis_t *apol_relabel_analysis_create(void)
{
	return calloc(1, sizeof(apol_relabel_analysis_t));
}

void apol_relabel_analysis_destroy(apol_relabel_analysis_t **r)
{
	if (*r != NULL) {
		free((*r)->type);
		free((*r)->result);
		apol_vector_destroy(&(*r)->classes, NULL);
		apol_vector_destroy(&(*r)->subjects, NULL);
		apol_regex_destroy(&(*r)->result_regex);
		free(*r);
		*r = NULL;
	}
}

int apol_relabel_analysis_set_dir(apol_policy_t *p,
				  apol_relabel_analysis_t *r,
				  unsigned int dir)
{
	switch (dir) {
	case APOL_RELABEL_DIR_BOTH:
	case APOL_RELABEL_DIR_TO:
	case APOL_RELABEL_DIR_FROM: {
		r->mode = APOL_RELABEL_MODE_OBJ;
		r->direction = dir;
		break;
	}
	case APOL_RELABEL_DIR_SUBJECT: {
		r->mode = APOL_RELABEL_MODE_SUBJ;
		r->direction = APOL_RELABEL_DIR_BOTH;
		break;
	}
	default: {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	}
	return 0;
}

int apol_relabel_analysis_set_type(apol_policy_t *p,
				   apol_relabel_analysis_t *r,
				   const char *name)
{
	if (name == NULL) {
		ERR(p, strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &r->type, NULL, name);
}

int apol_relabel_analysis_append_class(apol_policy_t *p,
				       apol_relabel_analysis_t *r,
				       const char *obj_class)
{
	char *s;
	if (obj_class == NULL) {
		apol_vector_destroy(&r->classes, free);
	}
	else if ((s = strdup(obj_class)) == NULL ||
	    (r->classes == NULL && (r->classes = apol_vector_create()) == NULL) ||
	    apol_vector_append(r->classes, s) < 0) {
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
}

int apol_relabel_analysis_append_subject(apol_policy_t *p,
					 apol_relabel_analysis_t *r,
					 const char *subject)
{
	char *s;
	if (subject == NULL) {
		apol_vector_destroy(&r->subjects, free);
	}
	else if ((s = strdup(subject)) == NULL ||
	    (r->subjects == NULL && (r->subjects = apol_vector_create()) == NULL) ||
	    apol_vector_append(r->subjects, s) < 0) {
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
}

int apol_relabel_analysis_set_result_regexp(apol_policy_t *p,
					    apol_relabel_analysis_t *r,
					    const char *result)
{
	return apol_query_set(p, &r->result, &r->result_regex, result);
}

/******************** functions to access relabel results ********************/

void apol_relabel_result_free(void *result)
{
	if (result != NULL) {
		apol_relabel_result_t *r = (apol_relabel_result_t *) result;
		apol_vector_destroy(&r->to, NULL);
		apol_vector_destroy(&r->from, NULL);
		apol_vector_destroy(&r->both, NULL);
		free(result);
	}
}

apol_vector_t *apol_relabel_result_get_to(apol_relabel_result_t *r)
{
	return r->to;
}

apol_vector_t *apol_relabel_result_get_from(apol_relabel_result_t *r)
{
	return r->from;
}

apol_vector_t *apol_relabel_result_get_both(apol_relabel_result_t *r)
{
	return r->both;
}
