/**
 * @file
 *
 * Takes a qpol_cond_t conditional expression and simplifies it using
 * the Quine-McCluskey algorithm.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2001-2007 Tresys Technology, LLC
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

#include <config.h>

#include <apol/cond-simplify.h>
#include <apol/util.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct minterm
{
	bool prime, essential, was_combined;
	apol_vector_t *indices;
	char *o_cube;
};

static void minterm_free(void *elem)
{
	if (elem != NULL) {
		struct minterm *m = (struct minterm *)elem;
		apol_vector_destroy(&(m->indices));
		free(m->o_cube);
		free(m);
	}
}

/**
 * Determine if the two minterms' o-cubes vary by only a single digit.
 *
 * @param a First minimum term to compare.
 * @param b Other term to compare.
 *
 * @return 0 if the terms are equivalent, 1 if there is exactly one
 * difference, or -1 if there are more than one differences.
 */
static int minterm_compare(const struct minterm *m1, const struct minterm *m2)
{
	int retval = 0;
	char *s, *t;
	for (s = m1->o_cube, t = m2->o_cube; *s != '\0'; s++, t++) {
		if (*s != *t) {
			if (retval != 0) {
				/* at least two differences found */
				return -1;
			}
			retval = 1;
		}
	}
	/* all o-cubes should be unique, so at least one difference must
	   exist */
	assert(retval == 1);
	return retval;
}

/**
 * Determine if the two minterms' o-cubes are equivalent.
 *
 * @param a First minimum term to compare.
 * @param b Other term to compare.
 * @param data Unused.
 *
 * @return 0 if the o-cubes are the same, non-zero if different.
 */
static int minterm_compare2(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const struct minterm *m1 = (const struct minterm *)a;
	const struct minterm *m2 = (const struct minterm *)b;
	return strcmp(m1->o_cube, m2->o_cube);
}

/**
 * Given two minterms, create a new minterm that has a combination of
 * their indices array and rewritten o-cube string.
 *
 * @param p Error handler.
 * @param m1 First minimum term with which to combine.
 * @param m2 Other term to combine.
 *
 * @return A newly allocate minimum term that is a combination of \a
 * m1 and \a m2.  The caller must call minterm_free() afterwards.
 */
static struct minterm *minterm_create_by_combining(const apol_policy_t * p, const struct minterm *m1, const struct minterm *m2)
{
	int error;
	struct minterm *new_minterm = NULL;

	if ((new_minterm = calloc(1, sizeof(*new_minterm))) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		errno = error;
		return NULL;
	}

	if ((new_minterm->indices = apol_vector_create_from_vector(m1->indices, NULL, NULL, NULL)) == NULL ||
	    apol_vector_cat(new_minterm->indices, m2->indices) < 0) {
		error = errno;
		ERR(p, "%s", strerror(error));
		minterm_free(new_minterm);
		errno = error;
		return NULL;
	}
	apol_vector_sort(new_minterm->indices, NULL, NULL);

	if ((new_minterm->o_cube = strdup(m1->o_cube)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		minterm_free(new_minterm);
		errno = error;
		return NULL;
	}
	char *s;
	const char *t;
	for (s = new_minterm->o_cube, t = m2->o_cube; *s != '\0'; s++, t++) {
		if (*s != *t) {
			*s = '-';
			return new_minterm;
		}
	}
	/* should never get here -- there has to be at least one
	   difference */
	assert(0);
	minterm_free(new_minterm);
	return NULL;
}

#ifdef SETOOLS_DEBUG
static void minterm_print_list(apol_vector_t * minterms)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(minterms); i++) {
		struct minterm *m = apol_vector_get_element(minterms, i);
		size_t j;
		printf("%s %s ", (m->prime ? "[p]" : "   "), (m->essential ? "[e]" : "   "));
		for (j = 0; j < apol_vector_get_size(m->indices); j++) {
			printf("%zd ", (size_t) apol_vector_get_element(m->indices, j));
		}
		printf(": %s\n", m->o_cube);
	}
}
#endif

/**
 * Given a conditional expression, return a vector of all unique
 * booleans (of type qpol_bool_t) in that expression.  The vector will
 * be unsorted.
 *
 * @param p Policy containing the conditional expression to simplify,
 * for error handling.
 * @param q Qpol policy within \a p.
 * @param cond Conditional expression from which to get booleans.
 *
 * @return A newly allocated vector of qpol_bool_t pointers.  Caller
 * must call apol_vector_destroy() afterwards.
 */
static apol_vector_t *cond_simplify_gather_booleans(const apol_policy_t * p, const qpol_policy_t * q, const qpol_cond_t * cond)
{
	int error;
	bool caught_error = true;
	apol_vector_t *bools = NULL;
	qpol_iterator_t *iter = NULL;

	if ((bools = apol_vector_create_with_capacity(1, NULL)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_cond_get_expr_node_iter(q, cond, &iter) < 0) {
		error = errno;
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cond_expr_node_t *node;
		uint32_t expr_type;
		qpol_bool_t *qbool;
		if (qpol_iterator_get_item(iter, (void **)&node) < 0 || qpol_cond_expr_node_get_expr_type(q, node, &expr_type) < 0) {
			error = errno;
			goto cleanup;

		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			continue;
		}
		if (qpol_cond_expr_node_get_bool(q, node, &qbool) < 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append_unique(bools, qbool, NULL, NULL) < 0) {
			error = errno;
			goto cleanup;
		}
	}

	caught_error = false;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (caught_error) {
		apol_vector_destroy(&bools);
		errno = error;
	}
	return bools;
}

/**
 * Given a conditional expression and a vector of booleans in that
 * expression, return an array of bools that represent the
 * expression's truth table.  For each element of the returned truth
 * table, the element's index encodes the bits of each boolean and the
 * element's value the truth.
 *
 * The index bitfield is in reverse order of \a bools.  For example,
 * suppose the expression is <tt>A + ~B<tt>.  \a bools will have
 * pointers to qpol_bool_t A and B, in that order, because the encoded
 * qpol_cond_t will be <code>A B ! ||</code>.  The generated truth
 * table will be:
 *
 * <pre>
 *   B A | t
 *  -----|---
 *   0 0 | 1
 *   0 1 | 1
 *   1 0 | 0
 *   1 1 | 1
 * </pre>
 *
 * Note the the order of booleans is reverse of \a bools.  The
 * returned array will be:  { true, true, false, true }
 *
 * Also note that this algorithm is limited by the number of bits in a
 * size_t.  If there are more booleans than bits in size_t then
 * unspecified behavior occurs.
 *
 * @param p Policy containing the conditional expression to simplify,
 * for error handling.
 * @param q Qpol policy within \a p.
 * @param cond Conditional expression from which to generate truth table.
 * @param bools Vector of booleans within \a cond.
 *
 * @return An array of booleans representing the truth table.  The
 * caller must free() this array afterwards.
 */
static bool *cond_simplify_build_truth_table(const apol_policy_t * p, qpol_policy_t * q, const qpol_cond_t * cond,
					     apol_vector_t * bools)
{
	int error, truthiness;
	bool caught_error = true, saved_states = false;
	size_t i, j;
	qpol_bool_t *b;
	bool *truth_table = NULL;
	const size_t total_bools = apol_vector_get_size(bools);
	const size_t total_states = 1 << total_bools;

	assert(total_bools > 0);
	if ((truth_table = malloc(total_states * sizeof(*truth_table))) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	/* store the current state of the boolean values */
	int *old_vals = NULL;
	if ((old_vals = malloc(total_bools * sizeof(*old_vals))) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < total_bools; i++) {
		b = (qpol_bool_t *) apol_vector_get_element(bools, i);
		if (qpol_bool_get_state(q, b, &(old_vals[i])) < 0) {
			error = errno;
			goto cleanup;
		}
	}
	saved_states = true;

	/* now construct the table */
	for (i = 0; i < total_states; i++) {
		for (j = 0; j < total_bools; j++) {
			b = (qpol_bool_t *) apol_vector_get_element(bools, j);
			truthiness = ((i & (1 << j)) ? 1 : 0);
			if (qpol_bool_set_state_no_eval(q, b, truthiness) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		uint32_t is_true;
		if (qpol_cond_eval(q, cond, &is_true) < 0) {
			error = errno;
			goto cleanup;
		}
		truth_table[i] = (is_true == 1);
	}

	caught_error = false;
      cleanup:
	if (saved_states) {
		for (i = 0; i < total_bools; i++) {
			b = (qpol_bool_t *) apol_vector_get_element(bools, i);
			truthiness = old_vals[i];
			qpol_bool_set_state_no_eval(q, b, truthiness);
		}
	}
	free(old_vals);
	if (caught_error) {
		free(truth_table);
		truth_table = NULL;
		errno = error;
	}
	return truth_table;
}

/**
 * For each element in truth table \a truth_table, create a minterm
 * object; return a newly allocated vector of those minterm objects.
 * These minterm objects can then be combined together to calculate
 * the prime implicants.
 *
 * @param p Error handler.
 * @param bools Vector of unique booleans in the truth table.
 * @param truth_table Array of booleans representing the truth table.
 *
 * @return A newly allocated vector of minterms.  The caller must call
 * apol_vector_destroy() afterwards.
 */
static apol_vector_t *cond_simplify_create_minterms(const apol_policy_t * p, apol_vector_t * bools, const bool * truth_table)
{
	int error;
	apol_vector_t *minterms = NULL;
	const size_t total_bools = apol_vector_get_size(bools);
	const size_t total_states = 1 << total_bools;
	size_t i, j, bit_pos;
	char *o_cube = NULL;
	apol_vector_t *indices = NULL;
	struct minterm *new_minterm = NULL;

	assert(total_bools > 0);
	if ((minterms = apol_vector_create_with_capacity(total_states, minterm_free)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	for (i = 0; i < total_states; i++) {
		if (truth_table[i]) {
			if ((o_cube = calloc(total_bools + 1, 1)) == NULL) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			memset(o_cube, '0', total_bools);
			for (j = i, bit_pos = total_bools - 1; j != 0; j >>= 1, bit_pos--) {
				if (j & 0x01) {
					o_cube[bit_pos] = '1';
				}
			}

			if ((indices = apol_vector_create_with_capacity(1, NULL)) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			if (apol_vector_append(indices, (void *)i) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}

			if ((new_minterm = calloc(1, sizeof(*new_minterm))) == NULL) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			new_minterm->o_cube = o_cube;
			new_minterm->indices = indices;
			o_cube = NULL;
			indices = NULL;
			if (apol_vector_append(minterms, new_minterm) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			new_minterm = NULL;
		}
	}
/* FIX ME: what about A || ~A ? */
	assert(apol_vector_get_size(minterms) > 0);

	return minterms;

      err:
	apol_vector_destroy(&minterms);
	free(o_cube);
	apol_vector_destroy(&indices);
	minterm_free(new_minterm);
	errno = error;
	return NULL;
}

/**
 * Iterate across all elements of \a minterms, finding pairs of
 * minterms that can be combined.  Append to \a minterms new minterms
 * that represent combinations, and then remove the old minterms.  If
 * a minterm cannot be combined with any other, then mark it as prime.
 * The function should be called repeatedly until no more prime
 * minterms are found.
 *
 * @param p Error handler.
 * @param minterms Vector of struct minterm, containing minterms to
 * try to combine.
 *
 * @return 0 if no further combinations have been found, positive
 * value if at least one combine occurred, or negative upon error.
 */
static int cond_simplify_combine_minterms(const apol_policy_t * p, apol_vector_t * minterms)
{
	int retval = 0;
	size_t i, j, orig_minterm_size = apol_vector_get_size(minterms);
	struct minterm *m, *n;
	for (i = 0; i < orig_minterm_size; i++) {
		m = (struct minterm *)apol_vector_get_element(minterms, i);
		if (m->prime) {
			continue;
		}
		bool is_prime = true;
		for (j = i + 1; j < orig_minterm_size; j++) {
			n = (struct minterm *)apol_vector_get_element(minterms, j);
			bool do_minterms_match = (minterm_compare(m, n) == 1);
			if (do_minterms_match) {
				is_prime = false;
				m->was_combined = true;
				n->was_combined = true;
				if ((n = minterm_create_by_combining(p, m, n)) == NULL) {
					return -1;
				}
				if (apol_vector_append(minterms, n) < 0) {
					int error = errno;
					ERR(p, "%s", strerror(error));
					minterm_free(n);
					errno = error;
					return -1;
				}
			}
		}
		m->prime = is_prime;
	}

	/* note that the end condition of the following loop can change as
	   the minterms vector shrinks */
	for (i = 0; i < orig_minterm_size;) {
		m = (struct minterm *)apol_vector_get_element(minterms, i);
		if (m->was_combined) {
			if (apol_vector_remove(minterms, i) < 0) {
				return -1;
			}
			minterm_free(m);
			orig_minterm_size--;
			retval++;
		} else {
			i++;
		}
	}
	apol_vector_sort_uniquify(minterms, minterm_compare2, NULL);
	return retval;
}

/**
 * Continually iterate across all minterms until the essential prime
 * implicants have been found.  Those minterms will be marked as
 * essential following completion of this function.
 *
 * @param minterms Vector of prime implicants; the essential ones will
 * be marked.
 * @param bools Vector of unique booleans in the truth table.
 * @param truth_table Original truth table, used to keep track of
 * essential implicants.  This table will be modified by this
 * function.
 */
static void cond_simplify_find_essential_primes(apol_vector_t * minterms, apol_vector_t * bools, bool * truth_table)
{
	size_t i, j, k, l;
	size_t num_minterms = apol_vector_get_size(minterms);
	void *index;
	struct minterm *m, *n;
	bool all_essentials_found;

	/* first mark off essential implicants */
	do {
		all_essentials_found = true;
		for (i = 0; i < num_minterms; i++) {
			m = (struct minterm *)apol_vector_get_element(minterms, i);
			if (m->essential) {
				continue;
			}
			bool this_is_essential = false;
			for (j = 0; j < apol_vector_get_size(m->indices); j++) {
				index = apol_vector_get_element(m->indices, j);
				for (k = 0; k < num_minterms; k++) {
					if (k == i) {
						continue;
					}
					n = (struct minterm *)apol_vector_get_element(minterms, k);
					if (apol_vector_get_index(n->indices, index, NULL, NULL, &l) == 0) {
						break;
					}
				}
				if (k == num_minterms) {
					this_is_essential = true;
					break;
				}
			}
			if (this_is_essential) {
				m->essential = true;
				/* mark off the truth table all
				   indices covered by this minterm */
				for (j = 0; j < apol_vector_get_size(m->indices); j++) {
					index = apol_vector_get_element(m->indices, j);
					truth_table[(size_t) index] = false;
				}
				all_essentials_found = false;
			}
		}
	} while (!all_essentials_found);

	/* now go and mark non-essential minterms that will be needed
	   to cover the remainder of the table */
	const size_t total_bools = apol_vector_get_size(bools);
	const size_t total_states = 1 << total_bools;
	for (i = 0; i < total_states; i++) {
		if (!truth_table[i]) {
			continue;
		}
		for (j = 0; j < num_minterms; j++) {
			m = (struct minterm *)apol_vector_get_element(minterms, j);
			if (m->essential) {
				continue;
			}
			if (apol_vector_get_index(m->indices, (void *)i, NULL, NULL, &l) == 0) {
				m->essential = true;
				break;
				/* mark off the truth table all indices covered by
				   this minterm */
				for (k = 0; k < apol_vector_get_size(m->indices); k++) {
					index = apol_vector_get_element(m->indices, k);
					assert(truth_table[(size_t) index]);
					truth_table[(size_t) index] = false;
				}
			}
		}
		/* ensure that at least one minterm will cover this value */
		assert(j < num_minterms);
	}
}

static void cond_term_free(void *elem)
{
	if (elem != NULL) {
            apol_cond_term_t *a = (apol_cond_term_t *) elem;
		apol_vector_destroy(&(a->included));
		apol_vector_destroy(&(a->excluded));
	}
}

static apol_vector_t *cond_simplify_create_equation(const apol_policy_t * p, apol_vector_t * bools, apol_vector_t * minterms)
{
	int error;
	apol_vector_t *v = NULL, *inc = NULL, *exc = NULL;
        apol_cond_term_t *c = NULL;
	if ((v = apol_vector_create_with_capacity(apol_vector_get_size(minterms), cond_term_free)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	size_t i;
	size_t num_bools = apol_vector_get_size(bools);
	for (i = 0; i < apol_vector_get_size(minterms); i++) {
		struct minterm *m = (struct minterm *)apol_vector_get_element(minterms, i);
		if (!m->essential) {
			continue;
		}
		if ((inc = apol_vector_create_with_capacity(num_bools, NULL)) == NULL ||
                    (exc = apol_vector_create_with_capacity(num_bools, NULL)) == NULL) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
		size_t j;
		const char *s;
                /* note that j counts backwards; this is because the
                   boolean names were inserted in reverse order in
                   cond_simplify_build_truth_table() */
		for (s = m->o_cube, j = num_bools - 1; *s != '\0'; s++, j--) {
			if (*s == '1') {
				if (apol_vector_append(inc, apol_vector_get_element(bools, j)) < 0) {
					error = errno;
					ERR(p, "%s", strerror(error));
					goto err;
				}
			}
			else if (*s == '0') {
				if (apol_vector_append(exc, apol_vector_get_element(bools, j)) < 0) {
					error = errno;
					ERR(p, "%s", strerror(error));
					goto err;
				}
			}
		}
		assert(apol_vector_get_size(inc) > 0 || apol_vector_get_size(exc) > 0);

                if ((c = calloc(1, sizeof(*c))) == NULL) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
                }
                c->included = inc;
                c->excluded = exc;
                inc = NULL;
                exc = NULL;

		if (apol_vector_append(v, c) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
		c = NULL;
	}

	return v;
      err:
	apol_vector_destroy(&v);
        cond_term_free(c);
	apol_vector_destroy(&inc);
	apol_vector_destroy(&exc);
	errno = error;
	return NULL;
}

/**
 * Perform the Quine-McCluskey algorithm as follows:
 *
 * 1. Determine the total number of boolean variables are actually
 *    used by the expression.
 *
 * 2. Convert the expression into a truth table.
 *
 * 3. Generate lists of minterms from 'true' values in the truth
 *    table.
 *
 * 4. Combine minterms.
 *
 * 5. Determine which minterms are essential (and are to be used) in
 *    the minimum boolean equation.
 *
 * 6. Create minimum equation from vector of implicants.
 */
apol_vector_t *apol_cond_simplify(const apol_policy_t * p, const qpol_cond_t * cond)
{
	int error = 0;
	bool caught_error = true;
	apol_vector_t *bools = NULL, *minterms = NULL, *retval = NULL;
	bool *truth_table = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);

	if (p == NULL || cond == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	if ((bools = cond_simplify_gather_booleans(p, q, cond)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((truth_table = cond_simplify_build_truth_table(p, q, cond, bools)) == NULL) {
		error = errno;
		goto cleanup;
	}

	if ((minterms = cond_simplify_create_minterms(p, bools, truth_table)) == NULL) {
		error = errno;
		goto cleanup;
	}
#ifdef SETOOLS_DEBUG
	minterm_print_list(minterms);
#endif
	int keep_combining;
	do {
		keep_combining = cond_simplify_combine_minterms(p, minterms);
		if (keep_combining < 0) {
			error = errno;
			goto cleanup;
		}
#ifdef SETOOLS_DEBUG
		printf("after a round of combining:\n");
		minterm_print_list(minterms);
#endif
	} while (keep_combining);

	cond_simplify_find_essential_primes(minterms, bools, truth_table);
#ifdef SETOOLS_DEBUG
	printf("after finding essential primes:\n");
	minterm_print_list(minterms);
#endif

	if ((retval = cond_simplify_create_equation(p, bools, minterms)) == NULL) {
		error = errno;
		goto cleanup;
	}

	caught_error = false;
      cleanup:
	apol_vector_destroy(&bools);
	free(truth_table);
	if (caught_error) {
		apol_vector_destroy(&retval);
		errno = error;
	}
	return retval;
}
