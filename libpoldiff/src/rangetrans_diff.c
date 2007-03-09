/**
 *  @file
 *  Implementation for computing a semantic differences in range
 *  transition rules.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include "poldiff_internal.h"

#include <apol/mls-query.h>
#include <apol/util.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_range_trans_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	apol_vector_t *diffs;
};

struct poldiff_range_trans
{
	char *source;
	char *target;
	char *target_class;
	poldiff_form_e form;
	poldiff_range_t *range;
};

void poldiff_range_trans_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->range_trans_diffs->num_added;
	stats[1] = diff->range_trans_diffs->num_removed;
	stats[2] = diff->range_trans_diffs->num_modified;
	stats[3] = diff->range_trans_diffs->num_added_type;
	stats[4] = diff->range_trans_diffs->num_removed_type;
}

char *poldiff_range_trans_to_string(poldiff_t * diff, const void *range_trans)
{
	const poldiff_range_trans_t *rt = range_trans;
	size_t len = 0;
	char *s = NULL;
	if (diff == NULL || range_trans == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (rt->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
		{
			if (apol_str_appendf(&s, &len, "+ range_transition %s %s : %s %s;", rt->source, rt->target,
					     rt->target_class, "<stuff>") < 0) {
				goto cleanup;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
		{
			if (apol_str_appendf(&s, &len, "- range_transition %s %s : %s %s;", rt->source, rt->target,
					     rt->target_class, "<stuff>") < 0) {
				goto cleanup;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:
		{
			if (apol_str_appendf
			    (&s, &len, "* range_transition %s %s : %s { %s  -->  %s };\n", rt->source, rt->target,
			     rt->target_class, "<stuff1>", "<stuff2>") < 0) {
				goto cleanup;;
			}
			return s;
		}
	default:
		{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
      cleanup:
	/* if this is reached then an error occurred */
	ERR(diff, "%s", strerror(ENOMEM));
	free(s);
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_range_trans_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->range_trans_diffs->diffs;
}

const char *poldiff_range_trans_get_source_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->source;
}

const char *poldiff_range_trans_get_target_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->target;
}

const char *poldiff_range_trans_get_target_class(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->target_class;
}

poldiff_range_t *poldiff_range_trans_get_range(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->range;
}

poldiff_form_e poldiff_range_trans_get_form(const void *range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_range_trans_t *)range_trans)->form;
}

poldiff_range_trans_summary_t *range_trans_create(void)
{
	poldiff_range_trans_summary_t *rts = calloc(1, sizeof(*rts));
	if (rts == NULL) {
		return NULL;
	}
	if ((rts->diffs = apol_vector_create()) == NULL) {
		range_trans_destroy(&rts);
		return NULL;
	}
	return rts;
}

static void range_trans_free(void *elem)
{
	if (elem != NULL) {
		poldiff_range_trans_t *rt = (poldiff_range_trans_t *) elem;
		free(rt->source);
		free(rt->target);
		free(rt->target_class);
		range_destroy(&rt->range);
		free(rt);
	}
}

void range_trans_destroy(poldiff_range_trans_summary_t ** rts)
{
	if (rts != NULL && *rts != NULL) {
		apol_vector_destroy(&(*rts)->diffs, range_trans_free);
		free(*rts);
		*rts = NULL;
	}
}

typedef struct pseudo_range_trans
{
	uint32_t source_type, target_type;
	/* pointer into a policy's class's symbol table */
	char *target_class;
	qpol_mls_range_t *range;
} pseudo_range_trans_t;

void range_trans_free_item(void *item)
{
	if (item != NULL) {
		pseudo_range_trans_t *prt = item;
		free(prt);
	}
}

int range_trans_comp(const void *x, const void *y, poldiff_t * diff __attribute__ ((unused)))
{
	const pseudo_range_trans_t *p1 = x;
	const pseudo_range_trans_t *p2 = y;

	if (p1->source_type != p2->source_type) {
		return p1->source_type - p2->source_type;
	}
	if (p1->target_type != p2->target_type) {
		return p1->target_type - p2->target_type;
	}
	return strcmp(p1->target_class, p2->target_class);
}

int range_trans_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	range_trans_destroy(&diff->range_trans_diffs);
	diff->range_trans_diffs = range_trans_create();
	if (diff->range_trans_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Allocate and return a new range trans difference object.  If the
 * pseudo-range trans's source and/or target expands to multiple read
 * types, then just choose the first one for display.
 */
static poldiff_range_trans_t *make_range_trans_diff(poldiff_t * diff, poldiff_form_e form, const pseudo_range_trans_t * prt)
{
	poldiff_range_trans_t *rt = NULL;
	const char *n1, *n2;
	int error;
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		n1 = type_map_get_name(diff, prt->source_type, POLDIFF_POLICY_MOD);
		n2 = type_map_get_name(diff, prt->target_type, POLDIFF_POLICY_MOD);
	} else {
		n1 = type_map_get_name(diff, prt->source_type, POLDIFF_POLICY_ORIG);
		n2 = type_map_get_name(diff, prt->target_type, POLDIFF_POLICY_ORIG);
	}
	assert(n1 != NULL && n2 != NULL);
	if ((rt = calloc(1, sizeof(*rt))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if ((rt->source = strdup(n1)) == NULL ||
	    (rt->target = strdup(n2)) == NULL || (rt->target_class = strdup(prt->target_class)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(errno));
		range_trans_free(rt);
		errno = error;
		return NULL;
	}
	return rt;
}

int range_trans_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	const pseudo_range_trans_t *prt = (const pseudo_range_trans_t *)item;
	apol_vector_t *v1, *v2;
	qpol_mls_range_t *orig_range = NULL, *mod_range = NULL;
	poldiff_range_trans_t *rt = NULL;
	int error;

	/* check if form should really become ADD_TYPE / REMOVE_TYPE,
	 * by seeing if the /other/ policy's reverse lookup is
	 * empty */
	if (form == POLDIFF_FORM_ADDED) {
		if ((v1 = type_map_lookup_reverse(diff, prt->source_type, POLDIFF_POLICY_ORIG)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, prt->target_type, POLDIFF_POLICY_ORIG)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_ADD_TYPE;
		}
		mod_range = prt->range;
	} else {
		if ((v1 = type_map_lookup_reverse(diff, prt->source_type, POLDIFF_POLICY_MOD)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, prt->target_type, POLDIFF_POLICY_MOD)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_REMOVE_TYPE;
		}
		orig_range = prt->range;
	}
	if ((rt = make_range_trans_diff(diff, form, prt)) == NULL ||
	    (rt->range = range_create(diff, orig_range, mod_range, form)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if (apol_vector_append(diff->range_trans_diffs->diffs, rt) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	/* increment appropriate counter */
	switch (form) {
	case POLDIFF_FORM_ADDED:
		{
			diff->range_trans_diffs->num_added++;
			break;
		}
	case POLDIFF_FORM_ADD_TYPE:
		{
			diff->range_trans_diffs->num_added_type++;
			break;
		}
	case POLDIFF_FORM_REMOVED:
		{
			diff->range_trans_diffs->num_removed++;
			break;
		}
	case POLDIFF_FORM_REMOVE_TYPE:
		{
			diff->range_trans_diffs->num_removed_type++;
			break;
		}
	default:
		{
			/* not reachable */
			assert(0);
		}
	}
	return 0;
      cleanup:
	range_trans_free(rt);
	errno = error;
	return -1;
}

/**
 *  Compare two pseudo range transition rules from the same policy.
 *  Compares the pseudo source type, pseudo target type, and target
 *  class.
 *
 *  @param x A pseudo_range_trans_t entry.
 *  @param y A pseudo_range_trans_t entry.
 *  @param arg The policy difference structure.
 *
 *  @return < 0, 0, or > 0 if the first rule is respectively less than,
 *  equal to, or greater than the second. If the return value would be 0
 *  but the default role is different a warning is issued.
 */
static int pseudo_range_trans_comp(const void *x, const void *y, void *arg)
{
	const pseudo_range_trans_t *a = x;
	const pseudo_range_trans_t *b = y;
	poldiff_t *diff = arg;
	int retval = range_trans_comp(a, b, diff);
	/* FIX ME: WARN() if types conflict */
	return retval;
}

/**
 * Convert a type to a vector of one element, or an attribute into a
 * vector of its types.
 */
/* FIX ME
static apol_vector_t *range_trans_get_type_vector(poldiff_t * diff, int which_pol, qpol_type_t * type) {
	unsigned char isattr = 0;
        apol_vector_t *v = NULL;
        int error;
        qpol_type_get_isattr(q, tmp_type, &isattr);
        if (!isattr) {
                if ((v = apol_vector_create_with_capacity(1)) == NULL ||
                    apol_vector_append(v, type) < 0) {
                        error = errno;
                        apol_vector_destroy(&v, NULL);
                        ERR(diff, "%s", strerror(error));
                        errno = error;
                        return NULL;
                }
        }
        qpol_iterator_t *attr_types = NULL;
        qpol_type_get_type_iter(q, type, &attr_types);
        if ((v = apol_vector_create_from_iter(attr_types)) == NULL) {
                error = errno;
                ERR(diff, "%s", strerror(error));
                errno = error;
                return NULL;
        }
        return v;
}
*/

apol_vector_t *range_trans_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_range_trans_t *qrt = NULL;
	qpol_type_t *source_type, *target_type;
	qpol_class_t *target_class;
	char *class_name;
	qpol_mls_range_t *range;
	pseudo_range_trans_t *prt = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0, which_pol;

	which_pol = (policy == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	if (qpol_policy_get_range_trans_iter(q, &iter)) {
		error = errno;
		goto err;
	}
	if ((v = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&qrt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		if (qpol_range_trans_get_source_type(q, qrt, &source_type) < 0 ||
		    qpol_range_trans_get_target_type(q, qrt, &target_type) < 0 ||
		    qpol_range_trans_get_target_class(q, qrt, &target_class) < 0 ||
		    qpol_class_get_name(q, target_class, &class_name) < 0 || qpol_range_trans_get_range(q, qrt, &range) < 0) {
			error = errno;
			goto err;
		}
		if (!(prt = calloc(1, sizeof(*prt)))) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt->source_type = type_map_lookup(diff, source_type, which_pol);
		prt->target_type = type_map_lookup(diff, target_type, which_pol);
		prt->target_class = class_name;
		prt->range = range;
		if (apol_vector_append(v, prt)) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt = NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort_uniquify(v, pseudo_range_trans_comp, diff, range_trans_free_item);
	return v;

      err:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&v, free);
	free(prt);
	errno = error;
	return NULL;
}

int range_trans_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
#if 0
	/* FIX ME */
	const pseudo_role_trans_t *prt1 = x;
	const pseudo_role_trans_t *prt2 = y;
	char *default1 = NULL, *default2 = NULL;
	poldiff_role_trans_t *rt = NULL;
	apol_vector_t *mapped_tgts = NULL;
	qpol_type_t *tgt_type = NULL;
	char *tgt = NULL;
	int error = 0;

	default1 = prt1->default_role;
	default2 = prt2->default_role;

	if (!strcmp(default1, default2))
		return 0;	       /* no difference */

	mapped_tgts = type_map_lookup_reverse(diff, prt1->pseudo_target, POLDIFF_POLICY_ORIG);
	if (!mapped_tgts)
		return -1;	       /* errors already reported */
	tgt_type = apol_vector_get_element(mapped_tgts, 0);
	if (!tgt_type) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	qpol_type_get_name(diff->orig_qpol, tgt_type, &tgt);
	rt = make_rt_diff(diff, POLDIFF_FORM_MODIFIED, prt1->source_role, tgt);
	if (!rt)
		return -1;	       /* errors already reported */
	rt->orig_default = default1;
	rt->mod_default = default2;
	if (apol_vector_append(diff->role_trans_diffs->diffs, rt)) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		free(rt);
		errno = error;
		return -1;
	};
	diff->role_trans_diffs->num_modified++;
#endif
	return 0;
}
