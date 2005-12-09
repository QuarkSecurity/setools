/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 *         Jeremy Mowery <jmowery@tresys.com>
 *
 * Date: December 8, 2005
 * 
 * refpol.h
 */

#include <refpol.h>

/* get a list of valid iface calls each with a single matching key */
static au_iface_call_t *au_iface_match_rules(au_iface_t *iface, au_iface_rule_key_t *keys)
{
	// TODO:
	// list = create_list()
	// foreach key
	//	c = create_call()
	//	foreach rule in iface
	//		if (rule.type != key.type)
	//			continue
	//		if (rule.src != key.src && !is_src_param(rule))
	//			continue
	//		if (rule.tgt != key.tgt && !is_tgt_param(rule))
	//			continue
	//		if (rule.obj != key.obj && !is_obj_param(rule))
	//			continue
	//		if (rule.perms != key.perms && !is_perms_param(rule))
	//			continue
	//
	//		/* at this point it could be a match */
	//		
	//		if (is_src_param(rule))
	//			idx = get_src_param_idx(rule, iface)
	//			if (!c->params[idx].val)
	//				c->params[idx].val = key.src.name
	//			else if (strcmp(key.src.name, c->params[idx].val))
	//				continue
	//		if (is_tgt_param(rule))
	//			idx = get_tgt_param_idx(rule, iface)
	//			if (!c->params[idx].val)
	//			       c->params[idx].val = key.tgt.name
	//			else if (strcmp(key.tgt.name, c->params[idx].val))
	//				continue
	//		if (is_obj_param(rule))
	//			idx = get_obj_param_idx(rule, iface)
	//			if (!c->params[idx].val)
	//				c->params[idx].val = key.obj.name
	//			else if (strcmp(key.obj.name, c->params[idx].val))
	//				continue
	//		if (is_perms_param(rule))
	//			idx = get_perms_param_idx(rule, iface)
	//			if (!c->params[idx].val)
	//				c->params[idx].val = key.perms.name
	//			else if (strcmp(key.perms.name, c->params[idx].val))
	//				continue
	//		add_key_to_call(c, key)
	//	if (is_valid_call(c))
	//		add_call_to_list(list, c)
	//	else
	//		free(c)
	// return list
	return NULL;
}

/* au_iface_call_rank()
 *
 * Rank the quality of the matches in a call.  High numbers are bad, 1 is perfect. */
static void au_iface_call_rank(au_iface_call_t *call)
{
	// TODO:
	// 
	// unsigned int weight
	//
	// weights:
	// 1  MATCH_UNCOND
	// 3  MATCH_ENABLED
	// 5  MATCH_UNKNOWN
	// 7  MATCH_DISABLED
	// 11 EXTRA_DISABLED
	// 13 EXTRA_COND
       	// 17 EXTRA_ENABLED
	// 19 EXTRA_UNCOND

	// iface = get_iface_from_call(call)
	// foreach rule in iface
	//	match = FALSE;
	// 	foreach key in call
	//		if (eq(key, rule->key))
	// 	 	 	/* here we have a match */
	//			match = TRUE
	//  		 	if (rule->scope & AU_IFACE_SCOPE_COND)
 	// 	 	 	 	if (unknown(rule->cond_exp))
	// 	 	 	 	 	weight += MATCH_UNKNOWN
	//	 	 	 	else if (is_true(rule->cond_exp))
	// 	 	 	 	 	weight += MATCH_ENABLED
 	// 	 	 	 	else
	// 	 	 	 	 	weight += MATCH_DISABLED
	//  	 		else if (rule->scope & AU_IFACE_SCOPE_OPTIONAL)
	//  	 	 		weight += MATCH_UNKNOWN
	// 	 		else if (rule->scope & AU_IFACE_SCOPE_IFELSE)
	//				weight += MATCH_UNKNOWN
	//			else
	//				weight += MATCH_UNCOND
	//			break
	//		else
	//			continue
	//
	//	if (match == false)
	//		/* here we have an extra rule */
	//		if (rule->scope & AU_IFACE_SCOPE_COND)
 	// 	 	 	if (unknown(rule->cond_exp))
	// 	 	 	 	weight += EXTRA_UNKNOWN
	//	 	 	else if (is_true(rule->cond_exp))
	// 	 	 	 	weight += EXTRA_ENABLED
 	// 	 	 	else
	// 	 	 	 	weight += EXTRA_DISABLED
	//  	 	else if (rule->scope & AU_IFACE_SCOPE_OPTIONAL)
	//  	 		weight += EXTRA_UNKNOWN
	// 	 	else if (rule->scope & AU_IFACE_SCOPE_IFELSE)
	//			weight += EXTRA_UNKNOWN
	//		else
	//			weight += EXTRA_UNCOND
	//  call->rank = weight / iface->num_rules
}

au_iface_graph_t *au_iface_graph_create()
{
	au_iface_graph_t *graph;

	graph = malloc(sizeof(au_iface_graph_t));
	if (graph == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return NULL;
	}
	memset(graph, 0, sizeof(au_iface_graph_t));
	return graph;
}

void au_iface_graph_destroy(au_iface_graph_t *graph)
{
	//TODO:
}

static bool_t is_valid_src_dir(const char *src_dir)
{
	if (src_dir == NULL)
		return FALSE;
	// TODO:
	// stat(src_dir/build.conf)
	// stat(src_dir/policy/support)
	// stat(src_dir/policy/modules/admin)
	// stat(src_dir/policy/modules/apps)
	// stat(src_dir/policy/modules/kernel)
	// stat(src_dir/policy/modules/services)
	// stat(src_dir/policy/modules/system)
	// stat(src_dir/Makefile)
	return TRUE;
}

int au_iface_graph_init(const char *ref_pol_src_dir)
{
	if (ref_pol_src_dir == NULL) {
		return -1;
	}
	
	// if (!is_valid_src_dir(ref_pol_src_dir))
	//	return -1
	// if (!make conf || !make policy.conf)
	//	return -2
	// rt = load_partial_policy(ref_pol_src_dir/policy.conf, &graph->policy, POL_OPT_SYMS)
	// if (rt < 0)
	//	return -3
	// rt = build_file_to_parse(ref_pol_src_dir, &file) /* see setools-test script */
	// if (rt < 0)
	//	return -4
	// rt = parse_file(graph, file)
	// if (rt < 0)
	//	return -5
	// close_file(file)
	// delete_file(file)
	return 0;
}

/*
 * consolidate_iface_calls()
 *
 * Take all the valid calls for an interface and set of keys, and consolidate them
 * into a list of valid calls such that each call has a complete set of parameter
 * arguments. */
static int consolidate_iface_calls(au_iface_call_t *calls[], int calls_sz)
{
	
}

au_iface_call_t *au_iface_graph_get_valid_iface_calls(au_iface_graph_t *graph, au_iface_rule_key_t *keys)
{
	// TODO:
	// foreach iface in graph
	//	iface_calls = au_iface_match_rules(keys, iface)
	//	iface_calls = consolidate_iface_calls(iface_calls)
	//	all_calls += iface_calls
	// return all_calls
	return NULL;
}

int au_iface_graph_rank_iface_calls(au_iface_graph_t *graph, au_iface_call_t *calls[], int calls_sz)
{
	// TODO:
	// foreach call in calls
	// 	au_iface_call_rank(call)
	// qsort(calls, calls_sz, compare_calls_rank())
	return 0;
}
