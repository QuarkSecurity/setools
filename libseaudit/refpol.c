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
static au_iface_call_t *au_iface_match_rules(au_iface_rule_key_t *keys, au_iface_t *iface)
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

/* rank a single iface call */
static int au_iface_rank_iface_call(au_iface_t *iface, au_iface_call_t *call)
{
	//TODO:

	return NULL;
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
	// test(make conf)
	// test(make policy.conf)
	return TRUE;
}

int au_iface_graph_init(const char *ref_pol_src_dir)
{
	if (ref_pol_src_dir == NULL || !is_valid_src_dir(ref_pol_src_dir)) {
		return -1;
	}
	// TODO: 
	// rt = build_file_to_parse(ref_pol_src_dir) /* see setools-test script */
	// if (rt < 0)
	//	return -2
	// rt = parse_file(graph)
	// if (rt < 0)
	//	return -3
	return 0;
}

void au_iface_graph_destroy(au_iface_graph_t *graph)
{
	//TODO:
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

// Do we return a newly allocated array with the ranks, or do we simply sort the calls array? */
int au_iface_rank_iface_calls(au_iface_call_t *calls, int **ranks)
{
	//TODO:
	return NULL;
}
