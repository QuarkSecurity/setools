/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 *
 * Date: December 8, 2005
 * 
 * refpol-test.c
 */

int main(int argc, char *argv[])
{
	au_iface_graph_t *graph;

	graph = au_iface_graph_create();
	au_iface_graph_init("/home/kcarr/svn/refpolicy/trunk/refpolicy");

	au_iface_call_t *au_get_valid_iface_calls(au_iface_rule_key_t *keys);
// Do we return a newly allocated array with the ranks, or do we simply sort the calls array? */
	int au_iface_rank_iface_calls(au_iface_call_t *calls, int **ranks);

	au_iface_graph_destroy(graph);
	return 0;
}
