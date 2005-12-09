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

#include <libapol/util.h>
#include <libapol/policy.h>

#ifndef AU_REFPOL_H
#define AU_REFPOL_H

/* structure to store the interface parameters */
typedef struct au_iface_params {
	bool_t 		optional;	/* is this an optional param */
	unsigned char	type;		/* type, obj, or permission */
	char		*value;		/* a value or NULL */
} au_iface_params_t;

/* structure to store the key for a rule in an interface */
typedef struct au_iface_rule_key {
	unsigned char	type;		/* what type of rule is this */
	int		*src_types;
	int		num_src_types;
	int		*tgt_types;
	int		num_tgt_types;
	int		*obj_classes;
	int		num_obj_classes;
	union {
		int 	*perms;		/* permissions */
		int 	dflt_type;	/* default type for type_trans rules */
	};
	int 		num_perms;
} au_iface_rule_key_t;

/* structure used to store a complete interface call */
typedef struct au_iface_call {
	char			*name;
	au_iface_params_t	*params;
	int			num_params;
	au_iface_rule_key_t	*keys;	/* rules that match this call */
	int			keys_sz;
} au_iface_call_t;

/* structure to store the complete rule from an interface */
typedef struct au_iface_rule {
	au_iface_rule_key_t	key;
#define AU_IFACE_SCOPE_COND	1
#define AU_IFACE_SCOPE_OPTIONAL	2
#define AU_IFACE_SCOPE_IFELSE	4
	unsigned char 	scope;		/* was this rule in a conditional, optional, or ifelse block */
	cond_expr_t	*cond_exp;	/* the conditional expresion */
	int		param_num; 	/* the parameter number for ifelse */
} au_iface_rule_t;

/* structure to store an interface */
typedef struct au_iface {
	char 			*name;
	au_iface_rule_t 	*rules;	/* rules in this interface */
	au_iface_params_t 	*params;/* parameter to this interface */
	int 			*interface_calls;	/* calls to other interfaces stored by indx in the graph*/
	int 			num_interface_calls;
	int 			num_rules;
	int 			num_params;
} au_iface_t;

// TODO: complete this graph struct
typedef struct au_iface_graph {
	au_iface_t *interfaces;
	int num_interfaces;
	// TODO: hash function goes here
} au_iface_graph_t;

au_iface_graph_t *au_iface_graph_create();
void au_iface_graph_destroy(au_iface_graph_t *graph);

/* au_iface_graph_init()
 * 
 * Call this function with the location of the reference policy directory.
 * The function will build the interface graph.
 *
 * -1: invalid policy source directory
 * -2: failed to build interfaces file
 * -3: parse error in interfaces file
 */
int au_iface_graph_init(const char *ref_pol_src_dir);

/* au_iface_graph_get_valid_iface_calls()
 *
 * Call this function to get all the valid interface calls in the graph
 * for the rule keys. */
int au_iface_graph_get_valid_iface_calls(au_iface_graph_t *graph, au_iface_rule_key_t *keys, 
					 int keys_sz, au_iface_calls_t **calls, int *calls_sz);

/* au_rank_iface_calls()
 * 
 * Call this function to sort the interface calls by order of how well
 * they solve their rule keys. This is basically the 
 * degree to which the calls are good for the user.  
 * TODO: what order ascending/decending? */
int au_rank_iface_calls(au_iface_call_t *calls, int calls_sz);

#define AU_REFPOL_H
