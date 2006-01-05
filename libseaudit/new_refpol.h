/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Kevin Carr <kcarr@tresys.com>
 *         Jeremy Mowery <jmowery@tresys.com>
 *
 * Date: January 5, 2006
 * 
 */

/* symbol type definitions */
#define RP_SYM_UNKNWN	0		/* unknown or uninitialized */
#define RP_SYM_TYPE	1		/* types/attributes namespace */
#define RP_SYM_ROLE	2		/* roles namespace */
#define RP_SYM_OBJ	3		/* object classes namespace */
#define RP_SYM_PERM	4		/* permissions namespace */
#define RP_SYM_BOOL	5		/* booleans namespace */
#define RP_SYM_PARAM	6		/* M4 $x parameter */
#define RP_SYM_STR	7		/* flat string (use sym.str) */
#define RP_SYM_MAX	7		/* maximum value of symbol type */
typedef struct rp_symbol {
	union {
		int	idx;		/* index of symbol in symbol table */
		char	*str;		/* string; type will be RP_SYM_STR */
	};
	unsigned char	type;		/* type of symbol; i.e. which table */
} rp_symbol_t;

typedef struct rp_param {
	rp_symbol_t	value;		/* value of the parameter */
	unsigned char	optional;	/* is this an optional parameter */
} rp_param_t;

/* use cond type definitions for scope type */
typedef struct rp_scope {
	unsigned char	type;		/* type of conditional container */
	int		idx;		/* index of container */
	unsigned char	side;		/* which side (true/false) */
	struct rp_scope *next;		/* next; i.e. container's container */
} rp_scope_t;

typedef struct rp_ifacecall {
	int		idx;		/* index of interface called */
	rp_param_t	*params;	/* list of params w/ values */
	int		num_params;	/* size of above array */
	rp_scope_t	*scope;		/* scope of this call */
} rp_ifacecall_t;

#define RP_RULE_UNKNWN		 0	/* unknown or uninitialized */
#define RP_RULE_ALLOW		 1	/* allow rule */
#define RP_RULE_AUDITALLOW	 2	/* auditallow rule */
#define RP_RULE_DONTAUDIT	 3	/* dontaudit rule */
#define RP_RULE_TYPETRANS	 4	/* type_transition rule */
#define RP_RULE_TYPEMEMBER	 5	/* type_member rule */
#define RP_RULE_TYPECHANGE	 6	/* type_change rule */
#define RP_RULE_ROLEALLOW	 7	/* role allow rule */
#define RP_RULE_ROLETYPE	 8	/* role type assignment */
#define RP_RULE_TYPEATTRIB	 9	/* type_attribute statement */
#define RP_RULE_TYPEALIAS	10	/* type_alias statement */
#define RP_RULE_MAX		10	/* maximum rule type value */
typedef struct rp_rule {
	unsigned char	type;		/* type of rule */
	rp_symbol_t	*srcs;		/* source/1st field */
	int		num_srcs;	/* size of above array */
	rp_symbol_t	*tgts;		/* target/2nd field */
	int		num_tgts;	/* size of above array */
	rp_symbol_t	*objs;		/* object classes */
	int		num_objs;	/* size of above array */
	rp_symbol_t	*perms;		/* permissions/3rd field */
	int		num_perms;	/* size of above array */
	rp_scope_t	*scope;		/* scope of this rule */
} rp_rule_t;

#define RP_EXPR_UNKNWN	0		/* unknown or uninitialized */
#define RP_EXPR_SYM	1		/* symbol */
#define RP_EXPR_NOT	2		/* !symbol */
#define RP_EXPR_OR	3		/* symbol || symbol */
#define RP_EXPR_AND	4		/* symbol && symbol */
#define RP_EXPR_XOR	5		/* symbol ^ symbol */
#define RP_EXPR_EQ	6		/* symbol == symbol */
#define RP_EXPR_NEQ	7		/* symbol != symbol */
#define RP_EXPR_MAX	7		/* maximum value of expression type */
typedef struct rp_cond_expr {
	unsigned char	type;		/* type of expression; i.e. operator */
	rp_symbol_t	symbol;		/* symbol used in this part of expr */
	struct rp_cond_expr *next;	/* next pointer */
} rp_cond_expr_t;

/* conditional type definitions */
#define RP_COND_UNKNWN	0		/* unknown or uninitialized */
#define RP_COND_TECOND	1		/* te conditional policy */
#define RP_COND_TUNABL	2		/* tunable policy */
#define RP_COND_OPT	3		/* optional policy */
#define RP_COND_IFDEF	4		/* m4 ifdef statement */
#define RP_COND_IFELSE	5		/* m4 ifelse statement */
#define RP_COND_MAX	5		/* maximum value of cond type */
typedef struct rp_cond {
	rp_cond_expr_t	*expr;		/* expression (NULL if not used) */
	unsigned char	type;		/* type of conditional statement */
	rp_scope_t	*scope;		/* scope of this conditional */
} rp_cond_t;

typedef struct rp_interface {
	char		*name;		/* name of the interface */
	char		*mod_name;	/* module containing this interface */
	rp_param_t	*params;	/* parameters for this interface */
	int		num_params;	/* size of above array */
	rp_ifacecall_t	*ifcalls;	/* other interfaces this one calls */
	int		num_ifcalls;	/* size of above array */
	rp_rule_t	*rules;		/* rules in this interface */
	int		num_rules;	/* size of above array */
	rp_cond_t	*te_conds;	/* te conditionals in the interface */
	int		num_te_conds;	/* size of above array */
	rp_cond_t	*optionals;	/* optional blocks */
	int		num_optionals;	/* size of above array */
	rp_cond_t	*tunables;	/* tunable policy blocks */
	int		num_tunables;	/* size of above array */
	rp_cond_t	*m4_ifdefs;	/* M4 ifdef statements */
	int		num_m4_ifdefs;	/* size of above array */
	rp_cond_t	*m4_ifelses;	/* M4 ifesle statements */
	int		num_m4_ifelses;	/* size of above array */
} rp_interface_t;

typedef struct rp_symtab_entry {
	char		*name;		/* name of the symbol */
	int		*expansions;	/* list of symbols to expand to */
	int		num_expansions;	/* size of above array */
} rp_symtab_entry_t;

typedef struct rp_symtab {
	//TODO
} rp_symtab_t;

typedef struct rp_iface_table {
	rp_interface_t	*ifaces;	/* list of interfaces */
	int		num_ifaces;	/* size of above array */
	rp_symtab_t	*symtab;	/* symbol table */
} rp_iface_table_t;

