/* Copyright (C) 2001-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

%{

//includes
#include <stdio.h>
#include "queue.h"
#include "policy.h"
#include "refpol.h"
#include "cond.h"

//globals
queue_t id_queue = NULL;
policy_t *policy = NULL;
au_iface_graph_t *graph = NULL;
au_iface_t *curr_iface = NULL;
au_iface_rule_ *tmp_rules = NULL;
int tmp_rules_sz = 0;
unsigned char curr_scope = AU_IFACE_SCOPE_UNCOND;

extern char yytext[];
extern int yywarn(char *msg);
extern int yyerror(char *msg);
static char errormsg[255];

//internal structs

//function prototypes
static int define_interface(void);
static int add_iface_call(void);
static int add_conditional(cond_expr_t *expr, bool_t has_else_clause);
static int add_role_def(void);
static int add_bool_def(void);
static int add_optional(bool_t has_else_clause);
static int add_m4_ifelse(bool_t keep);
static int add_special_nested_line(void);
static int add_te_rule(unsigned int rule_type);
static int insert_separator(void);
static int insert_id(char *id);

%}

%union {
	int sval;
	unsigned int val;
	void *ptr;
}

//%type statements

//%token statements

//%left and %right

%%

interfaces		: interface_def
			| interfaces interface_def
			;
interface_def		: INTERFACE  '(' identifier ',' if_contents ')'
			{ if (define_interface($3)) return -1;}
			;
if_contents		: if_element
			| if_contents if_element
			;
if_element		: if_call
			| conditional
			| te_rules
			| role_def
			| bool_def
			| optional_stmnt
			| ifelse
			;
if_call			: identifier '(' id_comma_list ')'
			{if (add_iface_call()) return -1;}
			;
conditional		: IF '(' cond_expr ')' '{' te_if_lines '}'
			{if (add_conditional($3, 0)) return -1;}
			| IF '(' cond_expr ')' '{' te_if_lines '}' ELSE '{' te_if_lines '}'
			{if (add_conditional($3, 1)) return -1;}
			;
te_if_lines		: te_if_line_def
			| te_if_lines te_if_line_def
			;
te_rules		: te_rule_def
			| te_rules te_rule_def
			;
role_def		: ROLE identifier TYPES names ';'
			{ if (add_role_def()) return -1;}
			;
bool_def		: BOOL identifier bool_val
			{ if (add_bool_def()) return -1;}
			;
bool_val		: CTRUE
			{ if (insert_id("T")) return -1; }
			| CFALSE
			{ if (insert_id("F")) return -1; }
			;
optional_stmnt		: OPTIONAL '{' opt_lines '}'
			{ if (add_optional(0)) return -1;}
			| OPTIONAL '{' opt_lines '}' ELSE '{' opt_lines '}'
			{ if (add_optional(1)) return -1;}
			;
ifelse			: IFELSE '(' identifier ',' ',' m4_if_lines ',' m4_if_lines ')'
			{ if (add_m4_ifelse(1)) return -1;}
			: IFELSE '(' ',' m4_if_lines ',' m4_if_lines ')'
			{ /* throw out */ if (add_m4_ifelse(0)) return -1;}
			;
opt_lines		: opt_line_def
			| opt_lines opt_line_def
			;
opt_line_def		: ifelse
			| te_rule_def
			| if_call
			| conditional
			;
m4_if_lines		: m4_if_lines m4_if_line_def
			| /* empty */
			;
m4_line_def		: ifelse
			| te_rule_def
			| role_def
			| bool_def
			| conditional
			| optional_stmnt
			| if_call
			| nested_special
			;
nested_special		: '}' ELSE '{'
			{ if (add_special_nested_line()) return -1;}
			;
te_if_line_def		: te_rule_def
			| ifelse
			| if_call
			;
te_rule_def		: ALLOW names names ':' names names ';'
			{ if (add_te_rule(AU_RULE_ALLOW)) return -1;}
			| AUDITALLOW names names ':' names names ';'
			{ if (add_te_rule(AU_RULE_AUDITALLOW)) return -1;}
			| DONTAUDIT names names ':' names names ';'
			{ if (add_te_rule(AU_RULE_DONTAUDIT)) return -1;}
			| TYPE_TRANSITION names names ':' names identifier ';'
			{ if (add_te_rule(AU_RULE_TYPETRANS)) return -1;}
			| TYPE_CHANGE names names ':' names identifier ';'
			{ if (add_te_rule(AU_RULE_TYPECHG)) return -1;}
			| TYPE_MEMBER names names ':' names identifier ';'
			{ if (add_te_rule(AU_RULE_TYPEMBR)) return -1;}
			| TYPEATTRIBUTE identifier id_comma_list ';'
			{ if (add_te_rule(AU_RULE_TYPEATTRIB)) return -1;}
			| TYPEALIAS identifier ALIAS names ';'
			{ if (add_te_rule(AU_RULE_TYPEALIAS)) return -1;}
			;
id_comma_list		: identifier
			| id_comma_list ',' identifier
			;
names			: identifier
			{ if (insert_separator()) return -1; }
			| nested_id_set
			{ if (insert_separator()) return -1; }
			| asterisk
			{ if (insert_id("*")) return -1; 
			  if (insert_separator()) return -1; }
			| tilde identifier
			{ if (insert_id("~")) return -1;
			  if (insert_separator()) return -1; }
			| identifier exclude { if (insert_id("-")) return -1; } identifier
			{ if (insert_separator()) return -1; }
			| tilde nested_id_set
			{ if (insert_id("~")) return -1; 
			  if (insert_separator()) return -1; }
			;
nested_id_set		: '{' nested_id_list '}'
			;
nested_id_list		: nested_id_element | nested_id_list nested_id_element
			;
nested_id_element	: identifier 
			| '-' { if (insert_id("-")) return -1; } identifier 
			| nested_id_set 
			;
identifier		: IDENTIFIER
			{ if (insert_id(yytext)) return -1; }
			;
%%

//funtion implementation

static int set_scope(unsigned char scope)
{
	//if scope == COND
		//if cur & COND
			//error
		//else
			//cur |= COND
	//else if scope == OPT
		//if cur & COND
			//error
		//else
			//cur |= OPT
	//else if scope == IFELSE
		//cur |= ifelse
	//else
		//error
}

static int define_interface(void)
{
	//set curr_iface to idx of name or
	//curr_iface = new interface
	//save name
	//save tmp rules
	//reset tmp rules
}

static int add_iface_call(void)
{
	//create new iface_call struce
	//get iface idx of name (or create place holder)
	//set up params (optional or not, type of value)
	//for each param set value
}

static int add_conditional(cond_expr_t *expr, bool_t has_else_clause)
{
	//save expr 
	//set rules exprs and list values
}

static int add_role_def(void)
{
	//create rule key
	//set type to role def
	//role name as src
	//types as tgt
	//create new rule
}

static int add_bool_def(void)
{
	//create new key
	//set type to bool def
	//save key
	//set which list to default of bool
}

static int add_optional(bool_t has_else_clause)
{
	//set scope + optional
}

static int add_m4_ifelse(bool_t keep)
{
	//set scope + ifelse
}

static int add_special_nested_line(void)
{

}

static int add_te_rule(unsigned int rule_type)
{

}

static int insert_separator(void)
{

}

static int insert_id(char *id)
{

}

