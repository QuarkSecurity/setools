/* Copyright (C) 2001-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

%{
#include "y.tab.h"
int yyerror(char *msg);
int yywarn(char *msg);
#define YY_NO_UNPUT
%}
%array
letter  [A-Za-z]
digit   [0-9]
hexval	[0-9A-Fa-f]
%%
role		|
ROLE		{return(ROLE);}
types		|
TYPES		{return(TYPES);}
interface	|
INTERFACE	{return(INTERFACE);}
if		|
IF		{return(IF);}
else		|
ELSE		{return(ELSE);}
bool		|
BOOL		{return(BOOL);}
true		|
TRUE		{return(CTRUE);}
false		|
FALSE		{return(CFALSE);}
optional	|
OPTIONAL	{return(OPTIONAL);}
ifelse		|
IFELSE		{return(IFELSE);}
allow		|
ALLOW		{return(ALLOW);}
auditallow	|
AUDITALLOW	{return(AUDITALLOW);}
dontaudit	|
DONTAUDIT	{return(DONTAUDIT);}
type_transition	|
TYPE_TRANSITION	{return(TYPE_TRANSITION);}
type_change	|
TYPE_CHANGE	{return(TYPE_CHANGE);}
type_member	|
TYPE_MEMBER	{return(TYPE_MEMBER);}
typeattribute	|
TYPEATTRIBUTE	{return(TYPEATTRIBUTE);}
typealias	|
TYPEALIAS	{return(TYPEALIAS);}
alias		|
ALIAS		{return(ALIAS);}
{letter}({letter}|{digit}|_|".")*("*")?	{return(IDENTIFIER);}
\${number}({number})*	{return(DOLLAR_PARAM);}
[ \t\f]+	{ /* delete whitespace */ }
\n		{ /* delete whitespace */ }
"=="		{return(EQUALS); }
"!="		{ return (NOTEQUAL); }
"&&"		{ return (AND); }
"||"		{ return (OR); }
"!"		{ return (NOT); }
"^"		{ return (XOR); }
","		|
":"		|
";"		|
"("		|
")"		|
"{"		|
"}"		|
"["		|
"-"		|
"."		|
"]"		|
"~"		|
"*" 		{ return(yytext[0]); } 
.		{ yywarn("unrecognized character");}
%%
int yyerror(char *msg)
{
	fprintf(stderr, "Error parsing interfaces: %s\n", msg);
	return -1;
}

int yywarn(char *msg)
{
	fprintf(stderr, "Warning parsing interfaces: %s\n", msg);
	return 0;
}
