 /* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* render.c */

/* Utility functions to render aspects of a policy into strings */

/* TODO: Need to add all rule rendering functions below, and change the
 * TCL interface (and any other) to use these rather than do their own
 * thing.
 */
 

#include "util.h"
#include "policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* global with rule names */
char *rulenames[] = {"allow", "auditallow", "auditdeny", "dontaudit", "neverallow", "type_transition", 
			"type_member", "type_change", "clone", "allow", "role_transition", "user"};
 /* classes and perm strings */
static int re_append_cls_perms(ta_item_t *list, 
				bool_t iscls,		/* 1 if list is classes, 0 if not (i.e., permissions) */
				unsigned char flags, 	/* from av_item_t object */
				char **buf,
				int *buf_sz,
				policy_t *policy)
{
	ta_item_t *ptr;
	int multiple = 0;

	if(flags & (!iscls ? AVFLAG_PERM_TILDA : AVFLAG_NONE)) {
		if(append_str(buf, buf_sz, " ~") != 0)
			return -1;
		}
	else {
		if(append_str(buf, buf_sz, " ") != 0 )
			return -1;
	}
	if(list != NULL && list->next != NULL) {
		multiple = 1;
		if(append_str(buf, buf_sz, "{ ") != 0) 
			return -1;
	}
	if(flags & (!iscls ? AVFLAG_PERM_STAR : AVFLAG_NONE))
		if(append_str(buf, buf_sz, "* ") != 0)
			return -1;
		
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		assert( (iscls && ptr->type == IDX_OBJ_CLASS) || (!iscls && ptr->type == IDX_PERM) );
		if(iscls) {
			if(append_str(buf, buf_sz, policy->obj_classes[ptr->idx].name) != 0)
				return -1;
		}
		else {
			if(append_str(buf, buf_sz, policy->perms[ptr->idx]) != 0)
				return -1;
		}
		if(append_str(buf, buf_sz, " ") != 0)
			return -1;
	}
	
	if(multiple) {
		if(append_str(buf, buf_sz, "}") != 0)
			return -1;
	}
	return 0;	
}
 
static int append_type_attrib(char **buf, int *buf_sz, ta_item_t *tptr, policy_t *policy)
{
	if (append_str(buf, buf_sz, " ") != 0)  {
		free(buf);
		return -1;
	}
	if ((tptr->type & IDX_SUBTRACT)) {
		if (append_str(buf, buf_sz, "-") != 0)  {
			free(buf);
			return -1;
		}
	}
	if ((tptr->type & IDX_TYPE)) {
		if (append_str(buf, buf_sz, policy->types[tptr->idx].name) != 0)  {
			free(buf);
			return -1;
		}
	} else if(tptr->type & IDX_ATTRIB) {
		if (append_str(buf, buf_sz,  policy->attribs[tptr->idx].name) != 0)  {
			free(buf);
			return -1;
		}
	} else {
		free(buf);
		return -1;
	}
	return 0;
}
 
/* return NULL for error, mallocs memory, caller must free */
char *re_render_av_rule(bool_t 	addlineno, 	/* add policy.conf line  */
			int	idx, 		/* rule idx */
			bool_t is_au,		/* whether audit rules */
			policy_t *policy
			) 
{
	av_item_t *rule;
	ta_item_t *tptr;
	char *buf;
	int buf_sz;	
	int multiple = 0;
	char tbuf[APOL_STR_SZ+64];

	if(policy == NULL || !is_valid_av_rule_idx(idx, (is_au ? 0:1), policy)) {
		return NULL;
	}
	if(!is_au) 
		rule = &(policy->av_access[idx]);
	else
		rule = &(policy->av_audit[idx]);
	
	
	/* remember to init the buffer */
	buf = NULL;
	buf_sz = 0;
	
	if(addlineno) {
		sprintf(tbuf, "[%7lu] ", rule->lineno);
		if(append_str(&buf, &buf_sz, tbuf) != 0) {
			free(buf);
			return NULL;
		}
	}
		
	if(append_str(&buf, &buf_sz, rulenames[rule->type]) != 0) {
		return NULL;
	}
	
	/* source types */
	if(rule->flags & AVFLAG_SRC_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->src_types != NULL && rule->src_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->src_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	
	/* tgt types */
	if(rule->flags & AVFLAG_TGT_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
				
	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	if(append_str(&buf, &buf_sz, " :") != 0) {
		free(buf);
		return NULL;
	}
	
	/* classes */
	if(re_append_cls_perms(rule->classes, 1, rule->flags, &buf, &buf_sz, policy) != 0) {
		free(buf);
		return NULL;
	}
		
	/* permissions */
	if(re_append_cls_perms(rule->perms, 0, rule->flags, &buf, &buf_sz, policy)!= 0) {
		free(buf);
		return NULL;
	}

	if(append_str(&buf, &buf_sz, ";") != 0) {
		free(buf);
		return NULL;
	}
		
	return buf;
}

/* return NULL for error, mallocs memory, caller must free */
char *re_render_tt_rule(bool_t addlineno, int idx, policy_t *policy) 
{
	tt_item_t *rule;
	ta_item_t *tptr;
	char *buf;
	int buf_sz;	
	int multiple = 0;
	char tbuf[APOL_STR_SZ+64];
	
	if(policy == NULL || !is_valid_tt_rule_idx(idx,  policy)) {
		return NULL;
	}
	
	/* remember to init the buffer */
	buf = NULL;
	buf_sz = 0;
	rule = &(policy->te_trans[idx]);

	if(addlineno) {
		sprintf(tbuf, "[%7lu] ", rule->lineno);
		if(append_str(&buf, &buf_sz, tbuf) != 0) {
			free(buf);
			return NULL;
		}
	}

	if(append_str(&buf, &buf_sz, rulenames[rule->type]) != 0) {
		free(buf);
		return NULL;
	}

	/* source types */
	if(rule->flags & AVFLAG_SRC_TILDA)  {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
					
	if(rule->src_types != NULL && rule->src_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;		
		}
	}
	if(rule->flags & AVFLAG_SRC_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->src_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}

	/* tgt types */
	if(rule->flags & AVFLAG_TGT_TILDA) {
		if(append_str(&buf, &buf_sz, " ~") != 0) {
			free(buf);
			return NULL;
		}
	}
	else {
		if(append_str(&buf, &buf_sz, " ") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->tgt_types != NULL && rule->tgt_types->next != NULL) {
		multiple = 1;
		if(append_str(&buf, &buf_sz, "{") != 0) {
			free(buf);
			return NULL;
		}
	}
	if(rule->flags & AVFLAG_TGT_STAR)
		if(append_str(&buf, &buf_sz, "*") != 0) {
			free(buf);
			return NULL;
		}
	
	for(tptr = rule->tgt_types; tptr != NULL; tptr = tptr->next) {
		if (append_type_attrib(&buf, &buf_sz, tptr, policy) == -1)
			return NULL;
	}
	if(multiple) {
		if(append_str(&buf, &buf_sz, " }") != 0) {
			free(buf);
			return NULL;
		}
		multiple = 0;
	}
	if(append_str(&buf, &buf_sz, " :") != 0) {
		free(buf);
		return NULL;
	}
			
	/* classes */
	if(re_append_cls_perms(rule->classes, 1, rule->flags, &buf, &buf_sz, policy) != 0) {
		free(buf);
		return NULL;
	}
		
	/* default type */
	if(rule->dflt_type.type == IDX_TYPE) {
		sprintf(tbuf, " %s", policy->types[rule->dflt_type.idx].name);
	}
	else if(rule->dflt_type.type == IDX_ATTRIB) {
		sprintf(tbuf, " %s", policy->attribs[rule->dflt_type.idx].name);
	}			
	else {
		fprintf(stderr, "Invalid index type: %d\n", rule->dflt_type.type);
		free(buf);
		return NULL;
	}	
	if(append_str(&buf, &buf_sz, tbuf) != 0) {
		free(buf);
		return NULL;
	}
	
	if(append_str(&buf, &buf_sz, ";") != 0) {
		free(buf);
		return NULL;
	}
		

	return buf;	

}

/* security contexts */
char *re_render_security_context(const security_con_t *context,
				 policy_t *policy
				 )
{
	char *buf, *name;
	int buf_sz;
	if(policy == NULL )
		return NULL;
	
	if(context != NULL && (!is_valid_type_idx(context->type, policy) || !is_valid_role_idx(context->role, policy) || 
			!is_valid_user_idx(context->user, policy)) )
		return NULL;

	/* initialize the buffer */
	buf = NULL;
	buf_sz = 0;

	/* handle case where initial SID does not have a context */
	if(context == NULL) {
		if(append_str(&buf, &buf_sz, "<no context>") != 0) 
			goto err_return;
		return buf;
	}

	/* render context */
	if(get_user_name2(context->user, &name, policy) != 0)
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);
	if(append_str(&buf, &buf_sz, ":") != 0) 
		goto err_return;
	if(get_role_name(context->role, &name, policy) != 0) 
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);
	if(append_str(&buf, &buf_sz, ":") != 0) 
		goto err_return;
	if(get_type_name(context->type, &name, policy) != 0) 
		goto err_return;
	if(append_str(&buf, &buf_sz, name) != 0) 
		goto err_return;
	free(name);	
	
	return buf;
err_return:
	if(buf != NULL) 
		free(buf);
	return NULL;	
}


char * re_render_initial_sid_security_context(int idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_initial_sid_idx(idx, policy) ) {
		return NULL;
	}
	return(re_render_security_context(policy->initial_sids[idx].scontext, policy));
}
