/* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* Test program for libapol
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include <assert.h>
#include <regex.h>
/* apol lib */
#include "../policy.h"
#include "../util.h"
#include "../analysis.h"
#include "../render.h"
#include "../perm-map.h"
#include "../policy-io.h"
#include "../policy-query.h"
#include "../infoflow.h"

FILE *outfile;
char *policy_file = NULL;


static int display_policy_stats(policy_t *p)
{
	if(p == NULL) {
		printf("\nERROR: No policy provided\n");
		return -1;
	}
	printf("\nCurrent policy Statics");
	if(is_binary_policy(p) )
		printf(" (binary):\n");
	else
		printf(" (.conf):\n");
	printf("     Classes:            %d\n", p->num_obj_classes);
	printf("     Permissions:        %d\n", p->num_perms);
	printf("     Initial Sids:       %d\n", p->num_initial_sids);
	printf("     Users:              %d\n", p->rule_cnt[RULE_USER]);
	printf("     Attributes:         %d\n", p->num_attribs);
	printf("     Types:              %d\n", p->num_types);
	printf("     Type Aliases:       %d\n", p->num_aliases);
	printf("     AV Rules:           %d\n", p->num_av_access);
	printf("     Audit Rules:        %d\n", p->num_av_audit);
	printf("     Type Rules:         %d\n", p->num_te_trans);
	printf("     Roles:              %d\n", p->num_roles);
	printf("     Role Rules:         %d\n", (p->num_role_allow + p->num_role_trans));
	printf("     Booleans            %d\n", p->num_cond_bools);
	return 0;
}

static int types_relation_get_dta_options(dta_query_t *dta_query, policy_t *policy)
{
	char ans[1024];
	int obj, type, i, j, num_perms, *perms = NULL;
	
	printf("\tSearch for ALL object classes and permissions (y/n)? ");
	fgets(ans, sizeof(ans), stdin);
	if (ans[0] == 'n' || ans[0] == 'N') {		
		while (1) {
			int object;
			
			printf("\tAdd object class or f to finish: ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans)-1] = '\0';
			if (strlen(ans) == 1 && ans[0] == 'f')
				break;
			object = get_obj_class_idx(ans, policy);
			if (object < 0) {
				fprintf(stderr, "Invalid object class\n");
				continue;
			} 
			if (dta_query_add_obj_class(dta_query, object) == -1) {
				fprintf(stderr, "error adding obj\n");
				return -1;
			}
																		
			printf("\tLimit specific permissions (y/n)? ");
			fgets(ans, sizeof(ans), stdin);
			if (ans[0] == 'y' || ans[0] == 'Y') {
				while (1) {
					int perm;
					printf("\tAdd object class permission or f to finish: ");
					fgets(ans, sizeof(ans), stdin);
					ans[strlen(ans)-1] = '\0';
					if (strlen(ans) == 1 && ans[0] == 'f') {
						break;
					}
					perm = get_perm_idx(ans, policy);
					if (perm < 0 || !is_valid_perm_for_obj_class(policy, object, perm)) {
						fprintf(stderr, "Invalid object class permission\n");
						continue;
					}
					if (dta_query_add_obj_class_perm(dta_query, object, perm) == -1) {
						fprintf(stderr, "error adding perm to query\n");
						return -1;
					}
				}
			}
		}
	} else {
		for (i = 0; i < policy->num_obj_classes; i++) {
			obj = get_obj_class_idx(policy->obj_classes[i].name, policy);
			if (obj < 0) {
				fprintf(stderr, "Invalid object class\n");
				continue;
			}
			if (get_obj_class_perms(obj, &num_perms, &perms, policy) == -1) {
				fprintf(stderr, "Error getting class perms.");
				return -1;	
			}
			for (j = 0; j < num_perms; j++) {
				if (dta_query_add_obj_class_perm(dta_query, obj, perms[j]) == -1) {
					fprintf(stderr, "error adding perm to query\n");
					return -1;
				}	
			}
			free(perms);
		}
	}
	printf("\tSearch for ALL object types (y/n)? ");
	fgets(ans, sizeof(ans), stdin);
	if (ans[0] == 'n' || ans[0] == 'N') {		
		while (1) {
			printf("\tAdd object type or f to finish: ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans)-1] = '\0';
			if (strlen(ans) == 1 && ans[0] == 'f')
				break;
			type = get_type_idx(ans, policy);
			if (type < 0) {
				fprintf(stderr, "invalid type\n");
				continue;
			} 
			if (dta_query_add_end_type(dta_query, type) != 0) {
				fprintf(stderr, "Memory error!\n");
				return -1;
			}
		}
	} else {
		for (i = 0; i < policy->num_types; i++) {
			type = get_type_idx(policy->types[i].name, policy);
			if (type < 0) {
				/* This is an invalid ending type, so ignore */
				continue;
			}
			if (dta_query_add_end_type(dta_query, type) != 0) {
				fprintf(stderr, "Memory error!\n");
				break;
			}
		}
	}
	return 0;
}

static int types_relation_get_dirflow_options(iflow_query_t *direct_flow_query, policy_t *policy)
{
	char ans[1024];
	unsigned int m_ret;
	FILE* pfp;
	int object;
	
	while (1) {	
		printf("\tAdd object class or f to finish: ");
		fgets(ans, sizeof(ans), stdin);
		ans[strlen(ans)-1] = '\0';
		if (strlen(ans) == 1 && ans[0] == 'f')
			break;
		object = get_obj_class_idx(ans, policy);
		if (object < 0) {
			fprintf(stderr, "Invalid object class\n");
			continue;
		}
		printf("\tLimit specific permissions (y/n)? ");
		fgets(ans, sizeof(ans), stdin);
		if (ans[0] == 'y' || ans[0] == 'Y') {
			while (1) {
				int perm;
				printf("\tAdd object class permission or f to finish: ");
				fgets(ans, sizeof(ans), stdin);
				ans[strlen(ans)-1] = '\0';
				if (strlen(ans) == 1 && ans[0] == 'f')
					break;
				perm = get_perm_idx(ans, policy);
				if (perm < 0 || !is_valid_perm_for_obj_class(policy, object, perm)) {
					fprintf(stderr, "Invalid object class permission\n");
					continue;
				}
				if (iflow_query_add_obj_class_perm(direct_flow_query, 
								   object, perm) != 0) {
					fprintf(stderr, "error adding perm\n");
					return -1;
				}
			}
		} else {
			if (iflow_query_add_obj_class(direct_flow_query, object) == -1) {
				fprintf(stderr, "error adding object class\n");
				return -1;
			}
		}
	}

	printf("\tPermission map file: ");
	fgets(ans, sizeof(ans), stdin);
	ans[strlen(ans)-1] = '\0';
	pfp = fopen(ans, "r");
	if(pfp == NULL) {
		fprintf(stderr, "Cannot open perm map file %s\n", ans);
		return -1;
	}
	m_ret = load_policy_perm_mappings(policy, pfp);
	if(m_ret & PERMMAP_RET_ERROR) {
		fprintf(stderr, "ERROR loading perm mappings from file: %s\n", ans);
		return -1;
	} 
	else if(m_ret & PERMMAP_RET_WARNINGS) {
		printf("There were warnings:\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_PERM) 
			printf("     Some permissions were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_OBJ)
			printf("     Some objects were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_PERM)
			printf("     Map contains unknown permissions, or permission assoicated with wrong objects.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_OBJ)
			printf("     Map contains unknown objects\n");
		if(m_ret & PERMMAP_RET_OBJ_REMMAPPED) 
			printf("     Some permissions were mapped more than once.\n");
	}
	fclose(pfp);
	printf("\n\tPermission map was loaded.....\n\n");
	return 0;
}

static int types_relation_get_transflow_options(iflow_query_t *trans_flow_query, policy_t *policy)
{
	char ans[1024];
	int type;
	
	while (1) {
		printf("\tAdd intermediate type or f to finish: ");
		fgets(ans, sizeof(ans), stdin);
		ans[strlen(ans)-1] = '\0';
		if (strlen(ans) == 1 && ans[0] == 'f')
			break;
		type = get_type_idx(ans, policy);
		if (type < 0) {
			fprintf(stderr, "Invalid ending type\n");
			continue;
		}
		if (iflow_query_add_type(trans_flow_query, type) != 0)
			return -1;
	}
	/* Use the direct flow function for setting object class/permission and perm map parameters */
	if (types_relation_get_dirflow_options(trans_flow_query, policy) != 0) {
		return -1;
	}
	return 0;
}

static int get_type_relation_options(types_relation_query_t **tr_query, policy_t *policy)
{
	char ans[1024];
	bool_t finish = FALSE;
	
	assert(tr_query != NULL && *tr_query != NULL && policy != NULL);
	printf("\n\tSelection load option:\n");
	printf("\t     0)  Common attributes\n");
	printf("\t     1)  Common roles\n");
	printf("\t     2)  Common users\n");
	printf("\t     3)  Domain transitions\n");
	printf("\t     4)  Direct flows\n");
	printf("\t     5)  Transitive flows\n");
	printf("\t     6)  Additional type transitions\n");
	printf("\t     7)  Common object type access\n");
	printf("\t     8)  Process interactions\n");
	printf("\t     9)  Unique access\n");
	printf("\tPress \'o\' to see options\n\n");
	while (1) {
		printf("\tEnter option (\'s\' to start analysis):  ");
		fgets(ans, sizeof(ans), stdin);	
		switch(ans[0]) {
		case '0':
			(*tr_query)->options |= TYPES_REL_COMMON_ATTRIBS;
			break;
		case '1':
			(*tr_query)->options |= TYPES_REL_COMMON_ROLES;
			break;
		case '2':
			(*tr_query)->options |= TYPES_REL_COMMON_USERS;
			break;
		case '3':			
			(*tr_query)->options |= TYPES_REL_DOMAINTRANS;
			/* Create the query structure */
			if (!(*tr_query)->dta_query) {
				(*tr_query)->dta_query = dta_query_create();
				if ((*tr_query)->dta_query == NULL) {
					fprintf(stderr, "Memory error allocating dta query.\n");
					return -1;
				}
			}
			if (types_relation_get_dta_options((*tr_query)->dta_query, policy) != 0) {
				return -1;
			}
			break;
		case '4':
			(*tr_query)->options |= TYPES_REL_DIRFLOWS;
			/* Create the query structure */
			if (!(*tr_query)->direct_flow_query) {
				(*tr_query)->direct_flow_query = iflow_query_create();
				if ((*tr_query)->direct_flow_query == NULL) {
					fprintf(stderr, "Memory error allocating direct iflow query.\n");
					return -1;
				}
			}
			if (types_relation_get_dirflow_options((*tr_query)->direct_flow_query, policy) != 0) {
				return -1;
			}
			break;
		case '5':
			(*tr_query)->options |= TYPES_REL_TRANSFLOWS;
			/* Create the query structure */
			if (!(*tr_query)->trans_flow_query) {
				(*tr_query)->trans_flow_query = iflow_query_create();
				if ((*tr_query)->trans_flow_query == NULL) {
					fprintf(stderr, "Memory error allocating transitive iflow query.\n");
					return -1;
				}
			}
			if (types_relation_get_transflow_options((*tr_query)->trans_flow_query, policy) != 0) {
				return -1;
			}
			break;
		case '6':
			(*tr_query)->options |= TYPES_REL_OTHER_TTRULES;
			break;
		case '7':
			(*tr_query)->options |= TYPES_REL_COMMON_ACCESS;
			break;
		case '8':
			(*tr_query)->options |= TYPES_REL_PROCESS_INTER;
			break;
		case '9':
			(*tr_query)->options |= TYPES_REL_UNIQUE_ACCESS;
			break;
		case 'o':
			printf("\n\tSelection load option:\n");
			printf("\t     0)  Common attributes\n");
			printf("\t     1)  Common roles\n");
			printf("\t     2)  Common users\n");
			printf("\t     3)  Domain transitions\n");
			printf("\t     4)  Direct flows\n");
			printf("\t     5)  Transitive flows\n");
			printf("\t     6)  Additional type transitions\n");
			printf("\t     7)  Common object type access\n");
			printf("\t     8)  Process interactions\n");
			printf("\t     9)  Unique access\n");
			printf("\tPress \'o\' to see options\n\n");
			break;
		case 's':
			finish = TRUE;
			break;
		default:
			printf("Invalid choice: %s\n", ans);
		}
		if (finish) 
			break;
	}
	return 0;
}

static int reload_with_options(policy_t **policy)
{
	char ans[81];
	unsigned int opts;
	int rt;
	
	printf("\nSelection load option:\n");
	printf("     0)  ALL of the policy\n");
	printf("     1)  Pass 1 policy only\n");
	printf("     2)  TE Policy only\n");
	printf("     3)  Types and roles only\n");
	printf("     4)  Classes and permissions only\n");
	printf("     5)  RRBAC policy\n");
	printf("     6)  Enter OPTIONS MASKS\n");
	printf("\nCommand (\'m\' for menu):  ");
	fgets(ans, sizeof(ans), stdin);	
	switch(ans[0]) {
	case '0':
		opts = POLOPT_ALL;
		break;
	case '1':
		opts = PLOPT_PASS_1;
		break;
	case '2':
		opts = POLOPT_TE_POLICY;
		break;
	case '3':
		opts = (POLOPT_TYPES|POLOPT_ROLES);
		break;
	case '4':
		opts = POLOPT_OBJECTS;
		break;
	case '5':
		opts = POLOPT_RBAC;
		break;
	case '6':
		printf("\n     Provide hex bit mask  :\n");
		fgets(ans, sizeof(ans), stdin);	
		if(sscanf(ans, "%x", &opts) != 1) {
			printf("\nInvalid bit mask\n");
			return -1;
		}
		break;
	default:
		printf("Invalid re-load choice\n");
		return -1;
	}
	printf("BEFORE mask: 0x%8x\n", opts);
	opts = validate_policy_options(opts);
	printf("AFTER  mask: 0x%8x\n", opts);
	
	free_policy(policy);
	/* policy_file is a global var */
	rt = open_partial_policy(policy_file, opts, policy);
	if(rt != 0) {
		free_policy(policy);
		fprintf(stderr, "open_policy error (%d)", rt);
		exit(1);
	}	
	
	return 0;
}


int test_print_ep(entrypoint_type_t *ep, policy_t *policy)
{
	int i;
	char *rule;
	char *file_type;
	extern FILE *outfile;
	
	if(get_type_name(ep->file_type, &file_type, policy) != 0) {
		fprintf(stderr, "\nproblem translating file_type (%d)\n", ep->file_type);
		return -1;
	}
	fprintf(outfile, "\n\t     %s (%d):\n", file_type, ep->file_type);
	free(file_type);
	
	fprintf(outfile, "\t          FILE ENTRYPOINT ACCESS RULES (%d rules):\n", ep->num_ep_rules);
	for(i = 0; i < ep->num_ep_rules; i++) {
		rule = re_render_av_rule(0,ep->ep_rules[i], 0, policy);
		if(rule == NULL) {
			fprintf(stderr, "problem rendering entrypoint rule %d\n", i);
			return -1;
		}
		fprintf(outfile, "\t          (%d) %s\n", get_rule_lineno(ep->ep_rules[i],RULE_TE_ALLOW, policy),rule);
		free(rule);
	}
	fprintf(outfile, "\n\t          FILE EXECUTE ACCESS RULES (%d rules):\n", ep->num_ex_rules);
	for(i = 0; i < ep->num_ex_rules; i++) {
		rule = re_render_av_rule(0,ep->ex_rules[i], 0, policy);
		if(rule == NULL) {
			fprintf(stderr, "problem rendering execute rule %d\n", i);
			return -1;
		}
		fprintf(outfile, "\t          (%d) %s\n",get_rule_lineno(ep->ex_rules[i],RULE_TE_ALLOW, policy), rule);
		free(rule);
	}	

	return 0;	
}
	

int test_print_trans_dom(trans_domain_t *t, policy_t *policy)
{
	int rt, i;
	char *tgt;
	char *rule;
	extern FILE *outfile;
	llist_node_t *x;
	entrypoint_type_t *ep;
	rt = get_type_name(t->trans_type, &tgt, policy);
	if(rt != 0) {
		fprintf(stderr, "\nproblem translating trans_type (%d)\n", t->trans_type);
		return -1;
	}
	fprintf(outfile, "\t%s (%d)\n", tgt, t->trans_type);
	free(tgt);	
	
	fprintf(outfile, "\t     PROCESS TRANSITION RULES (%d rules):\n", t->num_pt_rules);
	for(i = 0; i < t->num_pt_rules; i++) {
		rule = re_render_av_rule(0,t->pt_rules[i], 0, policy);
		if(rule == NULL) {
			fprintf(stderr, "\nproblem rendering transition rule %d\n", i);
			return -1;
		}
		fprintf(outfile, "\t     (%d) %s\n", get_rule_lineno(t->pt_rules[i], RULE_TE_ALLOW, policy), rule);	
		free(rule);
	}
	fprintf(outfile, "\n\t     ENTRYPOINT FILE TYPES (%d types):\n", t->entry_types->num);
	for(x = t->entry_types->head; x != NULL; x = x->next) {
		ep = (entrypoint_type_t *)x->data;
		assert(t->start_type == ep->start_type);
		assert(t->trans_type == ep->trans_type);
		if(test_print_ep(ep, policy) != 0) {
			fprintf(stderr, "\nproblem printing entrypoint file type\n");
			return -1;
		}
	}
	fprintf(outfile, "\n\t     ADDITIONAL RULES (%d rules):\n", t->num_other_rules);
	for(i = 0; i < t->num_other_rules; i++) {
		rule = re_render_av_rule(0, t->other_rules[i], 0, policy);
		if(rule == NULL) {
			fprintf(stderr, "\nproblem rendering transition rule %d\n", i);
			return -1;
		}
		fprintf(outfile, "\t     (%d) %s\n", get_rule_lineno(t->other_rules[i], RULE_TE_ALLOW, policy), rule);	
		free(rule);
	}
	
	fprintf(outfile, "\n");
	
	return 0;
}

int test_print_direct_flow_analysis(policy_t *policy, int num_answers, iflow_t *answers)
{
	int i, j, k;

	for (i = 0; i < num_answers; i++) {
		fprintf(outfile, "%d ", i);

		fprintf(outfile, "flow from %s to %s", policy->types[answers->start_type].name,
			policy->types[answers[i].end_type].name);

		if (answers[i].direction == IFLOW_BOTH)
			fprintf(outfile, " [In/Out]\n");
		else if (answers[i].direction == IFLOW_OUT)
			fprintf(outfile, " [Out]\n");
		else
			fprintf(outfile, " [In]\n");

		for (j = 0; j < answers[i].num_obj_classes; j++) {
			if (answers[i].obj_classes[j].num_rules) {
				fprintf(outfile, "%s\n", policy->obj_classes[j].name);
				for (k = 0; k < answers[i].obj_classes[j].num_rules; k++) {
					char *rule;
					rule = re_render_av_rule(TRUE, answers[i].obj_classes[j].rules[k], FALSE, policy);
					fprintf(outfile, "\t%s\n", rule);
					free(rule);
				}	
			}
		}
	}
	return 0;
}

void test_print_iflow_path(policy_t *policy, iflow_path_t *path)
{
	int i, j, k, path_num = 0;
	iflow_path_t *cur;

	for (cur = path; cur != NULL; cur = cur->next) {
		fprintf(outfile, "\tPath %d length is %d\n", path_num++, cur->num_iflows);
		for (i = 0; i < cur->num_iflows; i++) {
			fprintf(outfile, "\t%s->%s\n", policy->types[cur->iflows[i].start_type].name,
			       policy->types[cur->iflows[i].end_type].name);
			for (j = 0; j < cur->iflows[i].num_obj_classes; j++) {
				if (cur->iflows[i].obj_classes[j].num_rules) {
					fprintf(outfile, "\t\tobject class %s\n", policy->obj_classes[j].name);
					for (k = 0; k < cur->iflows[i].obj_classes[j].num_rules; k++) {
						char *rule;
						rule = re_render_av_rule(TRUE, cur->iflows[i].obj_classes[j].rules[k], FALSE,
									 policy);
						fprintf(outfile, "\t\t\t%s\n", rule);
						free(rule);
					}
				}
			}
		}
	}
}

int test_print_transitive_flow_analysis(iflow_query_t *q, iflow_transitive_t *a, policy_t *policy)
{
	int i;

	if (q->direction == IFLOW_IN)
		fprintf(outfile, "Found %d in flows\n", a->num_end_types);
	else
		fprintf(outfile, "Found %d out flows\n", a->num_end_types);

	for (i = 0; i < a->num_end_types; i++) {
		fprintf(outfile, "%s to %s\n", policy->types[a->start_type].name,
			policy->types[a->end_types[i]].name);
		test_print_iflow_path(policy, a->paths[i]);
	}
	return 0;
}


static int test_print_type_relation_results(types_relation_query_t *tr_query, 
					    types_relation_results_t *tr_results, 
					    policy_t *policy)
{
	char *name = NULL, *rule = NULL;
	llist_node_t *x = NULL;
	int i, rt;
	
	if (tr_query->options & TYPES_REL_COMMON_ATTRIBS) {
		if (tr_results->num_common_attribs)
			fprintf(outfile, "\nCommon Attributes:\n");
		else
			fprintf(outfile, "\nCommon Attributes: none\n");
		for (i = 0; i < tr_results->num_common_attribs; i++) {
			if (get_attrib_name(tr_results->common_attribs[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting attribute name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
	}
	if (tr_query->options & TYPES_REL_COMMON_ROLES) {
		if (tr_results->num_common_roles)
			fprintf(outfile, "\nCommon Roles:\n");
		else
			fprintf(outfile, "\nCommon Roles: none\n");
		for (i = 0; i < tr_results->num_common_roles; i++) {
			if (get_role_name(tr_results->common_roles[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting role name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
	}
	if (tr_query->options & TYPES_REL_COMMON_USERS) {
		if (tr_results->num_common_users)
			fprintf(outfile, "\nCommon Users:");
		else
			fprintf(outfile, "\nCommon Users: none\n");
		for (i = 0; i < tr_results->num_common_users; i++) {
			if (get_user_name2(tr_results->common_users[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting user name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
	}
	
	if (tr_query->options & TYPES_REL_DOMAINTRANS) {
		if (tr_results->dta_results_A_to_B) {
			fprintf(outfile, "\n\nDomain transitions (A->B):\n");
			for(x = tr_results->dta_results_A_to_B->trans_domains->head; x != NULL; x = x->next) {
				rt = test_print_trans_dom((trans_domain_t *)x->data, policy);
				if (rt != 0) {
					types_relation_destroy_results(tr_results);
					return -1;
				}
			}
		} 
		if (tr_results->dta_results_B_to_A) {
			fprintf(outfile, "\nDomain transitions (B->A):\n");
			for(x = tr_results->dta_results_B_to_A->trans_domains->head; x != NULL; x = x->next) {
				rt = test_print_trans_dom((trans_domain_t *)x->data, policy);
				if (rt != 0) {
					types_relation_destroy_results(tr_results);
					return -1;
				}
			}
		}
	}
	
	if ((tr_query->options & TYPES_REL_DIRFLOWS) && tr_results->direct_flow_results) {
		test_print_direct_flow_analysis(policy, tr_results->num_dirflows, tr_results->direct_flow_results);
	}
	if (tr_query->options & TYPES_REL_TRANSFLOWS) {
		if (tr_results->trans_flow_results_A_to_B) {
			test_print_transitive_flow_analysis(tr_query->trans_flow_query,
							    tr_results->trans_flow_results_A_to_B, 
							    policy);
		}
		if (tr_results->trans_flow_results_B_to_A) {
			test_print_transitive_flow_analysis(tr_query->trans_flow_query,
							    tr_results->trans_flow_results_B_to_A, 
							    policy);
		}
	}
	if ((tr_query->options & TYPES_REL_OTHER_TTRULES) && tr_results->other_tt_rules_results) {
		fprintf(outfile, "\nAdditional type transition rules:\n");
		for(i = 0; i < tr_results->num_other_tt_rules; i++) {
			rule = re_render_tt_rule(1, tr_results->other_tt_rules_results[i], policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}
		fprintf(outfile, "\n");
	}

	if ((tr_query->options & TYPES_REL_PROCESS_INTER) && tr_results->process_inter_results) {
		fprintf(outfile, "\nProcess interaction rules:\n");
		for(i = 0; i < tr_results->num_process_inter_rules; i++) {
			rule = re_render_av_rule(1, tr_results->process_inter_results[i], 0, policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}
		fprintf(outfile, "\n");
	}
	
	if ((tr_query->options & TYPES_REL_COMMON_ACCESS) && tr_results->common_obj_types_results) {
		fprintf(outfile, "\nCommon objects:");
		fprintf(outfile, "\nTypeA common objects: %d\n", tr_results->common_obj_types_results->num_objs_A);
		for(i = 0; i < tr_results->common_obj_types_results->num_objs_A; i++) {
			if (get_type_name(tr_results->common_obj_types_results->objs_A[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting attribute name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
				
		fprintf(outfile, "\nCommon object rules for type A: %d\n", 
		        tr_results->common_obj_types_results->num_obj_type_rules_A);
		for(i = 0; i < tr_results->common_obj_types_results->num_obj_type_rules_A; i++) {
			rule = re_render_av_rule(1, tr_results->common_obj_types_results->obj_type_rules_A[i], 0, policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}
		fprintf(outfile, "\nTypeB common objects: %d\n", tr_results->common_obj_types_results->num_objs_B);
		for(i = 0; i < tr_results->common_obj_types_results->num_objs_B; i++) {
			if (get_type_name(tr_results->common_obj_types_results->objs_B[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting attribute name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
		fprintf(outfile, "\n");
		
		fprintf(outfile, "\nCommon object rules for type B: %d\n",
			tr_results->common_obj_types_results->num_obj_type_rules_B);
		for(i = 0; i < tr_results->common_obj_types_results->num_obj_type_rules_B; i++) {
			rule = re_render_av_rule(1, tr_results->common_obj_types_results->obj_type_rules_B[i], 0, policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}
		fprintf(outfile, "\n");
	}
	if ((tr_query->options & TYPES_REL_UNIQUE_ACCESS) && tr_results->unique_obj_types_results) {
		fprintf(outfile, "\nUnique objects:");
		fprintf(outfile, "\nTypeA unique objects: %d\n", tr_results->unique_obj_types_results->num_objs_A);
		for(i = 0; i < tr_results->unique_obj_types_results->num_objs_A; i++) {
			if (get_type_name(tr_results->unique_obj_types_results->objs_A[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting attribute name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}		
		fprintf(outfile, "\nUnique object rules for type A: %d\n",
			tr_results->unique_obj_types_results->num_obj_type_rules_A);
		for(i = 0; i < tr_results->unique_obj_types_results->num_obj_type_rules_A; i++) {
			rule = re_render_av_rule(1, tr_results->unique_obj_types_results->obj_type_rules_A[i], 0, policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}		
		fprintf(outfile, "\nTypeB unique objects: %d\n", tr_results->unique_obj_types_results->num_objs_B);
		for(i = 0; i < tr_results->unique_obj_types_results->num_objs_B; i++) {
			if (get_type_name(tr_results->unique_obj_types_results->objs_B[i], &name, policy) != 0) {
				fprintf(stderr, "Error getting attribute name.");
				free(name);
				types_relation_destroy_results(tr_results);
				return -1;
			}
			fprintf(outfile, "%s\n", name);
			free(name);
		}
		fprintf(outfile, "\nUnique object rules for type B: %d\n",
			tr_results->unique_obj_types_results->num_obj_type_rules_B);
		for(i = 0; i < tr_results->unique_obj_types_results->num_obj_type_rules_B; i++) {
			rule = re_render_av_rule(1, tr_results->unique_obj_types_results->obj_type_rules_B[i], 0, policy);
			if (rule == NULL)
				return -1;
			fprintf(outfile, "%s\n", rule);
			free(rule);
		}
		fprintf(outfile, "\n");
	}
	
	return 0;
}

int test_disaply_perm_map(classes_perm_map_t *map, policy_t *p)
{
	int i, j;
	class_perm_map_t *cls;
	fprintf(outfile, "\nNumber of classes: %d (mapped?: %s)\n\n", map->num_classes, (map->mapped ? "yes" : "no"));
	for(i = 0; i < map->num_classes; i++) {
		cls = &map->maps[i];
		fprintf(outfile, "\nclass %s %d\n", p->obj_classes[cls->cls_idx].name, cls->num_perms);
		for(j = 0; j < cls->num_perms; j++) {
			fprintf(outfile, "%18s     ", p->perms[cls->perm_maps[j].perm_idx]);
			if((cls->perm_maps[j].map & PERMMAP_BOTH) == PERMMAP_BOTH) {
				fprintf(outfile, "b\n");
			} 
			else {
				switch(cls->perm_maps[j].map & (PERMMAP_READ|PERMMAP_WRITE|PERMMAP_NONE|PERMMAP_UNMAPPED)) {
				case PERMMAP_READ: 	fprintf(outfile, "r\n");
							break;
				case PERMMAP_WRITE: 	fprintf(outfile, "w\n");
							break;	
				case PERMMAP_NONE: 	fprintf(outfile, "n\n");
							break;
				case PERMMAP_UNMAPPED: 	fprintf(outfile, "u\n");
							break;	
				default:		fprintf(outfile, "?\n");
				} 
			} 
		} 
	} 
	return 0;
}

int get_iflow_query(iflow_query_t *query, policy_t *policy)
{
	unsigned int m_ret;
	FILE* pfp;
	char buf[1024];

	printf("Starting type: ");
	fgets(buf, sizeof(buf), stdin);
	buf[strlen(buf)-1] = '\0';
	query->start_type = get_type_idx(buf, policy);
	if (query->start_type < 0) {
		fprintf(stderr, "Invalid starting type");
		return -1;
	}

	while (1) {
		int type;
		printf("Add ending type or f to finish: ");
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf)-1] = '\0';
		if (strlen(buf) == 1 && buf[0] == 'f')
			break;
		type = get_type_idx(buf, policy);
		if (type < 0) {
			fprintf(stderr, "Invalid ending type\n");
			continue;
		}
		if (iflow_query_add_end_type(query, type) != 0)
			return -1;
	}

	while (1) {
		int type;
		printf("Add intermediate type or f to finish: ");
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf)-1] = '\0';
		if (strlen(buf) == 1 && buf[0] == 'f')
			break;
		type = get_type_idx(buf, policy);
		if (type < 0) {
			fprintf(stderr, "Invalid ending type\n");
			continue;
		}
		if (iflow_query_add_type(query, type) != 0)
			return -1;
	}

	while (1) {
		int object;
		printf("Add object class or f to finish: ");
		fgets(buf, sizeof(buf), stdin);
		buf[strlen(buf)-1] = '\0';
		if (strlen(buf) == 1 && buf[0] == 'f')
			break;
		object = get_obj_class_idx(buf, policy);
		if (object < 0) {
			fprintf(stderr, "Invalid object class\n");
			continue;
		}
		printf("Limit specific permissions (y/n)? ");
		fgets(buf, sizeof(buf), stdin);
		if (buf[0] == 'y' || buf[0] == 'Y') {
			while (1) {
				int perm;
				printf("Add object class permission or f to finish: ");
				fgets(buf, sizeof(buf), stdin);
				buf[strlen(buf)-1] = '\0';
				if (strlen(buf) == 1 && buf[0] == 'f')
					break;
				perm = get_perm_idx(buf, policy);
				if (perm < 0 || !is_valid_perm_for_obj_class(policy, object, perm)) {
					fprintf(stderr, "Invalid object class permission\n");
					continue;
				}
				if (iflow_query_add_obj_class_perm(query, object, perm) != 0) {
					fprintf(stderr, "error adding perm\n");
					return -1;
				}
			}
		} else {
			if (iflow_query_add_obj_class(query, object) == -1) {
				fprintf(stderr, "error adding object class\n");
				return -1;
			}
		}
	}

	printf("Permission map file: ");
	fgets(buf, sizeof(buf), stdin);
	buf[strlen(buf)-1] = '\0';
	pfp = fopen(buf, "r");
	if(pfp == NULL) {
		fprintf(stderr, "Cannot open perm map file %s\n", buf);
		return -1;
	}
	m_ret = load_policy_perm_mappings(policy, pfp);
	if(m_ret & PERMMAP_RET_ERROR) {
		fprintf(stderr, "ERROR loading perm mappings from file: %s\n", buf);
		return -1;
	} 
	else if(m_ret & PERMMAP_RET_WARNINGS) {
		printf("There were warnings:\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_PERM) 
			printf("     Some permissions were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNMAPPED_OBJ)
			printf("     Some objects were unmapped.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_PERM)
			printf("     Map contains unknown permissions, or permission assoicated with wrong objects.\n");
		if(m_ret & PERMMAP_RET_UNKNOWN_OBJ)
			printf("     Map contains unknown objects\n");
		if(m_ret & PERMMAP_RET_OBJ_REMMAPPED) 
			printf("     Some permissions were mapped more than once.\n");
	}
	fclose(pfp);
	printf("\nPermission map was loaded.....\n\n");
	return 0;
}

void test_print_bools(policy_t *policy)
{
        int i;
        
        for (i = 0; i < policy->num_cond_bools; i++) {
                fprintf(outfile, "name: %s state: %d\n", policy->cond_bools[i].name, policy->cond_bools[i].state);
        }

}

void test_print_expr(cond_expr_t *exp, policy_t *policy)
{

	cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			printf("%s ", policy->cond_bools[cur->bool].name);
			break;
		case COND_NOT:
			printf("! ");
			break;
		case COND_OR:
			printf("|| ");
			break;
		case COND_AND:
			printf("&& ");
			break;
		case COND_XOR:
			printf("^ ");
			break;
		case COND_EQ:
			printf("== ");
			break;
		case COND_NEQ:
			printf("!= ");
			break;
		default:
			printf("error!");
			break;
		}
	}
}

void test_print_cond_list(cond_rule_list_t *list, policy_t *policy)
{
	int i;
	
	if (!list)
		return;
	
	for (i = 0; i < list->num_av_access; i++) {
		char *rule;
		rule = re_render_av_rule(FALSE, list->av_access[i], FALSE, policy);
		assert(rule);
		fprintf(outfile, "\t%d %s\n", policy->av_access[list->av_access[i]].enabled, rule);
		free(rule);
	}
	for (i = 0; i < list->num_av_audit; i++) {
		char *rule;
		rule = re_render_av_rule(FALSE, list->av_audit[i], TRUE, policy);
		assert(rule);
		fprintf(outfile, "\t%d %s\n", policy->av_audit[list->av_audit[i]].enabled, rule);
		free(rule);
	}
	for (i = 0; i < list->num_te_trans; i++) {
		char *rule;
		rule = re_render_tt_rule(FALSE, list->te_trans[i], policy);
		assert(rule);
 		fprintf(outfile, "\t%d %s\n", policy->te_trans[list->te_trans[i]].enabled, rule);
		free(rule);
	}
}

void test_print_cond_exprs(policy_t *policy)
{
        int i;
        

        
        for (i = 0; i < policy->num_cond_exprs; i++) {
 	        fprintf(outfile, "\nconditional expression %d: [ ", i);
                test_print_expr(policy->cond_exprs[i].expr, policy);
		fprintf(outfile, "]\n");
		fprintf(outfile, "TRUE list:\n");
		test_print_cond_list(policy->cond_exprs[i].true_list, policy);
		fprintf(outfile, "FALSE list:\n");
		test_print_cond_list(policy->cond_exprs[i].false_list, policy);
        }
}

int check_for_duplicate_object(int *classes, int num_objs, int obj_class)
{
	int i;

	assert(classes);
	assert(obj_class >= 0 && num_objs >= 0);

	for (i = 0; i < num_objs; i++) {
		if (classes[i] == obj_class) {
			return i;
		}
	}
	return -1;
}

int menu() {
	printf("\nSelect a command:\n");
	printf("0)  analyze forward domain transitions\n");
	printf("1)  analyze reverse domain transitions\n");
	printf("2)  load permission maps\n");
	printf("3)  analyze direct information flows\n");
	printf("4)  test regex type name matching\n");
	printf("5)  test transitive inflormation flows\n");
	printf("6)  display initial SIDs and contexts\n");
        printf("7)  display policy booleans and expressions\n");
	printf("8)  set the value of a boolean\n");
	printf("9)  search for conditional expressions\n");
	printf("t)  analyze types relationship\n");
	printf("\n");
	printf("r)  re-load policy with options\n");
	printf("s)  display policy statics\n");
	printf("f)  set output file\n");
	printf("v)  show libapol version\n");
	printf("m)  display menu\n");
	printf("q)  quit\n");
	return 0;
}

int main(int argc, char *argv[])
{
	int rt;
	char ans[81];
	extern FILE *outfile;
	char OutfileName[121];
	policy_t *policy = NULL;
	FILE *test_f;
	char *ans_ptr = &ans[0];
	
	outfile = stdout;		/* Default output to  stdout */
	if(argc != 2 )
		goto usage;
		
	policy_file = argv[1];
	/* Test open the policy file; open_policy() will also open file */
	if ((test_f = fopen(policy_file, "r")) == NULL) {
		fprintf (stderr, "%s: cannot open policy file %s\n", argv[0], argv[1]);
		exit(1);
	}
	fclose(test_f);

	/* open policy */
	rt = open_policy(policy_file, &policy);
	if(rt != 0) {
		free_policy(&policy);
		fprintf(stderr, "open_policy error (%d)\n", rt);
		exit(1);
	}

	/* test menu here */
	menu();
	for(;;) {
		printf("\nCommand (\'m\' for menu):  ");
		fgets(ans, sizeof(ans), stdin);	
		
		switch(ans[0]) {

		case '0':
		{
			domain_trans_analysis_t *dta = NULL;
			dta_query_t *dta_query = NULL;
			char *start_domain = NULL;
			llist_node_t *x = NULL;
			
			/* Create the query structure */
			dta_query = dta_query_create();
			if (dta_query == NULL) {
				fprintf(stderr, "Memory error allocating dta query.\n");
				break;
			}
			printf("\tenter starting domain type name:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			
			/* Set the start type for our query */ 					
			dta_query->start_type = get_type_idx(ans, policy);
			if (dta_query->start_type < 0) {
				dta_query_destroy(dta_query);
				fprintf(stderr, "Invalid starting type.");
				break;
			}
			
			/* determine if requesting a reverse DT analysis */
			dta_query->reverse = FALSE;
			
			if (types_relation_get_dta_options(dta_query, policy) != 0) {
				dta_query_destroy(dta_query);
				return -1;
			}
			
			/* Perform the analysis */
			rt = determine_domain_trans(dta_query, &dta, policy);
			if(rt == -2) {
				fprintf(stderr, "\n%s is not a valid type name\n", ans);
				break;
			}
			else if(rt < 0) {
				fprintf(stderr, "\n error with analysis\n");
				break;
			}
			dta_query_destroy(dta_query);
			rt = get_type_name(dta->start_type, &start_domain, policy);
			if(rt != 0) {
				free_domain_trans_analysis(dta);
				fprintf(stderr, "\nproblem translating starting domain type (%d)\n", dta->start_type);
				break;
			}
			fprintf(outfile, "\nStarting domain type (%d): %s (%d transition domains)\n", dta->start_type, start_domain, dta->trans_domains->num);
			free(start_domain);
			for(x = dta->trans_domains->head; x != NULL; x = x->next) {
				rt = test_print_trans_dom((trans_domain_t *)x->data, policy);
				if(rt != 0) {
					free_domain_trans_analysis(dta);
					break;
				}
			}
			
			
			free_domain_trans_analysis(dta);
			if (outfile != stdout) {
				fclose(outfile);
				outfile = stdout;
			}
			
		}	
			break;
		case '1':
		{
			domain_trans_analysis_t *dta = NULL;
			dta_query_t *dta_query = NULL;
			char *start_domain = NULL;
			llist_node_t *x;
			
			/* Create the query structure */
			dta_query = dta_query_create();
			if (dta_query == NULL) {
				fprintf(stderr, "Memory error allocating dta query.\n");
				break;
			}
			
			printf("\tenter ending domain type name:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			
			/* Set the start type for our query */ 					
			dta_query->start_type = get_type_idx(ans, policy);
			if (dta_query->start_type < 0) {
				dta_query_destroy(dta_query);
				fprintf(stderr, "Invalid starting type.");
				break;
			}
			
			/* determine if requesting a reverse DT analysis */
			dta_query->reverse = TRUE;
									
			/* Perform the analysis */
			rt = determine_domain_trans(dta_query, &dta, policy);
			if(rt == -2) {
				fprintf(stderr, "\n%s is not a valid type name\n", ans);
				break;
			}
			else if(rt < 0) {
				fprintf(stderr, "\n error with analysis\n");
				break;
			}
			dta_query_destroy(dta_query);
			rt = get_type_name(dta->start_type, &start_domain, policy);
			if(rt != 0) {
				free_domain_trans_analysis(dta);
				fprintf(stderr, "\nproblem translating starting domain type (%d)\n", dta->start_type);
				break;
			}
			fprintf(outfile, "\nEnding domain type (%d): %s (%d transition domains)\n", dta->start_type, start_domain, dta->trans_domains->num);
			free(start_domain);
			for(x = dta->trans_domains->head; x != NULL; x = x->next) {
				rt = test_print_trans_dom((trans_domain_t *)x->data, policy);
				if(rt != 0) {
					free_domain_trans_analysis(dta);
					break;
				}
			}
			
			
			free_domain_trans_analysis(dta);
			if (outfile != stdout) {
				fclose(outfile);
				outfile = stdout;
			}
			
		}	
			break;
		case '2':
		{
			FILE *pfp;
			char PermFileName[81];
			unsigned int m_ret;
			bool_t display = FALSE;
			
			printf("\nDisplay map after loading? [n]: ");
			fgets(ans, sizeof(ans), stdin);	
			if(ans[0] == 'y') 
				display = TRUE;
			
			printf("Permission map file: ");
			fgets(PermFileName, sizeof(PermFileName), stdin);
			PermFileName[strlen(PermFileName)-1] = '\0';
			pfp = fopen(PermFileName, "r");
			if(pfp == NULL) {
				fprintf(stderr, "Cannot open perm map file %s]n", PermFileName);
				break;
			}
			m_ret = load_policy_perm_mappings(policy, pfp);
			if(m_ret & PERMMAP_RET_ERROR) {
				fprintf(stderr, "ERROR loading perm mappings from file: %s\n", PermFileName);
				break;
			} 
			else if(m_ret & PERMMAP_RET_WARNINGS) {
				printf("There were warnings:\n");
				if(m_ret & PERMMAP_RET_UNMAPPED_PERM) 
					printf("     Some permissions were unmapped.\n");
				if(m_ret & PERMMAP_RET_UNMAPPED_OBJ)
					printf("     Some objects were unmapped.\n");
				if(m_ret & PERMMAP_RET_UNKNOWN_PERM)
					printf("     Map contains unknown permissions, or permission assoicated with wrong objects.\n");
				if(m_ret & PERMMAP_RET_UNKNOWN_OBJ)
					printf("     Map contains unknown objects\n");
				if(m_ret & PERMMAP_RET_OBJ_REMMAPPED) 
					printf("     Some permissions were mapped more than once.\n");
			}
			fclose(pfp);
			printf("\nPermission map was loaded.....\n\n");
			
			if(display)
				test_disaply_perm_map(policy->pmap, policy);
			
			break;
		}
		case '3':
		{
			int num_answers;
			iflow_t* answers;
			unsigned char display = FALSE;
			iflow_query_t* query = NULL;

			query = iflow_query_create();
			if (query == NULL) {
				fprintf(stderr, "Memory error allocating query\n");
				break;
			}
			
			printf("\nDisplay analysis after loading? [n]: ");
			fgets(ans, sizeof(ans), stdin);	
			if(ans[0] == 'y') 
				display = TRUE;

			printf("\nChoose flow types\n");
			printf("\ti) In\n");
			printf("\to) Out\n");
			printf("\tb) Both\n");
			printf("\te) Either\n");
			printf("\nchoice [b]:  ");
			fgets(ans, sizeof(ans), stdin);	
			if(ans[0] == 'i') 
				query->direction = IFLOW_IN;
			else if(ans[0] == 'o') 
				query->direction = IFLOW_OUT;
			else if(ans[0] == 'b') 
				query->direction = IFLOW_BOTH;
			else if(ans[0] == 'e') 
				query->direction = IFLOW_EITHER;
			
			if (get_iflow_query(query, policy) != 0) {
				iflow_query_destroy(query);
				break;
			}

			num_answers = 0;
			answers = NULL;
			if (iflow_direct_flows(policy, query, &num_answers, &answers) < 0) {
				fprintf(stderr, "There were errors in the information flow analysis\n");
				break;
			}
			printf("\nAnalysis completed . . . \n\n");
			if (display) {
				test_print_direct_flow_analysis(policy, num_answers, answers);
			}

			iflow_destroy(answers);
			iflow_query_destroy(query);
			break;
		}
		case '4': /* simple test of the new function to get a list of types using
			   * a regex.  At some point we can remove this case and reuse it
			   * since this is really a simple funciton */
		{
			int *types, num, rt, sz, i;
			regex_t reg;
			char *err, *name;
			
			printf("\tenter regular expression:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			
			rt = regcomp(&reg, ans, REG_ICASE|REG_EXTENDED|REG_NOSUB);
			if(rt != 0) {
				sz = regerror(rt, &reg, NULL, 0);
				if((err = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "out of memory");
					return -1;
				}
				regerror(rt, &reg, err, sz);
				fprintf(stderr, "%s\n", err);
				regfree(&reg);
				free(err);
				break;
			}
			rt = get_type_idxs_by_regex(&types, &num, &reg, TRUE, policy);
			regfree(&reg);
			if(rt < 0) {
				fprintf(stderr, "Error searching types\n");
				break;
			}
			printf("\nThere were %d matching types:\n", num);
			for(i = 0; i < num; i++) {
				rt = get_type_name(types[i], &name, policy);
				if(rt < 0) {
					fprintf(stderr, "Problem getting %dth matching type name for idx %d\n", i, types[i]);
					break;
				}
				printf("\t%s\n", name);
				free(name);
			} 
			if(num > 0) 
				free(types);
			
			break;
		}
		case '5':
		{
			iflow_transitive_t* answers;
			unsigned char display = FALSE;
			iflow_query_t* query = NULL;

			query = iflow_query_create();
			if (query == NULL) {
				fprintf(stderr, "Memory error allocating query\n");
				break;
			}
			
			printf("\nDisplay analysis after loading? [n]: ");
			fgets(ans, sizeof(ans), stdin);	
			if(ans[0] == 'y') 
				display = TRUE;

			printf("\nChoose flow type\n");
			printf("\ti) In\n");
			printf("\to) Out\n");
			printf("\nchoice [o]:  ");
			fgets(ans, sizeof(ans), stdin);	
			if(ans[0] == 'i') 
				query->direction = IFLOW_IN;
			else
				query->direction = IFLOW_OUT;
			
			if (get_iflow_query(query, policy) != 0) {
				iflow_query_destroy(query);
				break;
			}

			answers = NULL;
			if ((answers = iflow_transitive_flows(policy, query)) == NULL) {
				fprintf(stderr, "There were errors in the information flow analysis\n");
				break;
			}
			printf("\nAnalysis completed . . . \n\n");
			if (display) {
				test_print_transitive_flow_analysis(query, answers, policy);
			}

			iflow_transitive_destroy(answers);
			iflow_query_destroy(query);
			break;
		}
		case '6':
		{
			int i;
			char *str, *user = NULL, *role = NULL, *type= NULL;
			bool_t search = FALSE;
			
			printf("Do you want to enter search criteria [n]?:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			if(ans[0] =='y' || ans[0] == 'Y') 
				search = TRUE;
				
			if(search) {
				int *isids = NULL, num_isids;
				ans[0] = '\0';
				printf("     User [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				trim_trailing_whitespace(&ans_ptr);
				if(ans[0] != '\0') {
					user = (char *)malloc(strlen(ans) + 1);
					strcpy(user, ans);
				}
				ans[0] = '\0';
				printf("     Role [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				trim_trailing_whitespace(&ans_ptr);
				if(ans[0] != '\0') {
					role = (char *)malloc(strlen(ans) + 1);
					strcpy(role, ans);
				}
				ans[0] = '\0';
				printf("     Type [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				trim_trailing_whitespace(&ans_ptr);
				if(ans[0] != '\0') {
					type = (char *)malloc(strlen(ans) + 1);
					strcpy(type, ans);
				}
				rt = search_initial_sids_context(&isids, &num_isids, user, role, type, policy);
				if( rt != 0) {
					fprintf(stderr, "Problem searching initial SID contexts\n");
					break;
				}
				printf("\nMatching Initial SIDs (%d)\n\n", num_isids);
				for(i = 0; i < num_isids; i++) {
					printf("%20s : ", policy->initial_sids[isids[i]].name);
					str = re_render_security_context(policy->initial_sids[isids[i]].scontext, policy);
					if(str == NULL) {
						fprintf(stderr, "\nProblem rendering security context for %dth initial SID.\n", isids[i]);
						break;
					}
					printf("%s\n", str);
					free(str);
				}
				free(isids);

			}
			else {
				printf("Initial SIDs (%d)\n\n", policy->num_initial_sids);
				for(i = 0; i < policy->num_initial_sids; i++) {
					printf("%20s : ", policy->initial_sids[i].name);
					str = re_render_security_context(policy->initial_sids[i].scontext, policy);
					if(str == NULL) {
						fprintf(stderr, "\nProblem rendering security context for %dth initial SID.\n", i);
						break;
					}
					printf("%s\n", str);
					free(str);
				}
			}
			printf("\n");
			break;
		}
                case '7':
                {
                        test_print_bools(policy);
                        test_print_cond_exprs(policy);
                        break;
                }
		case '8':
		{
			int bool_idx;
			bool_t bool_val;
			printf("boolean name: ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			bool_idx = get_cond_bool_idx(ans, policy);
			if (bool_idx < 0) {
				fprintf(stderr, "Invalid boolean name\n");
				break;
			}
			printf("value (t or f): ");
			fgets(ans, sizeof(ans), stdin);
			if (ans[0] == 't')
				bool_val = TRUE;
			else if (ans[0] == 'f')
				bool_val = FALSE;
			else {
				fprintf(stderr, "Invalid response\n");
				break;
			}
			if (set_cond_bool_val(bool_idx, bool_val, policy) != 0) {
				fprintf(stderr, "Error setting boolean\n");
				break;
			}
			if (update_cond_expr_items(policy) != 0)
				fprintf(stderr, "Error updating conditional expressions\n");
				
			break;
		}
		case '9':
		{
			bool_t regex, *exprs_b;
			char *error_msg;
			int i;
			
			printf("use regex [y|N]: ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			if (ans[0] == 'y')
				regex = TRUE;
			else
				regex = FALSE;
			
			printf("boolean name: ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);
			
			exprs_b = (bool_t*)malloc(sizeof(bool_t) * policy->num_cond_exprs);
			if (!exprs_b) {
				fprintf(stderr, "Memory error\n");
				break;
			}
			memset(exprs_b, FALSE, sizeof(bool_t) * policy->num_cond_exprs);
			
			if (search_conditional_expressions(ans, regex, exprs_b, &error_msg, policy) != 0) {
				fprintf(stderr, "Error searching conditional expressions: %s\n", error_msg);
				free(error_msg);
				break;
			}
			
			fprintf(outfile, "Found the following expressions:\n");
			for (i = 0; i < policy->num_cond_exprs; i++) {
				if (exprs_b[i]) {
					fprintf(outfile, "\nconditional expression %d: [ ", i);
					test_print_expr(policy->cond_exprs[i].expr, policy);
					fprintf(outfile, "]\n");
					fprintf(outfile, "TRUE list:\n");
					test_print_cond_list(policy->cond_exprs[i].true_list, policy);
					fprintf(outfile, "FALSE list:\n");
					test_print_cond_list(policy->cond_exprs[i].false_list, policy);
				}
			}
			free(exprs_b);
			
			break;
		}
		case 't':
		{
			types_relation_query_t *tr_query = NULL;
			types_relation_results_t *tr_results = NULL;
											
			tr_query = types_relation_query_create();
			if (tr_query == NULL) {
				fprintf(stderr, "Error creating query.");
				break;
			}
			printf("\tenter type A:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);	
			tr_query->type_name_A = (char *)malloc((strlen(ans) + 1) * sizeof(char));
			if (tr_query->type_name_A == NULL) {
				types_relation_query_destroy(tr_query);
				fprintf(stderr, "out of memory");
				break;
			}
			strcpy(tr_query->type_name_A, ans);	
	
			printf("\tenter type B:  ");
			fgets(ans, sizeof(ans), stdin);
			trim_trailing_whitespace(&ans_ptr);	
			tr_query->type_name_B = (char *)malloc((strlen(ans) + 1) * sizeof(char));
			if (tr_query->type_name_B == NULL) {
				types_relation_query_destroy(tr_query);
				fprintf(stderr, "out of memory");
				break;
			}
			strcpy(tr_query->type_name_B, ans);
			
			if (get_type_relation_options(&tr_query, policy) != 0) {
				types_relation_query_destroy(tr_query);
				break;
			}
			
			/* Perform the analysis */
			rt = types_relation_determine_relationship(tr_query, &tr_results, policy);
			if (rt != 0) {	
				types_relation_query_destroy(tr_query);
				fprintf(stderr, "\nAnalysis error.\n");
				break;
			}
		
			test_print_type_relation_results(tr_query, tr_results, policy); 
			
			types_relation_query_destroy(tr_query);	
			if (tr_results) types_relation_destroy_results(tr_results);
			break;
		}
		case 'f':
			printf("\nFilename for output (<CR> for screen output): ");
			fgets(OutfileName, sizeof(OutfileName), stdin);	
			OutfileName[strlen(OutfileName)-1] = '\0'; /* fix_string (remove LF) */
			if (strlen(OutfileName) == 0) 
				outfile = stdout;
			else if ((outfile = fopen(OutfileName, "w")) == NULL) {
				fprintf (stderr, "Cannot open output file %s\n", OutfileName);
				outfile = stdout;
			}
			if (outfile != stdout) 
				printf("\nOutput to file: %s\n", OutfileName);
			break;
		case 'r': /* Test reloading current policy using load options */
			rt = reload_with_options(&policy);
			if(rt != 0) {
				printf("Problem re-loading\n");
				break;
			}
			break;
		case 's':
			display_policy_stats(policy);
			break;
		case 'v':
			printf("\n%s\n", LIBAPOL_VERSION_STRING);
			break;
		case 'q':
			close_policy(policy);
			exit(0);
			break;
		case 'm':
			menu();
			break;
		default:
			printf("\nInvalid choice\n");
			menu();
			break;
		}
	}
usage:
	printf("\nUsage: %s policy.conf_file \n", argv[0]);
	exit(1);

}
