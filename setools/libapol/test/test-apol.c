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

FILE *outfile;
char *policy_file = NULL;


static int display_policy_stats(policy_t *p)
{
	if(p == NULL) {
		printf("\nERROR: No policy provided\n");
		return -1;
	}
	printf("\nCurrent policy Statics:\n");
	printf("     Classes:            %d\n", p->num_obj_classes);
	printf("     Permissions:        %d\n", p->num_perms);
	printf("     Initial Sids:       %d\n", p->num_initial_sids);
	printf("     Attributes:         %d\n", p->num_attribs);
	printf("     Types:              %d\n", p->num_types);
	printf("     Type Aliases:       %d\n", p->num_aliases);
	printf("     AV Rules:           %d\n", p->num_av_access);
	printf("     Audit Rules:        %d\n", p->num_av_audit);
	printf("     Type Rules:         %d\n", p->num_te_trans);
	printf("     Roles:              %d\n", p->num_roles);
	printf("     Role Rules:         %d\n", p->num_role_allow + p->num_role_trans);
	printf("     Booleans            %d\n", p->num_cond_bools);
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
		opts = POLOPT_TYPES;
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
	
	fprintf(outfile, "\n");
	
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

int test_print_direct_flow_analysis(policy_t *policy, iflow_query_t* q, int num_answers, iflow_t* answers)
{
	int i, j, k;

	for (i = 0; i < num_answers; i++) {
		fprintf(outfile, "%d ", i);

		fprintf(outfile, "flow from %s to %s", policy->types[q->start_type].name,
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

void test_print_iflow_path(policy_t *policy, iflow_query_t* q, iflow_path_t *path)
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

int test_print_transitive_flow_analysis(iflow_query_t* q, iflow_transitive_t* a, policy_t *policy)
{
	int i;

	if (q->direction == IFLOW_IN)
		fprintf(outfile, "Found %d in flows\n", a->num_end_types);
	else
		fprintf(outfile, "Found %d out flows\n", a->num_end_types);

	for (i = 0; i < a->num_end_types; i++) {
		fprintf(outfile, "%s to %s\n", policy->types[q->start_type].name,
			policy->types[a->end_types[i]].name);
		test_print_iflow_path(policy, q, a->paths[i]);
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
                fprintf(outfile, "name: %s val: %d\n", policy->cond_bools[i].name, policy->cond_bools[i].val);
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

	/* open policy.conf */
	rt = open_policy(policy_file, &policy);
	if(rt != 0) {
		free_policy(&policy);
		fprintf(stderr, "open_policy error (%d)", rt);
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
			domain_trans_analysis_t *dta;
			char *start_domain;
			llist_node_t *x;
			
			printf("\tenter starting domain type name:  ");
			fgets(ans, sizeof(ans), stdin);
			fix_string(ans, sizeof(ans));
			
			rt = determine_domain_trans(0, ans, &dta, policy);
			if(rt == -2) {
				fprintf(stderr, "\n%s is not a valid type name\n", ans);
				break;
			}
			else if(rt < 0) {
				fprintf(stderr, "\n error with analysis\n");
				break;
			}
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
			domain_trans_analysis_t *dta;
			char *start_domain;
			llist_node_t *x;
			
			printf("\tenter ending domain type name:  ");
			fgets(ans, sizeof(ans), stdin);
			fix_string(ans, sizeof(ans));
			
			rt = determine_domain_trans(1, ans, &dta, policy);
			if(rt == -2) {
				fprintf(stderr, "\n%s is not a valid type name\n", ans);
				break;
			}
			else if(rt < 0) {
				fprintf(stderr, "\n error with analysis\n");
				break;
			}
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
				test_print_direct_flow_analysis(policy, query,
								num_answers, answers);
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
			fix_string(ans, sizeof(ans));
			
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
			fix_string(ans, sizeof(ans));
			if(ans[0] =='y' || ans[0] == 'Y') 
				search = TRUE;
				
			if(search) {
				int *isids = NULL, num_isids;
				ans[0] = '\0';
				printf("     User [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				fix_string(ans, sizeof(ans));
				if(ans[0] != '\0') {
					user = (char *)malloc(strlen(ans) + 1);
					strcpy(user, ans);
				}
				ans[0] = '\0';
				printf("     Role [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				fix_string(ans, sizeof(ans));
				if(ans[0] != '\0') {
					role = (char *)malloc(strlen(ans) + 1);
					strcpy(role, ans);
				}
				ans[0] = '\0';
				printf("     Type [none]:  ");
				fgets(ans, sizeof(ans), stdin);
				fix_string(ans, sizeof(ans));
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
                        test_print_bools(policy);
                        test_print_cond_exprs(policy);
                        break;
		case '8':
		{
			int bool_idx;
			bool_t bool_val;
			printf("boolean name: ");
			fgets(ans, sizeof(ans), stdin);
			fix_string(ans, sizeof(ans));
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
			if (set_cond_bool_val(bool_idx, bool_val, policy) != 0)
				fprintf(stderr, "Error setting boolean\n");
				
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
