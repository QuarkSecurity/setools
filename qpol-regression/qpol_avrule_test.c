#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "test.h"
#include "test_avrule.h"
/* qpol */
#include <qpol/policy_query.h>
#include <qpol/policy.h>

void call_test_funcs(qpol_policy_t *policy);

int main(int argc, char* argv[])
{
	qpol_policy_t *policy;
	TEST("number of arguments", (argc == 3));
	TEST("open binary policy", ! (qpol_open_policy_from_file(argv[1], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	TEST("open source policy", ! (qpol_open_policy_from_file(argv[2], &policy, NULL, NULL) < 0));
	call_test_funcs(policy);
	return 0;
}

void call_test_funcs(qpol_policy_t *policy)
{
	qpol_iterator_t *rules, *perms;
	qpol_avrule_t *tmp_rule;
	qpol_type_t *tmp_src, *tmp_tgt;
	qpol_class_t *tmp_obj;
	uint32_t ruletype, tmp_list;
	qpol_cond_t *tmp_cond;
	int wrong_rule;
	unsigned int i, tmp_enabled;
	char * tmp_str;
	ruletype = tmp_list = 0;

	for (i = 0; i < NUM_RULETYPES; i++)
	{
		tmp_str = calloc(26+strlen(rule_types[i].name), sizeof(char));
		if (!tmp_str) {
			errno = ENOMEM;
			fprintf(stderr, "%s\n", strerror(errno));
			exit(1);
		}
		strcat(tmp_str, "get avrule iterator over ");
		strcat(tmp_str, rule_types[i].name);

		TEST(tmp_str, !qpol_policy_get_avrule_iter(policy,
					rule_types[i].rule, &rules));
		wrong_rule = 0;
		if (!qpol_iterator_end(rules))
		{
			qpol_iterator_get_item(rules, (void **) (&tmp_rule));
			qpol_avrule_get_rule_type(policy, tmp_rule, &ruletype);
			if (ruletype != rule_types[i].rule) {
				wrong_rule = 1;
				break;
			}
		}
		TEST("if rules were proper type", !wrong_rule);
		qpol_iterator_destroy(&rules);
		free(tmp_str);
		tmp_str = NULL;
	}

	TEST("get avrule iterator over ALL",
			!qpol_policy_get_avrule_iter(policy, QPOL_RULE_ALL, &rules));
	while (!qpol_iterator_end(rules))
	{
		qpol_iterator_get_item(rules, (void **) &tmp_rule);
		TEST("get rule source type", !qpol_avrule_get_source_type(policy, 
					tmp_rule, &tmp_src));
		TEST("get rule target type", !qpol_avrule_get_target_type(policy, 
					tmp_rule, &tmp_tgt));
		TEST("get rule object class", !qpol_avrule_get_object_class(policy, 
					tmp_rule, &tmp_obj));
		TEST("get iterator over permissions", !qpol_avrule_get_perm_iter(policy, 
					tmp_rule, &perms));
		qpol_iterator_destroy(&perms);
		TEST("get rule type", !qpol_avrule_get_rule_type(policy,
					tmp_rule, &ruletype));
		TEST("get conditional", !qpol_avrule_get_cond(policy, tmp_rule,
					&tmp_cond));
		TEST("get whether rule is enabled", !qpol_avrule_get_is_enabled(policy, 
					tmp_rule, &tmp_enabled));
		if (tmp_cond) {
			TEST("get which list a conditional rule is in",
					!qpol_avrule_get_which_list(policy, tmp_rule,
						&tmp_list));
		}
		qpol_iterator_next(rules);
	}
	qpol_iterator_destroy(&rules);
}
