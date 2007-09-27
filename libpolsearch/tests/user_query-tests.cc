/**
 *  @file
 *
 *  Test user querying, introduced in SETools 3.4.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include <CUnit/CUnit.h>

#include <polsearch/user_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/regex_parameter.hh>
#include <polsearch/level_parameter.hh>
#include <polsearch/range_parameter.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>

#include <vector>
#include <string>
#include <stdexcept>

#include <apol/policy.h>
#include <apol/policy-path.h>

using std::vector;
using std::string;

#define SOURCE_POLICY TEST_POLICIES "/setools-3.0/apol/user_mls_testing_policy.conf"

static apol_policy_t *sp;

static void create_query(void)
{
	polsearch_user_query *uq = new polsearch_user_query(POLSEARCH_MATCH_ALL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(uq);
	CU_ASSERT(uq->match() == POLSEARCH_MATCH_ALL);
	polsearch_test & nt = uq->addTest(POLSEARCH_TEST_NAME);
	CU_ASSERT(nt.testCond() == POLSEARCH_TEST_NAME);
	polsearch_criterion & nc = nt.addCriterion(POLSEARCH_OP_MATCH_REGEX);
	CU_ASSERT(nc.op() == POLSEARCH_OP_MATCH_REGEX);
	polsearch_regex_parameter *rxp = new polsearch_regex_parameter("^[pqt]");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rxp);
	nc.param(rxp);
	CU_ASSERT(polsearch_is_test_continueable(nt.testCond()) == false);

	vector < polsearch_test_cond > valid = polsearch_get_valid_tests(uq->elementType());
	bool found_name = false, found_roles = false, found_fcentry = false, found_default_level = false, found_range = false;
	for (vector < polsearch_test_cond >::const_iterator i = valid.begin(); i != valid.end(); i++)
	{
		switch (*i)
		{
		case POLSEARCH_TEST_NAME:
			found_name = true;
			break;
		case POLSEARCH_TEST_ROLES:
			found_roles = true;
			break;
		case POLSEARCH_TEST_FCENTRY:
			found_fcentry = true;
			break;
		case POLSEARCH_TEST_DEFAULT_LEVEL:
			found_default_level = true;
			break;
		case POLSEARCH_TEST_RANGE:
			found_range = true;
			break;
		default:
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_name && found_roles && found_fcentry && found_default_level && found_range);

	bool caught_invalid_argument = false;
	try
	{
		uq->addTest(POLSEARCH_TEST_STATE);
	}
	catch(std::invalid_argument & e)
	{
		caught_invalid_argument = true;
	}
	catch(...)
	{
	}
	CU_ASSERT(caught_invalid_argument);

	vector < polsearch_result > res_v = uq->run(sp, NULL);
	CU_ASSERT(!res_v.empty());
	CU_ASSERT(res_v.size() == 2);
	//results should be pwn_u and tom_u;
	bool found_pwn = false, found_tom = false;
	for (vector < polsearch_result >::const_iterator i = res_v.begin(); i != res_v.end(); i++)
	{
		CU_ASSERT(i->proof().size() == 1);
		CU_ASSERT(i->proof()[0].testCond() == POLSEARCH_TEST_NAME);
		const polsearch_proof *pr = &(i->proof()[0]);
		string name(static_cast < const char *>(pr->element()));
		if (name == "pwn_u")
		{
			found_pwn = true;
		}
		else if (name == "tom_u")
		{
			found_tom = true;
		}
		else
		{
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_pwn && found_tom);
	delete uq;
}

static void level_query(void)
{
	polsearch_user_query *uq = new polsearch_user_query(POLSEARCH_MATCH_ALL);
	polsearch_test & lt = uq->addTest(POLSEARCH_TEST_DEFAULT_LEVEL);
	CU_ASSERT(lt.testCond() == POLSEARCH_TEST_DEFAULT_LEVEL);

	vector < polsearch_op > valid = polsearch_get_valid_operators(uq->elementType(), POLSEARCH_TEST_DEFAULT_LEVEL);
	bool found_level_exact = false, found_level_dom = false, found_level_domby = false;
	for (vector < polsearch_op >::const_iterator i = valid.begin(); i != valid.end(); i++)
	{
		switch (*i)
		{
		case POLSEARCH_OP_LEVEL_EXACT:
			found_level_exact = true;
			break;
		case POLSEARCH_OP_LEVEL_DOM:
			found_level_dom = true;
			break;
		case POLSEARCH_OP_LEVEL_DOMBY:
			found_level_domby = true;
			break;
		default:
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_level_exact && found_level_dom && found_level_domby);

	polsearch_criterion & nc = lt.addCriterion(POLSEARCH_OP_LEVEL_EXACT);
	CU_ASSERT(nc.op() == POLSEARCH_OP_LEVEL_EXACT);

	polsearch_regex_parameter *rxp = NULL;
	bool caught_invalid_parameter = false;
	try
	{
		rxp = new polsearch_regex_parameter("^[pqt]");
		nc.param(rxp);
	}
	catch(std::invalid_argument & e)
	{
		caught_invalid_parameter = true;
	}
	catch(...)
	{
	}
	CU_ASSERT(caught_invalid_parameter);
	delete rxp;

	apol_mls_level_t *l = apol_mls_level_create_from_string(sp, "s3");
	CU_ASSERT_PTR_NOT_NULL_FATAL(l);
	polsearch_level_parameter *lp = new polsearch_level_parameter(l);
	apol_mls_level_destroy(&l);
	nc.param(lp);
	CU_ASSERT(polsearch_is_test_continueable(lt.testCond()) == false);

	vector < polsearch_result > res_v = uq->run(sp, NULL);
	CU_ASSERT(!res_v.empty());
	CU_ASSERT(res_v.size() == 1);
	const polsearch_result & res = res_v[0];

	CU_ASSERT(res.proof().size() == 1);
	const polsearch_proof *pr = &(res.proof()[0]);
	CU_ASSERT(pr->testCond() == POLSEARCH_TEST_DEFAULT_LEVEL);
	CU_ASSERT(pr->elementType() == POLSEARCH_ELEMENT_MLS_LEVEL);
	const apol_mls_level_t *cl = static_cast < const apol_mls_level_t * >(pr->element());
	char *s = apol_mls_level_render(sp, cl);
	CU_ASSERT_STRING_EQUAL(s, "s3");
	free(s);

	const qpol_user_t *user = static_cast < const qpol_user_t * >(res.element());
	const char *name;
	qpol_user_get_name(apol_policy_get_qpol(sp), user, &name);
	CU_ASSERT_STRING_EQUAL(name, "simple_u");

	delete uq;
}

static void range_query(void)
{
}

CU_TestInfo user_query_tests[] = {
	{"create query", create_query},
	{"level query", level_query},
	{"range query", range_query},
	CU_TEST_INFO_NULL
};

int user_query_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL)
	{
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL)
	{
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int user_query_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
