/**
 *  @file
 *
 *  Test the user queries.
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
#include <apol/user-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>

#define SOURCE_POLICY TEST_POLICIES "/setools/apol/user_mls_testing_policy.conf"

static apol_policy_t *sp = NULL;

static void user_basic(void)
{

}

static void user_regex(void)
{
}

CU_TestInfo user_tests[] = {
	{"basic query", user_basic}
	,
	{"regex query", user_regex}
	,
	CU_TEST_INFO_NULL
};

int user_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int user_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
