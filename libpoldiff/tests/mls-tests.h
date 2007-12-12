/**
 *  @file
 *
 *  Header file for libpoldiff's correctness of MLS.
 *
 *  @author Paul Rosenfeld prosenfeld@tresys.com
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

#ifndef MLS_TEST
#define MLS_TEST

#include <CUnit/CUnit.h>

extern CU_TestInfo mls_tests[];
extern int mls_test_init(void);
extern int mls_test_cleanup(void);

void build_category_vecs();
void build_rangetrans_vecs();
void build_level_vecs();
void build_user_vecs();

#endif
