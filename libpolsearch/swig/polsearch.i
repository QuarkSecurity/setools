/**
 * @file
 * SWIG declarations for libpolsearch.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
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

%module polsearch

%{
#include <polsearch/polsearch.hh>
#include <polsearch/query.hh>
#include <polsearch/attribute_query.hh>
#include <polsearch/bool_query.hh>
#include <polsearch/cat_query.hh>
#include <polsearch/class_query.hh>
#include <polsearch/common_query.hh>
#include <polsearch/level_query.hh>
#include <polsearch/role_query.hh>
#include <polsearch/type_query.hh>
#include <polsearch/user_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/parameter.hh>
#include <polsearch/bool_parameter.hh>
#include <polsearch/level_parameter.hh>
#include <polsearch/number_parameter.hh>
#include <polsearch/range_parameter.hh>
#include <polsearch/regex_parameter.hh>
#include <polsearch/string_expression_parameter.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>
#include <polsearch/util.hh>
#include <sefs/fclist.hh>
#include <sefs/fcfile.hh>
#include <sefs/filesystem.hh>
#include <sefs/db.hh>
#include <sefs/entry.hh>
#include <string>
#include <vector>
#include <stdexcept>
%}

%import qpol.i
%import apol.i
%import sefs.i

%exception;
%nodefaultctor;

%include std_string.i
%include std_vector.i
%include std_except.i
%naturalvar std::string;

/******************** Java specializations ********************/

#ifdef SWIGJAVA

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE, FILE* %{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}
/* the following handles the dependencies on qpol, apol, and sefs */
%pragma(java) jniclassimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}
%pragma(java) jniclasscode=%{
	static {
		try
		{
			libpolsearch_get_version ();
		}
		catch (UnsatisfiedLinkError ule)
		{
			System.loadLibrary("jpolsearch");
		}
	}
%}
%pragma(java) moduleimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
import com.tresys.setools.sefs.*;
%}

%javaconst(1);

%template(opVector) std::vector<polsearch_op>;
%template(testCondVector) std::vector<polsearch_test_cond>;

#else
/* not in java so handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif

#endif  // end of Java specific code


/******************** Python specializations ********************/


#ifdef SWIGPYTHON

%define python_enum_vector(T)
	%typemap(out) std::vector<T> {
		$result = PyList_New(0);
		for (std::vector<T>::iterator i = $1.begin(); i != $1.end(); i++)
		{
			PyList_Append($result, PyInt_FromLong(*i));
		}
	}
%enddef

python_enum_vector(polsearch_op);
python_enum_vector(polsearch_test_cond);

#endif  // end of Python specific code


/******************** Tcl specializations ********************/


#ifdef SWIGTCL

%wrapper %{
/* Tcl module's initialization routine is expected to be named
 * Polsearch_Init(), but the output file will be called
 * libtpolsearch.so instead of libpolsearch.so.  Therefore add an
 * alias from Tpolsearch_Init() to the real Polsearch_Init().
 */
SWIGEXPORT int Tpolsearch_Init(Tcl_Interp *interp) {
	return SWIG_init(interp);
}
%}

%typemap(out) time_t {
	Tcl_SetObjResult(interp, Tcl_NewLongObj((long) $1));
}

%define tcl_enum_vector(T)
%typemap(out) std::vector<T> {
	for (unsigned int i=0; i<$1.size(); i++) {
               Tcl_ListObjAppendElement(interp, $result, \
                                         Tcl_NewIntObj((($1_type &)$1)[i]));
	}
}
%enddef

tcl_enum_vector(polsearch_op);
tcl_enum_vector(polsearch_test_cond);

#endif  // end of Tcl specific code


/******************** rest of SWIG stuff ********************/

%ignore fcentry_callback;
//Java can't handle const and non-const versions of same function
%ignore polsearch_criterion::param()const;
%ignore *::clone() const;
%ignore *::operator==;
%ignore *::operator!=;
%ignore *::operator=;

#define __attribute__(x)

//tell SWIG which types of vectors the target language will be used
namespace std {
	%template(testVector) vector<polsearch_test>;
	%template(criterionVector) vector<polsearch_criterion>;
	%template(resultVector) vector<polsearch_result>;
	%template(proofVector) vector<polsearch_proof>;
	%template(stringVector) vector<string>;
}

#define SWIG_FRIENDS

const char *libpolsearch_get_version (void);

%include <polsearch/polsearch.hh>
%include <polsearch/query.hh>
%include <polsearch/attribute_query.hh>
%include <polsearch/bool_query.hh>
%include <polsearch/cat_query.hh>
%include <polsearch/class_query.hh>
%include <polsearch/common_query.hh>
%include <polsearch/level_query.hh>
%include <polsearch/role_query.hh>
%include <polsearch/type_query.hh>
%include <polsearch/user_query.hh>
%include <polsearch/test.hh>
%include <polsearch/criterion.hh>
%include <polsearch/parameter.hh>
%include <polsearch/bool_parameter.hh>
%include <polsearch/level_parameter.hh>
%include <polsearch/number_parameter.hh>
%include <polsearch/range_parameter.hh>
%include <polsearch/regex_parameter.hh>
%include <polsearch/string_expression_parameter.hh>
%include <polsearch/result.hh>
%include <polsearch/proof.hh>
