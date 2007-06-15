/**
 * @file
 * SWIG declarations for libsefs.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

%module sefs

%{
#include <sefs/db.hh>
#include <sefs/entry.hh>
#include <sefs/fcfile.hh>
#include <sefs/fclist.hh>
#include <sefs/filesystem.hh>
#include <sefs/query.hh>
#include <sefs/util.h>
%}

%import apol.i

#ifdef SWIGJAVA

/* handle size_t correctly in java as architecture independent */
%typemap(jni) size_t "jlong"
%typemap(jtype) size_t "long"
%typemap(jstype) size_t "long"
%typemap("javaimports") SWIGTYPE, FILE* %{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
/* the following handles the dependencies on qpol and apol */
%pragma(java) jniclassimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
%pragma(java) jniclasscode=%{
	static {
		System.loadLibrary("jsefs");
	}
%}
%pragma(java) moduleimports=%{
import com.tresys.setools.qpol.*;
import com.tresys.setools.apol.*;
%}
#else
/* not in java so handle size_t as architecture dependent */
#ifdef SWIGWORDSIZE64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif
#endif

#ifdef SWIGTCL
/* implement a custom non thread-safe error handler */
%{
static char *message = NULL;
static void tcl_clear_error(void)
{
        free(message);
        message = NULL;
}
static char *tcl_get_error(void)
{
	return message;
}
#undef SWIG_exception
#define SWIG_exception(code, msg) {tcl_throw_error(msg); goto fail;}
%}

%wrapper %{
/* Tcl module's initialization routine is expected to be named
 * Sefs_Init(), but the output file will be called libtsefs.so instead
 * of libsefs.so.  Therefore add an alias from Tsefs_Init() to the
 * real Sefs_Init().
 */
SWIGEXPORT int Tsefs_Init(Tcl_Interp *interp) {
	return SWIG_init(interp);
}
%}

#endif

%nodefaultctor;

#define __attribute__(x)

// don't wrap private friend functions
#define SWIG_FRIENDS

%include <sefs/fclist.hh>
%include <sefs/db.hh>
%include <sefs/entry.hh>
%include <sefs/fcfile.hh>
%include <sefs/filesystem.hh>
%include <sefs/query.hh>

const char *libsefs_get_version (void);
char *sefs_default_file_contexts_get_path(void);
