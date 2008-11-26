if DO_SWIGIFY_PYTHON
  MAYBE_PYSWIG = python
endif

if DO_SWIGIFY_JAVA
  MAYBE_JSWIG = java
endif

if DO_SWIGIFY_TCL
  MAYBE_TCLSWIG = tcl
endif

SUBDIRS = . $(MAYBE_PYSWIG) $(MAYBE_JSWIG) $(MAYBE_TCLSWIG) tests

dist_noinst_DATA = libpolsearch.map polsearch.i

lib_LIBRARIES = libpolsearch.a

polsearchso_DATA = libpolsearch.so.@libpolsearch_version@
polsearchsodir = $(libdir)

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@

libpolsearch_a_SOURCES = \
	attribute_query.cc \
	bool_parameter.cc \
	bool_query.cc \
	cat_query.cc \
	class_query.cc \
	common_query.cc \
	criterion.cc \
	level_parameter.cc \
	level_query.cc \
	number_parameter.cc \
	parameter.cc \
	polsearch.cc \
	polsearch_internal.hh \
	proof.cc \
	query.cc \
	range_parameter.cc \
	regex_parameter.cc \
	result.cc \
	role_query.cc \
	string_expression_parameter.cc \
	test.cc \
	type_query.cc \
	user_query.cc \
	util.cc

libpolsearch_a_DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libsefs.so

libpolsearch_so_OBJS = $(patsubst %.cc,%.o,$(filter %.cc,$(libpolsearch_a_SOURCES)))
LIBPOLSEARCH_SONAME = @libpolsearch_soname@

$(polsearchso_DATA): $(libpolsearch_so_OBJS) libpolsearch.map
	$(CXX) -shared -o $@ $(libpolsearch_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBPOLSEARCH_SONAME),--version-script=$(srcdir)/libpolsearch.map,-z,defs $(libpolsearch_a_DEPENDENCIES)
	cp -f $@ $(top_builddir)/lib/$@
	$(LN_S) -f $@ $(top_builddir)/lib/@libpolsearch_soname@
	$(LN_S) -f $@ $(top_builddir)/lib/libpolsearch.so

install-data-hook:
	cd $(DESTDIR)$(polsearchsodir) && $(LN_S) -f $(polsearchso_DATA) @libpolsearch_soname@
	cd $(DESTDIR)$(polsearchsodir) && $(LN_S) -f $(polsearchso_DATA) libpolsearch.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(polsearchso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(polsearchsodir)/$(polsearchso_DATA) $(DESTDIR)$(polsearchsodir)/@libpolsearch_soname@ $(DESTDIR)$(polsearchsodir)/libpolsearch.so
