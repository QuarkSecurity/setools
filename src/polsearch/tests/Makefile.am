TESTS = libpolsearch-tests
check_PROGRAMS = libpolsearch-tests

libpolsearch_tests_SOURCES = \
	bool_query-tests.hh \
	bool_query-tests.cc \
	user_query-tests.cc user_query-tests.hh \
	libpolsearch-tests.cc

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libpolsearch_tests_DEPENDENCIES = $(top_builddir)/lib/libpolsearch.so
