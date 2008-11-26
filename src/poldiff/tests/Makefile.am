TESTS = libpoldiff-tests
check_PROGRAMS = libpoldiff-tests

libpoldiff_tests_SOURCES = \
	components-tests.c components-tests.h \
	conditionals.c conditionals.h \
	libpoldiff-tests.c libpoldiff-tests.h \
	mls-tests.c mls-tests.h \
	nomls-tests.c nomls-tests.h \
	rules-tests.c rules-tests.h

AM_CFLAGS = @SETOOLS_CFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libpoldiff_tests_DEPENDENCIES = $(top_builddir)/lib/libpoldiff.so
