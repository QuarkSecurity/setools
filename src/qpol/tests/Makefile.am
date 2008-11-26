TESTS = libqpol-tests
check_PROGRAMS = libqpol-tests

libqpol_tests_SOURCES = \
	capabilities-tests.c capabilities-tests.h \
	iterators-tests.c iterators-tests.h \
	policy-features-tests.c policy-features-tests.h \
	libqpol-tests.c

AM_CFLAGS = @SETOOLS_CFLAGS@ -I$(srcdir)/..

AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libqpol_tests_DEPENDENCIES = $(top_builddir)/lib/libqpol.so
