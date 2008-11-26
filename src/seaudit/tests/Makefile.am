TESTS = libseaudit-tests
check_PROGRAMS = libseaudit-tests

libseaudit_tests_SOURCES = \
	filters.c filters.h \
	parse_file.c parse_file.h \
	libseaudit-tests.c

AM_CFLAGS = @SETOOLS_CFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libseaudit_tests_DEPENDENCIES = $(top_builddir)/lib/libseaudit.so
