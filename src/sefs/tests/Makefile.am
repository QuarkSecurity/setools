TESTS = libsefs-tests
check_PROGRAMS = libsefs-tests

libsefs_tests_SOURCES = \
	fcfile-tests.cc fcfile-tests.hh \
	libsefs-tests.cc

EXTRA_DIST = file_contexts.confed file_contexts.union file_contexts.broken

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -DSRCDIR="\"$(srcdir)\""

AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libsefs_tests_DEPENDENCIES = $(top_builddir)/lib/libsefs.so