noinst_LTLIBRARIES = libsechecker.la

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ @XML_CFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@

libsechecker_la_DEPENDENCIES = \
	$(top_builddir)/lib/libsefs.so \
	$(top_builddir)/lib/libpolsearch.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libqpol.so

libsechecker_la_SOURCES = \
	sechecker.cc sechecker.hh \
	module.cc module.hh \
	option.cc option.hh \
	profile.cc profile.hh \
	report.cc report.hh \
	requirement.cc requirement.hh \
	result.cc result.hh \
	util.cc util.hh

