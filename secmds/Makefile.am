# various setools command line tools

bin_PROGRAMS = seinfo sesearch findcon replcon indexcon

# These are for indexcon so that it is usable on machines without setools
STATICLIBS = $(top_builddir)/src/sefs/libsefs.a $(top_builddir)/src/apol/libapol.a $(top_builddir)/src/qpol/libqpol.a -lsqlite3

AM_CFLAGS = @SETOOLS_CFLAGS@
AM_CXXFLAGS = @SETOOLS_CXXFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libapol.so $(top_builddir)/lib/libqpol.so

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

indexcon_SOURCES = indexcon.cc
indexcon_LDADD = @SELINUX_LIB_FLAG@ $(STATICLIBS)
indexcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/lib/libsefs.so

findcon_SOURCES = findcon.cc
findcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
findcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/lib/libsefs.so

replcon_SOURCES = replcon.cc
replcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
replcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/lib/libsefs.so
