SUBDIRS = lib modules

setoolsdir = @setoolsdir@
bin_PROGRAMS = sechecker

dist_setools_DATA = \
	sechecker_help.txt

profilesdir = @sechecker_profile_dir@
dist_profiles_DATA = \
	profiles/all.profile \
	profiles/all-no-mls.profile \
	profiles/analysis.profile \
	profiles/development.profile \
	profiles/sechecker.dtd

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -I${srcdir}/lib \
	-DPROFILE_INSTALL_DIR='"${sechecker_profile_dir}"' \
	-DMODULES_INSTALL_DIR='"${sechecker_modules_dir}"'
AM_LDFLAGS = @SETOOLS_LDFLAGS@ -export-dynamic

sechecker_LDADD = lib/libsechecker.la \
	@SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@

sechecker_DEPENDENCIES = \
	$(top_builddir)/lib/libsefs.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libqpol.so

sechecker_SOURCES = \
	main.cc
