SUBDIRS = modules

setoolsdir = @setoolsdir@
bin_PROGRAMS = sechecker

dist_setools_DATA = \
	sechecker_help.txt

profilesdir = @profile_install_dir@
dist_profiles_DATA = \
	profiles/all.profile \
	profiles/all-no-mls.profile \
	profiles/analysis.profile \
	profiles/development.profile \
	profiles/sechecker.dtd

AM_CXXFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ @POLSEARCH_CFLAGS@ @XML_CFLAGS@ \
	-DPROFILE_INSTALL_DIR='"${profile_install_dir}"' -rdynamic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@
sechecker_DEPENDENCIES = \
	$(top_builddir)/libsefs/src/libsefs.so \
	$(top_builddir)/libpolsearch/src/libpolsearch.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

sechecker_SOURCES = \
	main.cc \
	sechecker.cc sechecker.hh \
	module.cc module.hh \
	option.cc option.hh \
	profile.cc profile.hh \
	report.cc report.hh \
	requirement.cc requirement.hh \
	result.cc result.hh \
	util.cc util.hh

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)
