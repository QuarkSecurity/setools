modulesdir = @profile_install_dir@
modules_DATA = \
	domain_and_file.so \
	find_domains.so \
	find_file_types.so

EXTRA_DIST = \
	domain_and_file.cc domain_and_file.hh \
	find_domains.cc find_domains.hh \
	find_file_types.cc find_file_types.hh

#dist_noinst_DATA = \
#	template/profiles.readme \
#	template/template.howto \
#	template/xx.c \
#	template/xx.h

AM_CXXFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ @POLSEARCH_CFLAGS@ @XML_CFLAGS@ \
	-DPROFILE_INSTALL_DIR='"${profile_install_dir}"' \
	-I$(top_srcdir)/sechecker -fPIC
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@

%.so: %.cc %.hh
	$(CXX) --shared $(AM_CXXFLAGS) $(CXXFLAGS) $(AM_LDFLAGS) $(LDFLAGS) $(LDADD) -I$(srcdir) -o $@ $<

MOSTLYCLEANFILES = $(modules_DATA)
