modulesdir = @profile_install_dir@
modules_DATA = \
	attribs_wo_types.so \
	domain_and_file.so \
	domains_wo_roles.so \
	find_domains.so \
	find_file_types.so \
	find_net_domains.so \
	find_netif_types.so \
	find_node_types.so \
	find_port_types.so \
	inc_mount.so \
	roles_wo_allow.so \
	roles_wo_types.so \
	roles_wo_users.so \
	spurious_audit.so \
	types_wo_allow.so \
	unused_attribs.so \
	users_wo_roles.so

EXTRA_DIST = \
	attribs_wo_types.cc attribs_wo_types.hh \
	domain_and_file.cc domain_and_file.hh \
	domains_wo_roles.cc domains_wo_roles.hh \
	find_domains.cc find_domains.hh \
	find_file_types.cc find_file_types.hh \
	find_net_domains.cc find_net_domains.hh \
	find_netif_types.cc find_netif_types.hh \
	find_node_types.cc find_node_types.hh \
	find_port_types.cc find_port_types.hh \
	inc_mount.cc inc_mount.hh \
	roles_wo_allow.cc roles_wo_allow.hh \
	roles_wo_types.cc roles_wo_types.hh \
	roles_wo_users.cc roles_wo_users.hh \
	spurious_audit.cc spurious_audit.hh \
	types_wo_allow.cc types_wo_allow.hh \
	unused_attribs.cc unused_attribs.hh \
	users_wo_roles.cc users_wo_roles.hh

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
