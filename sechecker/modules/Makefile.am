modulesdir = @sechecker_modules_dir@
modules_LTLIBRARIES = \
	attribs_wo_types.la \
	domain_and_file.la \
	domains_wo_roles.la \
	find_domains.la \
	find_file_types.la \
	find_net_domains.la \
	find_netif_types.la \
	find_node_types.la \
	find_port_types.la \
	imp_range_trans.la \
	inc_mount.la \
	roles_wo_allow.la \
	roles_wo_types.la \
	roles_wo_users.la \
	spurious_audit.la \
	types_wo_allow.la \
	unused_attribs.la \
	users_wo_roles.la

attribs_wo_types_la_SOURCES = attribs_wo_types.cc attribs_wo_types.hh
domain_and_file_la_SOURCES = domain_and_file.cc domain_and_file.hh
domains_wo_roles_la_SOURCES = domains_wo_roles.cc domains_wo_roles.hh
find_domains_la_SOURCES = find_domains.cc find_domains.hh
find_file_types_la_SOURCES = find_file_types.cc find_file_types.hh
find_net_domains_la_SOURCES = find_net_domains.cc find_net_domains.hh
find_netif_types_la_SOURCES = find_netif_types.cc find_netif_types.hh
find_node_types_la_SOURCES = find_node_types.cc find_node_types.hh
find_port_types_la_SOURCES = find_port_types.cc find_port_types.hh
imp_range_trans_la_SOURCES = imp_range_trans.cc imp_range_trans.hh
inc_mount_la_SOURCES = inc_mount.cc inc_mount.hh
roles_wo_allow_la_SOURCES = roles_wo_allow.cc roles_wo_allow.hh
roles_wo_types_la_SOURCES = roles_wo_types.cc roles_wo_types.hh
roles_wo_users_la_SOURCES = roles_wo_users.cc roles_wo_users.hh
spurious_audit_la_SOURCES = spurious_audit.cc spurious_audit.hh
types_wo_allow_la_SOURCES = types_wo_allow.cc types_wo_allow.hh
unused_attribs_la_SOURCES = unused_attribs.cc unused_attribs.hh
users_wo_roles_la_SOURCES = users_wo_roles.cc users_wo_roles.hh

#dist_noinst_DATA = \
#	template/profiles.readme \
#	template/template.howto \
#	template/xx.c \
#	template/xx.h

AM_CXXFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ @POLSEARCH_CFLAGS@ @XML_CFLAGS@ \
	-DPROFILE_INSTALL_DIR='"${profile_install_dir}"' \
	-I$(top_srcdir)/sechecker/lib -fPIC
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ -module

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@

MOSTLYCLEANFILES = $(modules_DATA)
