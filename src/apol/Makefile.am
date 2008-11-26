if DO_SWIGIFY_PYTHON
  MAYBE_PYSWIG = python
endif

if DO_SWIGIFY_JAVA
  MAYBE_JSWIG = java
endif

if DO_SWIGIFY_TCL
  MAYBE_TCLSWIG = tcl
endif

SUBDIRS = . $(MAYBE_PYSWIG) $(MAYBE_JSWIG) $(MAYBE_TCLSWIG) tests

dist_noinst_DATA = libapol.map apol.i

lib_LIBRARIES = libapol.a
setoolsdir = @setoolsdir@

apolso_DATA = libapol.so.@libapol_version@
apolsodir = $(libdir)

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic \
	-DAPOL_LIB_INSTALL_DIR='"${setoolslibdir}"' \
	-DAPOL_INSTALL_DIR='"${setoolsdir}"' \
	-DLIBAPOL_POLICY_INSTALL_DIR='"@selinux_policy_dir@/policy"' \
	-DLIBAPOL_DEFAULT_POLICY='"@selinux_default_policy@"'
AM_LDFLAGS = @SETOOLS_LDFLAGS@

libapol_a_SOURCES = \
	avrule-query.c \
	bool-query.c \
	bst.c \
	class-perm-query.c \
	cond-simplify.c \
	condrule-query.c \
	constraint-query.c \
	context-query.c \
	domain-trans-analysis.c domain-trans-analysis-internal.h \
	fscon-query.c \
	infoflow-analysis.c infoflow-analysis-internal.h \
	isid-query.c \
	mls-query.c \
	mls_level.c \
	mls_range.c \
	netcon-query.c \
	perm-map.c \
	policy.c \
	policy-path.c \
	policy-query.c \
	queue.c \
	range_trans-query.c \
	rbacrule-query.c \
	relabel-analysis.c \
	render.c \
	role-query.c \
	terule-query.c \
	type-query.c \
	types-relation-analysis.c \
	user-query.c \
	util.c \
	vector.c vector-internal.h \
	policy-query-internal.h queue.h

libapol_a_DEPENDENCIES = $(top_builddir)/lib/libqpol.so

libapol_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libapol_a_SOURCES)))
LIBAPOL_SONAME = @libapol_soname@

$(apolso_DATA): $(libapol_so_OBJS) libapol.map
	$(CC) -shared -o $@ $(libapol_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBAPOL_SONAME),--version-script=$(srcdir)/libapol.map,-z,defs $(libapol_a_DEPENDENCIES)
	cp -f $@ $(top_builddir)/lib/$@
	$(LN_S) -f $@ $(top_builddir)/lib/@libapol_soname@
	$(LN_S) -f $@ $(top_builddir)/lib/libapol.so

install-data-hook:
	cd $(DESTDIR)$(apolsodir) && $(LN_S) -f $(apolso_DATA) @libapol_soname@
	cd $(DESTDIR)$(apolsodir) && $(LN_S) -f $(apolso_DATA) libapol.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(apolso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(apolsodir)/$(apolso_DATA) $(DESTDIR)$(apolsodir)/@libapol_soname@ $(DESTDIR)$(apolsodir)/libapol.so
