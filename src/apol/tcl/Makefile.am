wrappedso_DATA = libtapol.so.@libapol_version@
wrappedso_SONAME = @libapol_tswig_soname@
short_name = libtapol.so
wrappedsodir = $(libdir)/setools/apol

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../apol.i
BUILT_SOURCES = apol_wrap.c

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_SPEC@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libapol_version@ -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/lib $(TCLSH_PROG)
	chmod 644 $@
	$(mkdir_p) apol
	cp $(wrappedso_DATA) $@ apol

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) apol/$(wrappedso_DATA) apol/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)
