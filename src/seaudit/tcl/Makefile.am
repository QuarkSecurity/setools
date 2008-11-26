wrappedso_DATA = libtseaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_tswig_soname@
short_name = libtseaudit.so
wrappedsodir = $(libdir)/setools/seaudit

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ \
	@SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libseaudit.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libseaudit_version@ -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/lib $(TCLSH_PROG)
	chmod 644 $@
	$(mkdir_p) seaudit
	cp $(wrappedso_DATA) $@ seaudit

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) seaudit/$(wrappedso_DATA) seaudit/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)
