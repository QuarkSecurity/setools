wrappedso_DATA = libtpolsearch.so.@libpolsearch_version@
wrappedso_SONAME = @libpolsearch_tswig_soname@
short_name = libtpolsearch.so
wrappedsodir = $(libdir)/setools/polsearch

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../polsearch.i
BUILT_SOURCES = polsearch_wrap.cc

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @TCL_LIB_SPEC@ \
	@POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libsefs.so \
	$(top_builddir)/lib/libpolsearch.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) -c++ $(SWIG_TCL_OPT) -pkgversion @libpolsearch_version@ -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/lib $(TCLSH_PROG)
	chmod 644 $@
	$(mkdir_p) polsearch
	cp $(wrappedso_DATA) $@ polsearch

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) polsearch/$(wrappedso_DATA) polsearch/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)
