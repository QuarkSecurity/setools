wrappedso_DATA = libtsefs.so.@libsefs_version@
wrappedso_SONAME = @libsefs_tswig_soname@
short_name = libtsefs.so
wrappedsodir = $(libdir)/setools/sefs

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../sefs.i
BUILT_SOURCES = sefs_wrap.cc

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @TCL_LIB_SPEC@ \
	@SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libsefs.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) -c++ $(SWIG_TCL_OPT) -pkgversion @libsefs_version@ -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/lib $(TCLSH_PROG)
	chmod 644 $@
	$(mkdir_p) sefs
	cp $(wrappedso_DATA) $@ sefs

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) sefs/$(wrappedso_DATA) sefs/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)
