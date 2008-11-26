wrappedso_DATA = _seaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

wrappedpy_DATA = seaudit.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @PYTHON_LDFLAGS@ @XML_LIBS@ \
	@SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libseaudit.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _seaudit.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _seaudit.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_seaudit.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _seaudit.so seaudit.pyc
