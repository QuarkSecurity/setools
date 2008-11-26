wrappedso_DATA = _qpol.so.@libqpol_version@
wrappedso_SONAME = @libqpol_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

pkgpython_PYTHON = __init__.py
wrappedpy_DATA = qpol.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../qpol.i
BUILT_SOURCES = qpol_wrap.c

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@ @QPOL_LIB_FLAG@ @PYTHON_LDFLAGS@
DEPENDENCIES = $(top_builddir)/lib/libqpol.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _qpol.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _qpol.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_qpol.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _qpol.so qpol.pyc
