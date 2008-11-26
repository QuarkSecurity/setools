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

dist_noinst_DATA = libseaudit.map seaudit.i

lib_LIBRARIES = libseaudit.a

seauditso_DATA = libseaudit.so.@libseaudit_version@
seauditsodir = $(libdir)

AM_CFLAGS = @SETOOLS_CFLAGS@ @XML_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@

libseaudit_a_SOURCES = \
	avc_message.c \
	bool_message.c \
	filter.c filter-internal.c filter-internal.h \
	load_message.c \
	log.c \
	message.c \
	model.c \
	parse.c \
	report.c \
	sort.c \
	util.c \
	seaudit_internal.h

libseaudit_a_DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so

libseaudit_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libseaudit_a_SOURCES)))
LIBSEAUDIT_SONAME = @libseaudit_soname@

$(seauditso_DATA): $(libseaudit_so_OBJS) libseaudit.map
	$(CC) -shared -o $@ $(libseaudit_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBSEAUDIT_SONAME),--version-script=$(srcdir)/libseaudit.map,-z,defs $(libseaudit_a_DEPENDENCIES) $(XML_LIBS)
	cp -f $@ $(top_builddir)/lib/$@
	$(LN_S) -f $@ $(top_builddir)/lib/@libseaudit_soname@
	$(LN_S) -f $@ $(top_builddir)/lib/libseaudit.so

install-data-hook:
	cd $(DESTDIR)$(seauditsodir) && $(LN_S) -f $(seauditso_DATA) @libseaudit_soname@
	cd $(DESTDIR)$(seauditsodir) && $(LN_S) -f $(seauditso_DATA) libseaudit.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(seauditso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(seauditsodir)/$(seauditso_DATA) $(DESTDIR)$(seauditsodir)/@libseaudit_soname@ $(DESTDIR)$(seauditsodir)/libseaudit.so
