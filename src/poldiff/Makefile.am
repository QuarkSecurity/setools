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

dist_noinst_DATA = libpoldiff.map poldiff.i writing-diffs-HOWTO

lib_LIBRARIES = libpoldiff.a

poldiffso_DATA = libpoldiff.so.@libpoldiff_version@
poldiffsodir = $(libdir)

AM_CFLAGS = @SETOOLS_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@

libpoldiff_a_SOURCES = \
	poldiff.c \
	attrib_diff.c attrib_internal.h \
	avrule_diff.c avrule_internal.h \
	bool_diff.c bool_internal.h \
	cat_diff.c cat_internal.h \
	class_diff.c class_internal.h \
	level_diff.c level_internal.h \
	range_diff.c range_internal.h \
	range_trans_diff.c range_trans_internal.h \
	rbac_diff.c rbac_internal.h \
	role_diff.c role_internal.h \
	terule_diff.c terule_internal.h \
	type_diff.c type_internal.h \
	user_diff.c user_internal.h \
	poldiff_internal.h \
	type_map.c type_map_internal.h \
	util.c

libpoldiff_a_DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so

libpoldiff_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libpoldiff_a_SOURCES)))
LIBPOLDIFF_SONAME = @libpoldiff_soname@

$(poldiffso_DATA): $(libpoldiff_so_OBJS) libpoldiff.map
	$(CC) -shared -o $@ $(libpoldiff_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBPOLDIFF_SONAME),--version-script=$(srcdir)/libpoldiff.map,-z,defs $(libpoldiff_a_DEPENDENCIES)
	cp -f $@ $(top_builddir)/lib/$@
	$(LN_S) -f $@ $(top_builddir)/lib/@libpoldiff_soname@
	$(LN_S) -f $@ $(top_builddir)/lib/libpoldiff.so

install-data-hook:
	cd $(DESTDIR)$(poldiffsodir) && $(LN_S) -f $(poldiffso_DATA) @libpoldiff_soname@
	cd $(DESTDIR)$(poldiffsodir) && $(LN_S) -f $(poldiffso_DATA) libpoldiff.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(poldiffso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(poldiffsodir)/$(poldiffso_DATA) $(DESTDIR)$(poldiffsodir)/@libpoldiff_soname@ $(DESTDIR)$(poldiffsodir)/libpoldiff.so
