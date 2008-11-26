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

dist_noinst_DATA = libsefs.map sefs.i

lib_LIBRARIES = libsefs.a

sefsso_DATA = libsefs.so.@libsefs_version@
sefssodir = $(libdir)

AM_CFLAGS = @SETOOLS_CFLAGS@ @SQLITE3_CFLAGS@ -fpic
AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ @SQLITE3_CFLAGS@ -fpic
AM_LDFLAGS = @SETOOLS_LDFLAGS@

libsefs_a_SOURCES = \
	db.cc \
	entry.cc \
	fcfile.cc \
	fclist.cc \
	filesystem.cc \
	new_ftw.c new_ftw.h \
	query.cc \
	sefs_internal.hh \
	util.c

libsefs_a_DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so

libsefs_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libsefs_a_SOURCES))) $(patsubst %.cc,%.o,$(filter %.cc,$(libsefs_a_SOURCES)))
libsefs_so_OBJS += $(patsubst %.c,libsqlite_a-%.o,$(filter %.c,$(notdir $(libsqlite_a_SOURCES))))

LIBSEFS_SONAME = @libsefs_soname@

$(sefsso_DATA): $(libsefs_so_OBJS) libsefs.map
	$(CXX) -shared -o $@ $(libsefs_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBSEFS_SONAME),--version-script=$(srcdir)/libsefs.map,-z,defs $(libsefs_a_DEPENDENCIES) $(SQLITE3_LIBS) -lselinux -lsepol
	cp -f $@ $(top_builddir)/lib/$@
	$(LN_S) -f $@ $(top_builddir)/lib/@libsefs_soname@
	$(LN_S) -f $@ $(top_builddir)/lib/libsefs.so

install-data-hook:
	cd $(DESTDIR)$(sefssodir) && $(LN_S) -f $(sefsso_DATA) @libsefs_soname@
	cd $(DESTDIR)$(sefssodir) && $(LN_S) -f $(sefsso_DATA) libsefs.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(sefsso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(sefssodir)/$(sefsso_DATA) $(DESTDIR)$(sefssodir)/@libsefs_soname@ $(DESTDIR)$(sefssodir)/libsefs.so
