SUBDIRS = hv

if INSTALL_TKHTML
  MAYBE_LIBTKHTML = libTkhtml3.a
  MAYBE_LIBTKHTMLSO = libTkhtml3.so.3.0
endif

lib_LIBRARIES = $(MAYBE_LIBTKHTML)

libTkhtml3so_DATA = $(MAYBE_LIBTKHTMLSO)
libTkhtml3so_SONAME = libTkhtml3.so.3
short_name = libTkhtml3.so
libTkhtml3sodir = $(libdir)/setools/libTkhtml3

package_SCRIPTS = pkgIndex.tcl
packagedir = $(libTkhtml3sodir)

libTkhtml3_a_SOURCES = \
	src/css.c src/css.h \
	src/cssInt.h \
	src/cssdynamic.c \
	src/cssparser.c \
	src/csssearch.c \
	src/html.h \
	src/htmldecode.c \
	src/htmldraw.c \
	src/htmlfloat.c \
	src/htmlhash.c \
	src/htmlimage.c \
	src/htmlinline.c \
	src/htmllayout.c src/htmllayout.h \
	src/htmlmacros.h \
	src/htmlparse.c \
	src/htmlprop.c src/htmlprop.h \
	src/htmlstyle.c \
	src/htmltagdb.c \
	src/htmltable.c \
	src/htmltcl.c \
	src/htmltext.c \
	src/htmltree.c \
	src/htmlutil.c \
	src/restrack.c src/restrack.h \
	src/swproc.c src/swproc.h

dist_noinst_DATA = \
	src/cssprop.tcl \
	src/html.css src/mkdefaultstyle.tcl \
	src/tkhtml.tcl src/tokenlist.txt

nodist_libTkhtml3_a_SOURCES = \
	cssprop.c cssprop.h \
	htmldefaultstyle.c \
	htmltokens.h

BUILT_SOURCES = \
	cssprop.c cssprop.h \
	htmldefaultstyle.c \
	htmltokens.c htmltokens.h

EXTRA_DIST = aclocal.m4 ChangeLog COMPILE.txt COPYRIGHT doc linux-gcc.mk \
	main.mk mingw.mk nightly.sh puppy.sh README tclconfig webpage

libTkhtml3so_OBJS = $(notdir $(patsubst %.c,%.o,$(filter %.c,$(libTkhtml3_a_SOURCES) $(nodist_libTkhtml3_a_SOURCES))))

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SWIG_TCL_CFLAGS@ -I src -fpic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

cssprop.c: src/cssprop.tcl
	$(TCLSH_PROG) $<

cssprop.h: cssprop.c

htmldefaultstyle.c: src/mkdefaultstyle.tcl src/tkhtml.tcl src/html.css 
	$(TCLSH_PROG) $< > $@

htmltokens.c: src/tokenlist.txt
	$(TCLSH_PROG) $<

htmltokens.h: htmltokens.c

$(libTkhtml3so_DATA): $(libTkhtml3so_OBJS)
	$(CC) -shared -o $@ $^ $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(libTkhtml3so_SONAME) -Ltk
	$(LN_S) -f $@ $(libTkhtml3so_SONAME)

# Create the pkgIndex by hand.  As that libTkhtml makes calls to Tk,
# autogeneration via pkg_mkIndex would necessitate a graphical
# environment.  This causes problems if libTkhtml were to be built
# from a console.
# echo "pkg_mkIndex -load Tk . $^ ; exit" | $(WISH_PROG)
$(package_SCRIPTS): $(libTkhtml3so_DATA)
	echo "package ifneeded Tkhtml 3.0 [list load [file join \$$dir libTkhtml3.so.3.0]]" > $@
	chmod 644 $@
	$(mkdir_p) libTkhtml3
	cp $^ $@ libTkhtml3

install-data-hook:
	cd $(DESTDIR)$(libTkhtml3sodir) && $(LN_S) -f $(libTkhtml3so_DATA) $(libTkhtml3so_SONAME)

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov $(libTkhtml3so_DATA) $(libTkhtml3so_SONAME)

uninstall-local:
	-rm -rf $(DESTDIR)$(libTkhtml3sodir)/$(libTkhtml3so_DATA) $(DESTDIR)$(libTkhtml3sodir)/$(libTkhtml3so_SONAME)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(libTkhtml3so_DATA) $(libTkhtml3so_SONAME) \
	libTkhtml3/$(libTkhtml3so_DATA) libTkhtml3/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)