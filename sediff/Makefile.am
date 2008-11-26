setoolsdir = @setoolsdir@

dist_setools_DATA = sediff_help.txt sediffx.glade \
	sediffx.png sediffx-small.png

if BUILD_GUI
  MAYBE_SEDIFFX = sediffx
endif

bin_PROGRAMS = sediff $(MAYBE_SEDIFFX)

AM_CFLAGS = @SETOOLS_CFLAGS@
AM_LDFLAGS = @SETOOLS_LDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@

sediff_CFLAGS = $(AM_CFLAGS)
sediffx_CFLAGS = $(AM_CFLAGS) \
	@GTK_CFLAGS@ @PIXBUF_CFLAGS@ @GLADE_CFLAGS@ @GTHREAD_CFLAGS@

# need the -rdynamic flag below - glade uses dlopen() upon sediffx callbacks
sediffx_LDFLAGS = $(AM_LDFLAGS) \
	@GTK_LIBS@ @PIXBUF_LIBS@ @GLADE_LIBS@ @GTHREAD_LIBS@ @XML_LIBS@ \
	-rdynamic

DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libpoldiff.so

sediff_SOURCES = sediff.c

sediffx_SOURCES = \
	find_dialog.c find_dialog.h \
	open_policies_dialog.c open_policies_dialog.h \
	policy_view.c policy_view.h \
	progress.c progress.h \
	remap_types_dialog.c remap_types_dialog.h \
	result_item.c result_item.h \
	result_item_render.c result_item_render.h \
	results.c results.h \
	select_diff_dialog.c select_diff_dialog.h \
	toplevel.c toplevel.h \
	utilgui.c utilgui.h \
	sediffx.c sediffx.h
