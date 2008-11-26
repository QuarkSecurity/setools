wrappedso_DATA = libapol_tcl.so.@libapol_version@
wrappedso_SONAME = $(wrappedso_DATA)
wrappedsodir = $(libdir)/setools/apol_tcl

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

bin_SCRIPTS = apol

dist_noinst_DATA = apol_tcl.i apol_tcl.cc apol.png foo_module.tcl
BUILT_SOURCES = apol_tcl_wrap.cc mkIndex.tcl init.tcl

dist_setools_DATA = apol_help.html \
	domaintrans_help.html \
	file_relabel_help.html \
	infoflow_help.html \
	types_relation_help.html \
	apol.gif

EXTRA_DIST = \
	analysis_tab.tcl \
	classes_perms_tab.tcl \
	common_widgets.tcl \
	cond_bools_tab.tcl \
	cond_rules_tab.tcl \
	context_dialog.tcl \
	context_selector.tcl \
	directflow_module.tcl \
	domaintrans_module.tcl \
	file_contexts_tab.tcl \
	file_relabel_module.tcl \
	find.tcl \
	fscontexts_tab.tcl \
	goto.tcl \
	head.tcl \
	html_viewer.tcl \
	initial_sids_tab.tcl \
	level_dialog.tcl \
	mls_tab.tcl \
	netcontexts_tab.tcl \
	open_policy_dialog.tcl \
	perms_map.tcl \
	policyconf.tcl \
	polsearch_module.tcl \
	prefs.tcl \
	progress_dialog.tcl \
	range_dialog.tcl \
	range_selector.tcl \
	range_trans.tcl \
	rbac_tab.tcl \
	roles_tab.tcl \
	terules_tab.tcl \
	transflow_module.tcl \
	types_relation_module.tcl \
	types_tab.tcl \
	users_tab.tcl \
	util.tcl \
	top.tcl
# top.tcl must be last one written because it spawns the rest of the script

TCL_STRIP_FILES = $(patsubst %,$(srcdir)/%,$(filter-out head.tcl,$(EXTRA_DIST)))
DEPENDENCIES = \
	$(top_builddir)/lib/libqpol.so \
	$(top_builddir)/lib/libapol.so \
	$(top_builddir)/lib/libsefs.so \
	$(top_builddir)/lib/libpolsearch.so \
	$(top_builddir)/src/qpol/tcl/libtqpol.so \
	$(top_builddir)/src/apol/tcl/libtapol.so \
	$(top_builddir)/src/sefs/tcl/libtsefs.so \
	$(top_builddir)/src/polsearch/tcl/libtpolsearch.so \
	$(top_builddir)/config.tcl

AM_CXXFLAGS = @SETOOLS_CXXFLAGS@ -fpic -I$(top_srcdir)
AM_LDFLAGS = @SETOOLS_LDFLAGS@ \
	@SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@

apol_tcl_wrap.cc: apol_tcl.i $(DEPENDENCIES)
	$(SWIG) -c++ $(SWIG_TCL_OPT) -pkgversion @libapol_version@ -o $@ @SWIG_FLAGS@ $<

$(wrappedso_DATA): apol_tcl.cc apol_tcl_wrap.cc
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)

$(package_SCRIPTS): $(wrappedso_DATA) mkIndex.tcl
	cat mkIndex.tcl | LD_LIBRARY_PATH=$(top_builddir)/lib $(TCLSH_PROG)
	$(mkdir_p) apol_tcl
	cp $< $@ apol_tcl

mkIndex.tcl: $(wrappedso_DATA) Makefile
	@echo "lappend auto_path $(top_builddir)/src/apol/tcl $(top_builddir)/src/sefs/tcl" > $@
	@echo "package require apol" >> $@
	@echo "package require sefs" >> $@
	@echo "pkg_mkIndex . $<" >> $@

TCL_AUTOPATH = @TCL_AUTOPATH@

init.tcl: Makefile
	@echo "proc tcl_config_init_libraries {} {" > $@
	@echo "    global auto_path" >> $@
	@echo "    lappend auto_path $(TCL_AUTOPATH)" >> $@
	@echo "    print_init \"Initializing libqpol... \"" >> $@
	@echo "    package require qpol @libqpol_version@" >> $@
	@echo "    print_init \"done.\nInitializing libapol... \"" >> $@
	@echo "    package require apol @libapol_version@" >> $@
	@echo "    print_init \"done.\nInitializing libsefs... \"" >> $@
	@echo "    package require sefs @libsefs_version@" >> $@
	@echo "    print_init \"done.\nInitializing libpolsearch... \"" >> $@
	@echo "    package require polsearch @libpolsearch_version@" >> $@
	@echo "    print_init \"done.\nInitializing libapol_tcl... \"" >> $@
	@echo "    package require apol_tcl @libapol_version@" >> $@
	@echo "    print_init \"done.\nInitializing Tk... \"" >> $@
	@echo "    package require Tk" >> $@
	@echo "    print_init \"done.\nInitializing Tkhtml... \"" >> $@
	@echo "    package require Tkhtml 3.0" >> $@
	@echo "    print_init \"done.\n\"" >> $@
	@echo "}" >> $@
	@echo "proc tcl_config_get_install_dir {} {" >> $@
	@echo "    return \"${setoolsdir}\"" >> $@
	@echo "}" >> $@

$(bin_SCRIPTS): $(package_SCRIPTS) head.tcl init.tcl $(top_builddir)/config.tcl $(TCL_STRIP_FILES)
	cat $(srcdir)/head.tcl init.tcl $(top_builddir)/config.tcl > $@
	cat $(TCL_STRIP_FILES) | perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' >> $@
	chmod u+x $@

%.tcl:
# do nothing

CLEANFILES = $(packages_SCRIPTS) $(bin_SCRIPTS) $(BUILT_SOURCES)

MOSTLYCLEANFILES = $(wrappedso_DATA) $(package_SCRIPTS) apol_tcl/$(wrappedso_DATA) apol_tcl/$(package_SCRIPTS)
