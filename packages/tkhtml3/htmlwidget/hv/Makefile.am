hv3_DATA = hv3-wrapped.tcl
hv3dir = $(setoolsdir)

EXTRA_DIST = \
	combobox.tcl \
	hv3.tcl \
	hv3_browser.tcl \
	hv3_doctype.tcl \
	hv3_dom.tcl \
	hv3_file.tcl \
	hv3_form.tcl \
	hv3_frameset.tcl \
	hv3_object.tcl \
	hv3_profile.tcl \
	hv3_request.tcl \
	hv3_widgets.tcl

dist_noinst_DATA = license.txt snit.tcl

if INSTALL_SNIT
  SNIT_FILES = snit.tcl
endif

hv3-wrapped.tcl: $(SNIT_FILES) $(EXTRA_DIST)
	cat $^ > $@

CLEANFILES = hv3-wrapped.tcl
