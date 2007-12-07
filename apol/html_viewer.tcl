# Copyright (C) 2007 Tresys Technology, LLC
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# The HTML viewer uses components from hv3, part of the Tkhtml
# project.  See its associated licensed for copyright issues.  The
# file wraps hv3 into a window suitable for showing help files and
# dynamically generated reports.

namespace eval Apol_HTML {
    variable viewer {}
}

proc Apol_HTML::init {} {
    if {[catch {package require snit 1.0}]} {
	source [file join [tcl_config_get_install_dir] snit.tcl]
    }
    package require http
    catch {::http::geturl}

    # Suppress the [source] command while loading hv3, because those
    # files have already been concatenated into hv3-wrapped.tcl.  Also
    # suppress the requirement of sqlite3, for the history feature is
    # implemented below.
    rename ::source ::real_source
    proc ::source {f} {}
    rename ::package ::real_package
    proc ::package {args} {
        if {[lindex $args end] != "sqlite3"} {
            eval ::real_package $args
        }
    }
    uplevel 1 ::real_source /tmp/setools-install/share/setools-3.4/hv3-wrapped.tcl
    rename ::source {}
    rename ::real_source ::source
    rename ::package {}
    rename ::real_package ::package
}

proc Apol_HTML::view_file {f} {
    variable viewer
    variable widgets
    if {![winfo exists $viewer]} {
        _create_viewer
        $widgets(browser) goto "file://$f"
        $viewer draw {} 0 600x500
    } else {
        raise $viewer
        $widgets(browser) goto "file://$f"
    }
}

#### private stuff below ####

# Suppress the superfluous functions that are shipped with hv3.
namespace eval hv3 {
    namespace eval profile {
        proc instrument {args} {}
    }
    proc dbinit {args} {}
    proc the_visited_db {args} {}
    proc cookies_scheme_init {args} {}
    proc history {args} { return ::hv3::do_nothing }
    proc do_nothing {args} {}
    proc the_cookie_manager {args} {}
    proc cookiemanager {args} {}
}

proc Apol_HTML::_create_viewer {} {
    variable viewer
    variable widgets
    set viewer [Dialog .apol_html_viewer -modal none -parent . \
                    -transient false -cancel 0 -default 0 -separator 1]
    $viewer add -text "Close" -command [list destroy $viewer]

    set f [$viewer getframe]
    frame $f.toolbar
    pack $f.toolbar -fill x -side top
    set widgets(back) [::hv3::toolbutton $f.toolbar.back -text Back \
                           -tooltip "Go Back" -relief raised]
    set widgets(forward) [::hv3::toolbutton $f.toolbar.forward -text Forward \
                              -tooltip "Go Forward" -relief raised]
    set widgets(search) [::hv3::toolbutton $f.toolbar.search -text Search \
                             -tooltip "Search for Text" -relief raised]
    pack $widgets(back) $widgets(forward) $widgets(search) -side left

    Separator $f.sep
    pack $f.sep -fill x -side top

    set widgets(browser) [::hv3::browser $f.browser]
    pack $widgets(browser) -fill both -expand 1
}

#foreach {family size} [list fixed 12] {break}
#        set stylesheet "html \{"
#        append stylesheet "background: white;\n"
#        append stylesheet "font-family: $family;\n"
#        append stylesheet "font-size: ${size}px;\n"
#        append stylesheet "\}"
#        $html style $stylesheet
#        $sw setwidget $html
#        update
#        grid propagate $sw 0
#        pack $sw -expand 1 -fill both -padx 4 -pady 4
#        $infoPopup2 draw
#    $infoPopup2 configure -title stuff
#    $html goto file://$helpfile
