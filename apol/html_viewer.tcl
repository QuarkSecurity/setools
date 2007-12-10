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
    variable widgets
}

proc Apol_HTML::init {} {
    if {[catch {package require snit 1.0}]} {
	source [file join [tcl_config_get_install_dir] snit.tcl]
    }
    package require http
    catch {::http::geturl}

    # Suppress the [source] command while loading hv3, because those
    # files have already been concatenated into hv3-wrapped.tcl.  Also
    # suppress the requirement of sqlite3, for bookmarks do not exist.
    rename ::source ::real_source
    proc ::source {f} {}
    rename ::package ::real_package
    proc ::package {args} {
        if {[lindex $args end] != "sqlite3"} {
            eval ::real_package $args
        }
    }
    uplevel \#0 ::real_source [file join [tcl_config_get_install_dir] hv3-wrapped.tcl]
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

# Suppress / override hv3 functions so that it works with apol.
namespace eval hv3 {
    namespace eval profile {
        proc instrument {args} {}
    }
    proc dbinit {args} {}
    proc the_visited_db {args} {}
    proc cookies_scheme_init {args} {}
    proc the_cookie_manager {args} {}
    proc cookiemanager {args} {}
}

proc Apol_HTML::_create_viewer {} {
    variable viewer
    variable widgets
    set viewer [Dialog .apol_html_viewer -modal none -parent . \
                    -transient false -cancel 0 -default 0 -separator 1]

    set f [$viewer getframe]
    frame $f.toolbar
    pack $f.toolbar -fill x -side top
    set widgets(back) [::hv3::toolbutton $f.toolbar.back -text Back \
                           -relief raised -state disabled]
    set widgets(forward) [::hv3::toolbutton $f.toolbar.forward -text Forward \
                              -relief raised -state disabled]
    set search [::hv3::toolbutton $f.toolbar.search -text Search \
                    -relief raised -command Apol_HTML::_searchButton]
    set close [::hv3::toolbutton $f.toolbar.close -text Close \
                   -relief raised -command [list destroy $viewer]]
    pack $widgets(back) $widgets(forward) $search $close -side left

    Separator $f.sep
    pack $f.sep -fill x -side top

    set widgets(browser) [::hv3::browser $f.browser]
    pack $widgets(browser) -fill both -expand 1
    $widgets(browser) configure -backbutton $widgets(back)
    $widgets(browser) configure -forwardbutton $widgets(forward)
    [$widgets(browser) hv3] configure -isvisitedcmd Apol_HTML::_isLinkVisited
    trace add variable [$widgets(browser) titlevar] write Apol_HTML::_titleChanged
}

proc Apol_HTML::_goto {args} {
    puts "got a goto: |$args|"
}

proc Apol_HTML::_searchButton {} {
    # FIX ME
}

# TODO: add right-click select/all commands

proc Apol_HTML::_isLinkVisited {uri} {
    return 0
}

proc Apol_HTML::_titleChanged {name1 name2 op} {
    variable viewer
    variable widgets
    wm title $viewer [set [$widgets(browser) titlevar]]
}
