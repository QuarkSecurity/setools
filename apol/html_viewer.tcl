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
    variable popup {}
    variable widgets
    variable prev_save {}
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
        _locationChanged - - -
    } else {
        raise $viewer
    }
    $widgets(browser) goto "file://$f"
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
    set viewer [toplevel .apol_html_viewer -width 600 -height 500]
    wm group $viewer .

    set f $viewer
    frame $f.toolbar
    pack $f.toolbar -fill x -side top
    set back [::hv3::toolbutton $f.toolbar.back -text Back \
                  -relief raised -state disabled]
    set forward [::hv3::toolbutton $f.toolbar.forward -text Forward \
                     -relief raised -state disabled]
    set widgets(copy) [::hv3::toolbutton $f.toolbar.copy -text Copy \
                           -relief raised -state disabled \
                           -command Apol_HTML::_copy]
    set search [::hv3::toolbutton $f.toolbar.search -text Search \
                    -relief raised -command Apol_HTML::_searchButton]
    set widgets(save) [::hv3::toolbutton $f.toolbar.save -text Save \
                           -relief raised -command Apol_HTML::_save]
    set close [::hv3::toolbutton $f.toolbar.close -text Close \
                   -relief raised -command [list destroy $viewer]]
    pack $back $forward $widgets(copy) $search $widgets(save) $close -side left

    Separator $f.sep
    pack $f.sep -fill x -side top

    set widgets(browser) [::hv3::browser $f.browser -zoom 1.33]
    pack $widgets(browser) -fill both -expand 1
    $widgets(browser) configure -backbutton $back
    $widgets(browser) configure -forwardbutton $forward
    [$widgets(browser) hv3] configure -isvisitedcmd Apol_HTML::_isLinkVisited
    trace add variable [$widgets(browser) titlevar] write Apol_HTML::_titleChanged
    trace add variable [$widgets(browser) locationvar] write Apol_HTML::_locationChanged
    bind $widgets(browser) <ButtonRelease-1> +Apol_HTML::_updateCopyButton
    bind $widgets(browser) <Button-3> [list Apol_HTML::_popup %W %x %y]
}

proc Apol_HTML::_searchButton {} {
    variable widgets
    $widgets(browser) Find
}

proc Apol_HTML::_isLinkVisited {uri} {
    return 0
}

proc Apol_HTML::_titleChanged {name1 name2 op} {
    variable viewer
    variable widgets
    wm title $viewer [set [$widgets(browser) titlevar]]
}

# Returns a list of three values: the protocol, path (everything
# following the '://'), and a 1 if the path represents a file from the
# SETools install location.
proc Apol_HTML::uri_split {uri} {
    if {[regexp -- {^([^:]+):\/\/(.*)} $uri -> protocol path]} {
        set setoolsdir [tcl_config_get_install_dir]
        if {$protocol == "file" &&
            [string compare -length [string length $setoolsdir] $path $setoolsdir] == 0} {
            list $protocol $path 1
        } else {
            list $protocol $path 0
        }
    } else {
        return {{} {} 0}
    }
}

proc Apol_HTML::_locationChanged {name1 name2 op} {
    variable viewer
    variable widgets
    set uri [set [$widgets(browser) locationvar]]
    foreach {protocol path is_install_file} [uri_split $uri] {break}
    if {$is_install_file} {
        $widgets(save) configure -state disabled
    } else {
        $widgets(save) configure -state normal
    }
}

proc Apol_HTML::_updateCopyButton {} {
    variable widgets
    set hv3 [$widgets(browser) hv3]
    if {[$hv3 selected] != {}} {
        $widgets(copy) configure -state normal
    } else {
        $widgets(copy) configure -state disabled
    }
}

proc Apol_HTML::_popup {path x y} {
    focus $path
    # create a global popup menu widget if one does not already exist
    variable popup
    if {![winfo exists $popup]} {
        set popup [menu .apol_html_popup -tearoff 0]
    }
    set callbacks {
        {"Copy" Apol_HTML::_copy}
        {"Select All" Apol_HTML::_selectAll}
    }
    ApolTop::popup $path $x $y $popup $callbacks $path
}

proc Apol_HTML::_copy {path} {
    variable widgets
    set hv3 [$widgets(browser) hv3]
    set data [$hv3 selected]
    if {$data != {}} {
        clipboard clear
        clipboard append -- $data
    }
}

proc Apol_HTML::_selectAll {path} {
    variable widgets
    set hv3 [$widgets(browser) hv3]
    $hv3 selectall
    $widgets(copy) configure -state normal
}

proc Apol_HTML::_save {} {
    variable viewer
    variable widgets
    variable prev_save
    set name [tk_getSaveFile -title "Save Page" -parent $viewer -initialfile $prev_save]
    if {$name != {}} {
        set uri [set [$widgets(browser) locationvar]]
        puts "would save $uri"
    }
}

# Callback invoked from hv3_browser when the escape key is pressed.
# Note the lack of Apol_HTML namespace.
proc gui_escape {} {
    $Apol_HTML::widgets(browser) escape
}
