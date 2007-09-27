#  Copyright (C) 2007 Tresys Technology, LLC
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

# This module implements the polsearch user interface for symbols.

namespace eval Apol_Analysis_polsearch {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_polsearch" "Symbol Search"
}

proc Apol_Analysis_polsearch::create {options_frame} {
    variable queries
    variable matches
    variable widgets

    _staticInitializeVals
    _reinitializeVals

    set req_f [frame $options_frame.req]
    pack $req_f -expand 0 -fill x -padx 4
    set l1 [label $req_f.l1 -text "Find all "]
    set qmb [menubutton $req_f.q -bd 2 -relief raised -indicatoron 1 -width 16 \
                -textvariable Apol_Analysis_polsearch::vals(query_label)]
    set menu [menu $qmb.m -type normal -tearoff 0]
    $qmb configure -menu $menu
    foreach {v l} $queries {
        $menu add radiobutton -label $l -value $v \
            -command [list Apol_Analysis_polsearch::_toggleQuery update] \
            -variable Apol_Analysis_polsearch::vals(query)
    }
    set l2 [label $req_f.l2 -text " that match "]
    set mmb [menubutton $req_f.m -bd 2 -relief raised -indicatoron 1 -width 10 \
                -textvariable Apol_Analysis_polsearch::vals(match_label)]
    set menu [menu $mmb.m -type normal -tearoff 0]
    $mmb configure -menu $menu
    foreach key [array names matches] {
        $menu add radiobutton -label $matches($key) -value $key \
            -command [list Apol_Analysis_polsearch::_toggleMatch] \
            -variable Apol_Analysis_polsearch::vals(match)
    }
    set l3 [label $req_f.l3 -text " such that:"]
    pack $l1 $qmb $l2 $mmb $l3 -side left -expand 0

    set sw [ScrolledWindow $options_frame.sw -auto horizontal]
    set widgets(rules) [ScrollableFrame $sw.rules -areaheight 0 -areawidth 0 \
                            -constrainedheight 0 -constrainedwidth 0 \
                            -width 500 -height 100 \
                            -bg [Apol_Prefs::getPref active_bg]]
    $sw setwidget $widgets(rules)
    pack $sw -expand 1 -fill both -padx 4 -pady 4

    set widgets(bb) [ButtonBox $options_frame.bb -homogeneous 1 -padx 4 \
                         -state disabled]
    $widgets(bb) add -text "Continue" -state disabled \
        -command Apol_Analysis_polsearch::_add_child_button
    $widgets(bb) add -text "Add" -state disabled \
        -command Apol_Analysis_polsearch::_add
    $widgets(bb) add -text "Remove" -state disabled \
        -command Apol_Analysis_polsearch::_remove
    pack $widgets(bb) -expand 0 -fill none -anchor e -padx 4
}

proc Apol_Analysis_polsearch::open {} {
    # do nothing
}

proc Apol_Analysis_polsearch::close {} {
    _reinitializeVals
    _reinitializeWidgets
}

proc Apol_Analysis_polsearch::getInfo {} {
    return "FIX ME: Does stuff."
}

proc Apol_Analysis_polsearch::newAnalysis {} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    if {[catch {_analyze} results]} {
        return $results
    }
    set f [_createResultsDisplay]
    _renderResults $f $results
    return {}
}


proc Apol_Analysis_polsearch::updateAnalysis {f} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    if {[catch {_analyze} results]} {
        return $results
    }
    _clearResultsDisplay $f
    _renderResults $f $results
    return {}
}

proc Apol_Analysis_polsearch::reset {} {
    _reinitializeVals
    _reinitializeWidgets
}

proc Apol_Analysis_polsearch::switchTab {query_options} {
    variable vals
    array set vals $query_options
    _reinitializeWidgets
}

proc Apol_Analysis_polsearch::saveQuery {channel} {
    variable vals
    variable widgets
    set vals(serialized_tests) [_serialize_tests]
    foreach {key value} [array get vals] {
        switch -glob -- $key {
            match_label -
            prev_query -
            query_label -
            t:*:* {
                # do nothing
            }
            default {
                puts $channel "$key $value"
            }
        }
    }
}

proc Apol_Analysis_polsearch::loadQuery {channel} {
    variable vals

    _reinitializeVals
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        set key {}
        set value {}
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }

    _reinitializeWidgets
}

proc Apol_Analysis_polsearch::getTextWidget {tab} {
    return [$tab.right getframe].res.tb
}


#################### private functions below ####################

proc Apol_Analysis_polsearch::_staticInitializeVals {} {
    variable queries [list \
                          $::POLSEARCH_ELEMENT_ATTRIBUTE "Attributes" \
                          $::POLSEARCH_ELEMENT_BOOL "Booleans" \
                          $::POLSEARCH_ELEMENT_CATEGORY "Categories" \
                          $::POLSEARCH_ELEMENT_CLASS "Classes" \
                          $::POLSEARCH_ELEMENT_COMMON "Common Classes" \
                          $::POLSEARCH_ELEMENT_LEVEL "Levels" \
                          $::POLSEARCH_ELEMENT_ROLE "Roles" \
                          $::POLSEARCH_ELEMENT_TYPE "Types" \
                          $::POLSEARCH_ELEMENT_USER "Users"]

    variable query_constructors
    array set query_constructors [list \
                           $::POLSEARCH_ELEMENT_ATTRIBUTE new_polsearch_attribute_query \
                           $::POLSEARCH_ELEMENT_BOOL new_polsearch_bool_query \
                           $::POLSEARCH_ELEMENT_CATEGORY new_polsearch_cat_query \
                           $::POLSEARCH_ELEMENT_CLASS new_polsearch_class_query \
                           $::POLSEARCH_ELEMENT_COMMON new_polsearch_common_query \
                           $::POLSEARCH_ELEMENT_LEVEL new_polsearch_level_query \
                           $::POLSEARCH_ELEMENT_ROLE new_polsearch_role_query \
                           $::POLSEARCH_ELEMENT_TYPE new_polsearch_type_query \
                           $::POLSEARCH_ELEMENT_USER new_polsearch_user_query]

    variable matches
    array set matches [list \
                           $::POLSEARCH_MATCH_ALL "All Rules" \
                           $::POLSEARCH_MATCH_ANY "Any Rule"]

    variable tests
    array set tests [list \
                         $::POLSEARCH_TEST_NAME "Its name" \
                         $::POLSEARCH_TEST_ALIAS "Its alias" \
                         $::POLSEARCH_TEST_ATTRIBUTES "Its attributes" \
                         $::POLSEARCH_TEST_ROLES "Its roles" \
                         $::POLSEARCH_TEST_AVRULE "There is an AV rule" \
                         $::POLSEARCH_TEST_TERULE "There is a type rule" \
                         $::POLSEARCH_TEST_ROLEALLOW "There is a role allow rule" \
                         $::POLSEARCH_TEST_ROLETRANS "There is a role transition rule" \
                         $::POLSEARCH_TEST_RANGETRANS "There is a range transition rule" \
                         $::POLSEARCH_TEST_FCENTRY "There is a file contexts entry" \
                         $::POLSEARCH_TEST_TYPES "Its types" \
                         $::POLSEARCH_TEST_USERS "Its users" \
                         $::POLSEARCH_TEST_DEFAULT_LEVEL "It has default level" \
                         $::POLSEARCH_TEST_RANGE "Its assigned range" \
                         $::POLSEARCH_TEST_COMMON "Its inherited common" \
                         $::POLSEARCH_TEST_PERMISSIONS "Its assigned permissions" \
                         $::POLSEARCH_TEST_CATEGORIES "Its assigned categories" \
                         $::POLSEARCH_TEST_STATE "Its default state"]

    variable ops
    array set ops [list \
                       $::POLSEARCH_OP_IS "is/are" \
                       $::POLSEARCH_OP_MATCH_REGEX "matches regular expression" \
                       $::POLSEARCH_OP_RULE_TYPE "with rule type" \
                       $::POLSEARCH_OP_INCLUDE "includes" \
                       $::POLSEARCH_OP_AS_SOURCE "with source" \
                       $::POLSEARCH_OP_AS_TARGET "with target" \
                       $::POLSEARCH_OP_AS_CLASS "with class" \
                       $::POLSEARCH_OP_AS_PERM "with permission" \
                       $::POLSEARCH_OP_AS_DEFAULT "with default" \
                       $::POLSEARCH_OP_AS_SRC_TGT "with source or target" \
                       $::POLSEARCH_OP_AS_SRC_TGT_DFLT "with source, target, or default" \
                       $::POLSEARCH_OP_AS_SRC_DFLT "with source or default" \
                       $::POLSEARCH_OP_IN_COND "in a conditional with boolean" \
                       $::POLSEARCH_OP_AS_LEVEL_EXACT "with level" \
                       $::POLSEARCH_OP_AS_LEVEL_DOM "with a level dominating" \
                       $::POLSEARCH_OP_AS_LEVEL_DOMBY "with a level dominated by" \
                       $::POLSEARCH_OP_AS_RANGE_EXACT "with range" \
                       $::POLSEARCH_OP_AS_RANGE_SUPER "with range within" \
                       $::POLSEARCH_OP_AS_RANGE_SUB "with range containing" \
                       $::POLSEARCH_OP_AS_USER "with user" \
                       $::POLSEARCH_OP_AS_ROLE "with role" \
                       $::POLSEARCH_OP_AS_TYPE "with type"]

    variable neg_ops
    array set neg_ops [list \
                       $::POLSEARCH_OP_IS "is/are not" \
                       $::POLSEARCH_OP_MATCH_REGEX "does not match regular expression" \
                       $::POLSEARCH_OP_RULE_TYPE "without rule type" \
                       $::POLSEARCH_OP_INCLUDE "does not include" \
                       $::POLSEARCH_OP_AS_SOURCE "without source" \
                       $::POLSEARCH_OP_AS_TARGET "without target" \
                       $::POLSEARCH_OP_AS_CLASS "without class" \
                       $::POLSEARCH_OP_AS_PERM "without permission" \
                       $::POLSEARCH_OP_AS_DEFAULT "without default" \
                       $::POLSEARCH_OP_AS_SRC_TGT "without source nor target" \
                       $::POLSEARCH_OP_AS_SRC_TGT_DFLT "without source, target, nor default" \
                       $::POLSEARCH_OP_AS_SRC_DFLT "without source nor default" \
                       $::POLSEARCH_OP_IN_COND "not in a conditional with boolean" \
                       $::POLSEARCH_OP_AS_LEVEL_EXACT "without level" \
                       $::POLSEARCH_OP_AS_LEVEL_DOM "with a level not dominating" \
                       $::POLSEARCH_OP_AS_LEVEL_DOMBY "with a level not dominated by" \
                       $::POLSEARCH_OP_AS_RANGE_EXACT "without range" \
                       $::POLSEARCH_OP_AS_RANGE_SUPER "with range not within" \
                       $::POLSEARCH_OP_AS_RANGE_SUB "with range not containing" \
                       $::POLSEARCH_OP_AS_USER "without user" \
                       $::POLSEARCH_OP_AS_ROLE "without role" \
                       $::POLSEARCH_OP_AS_TYPE "without type"]

    variable param_types
    array set param_types [list \
                               $::POLSEARCH_PARAM_TYPE_REGEX _param_expression \
                               $::POLSEARCH_PARAM_TYPE_STR_EXPR _param_str_expr \
                               $::POLSEARCH_PARAM_TYPE_AVRULE_TYPE _param_avrule_type \
                               $::POLSEARCH_PARAM_TYPE_TERULE_TYPE _param_terule_type \
                               $::POLSEARCH_PARAM_TYPE_BOOL _param_bool \
                               $::POLSEARCH_PARAM_TYPE_LEVEL _param_level \
                               $::POLSEARCH_PARAM_TYPE_RANGE _param_range]

    variable elements
    array set elements [list \
                            $::POLSEARCH_ELEMENT_TYPE qpol_type_from_void \
                            $::POLSEARCH_ELEMENT_ATTRIBUTE qpol_type_from_void \
                            $::POLSEARCH_ELEMENT_ROLE qpol_role_from_void \
                            $::POLSEARCH_ELEMENT_USER qpol_user_from_void \
                            $::POLSEARCH_ELEMENT_CLASS qpol_class_from_void \
                            $::POLSEARCH_ELEMENT_COMMON qpol_common_from_void \
                            $::POLSEARCH_ELEMENT_CATEGORY qpol_category_from_void \
                            $::POLSEARCH_ELEMENT_LEVEL qpol_level_from_void \
                            $::POLSEARCH_ELEMENT_BOOL qpol_bool_from_void]

    variable avrules [list $::QPOL_RULE_ALLOW allow \
                          $::QPOL_RULE_AUDITALLOW auditallow \
                          $::QPOL_RULE_DONTAUDIT dontaudit \
                          $::QPOL_RULE_NEVERALLOW neverallow]
    variable terules [list $::QPOL_RULE_TYPE_TRANS type_transition \
                          $::QPOL_RULE_TYPE_MEMBER type_member \
                          $::QPOL_RULE_TYPE_CHANGE type_change]
}

proc Apol_Analysis_polsearch::_reinitializeVals {} {
    variable vals
    array unset vals t:*
    array set vals {
        query {}
        query_label {}
        prev_query {}
        serialized_tests {}
    }
    set vals(match) $::POLSEARCH_MATCH_ALL
    _toggleMatch
}

proc Apol_Analysis_polsearch::_reinitializeWidgets {} {
    variable widgets
    set widgets(line_selected) {-1 -1}
    $widgets(bb) itemconfigure 0 -state disabled
    $widgets(bb) itemconfigure 1 -state disabled
    $widgets(bb) itemconfigure 2 -state disabled
    _toggleQuery init
    _toggleMatch
}

proc Apol_Analysis_polsearch::_toggleQuery {state} {
    variable vals
    variable widgets

    if {$vals(query) == $vals(prev_query) && $state == "update"} {
        # user selected same query type, so do nothing
        return
    }

    set vals(prev_query) $vals(query)

    foreach w [winfo children [$widgets(rules) getframe]] {
        destroy $w
    }
    array unset vals t:*
    array unset widgets t:*
    set widgets(next_test) 0
    set widgets(line_selected) {-1 -1}

    if {$state == "init"} {
        # create all widgets to represent existing tests stored in vals
        if {[info exists vals(serialized_tests)]} {
            foreach test $vals(serialized_tests) {
                _add $test
            }
        }
    } else {
        # clear away all existing tests, then add the initial test
        _add
    }

    variable queries
    if {$vals(query) == {}} {
        set vals(query_label) {}
    } else {
        set i [lsearch $queries $vals(query)]
        set vals(query_label) [lindex $queries [expr {$i+ 1}]]
    }
}

proc Apol_Analysis_polsearch::_toggleMatch {} {
    variable vals
    variable matches
    set vals(match_label) $matches($vals(match))
}

# Called when the user clicks on the add button.
proc Apol_Analysis_polsearch::_add {{existing_test {}}} {
    variable tests
    variable vals
    variable widgets

    set x $widgets(next_test)
    incr widgets(next_test)
    set f [frame [$widgets(rules) getframe].f$x \
               -bg [Apol_Prefs::getPref active_bg] -bd 2]
    set widgets(t:$x:frame) $f
    pack $f -expand 1 -fill x

    set f0 [frame $f.f0 -bd 2]
    set widgets(t:$x:next_op) 1
    set widgets(t:$x:0:frame) $f0

    bind $f0 <Button-1> [list Apol_Analysis_polsearch::_line_selected $x 0]
    pack $f0 -expand 1 -fill x

    set test_mb [menubutton $f0.t -bd 2 -relief raised -indicatoron 1 \
                     -width 24 \
                     -textvariable Apol_Analysis_polsearch::vals(t:$x:test_label)]
    set test_menu [menu $test_mb.m -type normal -tearoff 0]
    $test_mb configure -menu $test_menu
    set op_mb [menubutton $f0.op -bd 2 -relief raised -indicatoron 1 -width 28 \
                   -textvariable Apol_Analysis_polsearch::vals(t:$x:0:op_label)]
    set op_menu [menu $op_mb.m -type normal -tearoff 0]
    $op_mb configure -menu $op_menu
    set pm [PagesManager $f0.param -background [Apol_Prefs::getPref active_bg]]
    pack $test_mb $op_mb $pm -side left -anchor w -padx 4 -pady 4

    # also widgets for each of the different types of parameters
    variable param_types
    foreach p [array names param_types] {
        set f [$pm add $p]
        $param_types($p) create $x 0 $f
    }
    $pm compute_size

    set valid_tests [polsearch_get_valid_tests $vals(query)]
    foreach t $valid_tests {
        $test_menu add radiobutton -label $tests($t) -value $t \
            -command [list Apol_Analysis_polsearch::_test_selected $x $op_menu $pm] \
            -variable Apol_Analysis_polsearch::vals(t:$x:test)
    }
    set vals(t:$x:test_label) $tests([lindex $valid_tests 0])

    set vals(t:$x:num_childops) 0
    set vals(t:$x:test_prev) $::POLSEARCH_TEST_NONE
    if {$existing_test == {}} {
        set vals(t:$x:test) [lindex $valid_tests 0]
        _test_selected $x $op_menu $pm
    } else {
        set vals(t:$x:test) [lindex $existing_test 0]
        _test_selected $x $op_menu $pm [lindex $existing_test 1]
        foreach child [lrange $existing_test 2 end] {
            _add_child $x $child

        }
    }
}

# Called when the user clicks on the continue button.
proc Apol_Analysis_polsearch::_add_child_button {} {
    variable widgets
    set x [lindex $widgets(line_selected) 0]
    _add_child $x
}

proc Apol_Analysis_polsearch::_add_child {x {existing_op {}}} {
    variable tests
    variable vals
    variable widgets

    set y $widgets(t:$x:next_op)
    incr widgets(t:$x:next_op)
    incr vals(t:$x:num_childops)

    set f $widgets(t:$x:frame)
    set f0 [frame $f.f$y -bd 2]
    set widgets(t:$x:$y:frame) $f0

    bind $f0 <Button-1> [list Apol_Analysis_polsearch::_line_selected $x $y]
    pack $f0 -expand 1 -fill x

    set l [label $f0.l -text "  and  "]
    pack $l -expand 1 -fill none -side left -anchor e -padx 4 -pady 4
    set op_mb [menubutton $f0.op -bd 2 -relief raised -indicatoron 1 -width 28 \
                   -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:op_label)]
    set op_menu [menu $op_mb.m -type normal -tearoff 0]
    $op_mb configure -menu $op_menu
    set pm [PagesManager $f0.param -background [Apol_Prefs::getPref active_bg]]
    pack $op_mb $pm -side left -anchor w -padx 4 -pady 4

    # also widgets for each of the different types of parameters
    variable param_types
    foreach p [array names param_types] {
        set f [$pm add $p]
        $param_types($p) create $x $y $f
    }
    $pm compute_size

    _add_op_common $x $y $op_menu $pm $existing_op
}

proc Apol_Analysis_polsearch::_test_selected {x op_menu pm {existing_op {}}} {
    variable tests
    variable vals
    variable widgets

    if {$vals(t:$x:test) == $vals(t:$x:test_prev)} {
        _line_selected $x 0
        return
    }

    foreach f [array names widgets t:$x:\[1-9\]*:frame] {
        foreach w [winfo children $widgets($f)] {
            destroy $w
        }
        destroy $widgets($f)
        array unset widgets $f
    }
    array unset vals t:$x:\[1-9\]*:*

    set vals(t:$x:num_childops) 0
    set vals(t:$x:test_prev) $vals(t:$x:test)
    set vals(t:$x:test_label) $tests($vals(t:$x:test))
    $op_menu delete 0 end
    _add_op_common $x 0 $op_menu $pm $existing_op
}

proc Apol_Analysis_polsearch::_add_op_common {x y op_menu pm existing_op} {
    variable vals

    variable neg_ops
    variable ops
    set valid_ops [polsearch_get_valid_operators $vals(query) $vals(t:$x:test)]
    foreach o $valid_ops {
        $op_menu add radiobutton -label $ops($o) -value [list $o 0] \
            -command [list Apol_Analysis_polsearch::_op_selected $pm $x $y] \
            -variable Apol_Analysis_polsearch::vals(t:$x:$y:op)
        $op_menu add radiobutton -label $neg_ops($o) -value [list $o 1] \
            -command [list Apol_Analysis_polsearch::_op_selected $pm $x $y] \
            -variable Apol_Analysis_polsearch::vals(t:$x:$y:op)
    }

    set vals(t:$x:$y:op_prev) {$::POLSEARCH_OP_NONE 0}
    if {$existing_op == {}} {
        set vals(t:$x:$y:op) [list [lindex $valid_ops 0] 0]
    } else {
        set vals(t:$x:$y:op) [lrange $existing_op 0 1]
    }

    foreach param [lrange $existing_op 2 end] {
        foreach {param_name v} $param {break}
        set vals(t:$x:$y:param:$param_name) $v
    }
    _op_selected $pm $x $y
}

proc Apol_Analysis_polsearch::_op_selected {pm x y} {
    variable vals

    if {$vals(t:$x:$y:op) == $vals(t:$x:$y:op_prev)} {
        _line_selected $x $y
        return
    }

    set vals(t:$x:$y:op_prev) $vals(t:$x:$y:op)
    foreach {op_num truthval} $vals(t:$x:$y:op) {break}
    if {$truthval == 0} {
        # in libpolsearch, the second parameter to addCriterion is 'invert'
        variable ops
        set vals(t:$x:$y:op_label) $ops($op_num)
    } else {
        variable neg_ops
        set vals(t:$x:$y:op_label) $neg_ops($op_num)
    }

    variable param_types
    set validParam [polsearch_get_valid_param_type $vals(query) $vals(t:$x:test) $op_num]
    set vals(t:$x:$y:param_valid) $validParam
    # the next call will also shift the line selection to this line
    $param_types($validParam) update $x $y
    $pm raise $validParam
}

proc Apol_Analysis_polsearch::_remove {} {
    variable vals
    variable widgets

    foreach {x y} $widgets(line_selected) {break}
    if {$y == 0} {
        destroy $widgets(t:$x:frame)
        array unset widgets t:$x:*
        array unset vals t:$x:*
    } else {
        destroy $widgets(t:$x:$y:frame)
        array unset widgets t:$x:$y:*
        array unset vals t:$x:$y:*
        incr vals(t:$x:num_childops) -1
    }

    # select the next line on the display
    if {$y == 0} {
        for {set next_x [expr {$x + 1}]} {$next_x < $widgets(next_test)} {incr next_x} {
            if {[info exists widgets(t:$next_x:frame)]} {
                _line_selected $next_x 0
                return
            }
        }
        for {set next_x [expr {$x - 1}]} {$next_x >= 0} {incr next_x -1} {
            if {[info exists widgets(t:$next_x:frame)]} {
                _line_selected $next_x 0
                return
            }
        }
    } else {
        for {set next_y [expr {$y + 1}]} {$next_y < $widgets(t:$x:next_op)} {incr next_y} {
            if {[info exists widgets(t:$x:$next_y:frame)]} {
                _line_selected $x $next_y
                return
            }
        }
        for {set next_y [expr {$y - 1}]} {$next_y >= 0} {incr next_y -1} {
            if {[info exists widgets(t:$x:$next_y:frame)]} {
                _line_selected $x $next_y
                return
            }
        }
    }
    _line_selected -1 -1
}

proc Apol_Analysis_polsearch::_line_selected {x y} {
    variable vals
    variable widgets

    foreach {old_x old_y} $widgets(line_selected) {break}
    if {$old_x == $x && $old_y == $y} {
        return
    }

    if {$old_x >= 0} {
        if {[info exists widgets(t:$old_x:$old_y:frame)]} {
            $widgets(t:$old_x:$old_y:frame) configure -bg [Apol_Prefs::getPref active_bg] -relief flat
            focus $widgets(t:$old_x:$old_y:frame)
        }
        if {$old_y == 0 && [info exists widgets(t:$old_x:frame)]} {
            $widgets(t:$old_x:frame) configure -bg [Apol_Prefs::getPref active_bg] -relief flat
            focus $widgets(t:$old_x:frame)
        }
    }

    $widgets(bb) itemconfigure 0 -state disabled

    if {$x >= 0} {
        $widgets(t:$x:$y:frame) configure -bg [Apol_Prefs::getPref select_bg]
        if {$y == 0} {
            $widgets(t:$x:frame) configure -bg [Apol_Prefs::getPref select_bg] -relief groove
        } else {
            $widgets(t:$x:$y:frame) configure -relief groove
        }

        # enable continue button only if the current test is continuable
        if {[polsearch_is_test_continueable $vals(t:$x:test)]} {
            $widgets(bb) itemconfigure 0 -state normal
        }
    }

    # always enable add button
    $widgets(bb) itemconfigure 1 -state normal

    # maybe enable remove button under certain circumstances
    if {$x >= 0 && ($y > 0 || $vals(t:$x:num_childops) == 0)} {
        $widgets(bb) itemconfigure 2 -state normal
    } else {
        $widgets(bb) itemconfigure 2 -state disabled
    }

    set widgets(line_selected) [list $x $y]
}

########## individual parameter widget handling routines ##########

# valid actions for parameters:
#   create: create the Tk widget to show the parameter
#   update: update the display to match vals array; also select the line
#   valid: return non-empty string if parameter is not useable yet for query
#   new_obj: return a filled-in polsearch object representing parameter

proc Apol_Analysis_polsearch::_param_expression {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set e [entry $f.e -width 30 \
                       -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:regex)]
            pack $e -expand 1 -fill x
            bind $e <Button-1> [list Apol_Analysis_polsearch::_line_selected $x $y]
        }
        update {
            _line_selected $x $y
        }
        valid {
            if {$vals(t:$x:$y:param:regex) == {}} {
                return "No regular expression provided."
            }
            return {}
        }
        new_obj {
            # FIX ME: icase
            new_polsearch_regex_parameter $vals(t:$x:$y:param:regex)
        }
    }
}

proc Apol_Analysis_polsearch::_param_str_expr {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set e [entry $f.e -width 30 \
                       -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:str_expr)]
            pack $e -expand 1 -fill x
            bind $e <Button-1> [list Apol_Analysis_polsearch::_line_selected $x $y]
        }
        update {
            _line_selected $x $y
        }
        valid {
            if {$vals(t:$x:$y:param:str_expr) == {}} {
                return "No string expression provided."
            }
            return {}
        }
        new_obj {
            set v {}
            foreach s [split $vals(t:$x:$y:param:str_expr)] {
                lappend v $s
            }
            new_polsearch_string_expression_parameter $v
        }
    }
}

proc Apol_Analysis_polsearch::_param_avrule_type {action x y args} {
    variable avrules
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set b_mb [menubutton $f.mb -bd 2 -relief raised -indicatoron 1 -width 10 \
                          -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:avrule_label)]
            pack $b_mb -expand 0 -fill x
            set b_menu [menu $b_mb.m -type normal -tearoff 0]
            $b_mb configure -menu $b_menu
            foreach {v l} $avrules {
                $b_menu add radiobutton -label $l -value $v \
                    -command [list Apol_Analysis_polsearch::_param_avrule_type update $x $y] \
                    -variable Apol_Analysis_polsearch::vals(t:$x:$y:param:avrule)
            }
            set vals(t:$x:$y:param:avrule) [lindex $avrules 0]
            set vals(t:$x:$y:param:avrule_label) [lindex $avrules 1]
        }
        update {
            _line_selected $x $y
            set new_label [lindex $avrules [expr {[lsearch $avrules $vals(t:$x:$y:param:avrule)] + 1}]]
            set vals(t:$x:$y:param:avrule_label) $new_label
        }
        valid {
            if {$vals(t:$x:$y:param:avrule) == $::QPOL_RULE_NEVERALLOW} {
                ApolTop::loadNeverAllows
                if {![ApolTop::is_capable "neverallow"]} {
                    return "The current policy does not support neverallow searching."
                }
            }
            return {}
        }
        new_obj {
            new_polsearch_number_parameter $vals(t:$x:$y:param:avrule)
        }
    }
}

proc Apol_Analysis_polsearch::_param_terule_type {action x y args} {
    variable terules
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set b_mb [menubutton $f.mb -bd 2 -relief raised -indicatoron 1 -width 12 \
                          -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:terule_label)]
            pack $b_mb -expand 0 -fill x
            set b_menu [menu $b_mb.m -type normal -tearoff 0]
            $b_mb configure -menu $b_menu
            foreach {v l} $terules {
                $b_menu add radiobutton -label $l -value $v \
                    -command [list Apol_Analysis_polsearch::_param_terule_type update $x $y] \
                    -variable Apol_Analysis_polsearch::vals(t:$x:$y:param:terule)
            }
            set vals(t:$x:$y:param:terule) [lindex $terules 0]
            set vals(t:$x:$y:param:terule_label) [lindex $terules 1]
        }
        update {
            _line_selected $x $y
            set new_label [lindex $terules [expr {[lsearch $terules $vals(t:$x:$y:param:terule)] + 1}]]
            set vals(t:$x:$y:param:terule_label) $new_label
        }
        valid {
            return {}
        }
        new_obj {
            new_polsearch_number_parameter $vals(t:$x:$y:param:terule)
        }
    }
}

proc Apol_Analysis_polsearch::_param_bool {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set b_mb [menubutton $f.mb -bd 2 -relief raised -indicatoron 1 -width 6 \
                          -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:bool)]
            pack $b_mb -expand 0 -fill x
            set b_menu [menu $b_mb.m -type normal -tearoff 0]
            $b_mb configure -menu $b_menu
            $b_menu add radiobutton -label true -value true \
                -command [list Apol_Analysis_polsearch::_param_bool update $x $y] \
                -variable Apol_Analysis_polsearch::vals(t:$x:$y:param:bool)
            $b_menu add radiobutton -label false -value false \
                -command [list Apol_Analysis_polsearch::_param_bool update $x $y] \
                -variable Apol_Analysis_polsearch::vals(t:$x:$y:param:bool)
            set vals(t:$x:$y:param:bool) true
        }
        update {
            _line_selected $x $y
        }
        valid {
            return {}
        }
        new_obj {
            new_polsearch_bool_parameter $vals(t:$x:$y:param:bool)
        }
    }
}

proc Apol_Analysis_polsearch::_param_level {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set b [button $f.l -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:level_text) \
                       -command [list Apol_Analysis_polsearch::_show_level_dialog $x $y]]
            pack $b -expand 0 -fill x
            set vals(t:$x:$y:param:level_text) "*"
            set vals(t:$x:$y:param:level) {}
        }
        update {
            _line_selected $x $y
            if {$::ApolTop::policy == {} || $vals(t:$x:$y:param:level_text) == "*"} {
                set vals(t:$x:$y:param:level) {}
            } else {
                set vals(t:$x:$y:param:level) [new_apol_mls_level_t $::ApolTop::policy $vals(t:$x:$y:param:level_text)]
                $vals(t:$x:$y:param:level) -acquire
            }
        }
        valid {
            if {$vals(t:$x:$y:param:level_text) == "*"} {
                return "No level selected."
            }
            return {}
        }
        new_obj {
            new_polsearch_level_parameter $vals(t:$x:$y:param:level)
        }
    }
}

proc Apol_Analysis_polsearch::_param_range {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set b [button $f.r -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:range_text) \
                       -command [list Apol_Analysis_polsearch::_show_range_dialog $x $y]]
            pack $b -expand 0 -fill x
            set vals(t:$x:$y:param:range_text) "* - *"
            set vals(t:$x:$y:param:range) {}
        }
        update {
            _line_selected $x $y
            if {$::ApolTop::policy == {} || $vals(t:$x:$y:param:range_text) == "* - *"} {
                set vals(t:$x:$y:param:range) {}
            } else {
                set vals(t:$x:$y:param:range) [new_apol_mls_range_t $::ApolTop::policy $vals(t:$x:$y:param:range_text)]
                $vals(t:$x:$y:param:range) -acquire
            }
        }
        valid {
            if {$vals(t:$x:$y:param:range_text) == "* - *"} {
                return "No range selected."
            }
            return {}
        }
        new_obj {
            new_polsearch_range_parameter $vals(t:$x:$y:param:range)
        }
    }
}

proc Apol_Analysis_polsearch::_show_level_dialog {x y} {
    variable vals
    _line_selected $x $y
    set new_level [Apol_Level_Dialog::getLevel $vals(t:$x:$y:param:level)]
    if {$new_level != {}} {
        set vals(t:$x:$y:param:level) $new_level
        $vals(t:$x:$y:param:level) -acquire
        set vals(t:$x:$y:param:level_text) [$vals(t:$x:$y:param:level) render $::ApolTop::policy]
    }
}

proc Apol_Analysis_polsearch::_show_range_dialog {x y} {
    variable vals
    _line_selected $x $y
    set new_range [Apol_Range_Dialog::getRange $vals(t:$x:$y:param:range)]
    if {$new_range != {}} {
        set vals(t:$x:$y:param:range) $new_range
        $vals(t:$x:$y:param:range) -acquire
        set vals(t:$x:$y:param:range_text) [$vals(t:$x:$y:param:range) render $::ApolTop::policy]
    }
}

#################### functions that do analyses ####################

proc Apol_Analysis_polsearch::_serialize_tests {} {
    variable vals
    set res {}
    foreach key [lsort [array names vals t:*:test]] {
        set x [lindex [split $key :] 1]
        set test $vals(t:$x:test)
        foreach key [lsort [array names vals t:$x:*:op]] {
            set y [lindex [split $key :] 2]
            set op $vals($key)
            foreach p {avrule bool regex str_expr terule level_text range_text} {
                lappend op [list $p $vals(t:$x:$y:param:$p)]
            }
            lappend test $op
        }
        lappend res $test
    }
    set res
}

proc Apol_Analysis_polsearch::_checkParams {} {
    variable param_types
    variable vals

    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened."
    }
    if {$vals(query) == {}} {
        return "The symbol to search has not yet been selected."
    }
    foreach key [array names vals t:*:*:param_valid] {
        foreach {t x y l} [split $key :] {break}
        set param $vals($key)
        if {[set r [$param_types($vals($key)) valid $x $y]] != {}} {
            _line_selected $x $y
            return $r
        }
    }
    set vals(serialized_tests) [_serialize_tests]
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_polsearch::_analyze {} {
    variable param_types
    variable query_constructors
    variable vals

    set db [Apol_File_Contexts::get_db]
    set query_obj [$query_constructors($vals(query))]
    $query_obj -acquire
    $query_obj match $vals(match)
    foreach key [array names vals t:*:test] {
        set x [lindex [split $key :] 1]
        set test_obj [$query_obj addTest $vals($key)]
        $test_obj -disown
        foreach key [array names vals t:$x:*:op] {
            set y [lindex [split $key :] 2]
            foreach {op neg} $vals($key) {break}
            set op_obj [$test_obj addCriterion $op $neg]
            $op_obj -disown
            set param_obj [$param_types($vals(t:$x:$y:param_valid)) new_obj $x $y]
            $param_obj -disown
            $op_obj param $param_obj
        }
    }
    if {$db != {}} {
        set res [$query_obj run $::ApolTop::policy $db]
    } else {
        set res [$query_obj run $::ApolTop::policy]
    }
    $query_obj -delete
    set res
}

################# functions that control analysis output #################

proc Apol_Analysis_polsearch::_createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Symbol Query" [array get vals]]

    set tree_tf [TitleFrame $f.left -text "Symbol Query Results"]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set tres [Apol_Widget::makeTreeResults [$tree_tf getframe].res -width 24]
    pack $tres -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Symbol Query Proof"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure subtitle_dir -foreground blue -font {Helvetica 10 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 10 bold}
    pack $res -expand 1 -fill both

    $tres.tree configure -selectcommand [list Apol_Analysis_polsearch::_treeSelect $res]
    return $f
}

proc Apol_Analysis_polsearch::_treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        $res.tb insert end "FIX ME: Proof info would go here." {}
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_polsearch::_clearResultsDisplay {f} {
    variable vals
    # FIX ME: delete vector of results from tree's root
    Apol_Widget::clearSearchTree [$f.left getframe].res
    set res [$f.right getframe].res
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_polsearch::_renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].res getframe].tree

    if {[llength $results] == 0} {
        set res [$f.right getframe].res
        $res.tb configure -state normal
        $res.tb insert end "No matching symbols found."
        $res.tb configure -state disabled
    } else {
        foreach r $results {
            set x [$r element]
            variable elements
            set q [$elements([$r elementType]) $x]
            set name [$q get_name $::ApolTop::qpolicy]
            set proofs [$r proof]
            $proofs -acquire
            set sorted_results($name) $proofs
        }
        foreach name [lsort [array names sorted_results]] {
            $tree insert end root x\#auto -text $name -drawcross never -data $sorted_results($name)
        }
        set first_node [$tree nodes root 0]
        $tree selection set $first_node
        $tree see $first_node
    }
}
