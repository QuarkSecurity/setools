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
    foreach key [lsort [array names queries]] {
        $menu add radiobutton -label $queries($key) -value $key \
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
    $widgets(bb) add -text "Continue" -state disabled
    $widgets(bb) add -text "Add" -state disabled -command Apol_Analysis_polsearch::_add
    $widgets(bb) add -text "Remove" -state disabled
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
    foreach {key value} [array get vals] {
        switch -glob $key -- {
            match_label -
            prev_query -
            query_label -
            query_obj -
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

    set vals(prev_query) {}
    _reinitializeWidgets
    FIX ME
    _toggleMatch
}

proc Apol_Analysis_polsearch::getTextWidget {tab} {
    return [$tab.right getframe].res.tb
}


#################### private functions below ####################

proc Apol_Analysis_polsearch::_staticInitializeVals {} {
    variable queries
    array set queries {
        polsearch_attribute_query "Attributes"
        polsearch_bool_query "Booleans"
        polsearch_cat_query "Categories"
        polsearch_class_query "Classes"
        polsearch_common_query "Common Classes"
        polsearch_level_query "Levels"
        polsearch_role_query "Roles"
        polsearch_type_query "Types"
        polsearch_user_query "Users"
    }

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
    variable terules [list $::QPOL_RULE_TYPE_TRANS type_trans \
                          $::QPOL_RULE_TYPE_MEMBER type_member \
                          $::QPOL_RULE_TYPE_CHANGE type_change]
}

proc Apol_Analysis_polsearch::_reinitializeVals {} {
    variable vals
    array unset vals t:*
    array set vals {
        query {}
        query_label {}
        query_obj {}
        prev_query {}
    }
    # $vals(query_obj) is a pointer to a libpolsearch object for
    # the query that is being constructed

    set vals(match) $::POLSEARCH_MATCH_ALL
    _toggleMatch
}

proc Apol_Analysis_polsearch::_reinitializeWidgets {} {
    variable widgets
    set widgets(line_selected) {0 0}
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
    set widgets(line_selected) {0 0}

    if {$vals(query) != {}} {
        set vals(query_obj) [new_$vals(query)]
        $vals(query_obj) -acquire
    } else {
        set vals(query_obj) {}
    }

    if {$state == "init"} {
        # FIX ME: create all rules widgets for the given query, based
        # upon info from file
    } else {
        _add
    }

    variable queries
    if {$vals(query) == {}} {
        set vals(query_label) {}
    } else {
        set vals(query_label) $queries($vals(query))
    }
}

proc Apol_Analysis_polsearch::_toggleMatch {} {
    variable vals
    variable matches
    set vals(match_label) $matches($vals(match))
    # FIX ME: actually set matching behavior
}

proc Apol_Analysis_polsearch::_add {} {
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
        $f configure -bg [Apol_Prefs::getPref active_bg]
        $param_types($p) create $x 0 $f
    }
    $pm compute_size

    set valid_tests [$vals(query_obj) getValidTests]
    foreach t $valid_tests {
        $test_menu add radiobutton -label $tests($t) -value $t \
            -command [list Apol_Analysis_polsearch::_test_selected $x $op_menu $pm] \
            -variable Apol_Analysis_polsearch::vals(t:$x:test)
    }
    set vals(t:$x:test_label) $tests([lindex $valid_tests 0])
    set vals(t:$x:test) [lindex $valid_tests 0]
    set vals(t:$x:test_prev) $::POLSEARCH_TEST_NONE
    _test_selected $x $op_menu $pm
}

proc Apol_Analysis_polsearch::_test_selected {x op_menu pm} {
    variable neg_ops
    variable ops
    variable tests
    variable vals
    variable widgets

    if {$vals(t:$x:test) == $vals(t:$x:test_prev)} {
        _line_selected $x 0
        return
    }

    if {[info exists vals(t:$x:test_num)]} {
        set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
        $vals(query_obj) removeTest $test_obj
        # FIX ME: destroy continued widgets
        array unset vals t:$x:\[1-9\]*:*
        foreach key [array names vals t:*:test_num] {
            if {$vals($key) > $vals(t:$x:test_num)} {
                incr vals($key) -1
            }
        }
    }

    set vals(t:$x:test_prev) $vals(t:$x:test)
    set vals(t:$x:test_label) $tests($vals(t:$x:test))

    set test_obj [$vals(query_obj) addTest $vals(t:$x:test)]
    $test_obj -disown
    set vals(t:$x:test_num) [expr {[$vals(query_obj) numTests] - 1}]
    set vals(t:$x:next_op) 0

    set valid_ops [$test_obj getValidOperators]
    $op_menu delete 0 end
    foreach o $valid_ops {
        $op_menu add radiobutton -label $ops($o) -value [list $o 0] \
            -command [list Apol_Analysis_polsearch::_op_selected $pm $x 0] \
            -variable Apol_Analysis_polsearch::vals(t:$x:0:op)
        $op_menu add radiobutton -label $neg_ops($o) -value [list $o 1] \
            -command [list Apol_Analysis_polsearch::_op_selected $pm $x 0] \
            -variable Apol_Analysis_polsearch::vals(t:$x:0:op)
    }
    set vals(t:$x:0:op_label) $ops([lindex $valid_ops 0])
    set vals(t:$x:0:op) [list [lindex $valid_ops 0] 0]
    set vals(t:$x:0:op_prev) {$::POLSEARCH_OP_NONE 1}
    _op_selected $pm $x 0
}

proc Apol_Analysis_polsearch::_op_selected {pm x y} {
    variable vals

    if {$vals(t:$x:$y:op) == $vals(t:$x:$y:op_prev)} {
        _line_selected $x $y
        return
    }

    set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
    if {[info exists vals(t:$x:$y:op_num)]} {
        set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
        $test_obj removeCriterion $op_obj
        foreach key [array names vals t:$x:*:op_num] {
            if {$vals($key) > $vals(t:$x:$y:op_num)} {
                incr vals($key) -1
            }
        }
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

    set op_obj [$test_obj addCriterion $op_num $truthval]
    $op_obj -disown
    set vals(t:$x:$y:op_num) [expr {[$test_obj numCriteria] - 1}]
    incr vals(t:$x:next_op)

    variable param_types
    set validParam [$op_obj getValidParamType]
    # the next call will also shift the line selection to this line
    $param_types($validParam) update $x $y focusin
    $pm raise $validParam
}

proc Apol_Analysis_polsearch::_line_selected {x y} {
    variable vals
    variable widgets

    foreach {old_x old_y} $widgets(line_selected) {break}
    $widgets(t:$old_x:$old_y:frame) configure -bg [Apol_Prefs::getPref active_bg] -relief flat
    if {$old_y == 0} {
        $widgets(t:$old_x:frame) configure -bg [Apol_Prefs::getPref active_bg] -relief flat
    }

    $widgets(t:$x:$y:frame) configure -bg [Apol_Prefs::getPref select_bg]
    if {$y == 0} {
        $widgets(t:$x:frame) configure -bg [Apol_Prefs::getPref select_bg] -relief groove
    } else {
        $widgets(t:$x:$y:frame) configure -relief groove
    }
    

    # enable continue button only if the current test is continuable
    set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
    if {[$test_obj isContinueable]} {
        $widgets(bb) itemconfigure 0 -state normal
    } else {
        $widgets(bb) itemconfigure 0 -state disabled
    }

    # always enable add button
    $widgets(bb) itemconfigure 1 -state normal

    # maybe enable remove button under certain circumstances
    $widgets(bb) itemconfigure 2 -state disabled
    # FIX ME

    set widgets(line_selected) [list $x $y]
}

########## individual parameter widget handling routines ##########

proc Apol_Analysis_polsearch::_param_expression {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set e [entry $f.e -width 30 \
                       -validate focus \
                       -vcmd [list Apol_Analysis_polsearch::_param_expression update $x $y %V] \
                       -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:regex)]
            pack $e -expand 0 -fill x
        }
        update {
            if {[lindex $args 0] == "focusin"} {
                _line_selected $x $y
            } else {
                set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
                set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
                if {$vals(t:$x:$y:param:regex) != {}} {
                    # FIX ME: add icase?
                    set p [new_polsearch_regex_parameter $vals(t:$x:$y:param:regex)]
                    $op_obj param $p
                    $p -disown
                }
            }
            return 1
        }
    }
}

proc Apol_Analysis_polsearch::_param_str_expr {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set e [entry $f.e -width 30 \
                       -validate focus \
                       -vcmd [list Apol_Analysis_polsearch::_param_str_expr update $x $y %V] \
                       -textvariable Apol_Analysis_polsearch::vals(t:$x:$y:param:str_expr) -bg red]
            # FIX ME: colored red to differentiate from regex entry
            pack $e -expand 0 -fill x
        }
        update {
            if {[lindex $args 0] == "focusin"} {
                _line_selected $x $y
            } else {
                set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
                set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
                if {$vals(t:$x:$y:param:str_expr) != {}} {
                    set v {}
                    foreach s [split $vals(t:$x:$y:param:str_expr)] {
                        if {$s != {}} {
                            lappend v $s
                        }
                    }
                    # FIX ME: add icase?
                    set p [new_polsearch_string_expression_parameter $v]
                    $op_obj param $p
                    $p -disown
                }
            }
            return 1
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
            pack $b_mb -expand 0 -fill none -anchor w
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
            set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
            set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
            set p [new_polsearch_number_parameter $vals(t:$x:$y:param:avrule)]
            $op_obj param $p
            $p -disown
            set new_label [lindex $avrules [expr {[lsearch $avrules $vals(t:$x:$y:param:avrule)] + 1}]]
            set vals(t:$x:$y:param:avrule_label) $new_label
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
            pack $b_mb -expand 0 -fill none -anchor w
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
            set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
            set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
            set p [new_polsearch_number_parameter $vals(t:$x:$y:param:terule)]
            $op_obj param $p
            $p -disown
            set new_label [lindex $terules [expr {[lsearch $terules $vals(t:$x:$y:param:terule)] + 1}]]
            set vals(t:$x:$y:param:terule_label) $new_label
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
            pack $b_mb -expand 0 -fill none -anchor w
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
            set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
            set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
            if {$vals(t:$x:$y:param:bool) == "true"} {
                set p [new_polsearch_bool_parameter 1]
            } else {
                set p [new_polsearch_bool_parameter 0]
            }
            $op_obj param $p
            $p -disown
        }
    }
}

proc Apol_Analysis_polsearch::_param_level {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set l [label $f.l -text "level goes here"]
            pack $l -expand 0 -fill x
        }
        update {
            set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
            set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
            # FIX ME: create a polsearch_level_parameter
        }
    }
}

proc Apol_Analysis_polsearch::_param_range {action x y args} {
    variable vals
    switch -- $action {
        create {
            set f [lindex $args 0]
            set l [label $f.l -text "range goes here"]
            pack $l -expand 0 -fill x
        }
        update {
            set test_obj [$vals(query_obj) getTest $vals(t:$x:test_num)]
            set op_obj [$test_obj getCriterion $vals(t:$x:$y:op_num)]
            # FIX ME: create a polsearch_range_parameter
        }
    }
}

#################### functions that do analyses ####################

proc Apol_Analysis_polsearch::_checkParams {} {
    variable vals
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened."
    }
    if {$vals(query_obj) == {}} {
        return "The symbol to search has not yet been selected."
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_polsearch::_analyze {} {
    variable vals
    set db [Apol_File_Contexts::get_db]
    if {$db != {}} {
        $vals(query_obj) run $::ApolTop::policy $db
    } else {
        $vals(query_obj) run $::ApolTop::policy
    }
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
        $res.tb insert end "Proof info would go here." {}
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

    foreach r $results {
        set x [$r element]
        variable elements
        set q [$elements([$r elementType]) $x]
        set name [$q get_name $::ApolTop::qpolicy]
        set proofs [$r proof]
        $proofs -acquire
        $tree insert end root x\#auto -text $name -drawcross never -data $proofs    }

    set first_node [$tree nodes root 0]
    if {$first_node == {}} {
        set res [$f.right getframe].res
        $res.tb configure -state normal
        $res.tb insert end "No matching symbols found."
        $res.tb configure -state disabled
    } else {
        $tree selection set $first_node
        $tree see $first_node
    }
}

proc pa {} {
    parray ::Apol_Analysis_polsearch::vals
}
