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
    set results [_analyze]
    set f [_createResultsDisplay]
    _renderResults $f $results
    $results -acquire
    $results -delete
    return {}
}


proc Apol_Analysis_polsearch::updateAnalysis {f} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    _clearResultsDisplay $f
    _renderResults $f $results
    $results -acquire
    $results -delete
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
            current_query -
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

    variable param_types
    array set param_types [list \
                               $::POLSEARCH_PARAM_TYPE_REGEX _param_expression \
                               $::POLSEARCH_PARAM_TYPE_STR_EXPR _param_str_expr \
                               $::POLSEARCH_PARAM_TYPE_RULE_TYPE _param_rule_type \
                               $::POLSEARCH_PARAM_TYPE_BOOL _param_bool \
                               $::POLSEARCH_PARAM_TYPE_LEVEL _param_level \
                               $::POLSEARCH_PARAM_TYPE_RANGE _param_range]
}

proc Apol_Analysis_polsearch::_reinitializeVals {} {
    variable vals
    array unset vals t:*
    array set vals {
        current_query {}
        query {}
        query_label {}
        prev_query {}
    }
    # vals(current_query) is a pointer to a libpolsearch object for
    # the query that is being constructed

    set vals(match) $::POLSEARCH_MATCH_ALL
    _toggleMatch
}

proc Apol_Analysis_polsearch::_reinitializeWidgets {} {
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

    set vals(current_query) [new_$vals(query)]
    $vals(current_query) -acquire
    foreach w [winfo children [$widgets(rules) getframe]] {
        destroy $w
    }

    set widgets(next_test) 0
    if {$state == "init"} {
        # FIX ME: create all rules widgets for the given query
    } else {
        _add
    }

    variable queries
    $widgets(bb) itemconfigure 0 -state disabled
    $widgets(bb) itemconfigure 1 -state disabled
    $widgets(bb) itemconfigure 2 -state disabled
    if {$vals(query) == {}} {
        set vals(query_label) {}
    } else {
        $widgets(bb) itemconfigure 1 -state normal
        set vals(query_label) $queries($vals(query))
    }
}

proc Apol_Analysis_polsearch::_toggleMatch {} {
    variable vals
    variable matches
    set vals(match_label) $matches($vals(match))
}

proc Apol_Analysis_polsearch::_add {} {
    variable tests
    variable vals
    variable widgets

    set x $widgets(next_test)
    set f [frame [$widgets(rules) getframe].f$x -bg [Apol_Prefs::getPref active_bg]]
    incr widgets(next_test)
    pack $f -expand 0 -fill x -anchor w -padx 4 -pady 4

    set test_mb [menubutton $f.t -bd 2 -relief raised -indicatoron 1 \
                     -width 24 \
                     -textvariable Apol_Analysis_polsearch::vals(t:$x:test_label)]
    set test_menu [menu $test_mb.m -type normal -tearoff 0]
    $test_mb configure -menu $test_menu
    set op_mb [menubutton $f.op -bd 2 -relief raised -indicatoron 1 -width 24 \
                   -textvariable Apol_Analysis_polsearch::vals(t:$x:op_label)]
    set op_menu [menu $op_mb.m -type normal -tearoff 0]
    $op_mb configure -menu $op_menu
    pack $test_mb $op_mb -side left -padx 4

    set valid_tests [$vals(current_query) getValidTests]
    foreach t $valid_tests {
        $test_menu add radiobutton -label $tests($t) -value $t \
            -command [list Apol_Analysis_polsearch::_test_selected $x $op_menu] \
            -variable Apol_Analysis_polsearch::vals(t:$x:test)
    }
    set vals(t:$x:test_label) $tests([lindex $valid_tests 0])
    set vals(t:$x:test) [lindex $valid_tests 0]
    set vals(t:$x:test_prev) $::POLSEARCH_TEST_NONE
    _test_selected $x $op_menu
}

proc Apol_Analysis_polsearch::_test_selected {x op_menu} {
    variable ops
    variable tests
    variable vals

    if {$vals(t:$x:test) == $vals(t:$x:test_prev)} {
        return
    }

    # FIX ME: delete existing test
    $op_menu delete 0 end

    set vals(t:$x:test_prev) $vals(t:$x:test)
    set vals(t:$x:test_label) $tests($vals(t:$x:test))

    set vals(t:$x:test_obj) [$vals(current_query) addTest $vals(t:$x:test)]
    set valid_ops [$vals(t:$x:test_obj) getValidOperators]

    foreach o $valid_ops {
        $op_menu add radiobutton -label $ops($o) -value $o \
            -command [list Apol_Analysis_polsearch::_op_selected $x] \
            -variable Apol_Analysis_polsearch::vals(t:$x:op)
    }
    set vals(t:$x:op_label) $ops([lindex $valid_ops 0])
    set vals(t:$x:op) [lindex $valid_ops 0]
    set vals(t:$x:op_prev) $::POLSEARCH_OP_NONE
    _op_selected $x
}

proc Apol_Analysis_polsearch::_op_selected {x} {
    variable ops
    variable vals

    if {$vals(t:$x:op) == $vals(t:$x:op_prev)} {
        return
    }

    # FIX ME: clear away previous parameter

    set vals(t:$x:op_prev) $vals(t:$x:op)
    set vals(t:$x:op_label) $ops($vals(t:$x:op))

    # FIX ME: can getValidParamTypes() return more than one thing?
    # FIX ME: flip to appropriate param display
}


#################### functions that do analyses ####################

proc Apol_Analysis_polsearch::_checkParams {} {
    variable vals
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened."
    }
    if {$vals(current_query) == {}} {
        return "The symbol to search has not yet been selected."
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_polsearch::_analyze {} {
    variable vals
    set q [new_apol_types_relation_analysis_t]
    $q set_first_type $::ApolTop::policy $vals(typeA)
    $q set_other_type $::ApolTop::policy $vals(typeB)
    set analyses 0
    foreach key [array names vals run:*] {
        set analyses [expr {$analyses | $vals($key)}]
    }
    $q set_analyses $::ApolTop::policy $analyses

    set results [$q run $::ApolTop::policy]
    $q -acquire
    $q -delete
    return $results
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
        set data [$tree itemcget $node -data]
        set name [$tree itemcget $node -text]
        if {[set parent [$tree parent $node]] != "root"} {
            set parent_name [$tree itemcget $parent -text]
            set parent_data [$tree itemcget $parent -data]
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_polsearch::_clearResultsDisplay {f} {
    variable vals
    Apol_Widget::clearSearchTree [$f.left getframe].res
    set res [$f.right getframe].res
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_polsearch::_renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].res getframe].tree
    set res [$f.right getframe].res
    set first_node [$tree nodes root 0]
    $tree selection set $first_node
    $tree see $first_node
}
