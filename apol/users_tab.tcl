# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::Apol_Users
#  
# The Users page
##############################################################
namespace eval Apol_Users {
# opts(opt), where opt =
    variable opts
    set opts(useRole)		   0
    set opts(showSelection)        all
    variable srchstr ""
    variable role_1ist ""
    variable users_list ""
    
    # Global Widgets
    variable resultsbox
    variable users_listbox
    variable role_combo_box

}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Users::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Users::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Users::set_Focus_to_Text {} {
	focus $Apol_Users::resultsbox
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::searchUsers
# ------------------------------------------------------------------------------
proc Apol_Users::searchUsers {} {
    variable opts
    variable resultsbox
    
    update idletasks
    
    if {$opts(showSelection) == "names"} {
	set name_only 1
    } else {
	set name_only 0
    }
    set rt [catch {set results [apol_GetUsersByRole $name_only $opts(useRole) \
				    $Apol_Users::role_list]} err]
    if {$rt != 0} {	
	tk_messageBox -icon error -type ok -title "Error" -message "$err"
	return 
    } else {
    	$resultsbox configure -state normal
	$resultsbox delete 0.0 end
	$resultsbox insert end $results
	ApolTop::makeTextBoxReadOnly $resultsbox 
    }
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::open
# ------------------------------------------------------------------------------
proc Apol_Users::open { } {
    variable role_list
    variable users_list
  
    set users_list [apol_GetNames users] 
    set users_list [lsort $users_list]
    $Apol_Users::role_combo_box configure -values $Apol_Roles::role_list
  
    return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Users::close
# ------------------------------------------------------------------------------
proc Apol_Users::close { } {
    set Apol_Users::role_list ""
    set Apol_Users::users_list ""
    
    $Apol_Users::role_combo_box configure -values ""
    $Apol_Users::resultsbox configure -state normal
    $Apol_Users::resultsbox delete 0.0 end
    ApolTop::makeTextBoxReadOnly $Apol_Users::resultsbox 
    
    return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::popupUserInfo
# ------------------------------------------------------------------------------
proc Apol_Users::popupUserInfo {which user} {
	set rt [catch {set info [apol_UserRoles $user]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	
	set w .user_infobox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	
	catch {destroy $w}
	toplevel $w 
	wm title $w "$user"
	wm protocol $w WM_DELETE_WINDOW "destroy $w"
    	wm withdraw $w
    	
	set sf [ScrolledWindow $w.sf  -scrollbar both -auto both]
	set f [text [$sf getframe].f -font {helvetica 10} -wrap none -width 35 -height 10]
	$sf setwidget $f
	set b1 [button $w.close -text Close -command "catch {destroy $w}" -width 10]
	pack $b1 -side bottom -anchor s -padx 5 -pady 5 
	pack $sf -fill both -expand yes
	set user_count [llength $info]
	$f insert end "$user ($user_count roles)\n\t"
	foreach role $info {
		$f insert end "$role\n\t"
	}
	wm geometry $w +50+50
	wm deiconify $w
	$f configure -state disabled	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::popupUserInfoMenu
# ------------------------------------------------------------------------------
proc Apol_Users::popupUserInfoMenu { global x y popup } {
    # Getting global coordinates of the application window (of position 0, 0)
    set gx [winfo rootx $global]	
    set gy [winfo rooty $global]
    
    # Add the global coordinates for the application window to the current mouse coordinates
    # of %x & %y
    set cmx [expr $gx + $x]
    set cmy [expr $gy + $y]
    
    # Posting the popup menu
    tk_popup $popup $cmx $cmy

    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::enable_role_list
# ------------------------------------------------------------------------------
proc Apol_Users::enable_role_list { entry } {
    variable role_combo_box
    if { $Apol_Users::opts(useRole) } {
	$entry configure -state normal -entrybg white
    } else {
	$entry configure -state disabled -entrybg $ApolTop::default_bg_color
	set $Apol_Users::role_list ""
	ComboBox::_unmapliste $role_combo_box
    }
	
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::_getIndexValue
# ------------------------------------------------------------------------------
proc Apol_Users::getIndexValue { path value } { 
    set listValues [Widget::getMegawidgetOption $path -values]

    return [lsearch -glob $listValues "$value*"]
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Users::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::_mapliste
# ------------------------------------------------------------------------------
proc Apol_Users::_mapliste { path } {
    set listb $path.shell.listb
    if { [Widget::cget $path -state] == "disabled" } {
        return
    }
    if { [set cmd [Widget::getMegawidgetOption $path -postcommand]] != "" } {
        uplevel \#0 $cmd
    }
    if { ![llength [Widget::getMegawidgetOption $path -values]] } {
        return
    }

    ComboBox::_create_popup $path
    ArrowButton::configure $path.a -relief sunken
    update

    $listb selection clear 0 end
    BWidget::place $path.shell [winfo width $path] 0 below $path
    wm deiconify $path.shell
    raise $path.shell
    BWidget::grab local $path

    return $listb
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::_create_popup
# ------------------------------------------------------------------------------
proc Apol_Users::_create_popup { path entryBox key } { 
    # Getting value from the entry subwidget of the combobox 
    # and then checking its' length
    set value  [Entry::cget $path.e -text]
    set len [string length $value]
    
    # Key must be an alphanumeric ASCII character.  
    if { [string is alpha $key] } {
	    #ComboBox::_unmapliste $path
	    set idx [ Apol_Users::getIndexValue $path $value ]  
	    
	    if { $idx != -1 } {
	    # Calling setSelection function to set the selection to the index value
	    	Apol_Users::setSelection $idx $path $entryBox $key
	    }
    } 
    
    if { $key == "Return" } {
    	    # If the dropdown box visible, then we just select the value and unmap the list.
    	    if {[winfo exists $path.shell.listb] && [winfo viewable $path.shell.listb]} {
    	    	    set index [$path.shell.listb curselection]
	    	    if { $index != -1 } {
		        if { [ComboBox::setvalue $path @$index] } {
			    set cmd [Widget::getMegawidgetOption $path -modifycmd]
		            if { $cmd != "" } {
		                uplevel \#0 $cmd
		            }
		        }
		    }
	    	ComboBox::_unmapliste $path
	    	focus -force .
	    }
    }
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::setSelection
# ------------------------------------------------------------------------------
proc Apol_Users::setSelection { idx path entryBox key } {
    if {$idx != -1} {
	set listb [Apol_Users::_mapliste $path]
	$listb selection set $idx
	$listb activate $idx
	$listb see $idx
    } 
    
    return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Users::create
# ------------------------------------------------------------------------------
proc Apol_Users::create {nb} {
    variable opts
    variable users_listbox 
    variable resultsbox 
    variable srchstr 
    variable role_combo_box

    # Layout frames
    set frame [$nb insert end $ApolTop::users_tab -text "Users"]
    set topf  [frame $frame.topf]
    set pw1   [PanedWindow $topf.pw -side top]
    set pane  [$pw1 add ]
    set spane [$pw1 add -weight 5]
    set pw2   [PanedWindow $pane.pw -side left]
    set rpane [$pw2 add -weight 3]

    # Title frames
    set userbox [TitleFrame $rpane.userbox -text "Users"]
    set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
    set resultsbox [TitleFrame $spane.rbox -text "Search Results"]

    # Placing layout
    pack $topf -fill both -expand yes 
    pack $pw1 -fill both -expand yes
    pack $pw2 -fill both -expand yes

    # Placing title frames
    pack $s_optionsbox -padx 2 -fill both
    pack $userbox -padx 2 -side left -fill both -expand yes
    pack $resultsbox -pady 2 -padx 2 -fill both -anchor n -side bottom -expand yes
   
    # Roles listbox widget
    set sw_r [ScrolledWindow [$userbox getframe].sw -auto both]
    set users_listbox [listbox [$sw_r getframe].lb -height 18 -width 20 -highlightthickness 0 \
		 -listvar Apol_Users::users_list -bg white] 
    $sw_r setwidget $users_listbox 
    	    
    # Popup menu widget
    menu .popupMenu_users
    .popupMenu_users add command -label "Display User Info" \
	-command { Apol_Users::popupUserInfo "users" [$Apol_Users::users_listbox get active] }
	    
    # Event binding on the users list box widget
    bindtags $users_listbox [linsert [bindtags $users_listbox] 3 ulist_Tag]  
    bind ulist_Tag <Double-Button-1> { Apol_Users::popupUserInfo "users" [$Apol_Users::users_listbox get active]}
    bind ulist_Tag <Button-3> { Apol_Users::popupUserInfoMenu %W %x %y .popupMenu_users }
        
    # Search options subframes
    set ofm [$s_optionsbox getframe]
    set l_innerFrame [LabelFrame $ofm.to \
                    -relief sunken -borderwidth 1]
    set c_innerFrame [LabelFrame $ofm.co \
                    -relief sunken -borderwidth 1]
    set r_innerFrame [frame $ofm.ro \
                    -relief flat -borderwidth 1]
    
    # Placing inner frames
    set lfm [$l_innerFrame getframe]
    set cfm [$c_innerFrame getframe]
    set rfm  $r_innerFrame
    
    # Search options widget items
    set role_combo_box [ComboBox $cfm.combo -width 30 -textvariable Apol_Users::role_list \
		  -helptext "Type or select a role"]
    $role_combo_box configure -state disabled 

    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $role_combo_box.e [linsert [bindtags $role_combo_box.e] 3 rolesTag]
    bind rolesTag <KeyPress> { Apol_Users::_create_popup $Apol_Users::role_combo_box %W %K }

    radiobutton $lfm.names_only -text "Names Only" -variable Apol_Users::opts(showSelection) -value names 
    radiobutton $lfm.all_info -text "All Information" -variable Apol_Users::opts(showSelection) -value all 
    checkbutton $cfm.cb -variable Apol_Users::opts(useRole) -text "Search Using Roles" \
	-command "Apol_Users::enable_role_list $role_combo_box"

    # Action Buttons
    button $rfm.ok -text OK -width 6 -command {Apol_Users::searchUsers}      
    #button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}

    # Display results window
    set sw_d [ScrolledWindow [$resultsbox getframe].sw -auto none]
    set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
    $sw_d setwidget $resultsbox

    # Placing all widget items
    pack $r_innerFrame -side right -fill both -expand yes -anchor ne
    pack $l_innerFrame -side left -fill both -anchor n
    pack $c_innerFrame -side right -expand yes -anchor nw -padx 5 -fill y
    pack $rfm.ok -side top -anchor e -pady 5 -padx 5
    pack $lfm.names_only $lfm.all_info -side top -anchor nw -pady 5 -padx 5
    pack $cfm.cb -side top -anchor nw -padx 10 -pady 5
    pack $role_combo_box -anchor w -pady 10 -padx 10
    pack $sw_r -fill both -expand yes
    pack $sw_d -side left -expand yes -fill both 
        
    return $frame	
}

