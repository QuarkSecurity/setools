# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Initial_SIDS
#  
# The Initial SIDS page
##############################################################
namespace eval Apol_Initial_SIDS {
	# opts(opt), where opt =
	variable opts
	set opts(user)			""
	set opts(role)			""
	set opts(type)			""
	variable attribute_selected	""
	variable user_cb_value		0
	variable role_cb_value		0
	variable type_cb_value		0
	variable attribute_cb_value	0
	variable sids_list 		""
	
	# Global Widgets
	variable resultsbox
	variable init_sids_listbox
	variable user_combo_box
	variable role_combo_box
	variable type_combo_box
	variable attribute_combo_box
	variable cb_attrib
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Initial_SIDS::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Initial_SIDS::set_Focus_to_Text {} {
	focus $Apol_Initial_SIDS::resultsbox
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::searchSIDs
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::searchSIDs {} {
	variable opts
	variable resultsbox
	
	if {$Apol_Initial_SIDS::user_cb_value && $opts(user) == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "You must provide a user."
		return -1
	} 
	if {$Apol_Initial_SIDS::role_cb_value && $opts(role) == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "You must provide a role."
		return -1
	} 
	if {$Apol_Initial_SIDS::type_cb_value && $opts(type) == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "You must provide a type."
		return -1
	} 
	
	set rt [catch {set results [apol_SearchInitialSIDs $opts(user) $opts(role) $opts(type)]} err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	} else {
		$resultsbox configure -state normal
		$resultsbox delete 0.0 end
		$resultsbox insert end $results
		ApolTop::makeTextBoxReadOnly $resultsbox 
	}

	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::open
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::open { } {
	variable sids_list
	
	set sids_list [apol_GetNames initial_sids] 
	set sids_list [lsort $sids_list]
	$Apol_Initial_SIDS::user_combo_box configure -values $Apol_Users::users_list
	$Apol_Initial_SIDS::role_combo_box configure -values $Apol_Roles::role_list
	$Apol_Initial_SIDS::type_combo_box configure -values $ApolTypes::typelist
	$Apol_Initial_SIDS::attribute_combo_box configure -values $ApolTypes::attriblist
	
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::user_cb_value $Apol_Initial_SIDS::user_combo_box
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::role_cb_value $Apol_Initial_SIDS::role_combo_box
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::type_cb_value $Apol_Initial_SIDS::type_combo_box
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::attribute_cb_value $Apol_Initial_SIDS::attribute_combo_box
	$Apol_Initial_SIDS::cb_attrib configure -state disabled
	return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::close
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::close { } {
	set Apol_Initial_SIDS::sids_list ""
	set Apol_Initial_SIDS::user_cb_value	0
	set Apol_Initial_SIDS::role_cb_value	0
	set Apol_Initial_SIDS::type_cb_value	0
	set Apol_Initial_SIDS::attribute_cb_value 0
	$Apol_Initial_SIDS::user_combo_box configure -values ""
	$Apol_Initial_SIDS::role_combo_box configure -values ""
	$Apol_Initial_SIDS::type_combo_box configure -values ""
	$Apol_Initial_SIDS::attribute_combo_box configure -values ""
	$Apol_Initial_SIDS::resultsbox configure -state normal
	$Apol_Initial_SIDS::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_Initial_SIDS::resultsbox 
	
	return 0	
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::popupSIDInfo
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::popupSIDInfo {sid} {
	set rt [catch {set info [apol_GetInitialSIDInfo $sid]} err]
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
	wm title $w "$sid Context"
	wm protocol $w WM_DELETE_WINDOW "destroy $w"
    	wm withdraw $w
    	
	set sf [ScrolledWindow $w.sf  -scrollbar both -auto both]
	set f [text [$sf getframe].f -font {helvetica 10} -wrap none -width 35 -height 10]
	$sf setwidget $f
	set b1 [button $w.close -text Close -command "catch {destroy $w}" -width 10]
	pack $b1 -side bottom -anchor s -padx 5 -pady 5 
	pack $sf -fill both -expand yes
	set user_count [llength $info]
	$f insert end "$sid:\n"
	$f insert end "   $info\n"
	
	wm geometry $w +50+50
	wm deiconify $w
	$f configure -state disabled	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::popupSIDInfoMenu
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::popupSIDInfoMenu { global x y popup } {
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
#  Command Apol_Initial_SIDS::enable_comboBox
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::enable_comboBox {cb_value combo_box} {
	selection clear -displayof $combo_box
	if {$cb_value} {
		$combo_box configure -state normal -entrybg white
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::enable_types_widgets
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::enable_types_widgets {} {
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::type_cb_value $Apol_Initial_SIDS::type_combo_box
	Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::attribute_cb_value $Apol_Initial_SIDS::attribute_combo_box
	if {$Apol_Initial_SIDS::type_cb_value} {
		$Apol_Initial_SIDS::cb_attrib configure -state normal
	} else {
		Apol_Initial_SIDS::enable_comboBox 0 $Apol_Initial_SIDS::attribute_combo_box
		$Apol_Initial_SIDS::cb_attrib configure -state disabled
	}
	
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::change_types_list { } { 
	variable type_combo_box
	variable attribute_selected
	
	$type_combo_box configure -text ""
	if {$Apol_Initial_SIDS::attribute_cb_value && $attribute_selected != "" } {	  
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $attribute_selected]} err]		
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -code error
		} 
		set attrib_typesList [lsort $attrib_typesList]
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
		$type_combo_box configure -values $attrib_typesList
        } else {
        	set attrib_typesList $ApolTypes::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$type_combo_box configure -values $attrib_typesList
        }
     	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Initial_SIDS::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Initial_SIDS::create
# ------------------------------------------------------------------------------
proc Apol_Initial_SIDS::create {nb} {
	variable opts
	variable init_sids_listbox 
	variable resultsbox 
	variable user_combo_box
	variable role_combo_box
	variable type_combo_box
	variable attribute_combo_box
	variable cb_attrib
	
	# Layout frames
	set frame [$nb insert end $ApolTop::initial_sids_tab -text "Initial SIDs"]
	set topf  [frame $frame.topf]
	set pw1   [PanedWindow $topf.pw -side top]
	set pane  [$pw1 add ]
	set spane [$pw1 add -weight 5]
	set pw2   [PanedWindow $pane.pw -side left]
	set rpane [$pw2 add -weight 3]
	
	# Title frames
	set sids_box 	 [TitleFrame $rpane.sids_box -text "Initial SIDs"]
	set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
	set resultsbox 	 [TitleFrame $spane.rbox -text "Search Results"]
	
	# Placing layout
	pack $topf -fill both -expand yes 
	pack $pw1 -fill both -expand yes
	pack $pw2 -fill both -expand yes
	
	# Placing title frames
	pack $s_optionsbox -padx 2 -fill both
	pack $sids_box -padx 2 -side left -fill both -expand yes
	pack $resultsbox -pady 2 -padx 2 -fill both -anchor n -side bottom -expand yes
	
	# Roles listbox widget
	set sw_r [ScrolledWindow [$sids_box getframe].sw -auto both]
	set init_sids_listbox [listbox [$sw_r getframe].lb -height 18 -width 20 -highlightthickness 0 \
		 -listvar Apol_Initial_SIDS::sids_list -bg white] 
	$sw_r setwidget $init_sids_listbox 
	    
	# Popup menu widget
	menu .popupMenu_sids
	.popupMenu_sids add command -label "Display Initial SIDs Context" \
		-command {Apol_Initial_SIDS::popupSIDInfo [$Apol_Initial_SIDS::init_sids_listbox get active]}
	    
	# Event binding on the users list box widget
	bindtags $init_sids_listbox [linsert [bindtags $init_sids_listbox] 3 ulist_Tag]  
	bind ulist_Tag <Double-Button-1> {Apol_Initial_SIDS::popupSIDInfo [$Apol_Initial_SIDS::init_sids_listbox get active]}
	bind ulist_Tag <Button-3> {Apol_Initial_SIDS::popupSIDInfoMenu %W %x %y .popupMenu_sids}
	
	# Search options subframes
	set ofm [$s_optionsbox getframe]
	set l_innerFrame [LabelFrame $ofm.to -relief sunken -bd 1]
	set c_innerFrame [LabelFrame $ofm.co -relief sunken -bd 1]
	set r_innerFrame [LabelFrame $ofm.ro -relief sunken -bd 1]
	set buttons_f    [LabelFrame $ofm.buttons_f]
	
	# Placing inner frames
	# Search options widget items
	set user_combo_box [ComboBox [$l_innerFrame getframe].user_combo_box -width 30 \
		-textvariable Apol_Initial_SIDS::opts(user) \
		-helptext "Type or select a user"]
	set role_combo_box [ComboBox [$c_innerFrame getframe].role_combo_box -width 30 \
		-textvariable Apol_Initial_SIDS::opts(role) \
		-helptext "Type or select a role"]
	set type_combo_box [ComboBox [$r_innerFrame getframe].type_combo_box -width 30 \
		-textvariable Apol_Initial_SIDS::opts(type) \
		-helptext "Type or select a type"]
	set attribute_combo_box [ComboBox [$r_innerFrame getframe].attribute_combo_box  \
    		-textvariable Apol_Initial_SIDS::attribute_selected \
    		-modifycmd {Apol_Initial_SIDS::change_types_list}]  
		
	$user_combo_box configure -state disabled 
	$role_combo_box configure -state disabled 
	$type_combo_box configure -state disabled 
	$attribute_combo_box configure -state disabled
	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $user_combo_box.e [linsert [bindtags $user_combo_box.e] 3 sid_user_Tag]
	bind sid_user_Tag <KeyPress> {Apol_Initial_SIDS::_create_popup $Apol_Initial_SIDS::user_combo_box %W %K}
	
	set cb_user [checkbutton [$l_innerFrame getframe].cb_user \
		-variable Apol_Initial_SIDS::user_cb_value -text "Search Using User" \
		-onvalue 1 -offvalue 0 \
		-command {Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::user_cb_value $Apol_Initial_SIDS::user_combo_box}]
	set cb_role [checkbutton [$c_innerFrame getframe].cb_role \
		-variable Apol_Initial_SIDS::role_cb_value -text "Search Using Role" \
		-onvalue 1 -offvalue 0 \
		-command {Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::role_cb_value $Apol_Initial_SIDS::role_combo_box}]
	set cb_attrib [checkbutton [$r_innerFrame getframe].cb_attrib \
		-text "Select type using attrib:" \
		-variable Apol_Initial_SIDS::attribute_cb_value \
		-offvalue 0 -onvalue 1 \
		-command {Apol_Initial_SIDS::enable_comboBox $Apol_Initial_SIDS::attribute_cb_value $Apol_Initial_SIDS::attribute_combo_box
				Apol_Initial_SIDS::change_types_list}]
	set cb_type [checkbutton [$r_innerFrame getframe].cb_type \
		-variable Apol_Initial_SIDS::type_cb_value -text "Search Using Type" \
		-onvalue 1 -offvalue 0 \
		-command "Apol_Initial_SIDS::enable_types_widgets"]
	$cb_attrib configure -state disabled			
	# Action Buttons
	set ok_button [button [$buttons_f getframe].ok -text OK -width 6 -command {Apol_Initial_SIDS::searchSIDs}]
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$resultsbox getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].resultsbox -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $ok_button -side top -anchor e -pady 5 -padx 5
	pack $l_innerFrame $c_innerFrame $r_innerFrame $buttons_f -side left -fill both -anchor nw -padx 4 -pady 4
	pack $buttons_f -side left -expand yes -fill both -anchor nw -padx 4 -pady 4
	pack $cb_user $cb_role $cb_type -side top -anchor nw
	pack $user_combo_box $role_combo_box $type_combo_box -side top -anchor nw -padx 4
	pack $cb_attrib -side top -expand yes -anchor nw -padx 15
	pack $attribute_combo_box -side top -fill x -expand yes -anchor nw -padx 25
	pack $sw_r -fill both -expand yes
	pack $sw_d -side left -expand yes -fill both 
	
	return $frame	
}

