namespace eval hv3 { set {version($Id: hv3_main.tcl,v 1.176 2007/11/17 11:24:21 danielk1977 Exp $)} 1 }

catch {memory init on}

proc sourcefile {file} [string map              \
  [list %HV3_DIR% [file dirname [info script]]] \
{ 
  return [file join {%HV3_DIR%} $file] 
}]

# Before doing anything else, set up profiling if it is requested.
# Profiling is only used if the "-profile" option was passed on
# the command line.
source [sourcefile hv3_profile.tcl]
::hv3::profile::init $argv

package require Tk
tk scaling 1.33333
package require Tkhtml 3.0

# If possible, load package "Img". Without it the script can still run,
# but won't be able to load many image formats.
#
if {[catch { package require Img } errmsg]} {
  puts stderr "WARNING: $errmsg (most image types will fail to load)"
}

source [sourcefile hv3_browser.tcl]
if {![llength [info procs ::console]]} {
    source [sourcefile hv3_console.tcl]
}

namespace eval ::hv3 {
  set log_source_option 0
  set reformat_scripts_option 0
}

# ::hv3::config
#
#     An instance of this class manages the application "View" menu, 
#     which contains all the runtime configuration options (font size, 
#     image loading etc.).
#
snit::type ::hv3::config {

  # The SQLite database containing the configuration used
  # by this application instance. 
  #
  variable myDb ""
  variable myPollActive 0

  foreach {opt def type} [list \
    -enableimages     1                         Boolean \
    -enablejavascript 0                         Boolean \
    -forcefontmetrics 1                         Boolean \
    -hidegui          0                         Boolean \
    -zoom             1.0                       Double  \
    -fontscale        1.0                       Double  \
    -guifont          11                        Integer \
    -debuglevel       0                         Integer \
    -fonttable        [list 8 9 10 11 13 15 17] SevenIntegers \
  ] {
    option $opt -default $def -validatemethod $type -configuremethod SetOption
  }
  
  constructor {db args} {
    set myDb $db

    $myDb transaction {
      set rc [catch {
        $myDb eval {
          CREATE TABLE cfg_options1(name TEXT PRIMARY KEY, value);
        }
      }]
      if {$rc == 0} {
        foreach {n v} [array get options] {
          $myDb eval {INSERT INTO cfg_options1 VALUES($n, $v)}
        } 
      } else {
        $myDb eval {SELECT name, value FROM cfg_options1} {
          set options($name) $value
          if {$name eq "-guifont"} {
            after idle [list ::hv3::SetFont [list -size $value]]
          }
        }
      }
    }

    $self configurelist $args
    after 2000 [list $self PollConfiguration]
  }

  method PollConfiguration {} {
    set myPollActive 1
    $myDb transaction {
      foreach n [array names options] {
        set v [$myDb one { SELECT value FROM cfg_options1 WHERE name = $n }]
        if {$options($n) ne $v} {
          $self configure $n $v
        }
      }
    }
    set myPollActive 0
    after 2000 [list $self PollConfiguration]
  }

  method populate_menu {path} {

    # Add the 'Gui Font (size)' menu
    ::hv3::menu ${path}.guifont
    $self PopulateRadioMenu ${path}.guifont -guifont [list \
        8      "8 pts" \
        9      "9 pts" \
        10    "10 pts" \
        11    "11 pts" \
        12    "12 pts" \
        14    "14 pts" \
        16    "16 pts" \
    ]
    $path add cascade -label {Gui Font} -menu ${path}.guifont

    $self populate_hidegui_entry $path
    $path add separator

    # Add the 'Zoom' menu
    ::hv3::menu ${path}.zoom
    $self PopulateRadioMenu ${path}.zoom -zoom [list \
        0.25    25% \
        0.5     50% \
        0.75    75% \
        0.87    87% \
        1.0    100% \
        1.131  113% \
        1.25   125% \
        1.5    150% \
        2.0    200% \
    ]
    $path add cascade -label {Browser Zoom} -menu ${path}.zoom

    # Add the 'Font Scale' menu
    ::hv3::menu ${path}.fontscale
    $self PopulateRadioMenu ${path}.fontscale -fontscale [list \
        0.8     80% \
        0.9     90% \
        1.0    100% \
        1.2    120% \
        1.4    140% \
        2.0    200% \
    ]
    $path add cascade -label {Browser Font Scale} -menu ${path}.fontscale
      
    # Add the 'Font Size Table' menu
    set fonttable [::hv3::menu ${path}.fonttable]
    $self PopulateRadioMenu $fonttable -fonttable [list \
        {7 8 9 10 12 14 16}    "Normal"            \
        {8 9 10 11 13 15 17}   "Medium"            \
        {9 10 11 12 14 16 18}  "Large"             \
        {11 12 13 14 16 18 20} "Very Large"        \
        {13 14 15 16 18 20 22} "Extra Large"       \
        {15 16 17 18 20 22 24} "Recklessly Large"  \
    ]
    $path add cascade -label {Browser Font Size Table} -menu $fonttable

    foreach {option label} [list \
        -forcefontmetrics "Force CSS Font Metrics" \
        -enableimages     "Enable Images"          \
        --                --                       \
        -enablejavascript "Enable ECMAscript"      \
    ] {
      if {$option eq "--"} {
        $path add separator
      } else {
        set var [myvar options($option)]
        set cmd [list $self Reconfigure $option]
        $path add checkbutton -label $label -variable $var -command $cmd
      }
    }
    if {[info commands ::see::interp] eq ""} {
      $path entryconfigure end -state disabled
    }
  }

  method populate_hidegui_entry {path} {
    $path add checkbutton -label "Hide Gui" -variable [myvar options(-hidegui)]
    $path entryconfigure end -command [list $self Reconfigure -hidegui]
  }

  method PopulateRadioMenu {path option config} {
    foreach {val label} $config {
      $path add radiobutton                      \
        -variable [myvar options($option)]       \
        -value $val                              \
        -command [list $self Reconfigure $option]  \
        -label $label 
    }
  }

  method Reconfigure {option} {
    $self configure $option $options($option)
  }

  method Boolean {option value} {
    if {![string is boolean $value]} { error "Bad boolean value: $value" }
  }
  method Double {option value} {
    if {![string is double $value]} { error "Bad double value: $value" }
  }
  method Integer {option value} {
    if {![string is integer $value]} { error "Bad integer value: $value" }
  }
  method SevenIntegers {option value} {
    set len [llength $value]
    if {$len != 7} { error "Bad seven-integers value: $value" }
    foreach elem $value {
      if {![string is integer $elem]} { 
        error "Bad seven-integers value: $value"
      }
    }
  }

  method SetOption {option value} {
    set options($option) $value
    if {$myPollActive == 0} {
      $myDb eval {REPLACE INTO cfg_options1 VALUES($option, $value)}
    }

    switch -- $option {
      -hidegui {
        if {$value} {
          . configure -menu ""
          pack forget .status
          pack forget .toolbar
        } else {
          . configure -menu .m
          pack .status -after .notebook -fill x -side bottom
          pack .toolbar -before .notebook -fill x -side top
        }
      }
      -guifont {
        ::hv3::SetFont [list -size $options(-guifont)]
      }
      -debuglevel {
        switch -- $value {
          0 {
            set ::hv3::reformat_scripts_option 0
            set ::hv3::log_source_option 0
          }
          1 {
            set ::hv3::reformat_scripts_option 0
            set ::hv3::log_source_option 1
          }
          2 {
            set ::hv3::reformat_scripts_option 1
            set ::hv3::log_source_option 1
          }
        }
      }
      default {
        $self configurebrowser [.notebook current]
      } 
    }
  }

  method StoreOptions {} {
  }
  method RetrieveOptions {} {
  }

  method configurebrowser {b} {
    if {$b eq ""} return
    foreach {option var} [list                       \
        -fonttable        options(-fonttable)        \
        -fontscale        options(-fontscale)        \
        -zoom             options(-zoom)             \
        -forcefontmetrics options(-forcefontmetrics) \
        -enableimages     options(-enableimages)     \
        -enablejavascript options(-enablejavascript) \
    ] {
      if {[$b cget $option] ne [set $var]} {
        $b configure $option [set $var]
        foreach f [$b get_frames] {
          if {[$f positionid] ne "0"} {
            $self configureframe $f
          }
        }
      }
    }
  }
  method configureframe {b} {
    foreach {option var} [list                       \
        -fonttable        options(-fonttable)        \
        -fontscale        options(-fontscale)        \
        -zoom             options(-zoom)             \
        -forcefontmetrics options(-forcefontmetrics) \
        -enableimages     options(-enableimages)     \
    ] {
      if {[$b cget $option] ne [set $var]} {
        $b configure $option [set $var]
      }
    }
  }

  destructor {
    after cancel [list $self PollConfiguration]
  }
}

snit::type ::hv3::search {

  typevariable SearchHotKeys -array [list  \
      {Google}    g         \
      {Tcl Wiki}  w         \
  ]
  
  variable mySearchEngines [list \
      ----------- -                                                        \
      {Google}    "http://www.google.com/search?q=%s"                      \
      {Tcl Wiki}  "http://wiki.tcl.tk/_search?S=%s"                        \
      ----------- -                                                        \
      {Ask.com}   "http://www.ask.com/web?q=%s"                            \
      {MSN}       "http://search.msn.com/results.aspx?q=%s"                \
      {Wikipedia} "http://en.wikipedia.org/wiki/Special:Search?search=%s"  \
      {Yahoo}     "http://search.yahoo.com/search?p=%s"                    \
  ]
  variable myDefaultEngine Google

  constructor {} {
    bind Hv3HotKeys <Control-f>  [list gui_current Find]
    bind Hv3HotKeys <Control-F>  [list gui_current Find]
    foreach {label} [array names SearchHotKeys] {
      set lc $SearchHotKeys($label)
      set uc [string toupper $SearchHotKeys($label)]
      bind Hv3HotKeys <Control-$lc> [list $self search $label]
      bind Hv3HotKeys <Control-$uc> [list $self search $label]
    }
  }

  method populate_menu {path} {
    set cmd [list gui_current Find] 
    set acc (Ctrl-F)
    $path add command -label {Find in page...} -command $cmd -accelerator $acc

    foreach {label uri} $mySearchEngines {
      if {[string match ---* $label]} {
        $path add separator
        continue
      }

      $path add command -label $label -command [list $self search $label]

      if {[info exists SearchHotKeys($label)]} {
        set acc "(Ctrl-[string toupper $SearchHotKeys($label)])"
        $path entryconfigure end -accelerator $acc
      }
    }
  }

  method search {{default ""}} {
    if {$default eq ""} {set default $myDefaultEngine}

    # The currently visible ::hv3::browser widget.
    set btl [.notebook current]

    set fdname ${btl}.findwidget
    set initval ""
    if {[llength [info commands $fdname]] > 0} {
      set initval [${fdname}.entry get]
      destroy $fdname
    }

    set conf [list]
    foreach {label uri} $mySearchEngines {
      if {![string match ---* $label]} {
        lappend conf $label $uri
      }
    }
  
    ::hv3::googlewidget $fdname  \
        -getcmd [list $btl goto] \
        -config $conf            \
        -initial $default

    $btl packwidget $fdname
    $fdname configure -borderwidth 1 -relief raised

    # Pressing <Escape> dismisses the search widget.
    bind ${fdname}.entry <KeyPress-Escape> gui_escape

    ${fdname}.entry insert 0 $initval
    focus ${fdname}.entry
  }
}

snit::type ::hv3::file_menu {

  variable MENU

  constructor {} {
    set MENU [list \
      "Open File..."  [list gui_openfile $::hv3::G(notebook)]           o  \
      "Open Tab"      [list $::hv3::G(notebook) add]                    t  \
      "Open Location" [list gui_openlocation $::hv3::G(location_entry)] l  \
      "-----"         ""                                                "" \
      "Bookmark Page" [list ::hv3::gui_bookmark]                        b  \
      "-----"         ""                                                "" \
      "Downloads..."  [list ::hv3::the_download_manager show]           "" \
      "-----"         ""                                                "" \
      "Close Tab"     [list $::hv3::G(notebook) close]                  "" \
      "Exit"          exit                                              q  \
    ]
  }

  method populate_menu {path} {
    $path delete 0 end

    foreach {label command key} $MENU {
      if {[string match ---* $label]} {
        $path add separator
        continue
      }
      $path add command -label $label -command $command 
      if {$key ne ""} {
        set acc "(Ctrl-[string toupper $key])"
        $path entryconfigure end -accelerator $acc
      }
    }

    if {[llength [$::hv3::G(notebook) tabs]] < 2} {
      $path entryconfigure "Close Tab" -state disabled
    }
  }

  method setup_hotkeys {} {
    foreach {label command key} $MENU {
      if {$key ne ""} {
        set uc [string toupper $key]
        bind Hv3HotKeys <Control-$key> $command
        bind Hv3HotKeys <Control-$uc> $command
      }
    }
  }
}

proc ::hv3::gui_bookmark {} {
  ::hv3::bookmarks::new_bookmark [gui_current hv3]
}

snit::type ::hv3::debug_menu {

  variable MENU

  variable myDebugLevel 0
  variable myHv3Options

  constructor {hv3_options} {
    set myHv3Options $hv3_options
    set myDebugLevel [$hv3_options cget -debuglevel]
    set MENU [list \
      "Cookies"              [list $::hv3::G(notebook) add cookies:]      "" \
      "About"                [list $::hv3::G(notebook) add home://about]  "" \
      "Polipo..."            [list ::hv3::polipo::popup]                  "" \
      "Events..."            [list gui_log_window $::hv3::G(notebook)]    "" \
      "-----"                [list]                                       "" \
      "Tree Browser..."      [list gui_current browse]                    "" \
      "Debugging Console..." [list ::hv3::launch_console]                 d  \
      "-----"                [list]                                       "" \
      "Exec firefox -remote" [list gui_firefox_remote]                    "" \
      "-----"                   [list]                                    "" \
      "Show Tcl Console"     [list ::console show]                        "" \
      "-----"                   [list]                                    "" \
      "Reset Profiling Data..." [list ::hv3::profile::zero]               "" \
      "Save Profiling Data..."  [list ::hv3::profile::report_to_file]     "" \
    ]
  }

  method populate_menu {path} {
    $path delete 0 end

    set m [::hv3::menu ${path}.debuglevel]
    $m add radiobutton                            \
        -variable [myvar myDebugLevel]            \
        -value 0                                  \
        -command [list $self SetDebugLevel]   \
        -label "No logging"
    $m add radiobutton                            \
        -variable [myvar myDebugLevel]            \
        -value 1                                  \
        -command [list $self SetDebugLevel]   \
        -label "Log source"
    $m add radiobutton                            \
        -variable [myvar myDebugLevel]            \
        -value 2                                  \
        -command [list $self SetDebugLevel]   \
        -label "Reformat and log source (buggy)"

    foreach {label command key} $MENU {
      if {[string match ---* $label]} {
        $path add separator
        continue
      }
      $path add command -label $label -command $command 
      if {$key ne ""} {
        set acc "(Ctrl-[string toupper $key])"
        $path entryconfigure end -accelerator $acc
      }
      if {$key eq "d"} {
        $path add cascade -menu $m -label "Application Source Logging"
      }
    }

    if {0 == [hv3::profile::enabled]} {
      $path entryconfigure end -state disabled
      $path entryconfigure [expr [$path index end] - 1] -state disabled
    }

    $self SetDebugLevel
  }

  method SetDebugLevel {} {
    $myHv3Options configure -debuglevel $myDebugLevel
  }

  method setup_hotkeys {} {
    foreach {label command key} $MENU {
      if {$key ne ""} {
        set uc [string toupper $key]
        bind Hv3HotKeys <Control-$key> $command
        bind Hv3HotKeys <Control-$uc> $command
      }
    }
  }
}


#--------------------------------------------------------------------------
# The following functions are all called during startup to construct the
# static components of the web browser gui:
#
#     gui_build
#     gui_menu
#       gui_load_tkcon
#       create_fontsize_menu
#       create_fontscale_menu
#

# gui_build --
#
#     This procedure is called once at the start of the script to build
#     the GUI used by the application. It creates all the widgets for
#     the main window. 
#
#     The argument is the name of an array variable in the parent context
#     into which widget names are written, according to the following 
#     table:
#
#         Array Key            Widget
#     ------------------------------------------------------------
#         stop_button          The "stop" button
#         back_button          The "back" button
#         forward_button       The "forward" button
#         location_entry       The location bar
#         notebook             The ::hv3::notebook instance
#         status_label         The label used for a status bar
#         history_menu         The pulldown menu used for history
#
proc gui_build {widget_array} {
  upvar $widget_array G
  global HTML

  # Create the top bit of the GUI - the URI entry and buttons.
  frame .toolbar
  frame .toolbar.b
  ::hv3::locationentry .toolbar.entry
  ::hv3::toolbutton .toolbar.b.back    -text {Back} -tooltip    "Go Back"
  ::hv3::toolbutton .toolbar.b.stop    -text {Stop} -tooltip    "Stop"
  ::hv3::toolbutton .toolbar.b.forward -text {Forward} -tooltip "Go Forward"

  ::hv3::toolbutton .toolbar.b.new -text {New Tab} -command [list .notebook add]
  ::hv3::toolbutton .toolbar.b.home -text Home -command [list \
      gui_current goto $::hv3::homeuri
  ]
  ::hv3::toolbutton .toolbar.bug -text {Report Bug} -command gui_report_bug

  .toolbar.b.new configure -tooltip "Open New Tab"
  .toolbar.b.home configure -tooltip "Go to Bookmarks Manager"

  .toolbar.bug configure -tooltip "Bug Report"

  catch {
    set backimg [image create photo -data $::hv3::back_icon]
    .toolbar.b.back configure -image $backimg
    set forwardimg [image create photo -data $::hv3::forward_icon]
    .toolbar.b.forward configure -image $forwardimg
    image create photo hv3_reloadimg -data $::hv3::reload_icon]
    image create photo hv3_stopimg -data $::hv3::stop_icon
    .toolbar.b.stop configure -image hv3_stopimg

    set newimg [image create photo -data $::hv3::new_icon]
    .toolbar.b.new configure -image $newimg
    set homeimg [image create photo -data $::hv3::home_icon]
    .toolbar.b.home configure -image $homeimg
    set bugimg [image create photo -data $::hv3::bug_icon]
    .toolbar.bug configure -image $bugimg
  }

  # Create the middle bit - the browser window
  #
  ::hv3::notebook .notebook              \
      -newcmd    gui_new                 \
      -switchcmd gui_switch

  # And the bottom bit - the status bar
  ::hv3::label .status -anchor w -width 1
  bind .status <1>     [list gui_current ProtocolGui toggle]

  bind .status <3>     [list gui_status_toggle $widget_array]
  bind .status <Enter> [list gui_status_enter  $widget_array]
  bind .status <Leave> [list gui_status_leave  $widget_array]

  # Set the widget-array variables
  set G(new_button)     .toolbar.b.new
  set G(stop_button)    .toolbar.b.stop
  set G(back_button)    .toolbar.b.back
  set G(forward_button) .toolbar.b.forward
  set G(home_button)    .toolbar.b.home
  set G(location_entry) .toolbar.entry
  set G(notebook)       .notebook
  set G(status_label)   .status

  # The G(status_mode) variable takes one of the following values:
  #
  #     "browser"      - Normal browser status bar.
  #     "browser-tree" - Similar to "browser", but displays the document tree
  #                      hierachy for the node the cursor is currently 
  #                      hovering over. This used to be the default.
  #     "memory"       - Show information to do with Hv3's memory usage.
  #
  # The "browser" mode uses less CPU than "browser-tree" and "memory". 
  # The user cycles through the modes by right-clicking on the status bar.
  #
  set G(status_mode)    "browser"

  # Pack the elements of the "top bit" into the .entry frame
  pack .toolbar.b.new -side left
  pack .toolbar.b.back -side left
  pack .toolbar.b.forward -side left
  pack .toolbar.b.stop -side left
  pack .toolbar.b.home -side left
  pack [frame .toolbar.b.spacer -width 2 -height 1] -side left

  pack .toolbar.b -side left
  pack .toolbar.bug -side right
  pack .toolbar.entry -fill x -expand true

  # Pack the top, bottom and middle, in that order. The middle must be 
  # packed last, as it is the bit we want to shrink if the size of the 
  # main window is reduced.
  pack .toolbar -fill x -side top 
  pack .status -fill x -side bottom
  pack .notebook -fill both -expand true
}

proc goto_gui_location {browser entry args} {
  set location [$entry get]
  $browser goto $location
}

# A helper function for gui_menu.
#
# This procedure attempts to load the tkcon package. An error is raised
# if the package cannot be loaded. On success, an empty string is returned.
#
proc gui_load_tkcon {} {
  foreach f [list \
    [file join $::tcl_library .. .. bin tkcon] \
    [file join $::tcl_library .. .. bin tkcon.tcl]
  ] {
    if {[file exists $f]} {
      uplevel #0 "source $f"
      package require tkcon
      return 
    }
  }
  error "Failed to load Tkcon"
  return ""
}

proc gui_openlocation {location_entry} {
  $location_entry selection range 0 end
  $location_entry OpenDropdown *
  focus ${location_entry}.entry
}

proc gui_populate_menu {eMenu menu_widget} {
  switch -- [string tolower $eMenu] {
    file {
      set cmd [list $::hv3::G(file_menu) populate_menu $menu_widget]
      $menu_widget configure -postcommand $cmd
    }

    search {
      $::hv3::G(search) populate_menu $menu_widget
    }

    options {
      $::hv3::G(config) populate_menu $menu_widget
    }

    debug {
      $::hv3::G(debug_menu) populate_menu $menu_widget
    }

    history {
      set cmd [list gui_current populate_history_menu $menu_widget]
      $menu_widget configure -postcommand $cmd
    }

    default {
      error "gui_populate_menu: No such menu: $eMenu"
    }
  }
}

proc gui_menu {widget_array} {
  upvar $widget_array G

  # Attach a menu widget - .m - to the toplevel application window.
  . config -menu [::hv3::menu .m]

  set G(config)     [::hv3::config %AUTO% ::hv3::sqlitedb]
  set G(file_menu)  [::hv3::file_menu %AUTO%]
  set G(search)     [::hv3::search %AUTO%]
  set G(debug_menu) [::hv3::debug_menu %AUTO% $G(config)]

  # Add the "File", "Search" and "View" menus.
  foreach m [list File Search Options Debug History] {
    set menu_widget .m.[string tolower $m]
    gui_populate_menu $m [::hv3::menu $menu_widget]
    .m add cascade -label $m -menu $menu_widget -underline 0
  }

  $G(file_menu) setup_hotkeys
  $G(debug_menu) setup_hotkeys
}
#--------------------------------------------------------------------------

proc gui_current {args} {
  eval [linsert $args 0 [.notebook current]]
}

proc gui_firefox_remote {} {
  set url [.toolbar.entry get]
  exec firefox -remote "openurl($url,new-tab)"
}

proc gui_switch {new} {
  upvar #0 ::hv3::G G

  # Loop through *all* tabs and detach them from the history
  # related controls. This is so that when the state of a background
  # tab is updated, the history menu is not updated (only the data
  # structures in the corresponding ::hv3::history object).
  #
  foreach browser [.notebook tabs] {
    $browser configure -backbutton    ""
    $browser configure -stopbutton    ""
    $browser configure -forwardbutton ""
    $browser configure -locationentry ""
  }

  # Configure the new current tab to control the history controls.
  #
  set new [.notebook current]
  $new configure -backbutton    $G(back_button)
  $new configure -stopbutton    $G(stop_button)
  $new configure -forwardbutton $G(forward_button)
  $new configure -locationentry $G(location_entry)

  # Attach some other GUI elements to the new current tab.
  #
  set gotocmd [list goto_gui_location $new $G(location_entry)]
  $G(location_entry) configure -command $gotocmd
  gui_status_leave ::hv3::G

  # Configure the new current tab with the contents of the drop-down
  # config menu (i.e. font-size, are images enabled etc.).
  #
  $G(config) configurebrowser $new

  # Set the top-level window title to the title of the new current tab.
  #
  wm title . [.notebook get_title $new]

  # Focus on the root HTML widget of the new tab.
  #
  focus [[$new hv3] html]
}

proc gui_new {path args} {
  set new [::hv3::browser $path]
  $::hv3::G(config) configurebrowser $new

  set var [$new titlevar]
  trace add variable $var write [list gui_settitle $new $var]

  set var [$new locationvar]
  trace add variable $var write [list gui_settitle $new $var]

  if {[llength $args] == 0} {
    $new goto $::hv3::homeuri
  } else {
    $new goto [lindex $args 0]
  }
  
  # This black magic is required to initialise the history system.
  # A <<Location>> event will be generated from within the [$new goto]
  # command above, but the history system won't see it, because 
  # events are not generated until the window is mapped. So generate
  # an extra <<Location>> when the window is mapped.
  #
  bind [$new hv3] <Map>  [list event generate [$new hv3] <<Location>>]
  bind [$new hv3] <Map> +[list bind <Map> [$new hv3] ""]

  # [[$new hv3] html] configure -logcmd print

  return $new
}

proc gui_settitle {browser var args} {
  if {[.notebook current] eq $browser} {
    wm title . [set $var]
  }
  .notebook set_title $browser [set $var]
}

# This procedure is invoked when the user selects the File->Open menu
# option. It launches the standard Tcl file-selector GUI. If the user
# selects a file, then the corresponding URI is passed to [.hv3 goto]
#
proc gui_openfile {notebook} {
  set browser [$notebook current]
  set f [tk_getOpenFile -filetypes [list \
      {{Html Files} {.html}} \
      {{Html Files} {.htm}}  \
      {{All Files} *}
  ]]
  if {$f != ""} {
    if {$::tcl_platform(platform) eq "windows"} {
      set f [string map {: {}} $f]
    }
    $browser goto file://$f 
  }
}

proc gui_log_window {notebook} {
  set browser [$notebook current]
  ::hv3::log_window [[$browser hv3] html]
}

proc gui_report_bug {} {
  upvar ::hv3::G G
  set uri [[[$G(notebook) current] hv3] uri get]
  .notebook add "home://bug/[::hv3::format_query [encoding system] $uri]"

  set cookie "tkhtml_captcha=[expr [clock seconds]+86399]; Path=/; Version=1"
  ::hv3::the_cookie_manager SetCookie http://tkhtml.tcl.tk/ $cookie
}

proc gui_escape {} {
  upvar ::hv3::G G
  gui_current escape
  $G(location_entry) escape
  focus [[gui_current hv3] html]
}
bind Hv3HotKeys <KeyPress-Escape> gui_escape

proc gui_status_enter {widget_array} {
  upvar $widget_array G
  after cancel [list gui_set_memstatus $widget_array]
  gui_status_help $widget_array
  $G(status_label) configure -textvar ::hv3::G(status_help)
}
proc gui_status_help {widget_array} {
  upvar $widget_array G
  set G(status_help)    "Current status-bar mode: "
  switch -- $G(status_mode) {
    browser      { append G(status_help) "Normal" }
    browser-tree { append G(status_help) "Tree-Browser" }
    memory       { append G(status_help) "Memory-Usage" }
  }
  append G(status_help) "        "
  append G(status_help) "(To toggle mode, right-click)"
  append G(status_help) "        "
  append G(status_help) "(To view outstanding resource requests, left-click)"
}
proc gui_status_leave {widget_array} {
  upvar $widget_array G

  switch -exact -- $G(status_mode) {
    browser {
      $G(status_label) configure -textvar [gui_current statusvar]
    }
    browser-tree {
      $G(status_label) configure -textvar [gui_current statusvar]
    }
    memory {
      $G(status_label) configure -textvar ""
      gui_set_memstatus $widget_array
    }
  }
}
proc gui_status_toggle {widget_array} {
  upvar $widget_array G
  set modes [list browser browser-tree memory]
  set iNewMode [expr {([lsearch $modes $G(status_mode)]+1)%[llength $modes]}]
  set G(status_mode) [lindex $modes $iNewMode]
  gui_status_help $widget_array
}

proc gui_set_memstatus {widget_array} {
  upvar $widget_array G
  if {$G(status_mode) eq "memory"} {
    set status "Script:   "
    append status "[::count_vars] vars, [::count_commands] commands,"
    append status "[::count_namespaces] namespaces"

    catch {
      array set v [::see::alloc]
      set nHeap [expr {int($v(GC_get_heap_size) / 1000)}]
      set nFree [expr {int($v(GC_get_free_bytes) / 1000)}]
      set nDom $v(SeeTclObject)
      append status "          "
      append status "GC Heap: ${nHeap}K (${nFree}K free) "
      append status "($v(SeeTclObject) DOM objects)"
    }
    catch {
      foreach line [split [memory info] "\n"] {
        if {[string match {current packets allocated*} $line]} {
          set nAllocs [lindex $line end]
        }
        if {[string match {current bytes allocated*} $line]} {
          set nBytes [lindex $line end]
        }
      }
      set nBytes "[expr {int($nBytes / 1000)}]K"
      append status "          Tcl Heap: ${nBytes} in $nAllocs allocs"
    }

    $G(status_label) configure -text $status
    after 2000 [list gui_set_memstatus $widget_array]
  }
}

# Override the [exit] command to check if the widget code leaked memory
# or not before exiting.
#
rename exit tcl_exit
proc exit {args} {
  destroy .notebook
  catch {destroy .prop.hv3}
  catch {::tkhtml::htmlalloc}
  eval [concat tcl_exit $args]
}

proc JS {args} {
  set script [join $args " "]
  [[gui_current hv3] dom] javascript $script
}

#--------------------------------------------------------------------------
# main URI
#
#     The main() program for the application. This proc handles
#     parsing of command line arguments.
#
proc main {args} {

  set docs [list]

  for {set ii 0} {$ii < [llength $args]} {incr ii} {
    set val [lindex $args $ii]
    switch -glob -- $val {
      -s* {                  # -statefile <file-name>
        if {$ii == [llength $args] - 1} ::hv3::usage
        incr ii
        set ::hv3::statefile [lindex $args $ii]
      }
      -profile { 
	# Ignore this here. If the -profile option is present it will 
        # have been handled already.
      }
      -enablejavascript { 
        set enablejavascript 1
      }
      default {
        set uri [::tkhtml::uri file:///[pwd]/]
        lappend docs [$uri resolve $val]
        $uri destroy
      }
    }
  }

  ::hv3::dbinit

  if {[llength $docs] == 0} {set docs [list home://bookmarks/]}
  # set ::hv3::homeuri [lindex $docs 0]
  set ::hv3::homeuri home://bookmarks/

  # Build the GUI
  gui_build     ::hv3::G
  gui_menu      ::hv3::G

  if {[info exists enablejavascript]} {
    $::hv3::G(config) configure -enablejavascript 1
  }

  ::hv3::downloadmanager ::hv3::the_download_manager

  # After the event loop has run to create the GUI, run [main2]
  # to load the startup document. It's better if the GUI is created first,
  # because otherwise if an error occurs Tcl deems it to be fatal.
  after idle [list main2 $docs]
}
proc main2 {docs} {
  foreach doc $docs {
    set tab [$::hv3::G(notebook) add $doc]
  }
  focus $tab
}
proc ::hv3::usage {} {
  puts stderr "Usage:"
  puts stderr "    $::argv0 ?-statefile <file-name>? ?<uri>?"
  puts stderr ""
  tcl_exit
}

set ::hv3::statefile ":memory:"

# Remote scaling interface:
proc hv3_zoom      {newval} { $::hv3::G(config) set_zoom $newval }
proc hv3_fontscale {newval} { $::hv3::G(config) set_fontscale $newval }
proc hv3_forcewidth {forcewidth width} { 
  [[gui_current hv3] html] configure -forcewidth $forcewidth -width $width
}

proc hv3_guifont {newval} { $::hv3::G(config) set_guifont $newval }

proc hv3_html {args} { 
  set html [[gui_current hv3] html]
  eval [concat $html $args]
}

# Set variable $::hv3::maindir to the directory containing the 
# application files. Then run the [main] command with the command line
# arguments passed to the application.
set ::hv3::maindir [file dirname [info script]] 
eval [concat main $argv]

proc print {args} { puts [join $args] }

#--------------------------------------------------------------------------

