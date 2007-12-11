# This file contains the mega-widget hv3::hv3 used by the hv3 demo web 
# browser. An instance of this widget displays a single HTML frame.
#
# Standard Functionality:
#
#     xview
#     yview
#     -xscrollcommand
#     -yscrollcommand
#     -width
#     -height
# 
# Widget Specific Options:
#
#     -requestcmd
#         If not an empty string, this option specifies a script to be
#         invoked for a GET or POST request. The script is invoked with a
#         download handle appended to it. See the description of class
#         ::hv3::download for a description.
#
#     -targetcmd
#         If not an empty string, this option specifies a script for
#         the widget to invoke when a hyperlink is clicked on or a form
#         submitted. The script is invoked with the node handle of the 
#         clicked hyper-link element appended. The script must return
#         the name of an hv3 widget to load the new document into. This
#         is intended to be used to implement frameset handling.
#
#     -isvisitedcmd
#         If not an empty string, this option specifies a script for
#         the widget to invoke to determine if a hyperlink node should
#         be styled with the :link or :visited pseudo-class. The
#         script is invoked with the node handle appended to it. If
#         true is returned, :visited is used, otherwise :link.
#
#     -fonttable
#         Delegated through to the html widget.
#
#     -locationvar
#         Set to the URI of the currently displayed document.
#
#     -scrollbarpolicy
#         This option may be set to either a boolean value or "auto". It
#         determines the visibility of the widget scrollbars. TODO: This
#         is now set internally by the value of the "overflow" property
#         on the root element. Maybe the option should be removed?
#
#
# Widget Sub-commands:
#
#     goto URI ?OPTIONS?
#         Load the content at the specified URI into the widget. 
#
#     stop
#         Cancel all pending downloads.
#
#     node        
#         Caching wrapper around html widget [node] command.
#
#     reset        
#         Wrapper around the html widget command of the same name. Also
#         resets all document related state stored by the mega-widget.
#
#     html        
#         Return the path of the underlying html widget. This should only
#         be used to determine paths for child widgets. Bypassing hv3 and
#         accessing the html widget interface directly may confuse hv3.
#
#     title        
#         Return the "title" of the currently loaded document.
#
#     location        
#         Return the location URI of the widget.
#
#     selectall
#         Select all text in the underlying html widget.
#
#     selected        
#         Return the currently selected text, or an empty string if no
#         text is currently selected.
#
#
# Widget Custom Events:
#
#     <<Goto>>
#         This event is generated whenever the goto method is called.
#
#     <<Complete>>
#         This event is generated once all of the resources required
#         to display a document have been loaded. This is analogous
#         to the Html "onload" event.
#
#     <<Location>>
#         This event is generated whenever the "location" is set.
#
#     <<SaveState>>
#         Generated whenever the widget state should be saved.

#
# The code in this file is partitioned into the following classes:
#
#     ::hv3::hv3
#     ::hv3::download
#     ::hv3::selectionmanager
#     ::hv3::dynamicmanager
#     ::hv3::hyperlinkmanager
#
# ::hv3::hv3 is, of course, the main mega-widget class. Class
# ::hv3::download is part of the public interface to ::hv3::hv3. A
# single instance of ::hv3::download represents a resource request made
# by the mega-widget package - for document, stylesheet, image or 
# object data.
#
# The three "manager" classes all implement the following interface. Each
# ::hv3::hv3 widget has exactly one of each manager class as a component.
# Further manager objects may be added in the future. Interface:
#
#     set manager [::hv3::XXXmanager $hv3]
#
#     $manager motion  X Y
#     $manager release X Y
#     $manager press   X Y
#
# The -targetcmd option of ::hv3::hv3 is delegated to the
# ::hv3::hyperlinkmanager component.
#
package require Tkhtml 3.0
package require snit

source [file join [file dirname [info script]] hv3_form.tcl]
source [file join [file dirname [info script]] hv3_object.tcl]
source [file join [file dirname [info script]] hv3_doctype.tcl]
source [file join [file dirname [info script]] hv3_request.tcl]
source [file join [file dirname [info script]] hv3_dom.tcl]

#--------------------------------------------------------------------------
# Class ::hv3::hv3::mousemanager
#
#     This type contains code for the ::hv3::hv3 widget to manage 
#     dispatching mouse events that occur in the HTML widget to the 
#     rest of the application. The following HTML4 events are handled:
#
#     Pointer movement:
#         onmouseover
#         onmouseout
#         motion
#
#     Click-related events:
#         onmousedown
#         onmouseup
#         onclick
#
#     Currently, the following hv3 subsystems subscribe to one or more of
#     these events:
#
#         ::hv3::hyperlinkmanager
#             Click events, mouseover and mouseout on all nodes.
#
#         ::hv3::dynamicmanager
#             Events mouseover, mouseout, mousedown mouseup on all nodes.
#
#         ::hv3::formmanager
#             Click events (for clickable controls) on all nodes.
#
#         ::hv3::selectionmanager
#             motion
#
snit::type ::hv3::hv3::mousemanager {

  variable myHv3 ""
  variable myHtml ""

  # In browsers with no DOM support, the following option is set to
  # an empty string.
  #
  # If not set to an empty string, this option is set to the name
  # of the ::hv3::dom object to dispatch events too. The DOM 
  # is a special client because it may cancel the "default action"
  # of mouse-clicks (it may also cancel other events, but they are
  # dispatched by other sub-systems).
  #
  # Each time an event occurs, the following script is executed:
  #
  #     $options(-dom) mouseevent EVENT-TYPE NODE X Y ?OPTIONS?
  #
  # where OPTIONS are:
  #
  #     -button          INTEGER        (default 0)
  #     -detail          INTEGER        (default 0)
  #     -relatedtarget   NODE-HANDLE    (default "")
  #
  # the EVENT-TYPE parameter is one of:
  #
  #     "click", "mouseup", "mousedown", "mouseover" or "mouseout".
  #
  # NODE is the target leaf node and X and Y are the pointer coordinates
  # relative to the top-left of the html widget window.
  #
  # For "click" events, if the $options(-dom) script returns false, then
  # the "click" event is not dispatched to any subscribers (this happens
  # when some javascript calls the Event.preventDefault() method). If it
  # returns true, proceed as normal. Other event types ignore the return 
  # value of the $options(-dom) script.
  #
  option -dom -default ""

  # This variable is set to the node-handle that the pointer is currently
  # hovered over. Used by code that dispatches the "mouseout", "mouseover"
  # and "mousemove" to the DOM.
  #
  variable myCurrentDomNode ""

  # Database of callback scripts for each event type.
  #
  variable myScripts -array [list]

  # List of nodes currently "hovered" over and "active". An entry in
  # the correspondoing array indicates the condition is true.
  #
  variable myHoverNodes  -array [list]
  variable myActiveNodes -array [list]

  # The "top" node from the myHoverNodes array. This is the node
  # that determines the pointer to display (via the CSS2 'cursor' 
  # property).
  #
  variable myTopHoverNode ""

  # List of handled HTML4 event types (a constant)
  variable EVENTS [list \
      onmouseover onmouseout onclick onmousedown onmouseup motion
  ]

  variable myCursor ""
  variable myCursorWin ""

  constructor {hv3} {
    foreach e $EVENTS {
      set myScripts($e) [list]
    }

    set myHv3 $hv3
    set myHtml [$hv3 html]
    set myCursorWin [$hv3 hull]

    bind $myHv3 <Motion>          "+[list $self Motion  %W %x %y]"
    bind $myHv3 <ButtonPress-1>   "+[list $self Press   %W %x %y]"
    bind $myHv3 <ButtonRelease-1> "+[list $self Release %W %x %y]"
  }

  method subscribe {event script} {

    # Check that the $event argument is Ok:
    if {0 > [lsearch $EVENTS $event]} {
      error "No such mouse-event: $event"
    }

    # Append the script to the callback list.
    lappend myScripts($event) $script
  }

  method reset {} {
    array unset myActiveNodes
    array unset myHoverNodes
    set myCurrentDomNode ""
  }

  method GenerateEvents {eventlist} {
    foreach {event node} $eventlist {
      if {[info commands $node] ne ""} {
        foreach script $myScripts($event) {
          eval $script $node
        }
      }
    }
  }

  proc AdjustCoords {to W xvar yvar} {
    upvar $xvar x
    upvar $yvar y
    while {$W ne "" && $W ne $to} {
      incr x [winfo x $W]
      incr y [winfo y $W]
      set W [winfo parent $W]
    }
  }

  # Mapping from CSS2 cursor type to Tk cursor type.
  #
  typevariable CURSORS -array [list \
      crosshair crosshair    \
      default   ""           \
      pointer   hand2        \
      move      fleur        \
      text      xterm        \
      wait      watch        \
      progress  box_spiral     \
      help      question_arrow \
  ]

  method Motion {W x y} {
    if {$W eq ""} return
    AdjustCoords "${myHv3}.html.widget" $W x y

    # Figure out the node the cursor is currently hovering over. Todo:
    # When the cursor is over multiple nodes (because overlapping content
    # has been generated), maybe this should consider all overlapping nodes
    # as "hovered".
    set nodelist [lindex [$myHtml node $x $y] end]
    
    # Handle the 'cursor' property.
    #
    set topnode [lindex $nodelist end]
    if {$topnode ne "" && $topnode ne $myTopHoverNode} {

      set Cursor ""
      if {[$topnode tag] eq ""} {
        set Cursor xterm
        set topnode [$topnode parent]
      }
      set css2_cursor [$topnode property cursor]
      catch { set Cursor $CURSORS($css2_cursor) }

      if {$Cursor ne $myCursor} {
        $myCursorWin configure -cursor $Cursor
        set myCursor $Cursor
      }
      set myTopHoverNode $topnode
    }

    # Dispatch any DOM events in this order:
    #
    #     mouseout
    #     mouseover
    #     mousemotion
    #
    set N [lindex $nodelist end]
    if {$N eq ""} {set N [$myHv3 node]}

    if {$options(-dom) ne ""} {
      if {$N ne $myCurrentDomNode} {
        $options(-dom) mouseevent mouseout $myCurrentDomNode $x $y
        $options(-dom) mouseevent mouseover $N $x $y
        set myCurrentDomNode $N
      }
      $options(-dom) mouseevent mousemove $N $x $y
    }

    foreach script $myScripts(motion) {
      eval $script $N $x $y
    }

    # After the loop runs, hovernodes will contain the list of 
    # currently hovered nodes.
    array set hovernodes [list]

    # Events to generate:
    set events(onmouseout)  [list]
    set events(onmouseover) [list]

    foreach node $nodelist {
      if {[$node tag] eq ""} {set node [$node parent]}

      for {set n $node} {$n ne ""} {set n [$n parent]} {
        if {[info exists hovernodes($n)]} {
          break
        } else {
          if {[info exists myHoverNodes($n)]} {
            unset myHoverNodes($n)
          } else {
            lappend events(onmouseover) $n
          }
          set hovernodes($n) ""
        }
      }
    }
    set events(onmouseout)  [array names myHoverNodes]

    array unset myHoverNodes
    array set myHoverNodes [array get hovernodes]

    set eventlist [list]
    foreach key [list onmouseover onmouseout] {
      foreach node $events($key) {
        lappend eventlist $key $node
      }
    }
    $self GenerateEvents $eventlist
  }

  method Press {W x y} {
    if {$W eq ""} return
    AdjustCoords "${myHv3}.html.widget" $W x y
    set N [lindex [$myHtml node $x $y] end]
    if {$N ne ""} {
      if {[$N tag] eq ""} {set N [$N parent]}
    }
    if {$N eq ""} {set N [$myHv3 node]}

    # Dispatch the "mousedown" event to the DOM, if any.
    #
    set rc ""
    if {$options(-dom) ne ""} {
      set rc [$options(-dom) mouseevent mousedown $N $x $y]
    }

    # If the DOM implementation called preventDefault(), do 
    # not start selecting text. But every mouseclick should clear
    # the current selection, otherwise the browser window can get
    # into an annoying state.
    #
    if {$rc eq "prevent"} {
      $myHv3 selectionmanager clear
    } else {
      $myHv3 selectionmanager press $N $x $y
    }

    for {set n $N} {$n ne ""} {set n [$n parent]} {
      set myActiveNodes($n) 1
    }

    set eventlist [list]
    foreach node [array names myActiveNodes] {
      lappend eventlist onmousedown $node
    }
    $self GenerateEvents $eventlist
  }

  method Release {W x y} {
    if {$W eq ""} return
    AdjustCoords "${myHv3}.html.widget" $W x y
    set N [lindex [$myHtml node $x $y] end]
    if {$N ne ""} {
      if {[$N tag] eq ""} {set N [$N parent]}
    }
    if {$N eq ""} {set N [$myHv3 node]}

    # Dispatch the "mouseup" event to the DOM, if any.
    #
    # In Tk, the equivalent of the "mouseup" (<ButtonRelease>) is always
    # dispatched to the same widget as the "mousedown" (<ButtonPress>). 
    # But in the DOM things are different - the event target for "mouseup"
    # depends on the current cursor location only.
    #
    if {$options(-dom) ne ""} {
      $options(-dom) mouseevent mouseup $N $x $y
    }

    # Check if the is a "click" event to dispatch to the DOM. If the
    # ::hv3::dom [mouseevent] method returns 0, then the click is
    # not sent to the other hv3 sub-systems (default action is cancelled).
    #
    set domrc ""
    if {$options(-dom) ne ""} {
      for {set n $N} {$n ne ""} {set n [$n parent]} {
        if {[info exists myActiveNodes($N)]} {
          set domrc [$options(-dom) mouseevent click $n $x $y]
          break
        }
      }
    }

    set eventlist [list]
    foreach node [array names myActiveNodes] {
      lappend eventlist onmouseup $node
    }
    
    if {$domrc ne "prevent"} {
      set onclick_nodes [list]
      for {set n $N} {$n ne ""} {set n [$n parent]} {
        if {[info exists myActiveNodes($n)]} {
          lappend onclick_nodes $n
        }
      }
      foreach node $onclick_nodes {
        lappend eventlist onclick $node
      }
    }

    $self GenerateEvents $eventlist

    array unset myActiveNodes
  }
}

#--------------------------------------------------------------------------
# ::hv3::hv3::selectionmanager
#
#     This type encapsulates the code that manages selecting text
#     in the html widget with the mouse.
#
snit::type ::hv3::hv3::selectionmanager {

  # Variable myMode may take one of the following values:
  #
  #     "char"           -> Currently text selecting by character.
  #     "word"           -> Currently text selecting by word.
  #     "block"          -> Currently text selecting by block.
  #
  variable myState false             ;# True when left-button is held down
  variable myMode char

  # The ::hv3::hv3 widget.
  #
  variable myHv3

  variable myFromNode ""
  variable myFromIdx ""

  variable myToNode ""
  variable myToIdx ""

  variable myIgnoreMotion 0

  constructor {hv3} {
    set myHv3 $hv3
    selection handle $myHv3 [list ::hv3::bg [list $self get_selection]]

    # bind $myHv3 <Motion>               "+[list $self motion %x %y]"
    # bind $myHv3 <ButtonPress-1>        "+[list $self press %x %y]"
    bind $myHv3 <Double-ButtonPress-1> "+[list $self doublepress %x %y]"
    bind $myHv3 <Triple-ButtonPress-1> "+[list $self triplepress %x %y]"
    bind $myHv3 <ButtonRelease-1>      "+[list $self release %x %y]"
  }

  # Clear the selection.
  #
  method clear {} {
    $myHv3 tag delete selection
    $myHv3 tag configure selection -foreground white -background darkgrey
    set myFromNode ""
    set myToNode ""
  }

  method press {N x y} {
    # Single click -> Select by character.
    $self clear
    set myState true
    set myMode char
    $self motion $N $x $y
  }

  # Given a node-handle/index pair identifying a character in the 
  # current document, return the index values for the start and end
  # of the word containing the character.
  #
  proc ToWord {node idx} {
    set t [$node text]
    set cidx [::tkhtml::charoffset $t $idx]
    set cidx1 [string wordstart $t $cidx]
    set cidx2 [string wordend $t $cidx]
    set idx1 [::tkhtml::byteoffset $t $cidx1]
    set idx2 [::tkhtml::byteoffset $t $cidx2]
    return [list $idx1 $idx2]
  }

  # Add the widget tag "selection" to the word containing the character
  # identified by the supplied node-handle/index pair.
  #
  method TagWord {node idx} {
    foreach {i1 i2} [ToWord $node $idx] {}
    $myHv3 tag add selection $node $i1 $node $i2
  }

  # Remove the widget tag "selection" to the word containing the character
  # identified by the supplied node-handle/index pair.
  #
  method UntagWord {node idx} {
    foreach {i1 i2} [ToWord $node $idx] {}
    $myHv3 tag remove selection $node $i1 $node $i2
  }

  method ToBlock {node idx} {
    set t [$myHv3 text text]
    set offset [$myHv3 text offset $node $idx]

    set start [string last "\n" $t $offset]
    if {$start < 0} {set start 0}
    set end   [string first "\n" $t $offset]
    if {$end < 0} {set end [string length $t]}

    set start_idx [$myHv3 text index $start]
    set end_idx   [$myHv3 text index $end]

    return [concat $start_idx $end_idx]
  }

  method TagBlock {node idx} {
    foreach {n1 i1 n2 i2} [$self ToBlock $node $idx] {}
    $myHv3 tag add selection $n1 $i1 $n2 $i2
  }
  method UntagBlock {node idx} {
    foreach {n1 i1 n2 i2} [$self ToBlock $node $idx] {}
    catch {$myHv3 tag remove selection $n1 $i1 $n2 $i2}
  }

  method doublepress {x y} {
    # Double click -> Select by word.
    $self clear
    set myMode word
    set myState true
    $self motion "" $x $y
  }

  method triplepress {x y} {
    # Triple click -> Select by block.
    $self clear
    set myMode block
    set myState true
    $self motion "" $x $y
  }

  method release {x y} {
    set myState false
  }

  method reset {} {
    set myState false

    # Unset the myFromNode variable, since the node handle it (may) refer 
    # to is now invalid. If this is not done, a future call to the [selected]
    # method of this object will cause an error by trying to use the
    # (now invalid) node-handle value in $myFromNode.
    set myFromNode ""
    set myToNode ""
  }

  method selectall {} {
      $self clear
      # start selection from the first text node
      set textlen [string length [$myHv3 text text]]
      for {set i 0} {$i < $textlen} {incr i} {
          foreach {myFromNode myFromIdx} [$myHv3 text index $i] {break}
          if {$myFromNode != {}} {
              break
          }
      }
      if {$myFromNode == {}} {
          # nothing to select
          return
      }
      foreach {myToNode myToIdx} [$myHv3 text index [expr {$textlen - 1}]] {break}
      $myHv3 tag add selection $myFromNode $myFromIdx $myToNode $myToIdx
      selection own $myHv3
  }

  method motion {N x y} {
    if {!$myState || $myIgnoreMotion} return

    set to [$myHv3 node -index $x $y]
    foreach {toNode toIdx} $to {}

    # $N containst the node-handle for the node that the cursor is
    # currently hovering over (according to the mousemanager component).
    # If $N is in a different stacking-context to the closest text, 
    # do not update the highlighted region in this event.
    #
    if {$N ne "" && [info exists toNode]} {
      if {[$N stacking] ne [$toNode stacking]} {
        set to ""
      }
    }

    if {[llength $to] > 0} {

  
      if {$myFromNode eq ""} {
        set myFromNode $toNode
        set myFromIdx $toIdx
      }
  
      # This block is where the "selection" tag is added to the HTML 
      # widget (so that the selected text is highlighted). If some
      # javascript has been messing with the tree, then either or
      # both of $myFromNode and $myToNode may be orphaned or deleted.
      # If so, catch the exception and clear the selection.
      #
      set rc [catch {
        if {$myToNode ne $toNode || $toIdx != $myToIdx} {
          switch -- $myMode {
            char {
              if {$myToNode ne ""} {
                $myHv3 tag remove selection $myToNode $myToIdx $toNode $toIdx
              }
              $myHv3 tag add selection $myFromNode $myFromIdx $toNode $toIdx
              if {$myFromNode ne $toNode || $myFromIdx != $toIdx} {
                selection own $myHv3
              }
            }
    
            word {
              if {$myToNode ne ""} {
                $myHv3 tag remove selection $myToNode $myToIdx $toNode $toIdx
                $self UntagWord $myToNode $myToIdx
              }
    
              $myHv3 tag add selection $myFromNode $myFromIdx $toNode $toIdx
              $self TagWord $toNode $toIdx
              $self TagWord $myFromNode $myFromIdx
              selection own $myHv3
            }
    
            block {
              set to_block2  [$self ToBlock $toNode $toIdx]
              set from_block [$self ToBlock $myFromNode $myFromIdx]
    
              if {$myToNode ne ""} {
                set to_block [$self ToBlock $myToNode $myToIdx]
                $myHv3 tag remove selection $myToNode $myToIdx $toNode $toIdx
                eval $myHv3 tag remove selection $to_block
              }
    
              $myHv3 tag add selection $myFromNode $myFromIdx $toNode $toIdx
              eval $myHv3 tag add selection $to_block2
              eval $myHv3 tag add selection $from_block
              selection own $myHv3
            }
          }
    
          set myToNode $toNode
          set myToIdx $toIdx
        }
      } msg]

      if {$rc && [regexp {[^ ]+ is an orphan} $msg]} {
        $self clear
      }
    }


    set motioncmd ""
    if {$y > [winfo height $myHv3]} {
      set motioncmd [list yview scroll 1 units]
    } elseif {$y < 0} {
      set motioncmd [list yview scroll -1 units]
    } elseif {$x > [winfo width $myHv3]} {
      set motioncmd [list xview scroll 1 units]
    } elseif {$x < 0} {
      set motioncmd [list xview scroll -1 units]
    }

    if {$motioncmd ne ""} {
      set myIgnoreMotion 1
      eval $myHv3 $motioncmd
      after 20 [list $self ContinueMotion]
    }
  }

  method ContinueMotion {} {
    set myIgnoreMotion 0
    set x [expr [winfo pointerx $myHv3] - [winfo rootx $myHv3]]
    set y [expr [winfo pointery $myHv3] - [winfo rooty $myHv3]]
    set N [lindex [$myHv3 node $x $y] 0]
    $self motion $N $x $y
  }

  # get_selection OFFSET MAXCHARS
  #
  #     This command is invoked whenever the current selection is selected
  #     while it is owned by the html widget. The text of the selected
  #     region is returned.
  #
  method get_selection {offset maxChars} {
    set t [$myHv3 text text]

    set n1 $myFromNode
    set i1 $myFromIdx
    set n2 $myToNode
    set i2 $myToIdx

    set stridx_a [$myHv3 text offset $myFromNode $myFromIdx]
    set stridx_b [$myHv3 text offset $myToNode $myToIdx]
    if {$stridx_a > $stridx_b} {
      foreach {stridx_a stridx_b} [list $stridx_b $stridx_a] {}
    }

    if {$myMode eq "word"} {
      set stridx_a [string wordstart $t $stridx_a]
      set stridx_b [string wordend $t $stridx_b]
    }
    if {$myMode eq "block"} {
      set stridx_a [string last "\n" $t $stridx_a]
      if {$stridx_a < 0} {set stridx_a 0}
      set stridx_b [string first "\n" $t $stridx_b]
      if {$stridx_b < 0} {set stridx_b [string length $t]}
    }
  
    set T [string range [$myHv3 text text] $stridx_a [expr $stridx_b - 1]]
    set T [string range $T $offset [expr $offset + $maxChars]]

#puts "document text {[$myHv3 text text]}"
#puts "from -> to {$n1 $i1 -> $n2 $i2}"
#puts "from -> to {$stridx_a -> $stridx_b}"

    return $T
  }

  method selected {} {
    if {$myFromNode eq ""} {return ""}
    return [$self get_selection 0 10000000]
  }

}
#
# End of ::hv3::hv3::selectionmanager
#--------------------------------------------------------------------------

#--------------------------------------------------------------------------
# Class ::hv3::hv3::dynamicmanager
#
#     This class is responsible for setting the dynamic :hover flag on
#     document nodes in response to cursor movements. It may one day
#     be extended to handle :focus and :active, but it's not yet clear
#     exactly how these should be dealt with.
#
snit::type ::hv3::hv3::dynamicmanager {

  constructor {hv3} {
    $hv3 Subscribe onmouseover [list $self handle_mouseover]
    $hv3 Subscribe onmouseout  [list $self handle_mouseout]
    $hv3 Subscribe onmousedown [list $self handle_mousedown]
    $hv3 Subscribe onmouseup   [list $self handle_mouseup]
  }

  method handle_mouseover {node} { $node dynamic set hover }
  method handle_mouseout {node}  { $node dynamic clear hover }

  method handle_mousedown {node} { $node dynamic set active }
  method handle_mouseup {node}   { $node dynamic clear active }
}
#
# End of ::hv3::hv3::dynamicmanager
#--------------------------------------------------------------------------

#--------------------------------------------------------------------------
# Class ::hv3::hv3::hyperlinkmanager
#
# Each instance of the hv3 widget contains a single hyperlinkmanager as
# a component. The hyperlinkmanager takes care of:
#
#     * -targetcmd option and associate callbacks
#     * -isvisitedcmd option and associate callbacks
#     * Modifying the cursor to the hand shape when over a hyperlink
#     * Setting the :link or :visited dynamic condition on hyperlink 
#       elements (depending on the return value of -isvisitedcmd).
#
# This class installs a node handler for <a> elements. It also subscribes
# to the <Motion>, <ButtonPress-1> and <ButtonRelease-1> events on the
# associated hv3 widget.
#

snit::type ::hv3::hv3::hyperlinkmanager {
  variable myHv3
  variable myBaseUri ""
  variable myLinkHoverCount 0

  option -isvisitedcmd -default "" -configuremethod SetVisitedCmd
  option -targetcmd -default ""

  constructor {hv3 baseuri} {
    set myHv3 $hv3
    set myBaseUri $baseuri

    # Set up the default -targetcmd script to always return $myHv3.
    set options(-targetcmd) [list ::hv3::ReturnWithArgs $hv3]

    $myHv3 Subscribe onclick     [list $self handle_onclick]
  }

  method reset {} {
    set myLinkHoverCount 0
  }

  # This is the configure method for the -isvisitedcmd option. This
  # option configures a callback script that sets or clears the 'visited' 
  # and 'link' properties of an <a href="..."> element. This is a 
  # performance critical operation because it is called so many times.
  #
  method SetVisitedCmd {option value} {
    set options($option) $value

    # Create a proc to use as the node-handler for <a> elements.
    #
    set P_NODE ${selfns}::a_node_handler
    catch {rename $P_NODE ""}
    set template [list \
      proc $P_NODE {node} {
        if {![catch {
          set uri [%BASEURI% resolve [$node attr href]]
        }]} {
          if {[%VISITEDCMD% $uri]} {
            $node dynamic set visited
          } else {
            $node dynamic set link
          }
        }
      }
    ]
    eval [::snit::Expand $template %BASEURI% $myBaseUri %VISITEDCMD% $value]

    # Create a proc to use as the attribute-handler for <a> elements.
    #
    set P_ATTR ${selfns}::a_attr_handler
    catch {rename $P_ATTR ""}
    set template [list \
      proc $P_ATTR {node attr val} {
        if {$attr eq "href"} {
          if {![catch {
            set uri [%BASEURI% resolve $val]
          }]} {
            if {[%VISITEDCMD% $uri]} {
              $node dynamic set visited
            } else {
              $node dynamic set link
            }
          }
        }
      }
    ]
    eval [::snit::Expand $template %BASEURI% $myBaseUri %VISITEDCMD% $value]

    $myHv3 handler node a $P_NODE
    $myHv3 handler attribute a $P_ATTR
  }

  # This method is called whenever an onclick event occurs. If the
  # node is an <A> with an "href" attribute that is not "#" or the
  # empty string, call the [goto] method of some hv3 widget to follow 
  # the hyperlink.
  #
  # The particular hv3 widget is located by evaluating the -targetcmd 
  # callback script. This allows the upper layer to implement frames,
  # links that open in new windows/tabs - all that irritating stuff :)
  #
  method handle_onclick {node} {
    if {[$node tag] eq "a"} {
      set href [$node attr -default "" href]
      if {$href ne "" && $href ne "#"} {
        set hv3 [eval [linsert $options(-targetcmd) end $node]]
        set href [$myBaseUri resolve $href]
        after idle [list $hv3 goto $href -referer [$myHv3 location]]
      }
    }
  }
}
#
# End of ::hv3::hv3::hyperlinkmanager
#--------------------------------------------------------------------------

snit::type ::hv3::hv3::framelog {
  variable myHv3 {}

  variable myStyleErrors {}
  variable myHtmlDocument {}

  constructor {hv3} {
    set myHv3 $hv3
  }

  method loghtml {data} {
    if {![info exists ::hv3::log_source_option]} return
    if {$::hv3::log_source_option} {
      append myHtmlDocument $data
    }
  }

  method log {id filename data parse_errors} {
    if {![info exists ::hv3::log_source_option]} return
    if {$::hv3::log_source_option} {
      lappend myStyleErrors [list $id $filename $data $parse_errors]
    }
  }

  method clear {} {
    set myStyleErrors ""
    set myHtmlDocument ""
  }

  method get {args} {
    switch -- [lindex $args 0] {
      html { 
        return $myHtmlDocument 
      }

      css { 
        return $myStyleErrors
      }
    }
  }
}

#--------------------------------------------------------------------------
# Class hv3 - the public widget class.
#
snit::widget ::hv3::hv3 {

  # Object components
  component myHtml                   ;# The [::hv3::scrolled html] widget
  component myHyperlinkManager       ;# The ::hv3::hv3::hyperlinkmanager
  component myDynamicManager         ;# The ::hv3::hv3::dynamicmanager
  component mySelectionManager -public selectionmanager
  component myFormManager            ;# The ::hv3::formmanager

  component myFrameLog -public log     ;# The ::hv3::hv3::framelog

  option -dom -default "" -configuremethod SetDom

  option -storevisitedcmd -default ""

  variable myStorevisitedDone 0

  component myMouseManager           ;# The ::hv3::hv3::mousemanager
  delegate method Subscribe to myMouseManager as subscribe

  # The current location URI and the current base URI. If myBase is "",
  # use the URI stored in myUri as the base.
  #
  component myUri -public uri
  variable myBase ""                ;# The current URI (type ::hv3::hv3uri)

  # Full text of referrer URI, if any.
  #
  # Note that the DOM attribute HTMLDocument.referrer has a double-r,
  # but the name of the HTTP header, "Referer", has only one.
  #
  variable myReferrer ""     

  # Used to assign internal stylesheet ids.
  variable myStyleCount 0 

  # This variable may be set to "unknown", "quirks" or "standards".
  variable myQuirksmode unknown

  variable myFirstReset 1

  # Current value to set the -cachecontrol option of download handles to.
  #
  variable myCacheControl normal

  # This variable stores the current type of resource being displayed.
  # When valid, it is set to one of the following:
  #
  #     * html
  #     * image
  #
  # Otherwise, it is set to an empty string, indicating that the resource
  # has been requested, but has not yet arrived.
  #
  variable myMimetype ""

  # This variable is only used when ($myMimetype eq "image"). It stores
  # the data for the image about to be displayed. Once the image
  # has finished downloading, the data in this variable is loaded into
  # a Tk image and this variable reset to "".
  #
  variable myImageData ""

  # If this variable is not set to the empty string, it is the id of an
  # [after] event that will refresh the current document (i.e from a 
  # Refresh header or <meta type=http-equiv> markup). This scheduled 
  # event should be cancelled when the [reset] method is called.
  #
  # There should only be one Refresh event scheduled at any one time.
  # The [Refresh] method, which calls [after] to schedule the events,
  # cancels any pending event before scheduling a new one.
  #
  variable myRefreshEventId ""

  # This boolean variable is set to zero until the first call to [goto].
  # Before that point it is safe to change the values of the -enableimages
  # option without reloading the document.
  #
  variable myGotoCalled 0

  # This boolean variable is set after the DOM "onload" event is fired.
  # It is cleared by the [reset] method.
  variable myOnloadFired 0

  variable myFragmentSeek ""

  # The ::hv3::download object used to retrieve the main document.
  #
  variable myDocumentHandle ""

  # List of handle objects that should be released after the page has
  # loaded. This is part of the hack to work around the polipo bug.
  #
  variable myShelvedHandles [list]

  # List of all active download handles.
  #
  variable myActiveHandles [list]

  constructor {} {

    # Create the scrolled html widget and bind it's events to the
    # mega-widget window.
    set myHtml [::hv3::scrolled html ${win}.html]
    ::hv3::profile::instrument [$myHtml widget]
    bindtags [$self html] [concat [bindtags [$self html]] $self]
    pack $myHtml -fill both -expand 1

    set myMouseManager [::hv3::hv3::mousemanager %AUTO% $self]

    # $myHtml configure -layoutcache 0

    # Location URI. The default URI is "blank://".
    set myUri  [::tkhtml::uri home://blank/]
    set myBase [::tkhtml::uri home://blank/]

    # Create the event-handling components.
    set myHyperlinkManager [::hv3::hv3::hyperlinkmanager %AUTO% $self $myBase]
    set mySelectionManager [::hv3::hv3::selectionmanager %AUTO% $self]
    set myDynamicManager   [::hv3::hv3::dynamicmanager   %AUTO% $self]

    # The frame log (records component HTML and CSS documents).
    #
    set myFrameLog         [::hv3::hv3::framelog   %AUTO% $self]

    $myMouseManager subscribe motion [list $mySelectionManager motion]

    set myFormManager [::hv3::formmanager %AUTO% $self]
    $myFormManager configure -getcmd  [list $self Formcmd get]
    $myFormManager configure -postcmd [list $self Formcmd post]

    # Attach an image callback to the html widget
    $myHtml configure -imagecmd [list $self Imagecmd]

    # Register node handlers to deal with the various elements
    # that may appear in the document <head>. In html, the <head> section
    # may contain the following elements:
    #
    #     <script>, <style>, <meta>, <link>, <object>, <base>, <title>
    #
    # All except <title> are handled by code in ::hv3::hv3. Note that the
    # handler for <object> is the same whether the element is located in
    # the head or body of the html document.
    #
    $myHtml handler node   link     [list $self link_node_handler]
    $myHtml handler node   base     [list $self base_node_handler]
    $myHtml handler node   meta     [list $self meta_node_handler]
    $myHtml handler node   title    [list $self title_node_handler]
    $myHtml handler script style    [list $self style_script_handler]
    $myHtml handler script script   [list $self ::hv3::ignore_script]

    # $myHtml handler script script   [list $self script_script_handler]

    # Register handler commands to handle <object> and kin.
    $myHtml handler node object   [list hv3_object_handler $self]
    $myHtml handler node embed    [list hv3_object_handler $self]

    # Register handler commands to handle <body>.
    $myHtml handler node body   [list $self body_node_handler]

    bind $win <Configure> [list $self goto_fragment]
  }

  destructor {
    # Cancel any and all pending downloads.
    #
    $self stop
    catch {$myDocumentHandle release }

    # Destroy the components. We don't need to destroy the scrolled
    # html component because it is a Tk widget - it is automatically
    # destroyed when it's parent widget is.
    catch { $mySelectionManager destroy }
    catch { $myDynamicManager   destroy }
    catch { $myHyperlinkManager destroy }
    catch { $myUri              destroy }
    catch { $myFormManager      destroy }
    catch { $myMouseManager     destroy }
    catch { $myBase             destroy }

    # Tell the DOM implementation that any Window object created for
    # this widget is no longer required.
    catch { $options(-dom) delete_window $self }

    # Cancel any refresh-event that may be pending.
    if {$myRefreshEventId ne ""} {
      after cancel $myRefreshEventId
      set myRefreshEventId ""
    }
  }

  # Return the location URI of the widget.
  #
  method location {} { return [$myUri get] }

  # Return the referrer URI of the widget.
  #
  method referrer {} { return $myReferrer }

  method forget {handle} {
    set idx [lsearch $myActiveHandles $handle]
    set myActiveHandles [lreplace $myActiveHandles $idx $idx]
  }

  # The argument download-handle contains a configured request. This 
  # method initiates the request. 
  #
  # This method is used by hv3 and it's component objects (i.e. code in
  # hv3_object_handler). Also the dom code, for XMLHTTPRequest.
  #
  method makerequest {downloadHandle} {

    lappend myActiveHandles $downloadHandle
    $downloadHandle finish_hook [list $self forget $downloadHandle]

    # Execute the -requestcmd script. Fail the download and raise
    # an exception if an error occurs during script evaluation.
    set cmd [concat $options(-requestcmd) [list $downloadHandle]]
    set rc [catch $cmd errmsg]
    if {$rc} {
      set einfo $::errorInfo
      catch {$downloadHandle destroy}
      error $errmsg $einfo
    }
  }

  # Based on the current contents of instance variable $myUri, set the
  # variable identified by the -locationvar option, if any.
  #
  method set_location_var {} {
    if {$options(-locationvar) ne ""} {
      uplevel #0 [list set $options(-locationvar) [$myUri get]]
    }
    event generate $win <<Location>>
  }

  method MightBeComplete {} {
    if {[llength $myActiveHandles] == 0} {
      event generate $win <<Complete>>

      # There are no outstanding HTTP transactions. So fire
      # the DOM "onload" event.
      if {$options(-dom) ne "" && !$myOnloadFired} {
        set bodynode [$myHtml search body]
	# Workaround. Currently meta reload causes empty completion.
	# XXX: Check this again!
	if {[llength $bodynode]} {
	    $options(-dom) event load [lindex $bodynode 0]
	}
      }
      set myOnloadFired 1
    }
  }

  method onload_fired {} { return $myOnloadFired }

  method resolve_uri {uri} {
    if {$uri eq ""} {
      set ret "[$myBase scheme]://[$myBase authority][$myBase path]"
    } else {
      set ret [$myBase resolve $uri]
    }
    return $ret
  }

  # This proc is registered as the -imagecmd script for the Html widget.
  # The argument is the URI of the image required.
  #
  # This proc creates a Tk image immediately. It also kicks off a fetch 
  # request to obtain the image data. When the fetch request is complete,
  # the contents of the Tk image are set to the returned data in proc 
  # ::hv3::imageCallback.
  #
  method Imagecmd {uri} {

    # Massage the URI a bit. Trim whitespace from either end.
    set uri [string trim $uri]

    if {[string match replace:* $uri]} {
        set img [string range $uri 8 end]
        return $img
    }
    set name [image create photo]

    if {$uri ne ""} {
      set full_uri [$self resolve_uri $uri]
    
      # Create and execute a download request. For now, "expect" a mime-type
      # of image/gif. This should be enough to tell the protocol handler to
      # expect a binary file (of course, this is not correct, the real
      # default mime-type might be some other kind of image).
      set handle [::hv3::download %AUTO%              \
          -uri          $full_uri                      \
          -mimetype     image/gif                      \
          -cachecontrol $myCacheControl                \
      ]
      $handle configure -finscript [list $self Imagecallback $handle $name]
      $self makerequest $handle
    }

    # Return a list of two elements - the image name and the image
    # destructor script. See tkhtml(n) for details.
    return [list $name [list image delete $name]]
  }

  # This method is called to handle the "Location" header for all requests
  # except requests for the main document (see the [Refresh] method for
  # these). If there is a Location method, then the handle object is
  # destroyed, a new one dispatched and 1 returned. Otherwise 0 is returned.
  #
  method HandleLocation {handle} {
    # Check for a "Location" header. TODO: Handling Location
    # should be done in one common location for everything except 
    # the main document. The main document is a bit different...
    # or is it?
    set location ""
    foreach {header value} [$handle cget -header] {
      if {[string equal -nocase $header "Location"]} {
        set location $value
      }
    }

    if {$location ne ""} {
      set finscript [$handle cget -finscript]
      $handle release
      set full_location [$self resolve_uri $location]
      set handle2 [::hv3::download $handle               \
          -uri          $full_location                   \
          -mimetype     image/gif                        \
          -cachecontrol $myCacheControl                  \
      ]
      $handle2 configure -finscript $finscript
      $self makerequest $handle2
      return 1
    }
    return 0
  }

  # This proc is called when an image requested by the -imagecmd callback
  # ([imagecmd]) has finished downloading. The first argument is the name of
  # a Tk image. The second argument is the downloaded data (presumably a
  # binary image format like gif). This proc sets the named Tk image to
  # contain the downloaded data.
  #
  method Imagecallback {handle name data} {
    if {0 == [$self HandleLocation $handle]} {
      # If the image data is invalid, it is not an error. Possibly hv3
      # should log a warning - if it had a warning system....
      catch { $name configure -data $data }
      $handle release
    }
  }

  # Request the resource located at URI $full_uri and treat it as
  # a stylesheet. The parent stylesheet id is $parent_id. This
  # method is used for stylesheets obtained by either HTML <link> 
  # elements or CSS "@import {...}" directives.
  #
  method Requeststyle {parent_id full_uri} {
    set id        ${parent_id}.[format %.4d [incr myStyleCount]]
    set importcmd [list $self Requeststyle $id]
    set urlcmd    [list ::hv3::ss_resolve_uri $full_uri]
    append id .9999

    set handle [::hv3::download %AUTO%              \
        -uri         $full_uri                      \
        -mimetype    text/css                       \
        -cachecontrol $myCacheControl               \
    ]
    $handle configure -finscript [
        list $self Finishstyle $handle $id $importcmd $urlcmd
    ]
    $self makerequest $handle
  }

  # Callback invoked when a stylesheet request has finished. Made
  # from method Requeststyle above.
  #
  method Finishstyle {handle id importcmd urlcmd data} {
    if {0 == [$self HandleLocation $handle]} {
      set full_id "$id.[$handle cget -uri]"
      $myHtml style              \
          -id $full_id           \
          -importcmd $importcmd  \
          -urlcmd $urlcmd        \
          -errorvar parse_errors \
          $data

      $myFrameLog log $full_id [$handle cget -uri] $data $parse_errors

      $self goto_fragment
      $self MightBeComplete
      $handle release
    }
  }

  # Node handler script for <meta> tags.
  #
  method meta_node_handler {node} {
    set httpequiv [string tolower [$node attr -default "" http-equiv]]
    set content   [$node attr -default "" content]

    switch -- $httpequiv {
      refresh {
        $self Refresh $content
      }

      content-type {
        foreach {a b enc} [::hv3::string::parseContentType $content] {}
	if {
           ![$myDocumentHandle cget -hastransportencoding] &&
           ![::hv3::encoding_isequal $enc [$self encoding]]
        } {
          # This occurs when a document contains a <meta> element that
          # specifies a character encoding and the document was 
          # delivered without a transport-layer encoding (Content-Type
          # header). We need to start reparse the document from scratch
          # using the new encoding.
          #
          # We need to be careful to work around a polipo bug here: If
          # there are more than two requests for a single resource
          # to a single polipo process, and one of the requests is 
          # cancelled, then the other (still active) request is truncated
          # by polipo. The polipo developers acknowledge that this is
          # a bug, but as it doesn't come up very often in normal polipo
          # usage it is not likely to be fixed soon.
          #
          # It's a problem for Hv3 because if the following [reset] cancels
          # any requests, then when reparsing the same document with a
          # different encoding the same resources are requested, we are 
          # likely to trigger this bug.
          #
          puts "INFO: This page triggers meta enc reload"
          
          # For all active handles except the document handle, configure
          # the -incrscript as a no-op, and have the finscript simply 
          # release the handle reference. This means the polipo bug will
          # not be triggered.
          foreach h $myActiveHandles {
            if {$h ne $myDocumentHandle} {
              set fin [list ::hv3::release_handle $h]
              $h configure -incrscript "" -finscript $fin
            }
          }

          $self InternalReset
          $myDocumentHandle configure -encoding $enc
          $self HtmlCallback                 \
              $myDocumentHandle              \
              [$myDocumentHandle isFinished] \
              [$myDocumentHandle data]
        }
      }
    }
  }

  # Return the default encoding that should be used for 
  # javascript and CSS resources.
  method encoding {} {
    if {$myDocumentHandle eq ""} { 
      return [encoding system] 
    }
    return [$myDocumentHandle encoding]
  }

  # This method is called to handle "Refresh" and "Location" headers
  # delivered as part of the response to a request for a document to
  # display in the main window. Refresh headers specified as 
  # <meta type=http-equiv> markup are also handled. The $content argument
  # contains a the content portion of the Request header, for example:
  #
  #     "5 ; URL=http://www.news.com"
  #
  # (wait 5 seconds before loading the page www.news.com).
  #
  # In the case of Location headers, a synthetic Refresh content header is
  # constructed to pass to this method.
  #
  # Returns 1 if immediate refresh (seconds = 0) is requested.
  #
  method Refresh {content} {
    # Use a regular expression to extract the URI and number of seconds
    # from the header content. Then dequote the URI string.
    set uri ""
    set re {([[:digit:]]+) *; *[Uu][Rr][Ll] *= *([^ ]+)}
    regexp $re $content -> seconds uri
    regexp {[^\"\']+} $uri uri                  ;# Primitive dequote

    if {$uri ne ""} {
      if {$myRefreshEventId ne ""} {
          after cancel $myRefreshEventId
      }
      set cmd [list $self RefreshEvent $uri]
      set myRefreshEventId [after [expr {$seconds*1000}] $cmd]

      # puts "Parse of content for http-equiv refresh successful! ($uri)"

      return [expr {$seconds == 0}]
    } else {
      # puts "Parse of content for http-equiv refresh failed..."
      return 0
    }
  }

  method RefreshEvent {uri} {
    set myRefreshEventId ""
    $self goto $uri -nosave
  }

  # System for handling <title> elements. This object exports
  # a method [titlevar] that returns a globally valid variable name
  # to a variable used to store the string that should be displayed as the
  # "title" of this document. The idea is that the caller add a trace
  # to that variable.
  #
  method title_node_handler {node} {
    set val ""
    foreach child [$node children] {
      append val [$child text]
    }
    set myTitleVar $val
  }
  variable myTitleVar ""
  method titlevar {}    {return [myvar myTitleVar]}
  method title {}       {return $myTitleVar}

  # Node handler script for <body> tags. The purpose of this handler
  # and the [body_style_handler] method immediately below it is
  # to handle the 'overflow' property on the document root element.
  # 
  method body_node_handler {node} {
    $node replace dummy -stylecmd [list $self body_style_handler $node]
  }
  method body_style_handler {bodynode} {

    if {$options(-scrollbarpolicy) ne "auto"} {
      $myHtml configure -scrollbarpolicy $options(-scrollbarpolicy)
      return
    }

    set htmlnode [$bodynode parent]
    set overflow [$htmlnode property overflow]

    # Variable $overflow now holds the value of the 'overflow' property
    # on the root element (the <html> tag). If this value is not "visible",
    # then the value is used to govern the viewport scrollbars. If it is
    # visible, then use the value of 'overflow' on the <body> element.
    # See section 11.1.1 of CSS2.1 for details.
    #
    if {$overflow eq "visible"} {
      set overflow [$bodynode property overflow]
    }
    switch -- $overflow {
      visible { $myHtml configure -scrollbarpolicy auto }
      auto    { $myHtml configure -scrollbarpolicy auto }
      hidden  { $myHtml configure -scrollbarpolicy 0 }
      scroll  { $myHtml configure -scrollbarpolicy 1 }
      default {
        puts stderr "Hv3 is confused: <body> has \"overflow:$overflow\"."
        $myHtml configure -scrollbarpolicy auto
      }
    }
  }

  # Node handler script for <link> tags.
  #
  method link_node_handler {node} {
    set rel  [string tolower [$node attr -default "" rel]]
    set href [string trim [$node attr -default "" href]]
    set media [string tolower [$node attr -default all media]]
    if {
        [string match *stylesheet* $rel] &&
        ![string match *alternat* $rel] &&
        $href ne "" && 
        [regexp all|screen $media]
    } {
      set full_uri [$self resolve_uri $href]
      $self Requeststyle author $full_uri
    }
  }

  # Node handler script for <base> tags.
  #
  method base_node_handler {node} {
    # Technically, a <base> tag is required to specify an absolute URI.
    # If a relative URI is specified, hv3 resolves it relative to the
    # current location URI. This is not standards compliant (a relative URI
    # is technically illegal), but seems like a reasonable idea.
    $myBase load [$node attr -default "" href]
  }

  # Script handler for <style> tags.
  #
  method style_script_handler {attr script} {
    array set attributes $attr
    if {[info exists attributes(media)]} {
      if {0 == [regexp all|screen $attributes(media)]} return ""
    }

    set id        author.[format %.4d [incr myStyleCount]]
    set importcmd [list $self Requeststyle $id]
    set urlcmd    [list $self resolve_uri]
    append id ".9999.<style>"
    $myHtml style -id $id      \
        -importcmd $importcmd  \
        -urlcmd $urlcmd        \
        -errorvar parse_errors \
        $script

    $myFrameLog log $id "<style> block $myStyleCount" $script $parse_errors

    return ""
  }

  method goto_fragment {} {
    switch -- [llength $myFragmentSeek] {
      0 { # Do nothing }
      1 {
        $myHtml _force
        $myHtml yview moveto [lindex $myFragmentSeek 0]
      }
      2 {
        set fragment [lindex $myFragmentSeek 1]
        set selector [format {[name="%s"]} $fragment]
        set goto_node [lindex [$myHtml search $selector] 0]

        # If there was no node with the name attribute set to the fragment,
        # search for a node with the id attribute set to the fragment.
        if {$goto_node eq ""} {
          set selector [format {[id="%s"]} $fragment]
          set goto_node [lindex [$myHtml search $selector] 0]
        }
  
        if {$goto_node ne ""} {
          $myHtml yview $goto_node
        }
      }
    }
  }

  method seek_to_fragment {fragment} {
    # A fragment was specified as part of the URI that has just started
    # loading. Set myFragmentSeek to the fragment name. Each time some
    # more of the document or a stylesheet loads, the [goto_fragment]
    # method will try to align the vertical scrollbar so that the 
    # named fragment is at the top of the view.
    #
    # If and when the user manually scrolls the viewport, the 
    # myFragmentSeek variable is cleared. This is so we don't wrest
    # control of the vertical scrollbar after the user has manually
    # positioned it.
    #
    $myHtml take_control [list set [myvar myFragmentSeek] ""]
    if {$fragment ne ""} {
      set myFragmentSeek [list # $fragment]
    }
  }

  method seek_to_yview {moveto} {
    $myHtml take_control [list set [myvar myFragmentSeek] ""]
    set myFragmentSeek $moveto
  }

  method documenthandle {} {
    return $myDocumentHandle
  }

  method documentcallback {handle referrer savestate final data} {

    if {$myMimetype eq ""} {
  
      # TODO: Real mimetype parser...
      set mimetype  [string tolower [string trim [$handle cget -mimetype]]]
      foreach {major minor} [split $mimetype /] {}

      switch -- $major {
        text {
          if {[lsearch [list html xml xhtml] $minor]>=0} {
            set q [::hv3::configure_doctype_mode $myHtml $data isXHTML]
            $self reset $savestate
            set myQuirksmode $q
            if {$isXHTML} { $myHtml configure -parsemode xhtml } \
            else          { $myHtml configure -parsemode html }
            set myMimetype html
          }
        }
  
        image {
          set myImageData ""
          $self reset $savestate
          set myMimetype image
        }
      }
  
  
      if {$myMimetype eq ""} {
        # Neither text nor an image. This is the upper layers problem.
        if {$options(-downloadcmd) ne ""} {
          # Remove the download handle from the list of handles to cancel
          # if [$hv3 stop] is invoked (when the user clicks the "stop" button
          # we don't want to cancel pending save-file operations).
          $self forget $handle
          eval [linsert $options(-downloadcmd) end $handle $data $final]
        } else {
          $handle release
          set sheepish "Don't know how to handle \"$mimetype\""
          tk_dialog .apology "Sheepish apology" $sheepish 0 OK
        }
        return
      }

      set myReferrer $referrer
  
      $myUri load [$handle cget -uri]
      $myBase load [$myUri get]
      $self set_location_var

      if {$myCacheControl ne "relax-transparency"} {
        $self seek_to_fragment [$myUri fragment]
      }

      set myStyleCount 0

      # If there is a "Location" or "Refresh" header, handle it now.
      set refreshheader ""
      foreach {name value} [$handle cget -header] {
        switch -- [string tolower $name] {
          location {
            set refreshheader "0 ; URL=$value"
          }
          refresh {
            set refreshheader $value
          }
        }
      }
      if {$refreshheader ne ""} {
	if {[$self Refresh $refreshheader]} {
	  # Immediate refresh is requested.
	  # No need to parse body.
	  $handle release
	  return
        }
      }
    }

    if {$myDocumentHandle ne $handle} {
      if {$myDocumentHandle ne ""} {
        $myDocumentHandle release
      }
      set myDocumentHandle $handle
    }

    switch -- $myMimetype {
      html  {$self HtmlCallback $handle $final $data}
      image {$self ImageCallback $handle $final $data}
    }


    if {$final} {
      #$handle release

      if {$myStorevisitedDone == 0 && $options(-storevisitedcmd) ne ""} {
        set myStorevisitedDone 1
        eval $options(-storevisitedcmd) 1
      }
      $self MightBeComplete
    }
  }

  method HtmlCallback {handle isFinal data} {
    $myFrameLog loghtml $data
    if {$isFinal} {
	$myHtml parse -final $data
    } else {
	$myHtml parse $data
    }
    $self goto_fragment
  }

  method ImageCallback {handle isFinal data} {
    append myImageData $data
    if {$isFinal} {
      set img [image create photo -data $myImageData]
      set myImageData ""
      set imagecmd [$myHtml cget -imagecmd]
      $myHtml configure -imagecmd [list ::hv3::ReturnWithArgs $img]
      $myHtml parse -final { <img src="unused"> }
      $myHtml _force
      $myHtml configure -imagecmd $imagecmd
    }
  }

  method Formcmd {method node uri querytype encdata} {
    set cmd [linsert [$self cget -targetcmd] end $node]
    [eval $cmd] Formcmd2 $method $uri $querytype $encdata
  }

  method Formcmd2 {method uri querytype encdata} {
    # puts "Formcmd $method $uri $querytype $encdata"
    set full_uri [$self resolve_uri $uri]

    event generate $win <<Goto>>

    set handle [::hv3::download %AUTO% -mimetype text/html]
    set myMimetype ""
    set referer [$self uri get]
    $handle configure                                       \
        -incrscript [list $self documentcallback $handle $referer 1 0] \
        -finscript  [list $self documentcallback $handle $referer 1 1] \
        -requestheader [list Referer $referer]              \

    if {$method eq "post"} {
      $handle configure -uri $full_uri -postdata $encdata
      $handle configure -enctype $querytype
      $handle configure -cachecontrol normal
    } else {
      $handle configure -uri "${full_uri}?${encdata}"
      $handle configure -cachecontrol $myCacheControl
    }
    $self makerequest $handle

    # Grab the keyboard focus for this widget. This is so that after
    # the form is submitted the arrow keys and PgUp/PgDown can be used
    # to scroll the main display.
    #
    focus [$self html]
  }

  method seturi {uri} {
    $myUri load $uri
    $myBase load [$myUri get]
  }

  #--------------------------------------------------------------------------
  # PUBLIC INTERFACE TO HV3 WIDGET STARTS HERE:
  #
  #     Method              Delegate
  # --------------------------------------------
  #     goto                N/A
  #     xview               $myHtml
  #     yview               $myHtml
  #     html                N/A
  #     hull                N/A
  #   

  method dom {} { 
    if {$options(-dom) eq ""} { return ::hv3::ignore_script }
    return $options(-dom)
  }

  #--------------------------------------------------------------------
  # Load the URI specified as an argument into the main browser window.
  # This method has the following syntax:
  #
  #     $hv3 goto URI ?OPTIONS?
  #
  # Where supported options are:
  #
  #     -cachecontrol "normal"|"relax-transparency"|"no-cache"
  #     -nosave
  #     -referer URI
  #     -history_handle  DOWNLOAD-HANDLE
  #
  # The -cachecontrol option (default "normal") specifies the value 
  # that will be used for all ::hv3::request objects issued as a 
  # result of this load URI operation.
  #
  # Normally, a <<SaveState>> event is generated. If -nosave is specified, 
  # this is suppressed.
  # 
  method goto {uri args} {

    set myGotoCalled 1

    # Process the argument switches. Local variable $cachecontrol
    # is set to the effective value of the -cachecontrol option.
    # Local boolean var $savestate is true unless the -nogoto
    # option is specified.
    set savestate 1
    set cachecontrol normal
    set referer ""
    set history_handle ""

    for {set iArg 0} {$iArg < [llength $args]} {incr iArg} {
      switch -- [lindex $args $iArg] {
        -cachecontrol {
          incr iArg
          set cachecontrol [lindex $args $iArg]
        }
        -referer {
          incr iArg
          set referer [lindex $args $iArg]
        }
        -nosave {
          set savestate 0
        }
        -history_handle {
          incr iArg
          set history_handle [lindex $args $iArg]
        }
        default {
          error "Bad option \"[lindex $args $iArg]\" to \[::hv3::hv3 goto\]"
        }
      }
    }

    # Special case. If this URI begins with "javascript:" (case independent),
    # pass it to the current running DOM implementation instead of loading
    # anything into the current browser.
    if {[string match -nocase javascript:* $uri]} {
      if {$options(-dom) ne ""} {
        $options(-dom) javascript $self [string range $uri 11 end]
      }
      return
    }

    set myCacheControl $cachecontrol

    set current_uri [$myUri get_no_fragment]
    set uri_obj [::tkhtml::uri [$self resolve_uri $uri]]
    set full_uri [$uri_obj get_no_fragment]
    set fragment [$uri_obj fragment]

    # Generate the <<Goto>> event.
    event generate $win <<Goto>>

    if {$full_uri eq $current_uri && $cachecontrol ne "no-cache"} {
      # Save the current state in the history system. This ensures
      # that back/forward controls work when navigating between
      # different sections of the same document.
      if {$savestate} {
        event generate $win <<SaveState>>
      }
      $myUri load $uri

      # If the cache-mode is "relax-transparency", then the history 
      # system is controlling this document load. It has already called
      # [seek_to_yview] to provide a seek offset.
      if {$cachecontrol ne "relax-transparency"} {
        if {$fragment eq ""} {
          $self seek_to_yview 0.0
        } else {
          $self seek_to_fragment $fragment
        }
      }
      $self goto_fragment

      $self set_location_var
      return [$myUri get]
    }

    # Abandon any pending requests
    if {$myStorevisitedDone == 0 && $options(-storevisitedcmd) ne ""} {
      set myStorevisitedDone 1
      eval $options(-storevisitedcmd) $savestate
    }
    $self stop
    set myMimetype ""

    if {$history_handle eq ""} {
      # Base the expected type on the extension of the filename in the
      # URI, if any. If we can't figure out an expected type, assume
      # text/html. The protocol handler may override this anyway.
      set mimetype text/html
      set path [$uri_obj path]
      if {[regexp {\.([A-Za-z0-9]+)$} $path dummy ext]} {
        switch -- [string tolower $ext] {
  	jpg  { set mimetype image/jpeg }
          jpeg { set mimetype image/jpeg }
          gif  { set mimetype image/gif  }
          png  { set mimetype image/png  }
          gz   { set mimetype application/gzip  }
          gzip { set mimetype application/gzip  }
          zip  { set mimetype application/gzip  }
          kit  { set mimetype application/binary }
        }
      }
  
      # Create a download request for this resource. We expect an html
      # document, but at this juncture the URI may legitimately refer
      # to kind of resource.
      #
      set handle [::hv3::download %AUTO%             \
          -uri         [$uri_obj get]                \
          -mimetype    $mimetype                     \
          -cachecontrol $myCacheControl              \
          -hv3          $self                        \
      ]
      $handle configure                                                        \
        -incrscript [list $self documentcallback $handle $referer $savestate 0]\
        -finscript  [list $self documentcallback $handle $referer $savestate 1] 
      if {$referer ne ""} {
        $handle configure -requestheader [list Referer $referer]
      }
  
      $self makerequest $handle
    } else {
      # The history system has supplied the data to load into the widget.
      # Use $history_handle instead of creating a new request.
      #
      $history_handle reference
      $self documentcallback $history_handle $referer $savestate 1 [
        $history_handle data
      ]
      $self goto_fragment
    }
    $uri_obj destroy
  }

  # Abandon all currently pending downloads. This method is 
  # part of the public interface.
  #
  method stop {} {
    foreach dl $myActiveHandles { 
      if {$dl eq $myDocumentHandle} {set myDocumentHandle ""}
      $dl release 
    }

    if {$myStorevisitedDone == 0 && $options(-storevisitedcmd) ne ""} {
      set myStorevisitedDone 1
      eval $options(-storevisitedcmd) 1
    }
  }

  method InternalReset {} {
    $myFrameLog clear

    foreach m [list \
        $myMouseManager $myFormManager          \
        $mySelectionManager $myHyperlinkManager \
    ] {
      if {$m ne ""} {$m reset}
    }
    $myHtml reset
    $myHtml configure -scrollbarpolicy $options(-scrollbarpolicy)

    if {$options(-dom) ne ""} {
      $options(-dom) clear_window $self
    }
  }

  method reset {isSaveState} {

    # Clear the "onload-event-fired" flag
    set myOnloadFired 0
    set myStorevisitedDone 0

    # Cancel any pending "Refresh" event.
    if {$myRefreshEventId ne ""} {
      after cancel $myRefreshEventId
      set myRefreshEventId ""
    }

    # Generate the <<Reset>> and <<SaveState> events.
    if {!$myFirstReset && $isSaveState} {
      event generate $win <<SaveState>>
    }
    set myFirstReset 0

    set myTitleVar ""
    set myQuirksmode unknown

    $self InternalReset
  }

  method SetOption {option value} {
    set options($option) $value
    switch -- $option {
      -enableimages {
        # The -enableimages switch. If false, configure an empty string
        # as the html widget's -imagecmd option. If true, configure the
        # same option to call the [Imagecmd] method of this mega-widget.
        #
        # We used to reload the frame contents here. But it turns out
        # that is really inconvenient. If the user wants to reload the
        # document the reload button is right there anyway.
        #
        if {$value} {
          $myHtml configure -imagecmd [list $self Imagecmd]
        } else {
          $myHtml configure -imagecmd ""
        }
      }
    }
  }

  method SetDom {option value} {
    set options(-dom) $value
    $myMouseManager configure -dom $options(-dom)
    if {$options(-dom) ne ""} {
      $myHtml handler script script   [list $options(-dom) script $self]
      $myHtml handler script noscript [list $options(-dom) noscript $self]
      $options(-dom) make_window $self
    } else {
      $myHtml handler script script   ::hv3::ignore_script
      $myHtml handler script noscript {}
    }
  }

  method pending {}  {
      return [llength $myActiveHandles]
  }
  method html {}     { return [$myHtml widget] }
  method hull {}     { return $hull }

  method yview {args} {
    eval $myHtml yview $args
  }
  method xview {args} {
    eval $myHtml xview $args
  }

  method javascriptlog {args} {
    if {$options(-dom) ne ""} {
      eval $options(-dom) javascriptlog $args
    }
  }

  option          -historydoccmd    -default ""

  # The option to display images (default true).
  option -enableimages     -default 1 -configuremethod SetOption

  option -scrollbarpolicy -default auto

  option          -locationvar      -default ""
  option          -downloadcmd      -default ""
  option          -requestcmd       -default ""
  delegate option -isvisitedcmd     to myHyperlinkManager
  delegate option -targetcmd        to myHyperlinkManager

  # Delegated public methods
  delegate method selected          to mySelectionManager
  delegate method selectall         to mySelectionManager
  delegate method *                 to myHtml

  # Standard scrollbar and geometry stuff is delegated to the html widget
  delegate option -xscrollcommand to myHtml
  delegate option -yscrollcommand to myHtml
  delegate option -width          to myHtml
  delegate option -height         to myHtml

  # Display configuration options implemented entirely by the html widget
  delegate option -fonttable        to myHtml
  delegate option -fontscale        to myHtml
  delegate option -zoom             to myHtml
  delegate option -forcefontmetrics to myHtml
}

proc ::hv3::release_handle {handle args} {
  $handle release
}

proc ::hv3::ignore_script {args} {}

# This proc is passed as the -urlcmd option to the [style] method of the
# Tkhtml3 widget. Returns the full-uri formed by resolving $rel relative
# to $base.
#
proc ::hv3::ss_resolve_uri {base rel} {
  set b [::tkhtml::uri $base]
  set ret [$b resolve $rel]
  $b destroy
  set ret
}

bind Html <Tab>       [list ::hv3::forms::tab %W]
bind Html <Shift-Tab> [list ::hv3::forms::tab %W]

proc ::hv3::bg {script args} {
  set eval [concat $script $args]
  set rc [catch [list uplevel $eval] result]
  if {$rc} {
    set cmd [list bgerror $result]
    set error [list $::errorInfo $::errorCode]
    after idle [list foreach {::errorInfo ::errorCode} $error $cmd]
    set ::errorInfo ""
    return ""
  }
  return $result
}

proc ::hv3::ReturnWithArgs {retval args} {
  return $retval
}

