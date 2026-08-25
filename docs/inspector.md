# Keystone Inspector guide

This guide is written to be read from top to bottom with a screen reader. It describes what the
Inspector does, every key you can press, and exactly what Keystone speaks so you never have to see
the screen to know the current state. Nothing in the Inspector changes the application you are
inspecting: your focus, the navigator object, caret position, values, and selection are all left
untouched.

## What the Inspector is for

The Inspector reports a single accessibility target: either the focus object or the navigator
object. It reads that target and shows you its identity and its properties as immutable evidence.
You can retarget it, follow focus, search the loaded hierarchy, and copy what you find. It never
writes to the inspected application and never moves that application's focus.

## Opening the Inspector

From anywhere, press NVDA+slash, release both keys, then press one command key:

- Press I to open the Inspector for the current focus object.
- Press O to open the Inspector for the current navigator object.

When the window opens, NVDA announces "Keystone Inspector". It reports the selected target without
changing focus, navigator position, value, or selection. Focus lands on the accessible object
hierarchy.

## Moving through the window

Every control is reachable from the keyboard, and each one has a spoken accessible name so you
always know where you are:

- Tab moves forward through the controls; Shift+Tab moves backward.
- Ctrl+I selects Inspector and Ctrl+E selects Event Monitor. Both live in one window and restore the
  last native control used on that page.
- The Inspection target group contains the target summary, Retarget to Focus, Retarget to Navigator,
  Follow Focus, Use Raw UIA, and Force UIA for the current application. Manage Custom UIA
  Properties and a disabled Open Snapshot action follow the group.
- The Accessible object hierarchy and the nested Property categories and detail area use ordinary
  splitters. The frame-level Close button is after both pages, so native Tab and Shift+Tab traversal
  reaches it without a custom focus loop.

## The source summary

The read-only source summary is named "Current Inspector source". It identifies the live or offline
source while you browse. It does not change the inspected application.

## Retargeting and Follow Focus

- The "Retarget to Focus" and "Retarget to Navigator" buttons re-read the current target. After a
  retarget Keystone announces the selected target and whether Raw UIA was applied.
- The "Use Raw UIA" checkbox asks Keystone to use the raw UI Automation view for the next retarget
  only. It never changes NVDA's global backend policy or app-module behavior. When a focused
  target has no direct Raw UIA reference, Keystone queries the existing UI Automation client at
  that target's screen position. It accepts that result only when its accessible name matches the
  selected target. If raw UIA is requested but unavailable or cannot be matched, Keystone adds
  "Raw UIA unavailable for this target; using NVDA-selected target." to the announcement.
  When Diagnostics reports `KS.RAW_UIA.NO_NATIVE_PROVIDER`, the target has no native UIA provider;
  Keystone safely retains the NVDA-selected target instead of treating a proxy as native UIA.
- "Force UIA for [application]" is a separate, persistent per-application choice. When enabled,
  Keystone replaces NVDA's app module for that executable with an explicit UIA override. This asks
  NVDA to use UIA even when its normal core policy would select a different backend. Keystone asks
  for confirmation, reloads app modules immediately, closes the Inspector, and announces the
  result. Reopen Inspector after returning to the application to check the available accessibility
  backend. Some applications expose only an MSAA or UIA-proxy surface, so forcing UIA does not
  guarantee a usable native UIA target. Disable the same checkbox to restore the original app module
  and reload again. This can remove an application's NVDA-specific gestures, object model, and
  compatibility workarounds; it does not alter the application itself or any other executable.
  See [advanced UIA](advanced-uia.md) for when to use this diagnostic option and its limits.
- The "Follow Focus" checkbox makes the Inspector re-root itself when focus moves to a new
  application. When it re-roots, Keystone announces "Inspector now follows" and the application name.
  Follow Focus is unavailable for offline snapshots, and the control says so.

## The accessible object hierarchy

The hierarchy is a tree named "Accessible object hierarchy". It shows the ancestors of the target
and the target's own children. Use the arrow keys as you would in any tree: Up and Down move between
items, Right expands, and Left collapses.

While children load, the tree shows a placeholder child item that reads "Loading children". If a
branch cannot be read you will hear "Children unavailable"; if some children were held back for
process safety you will hear "More children not shown"; a cancelled load reads "Child load
cancelled"; and a load stopped by a safety limit reads "Child load rejected". These placeholders let
you understand the state of a branch without any visual cue.

The hierarchy context menu copies the selected branch and provides Inspect this element and Monitor
this element. Monitor this element switches to Event Monitor and announces the selected object's
proposed scope.

## Property categories

Property categories is a report list containing Core, UIA, Annotations, and Advanced. Its selected
category replaces the adjacent detail area. Core, Annotations, and Advanced present Property, Value,
and Status columns under a group named after the active category. UIA presents a visible-root tree
under "UIA properties". Its sections always appear in this order: Custom properties, Unavailable or
unsupported Custom UIA properties, Standard UIA properties, Unavailable or unsupported Standard UIA
properties, Supported patterns, and Provider discovery. The availability sections preserve each
property's precise result, such as Unsupported or Unavailable.

Every property row names the property and then its value. When a value is not a plain value, Keystone
speaks a clear state word instead so the meaning is never ambiguous: Value, Empty, Unsupported, Not
applicable, Unavailable, Redacted, Truncated, Stale, Rejected, or Failed. Redacted means the value
was withheld for privacy; Truncated means it was shortened to a safe length; Rejected means a safety
limit refused it; Failed means retrieval raised an error. Redacted appears only while you have
redaction turned on, because Keystone shows protected values by default.

When the Annotations list has focus, press Alt+T to show the selected annotation target in Inspector.
The annotation context menu provides the same action when that target is still available.

## Searching the loaded hierarchy

Press Ctrl+F to open the native Find dialog for the loaded hierarchy. Press F3 for the next result or
Shift+F3 for the previous result. Search only looks at nodes that are already loaded; unexpanded
branches are not searched.

- If no Find query exists, F3 announces that you must open Find with Ctrl+F first.
- If the query is empty, Keystone announces "Enter text to search loaded nodes."
- If nothing matches, Keystone announces that no loaded node matches your text and reminds you that
  unexpanded branches were not searched.
- When a search wraps past the last match it announces "Search wrapped to the end.", and when it
  wraps before the first match it announces "Search wrapped to the beginning."

## Copying evidence

Ctrl+C copies the focused semantic unit. A hierarchy or UIA-tree selection copies its complete
selected subtree, indented with two spaces per depth. A property row copies its Property, Value, and
Status cells; a category copies all visible category data. A successful copy announces the outcome.

## Custom UIA Properties

Press NVDA+slash, then C, or activate Manage Custom UIA Properties in Inspector. The separate native
manager starts with a grouped report list of definitions and visible Add, Replace, and Export actions.
Add and Edit open a separate editor with Definition and Advanced application filters groups. Context
menu actions, Ctrl+C, and Delete apply to the selected mutable definition. The same action appears in
NVDA Preferences, Input Gestures, Keystone so you can assign another gesture.

Export defaults include the current executable when available, for example
`notepad-keystone-custom-uia.json`.

Replace loads the chosen file as the complete definition set. It warns before overwriting saved
definitions, including definitions that are not present in the selected file. Export first if you
want a backup.

Keystone derives each definition's internal identity from its Property GUID. The editor asks for the
UI Automation Programmatic name and an optional Display name. Keystone reads the Display name in the
manager and Inspector; when it is blank, it uses the Programmatic name instead.

Choose Enum as the property type when a provider returns an integer with named states. Enter its
values as one `number = name` mapping per line, such as `9 = ViewNormal`. Keystone reads a known
value as `ViewNormal (9)` and retains an unmapped value as its number.

## Event Monitor

Press NVDA+slash, then E, or NVDA+Shift+slash. The command-layer E shortcut first selects the
currently focused live object in Inspector, then opens Event Monitor, so its default Selected element
scope is ready to start. Event Monitor is the second page of the same Keystone Inspector window.
Press Ctrl+E to select it and Ctrl+I to return to Inspector.

Press NVDA+slash, then F5 from any application to start or stop monitoring. It stops an active
session without changing its target. When stopped, it selects the currently focused live object and
starts the last selected scope. On start, Keystone announces the focused element name when available,
the selected scope, and whether Raw UIA events are included.

The Monitoring group orders Start or Stop Monitoring, Restart with Current Inspector Selection, Event
Filter, Include Raw UIA Events, Follow Newest, and Scope. The next groups are Monitored events,
Selected event details, and History actions. History actions contains only Export and Clear. Opening
the page leaves monitoring stopped and focuses Start Monitoring.

Within Event Monitor, F5 starts or stops monitoring. NVDA+/, then F5 provides the same toggle from
any application.

For a single-application scope, Export defaults to that executable, for example
`notepad-keystone-events.json`; broad scopes keep the generic `keystone-events.json` name.

The event list has Event, Source, Changed value, and Time columns. With the list or selected-event
details focused, Ctrl+C copies the selected event as text; Delete removes it from retained history.
The event context menu adds JSON and Markdown copies plus Show source in Inspector. It is the only
place for row-specific actions.

### Choosing what is monitored

The scope choice decides what Start freezes:

- Selected element monitors only the object currently selected in the Inspector hierarchy.
- Selected subtree monitors that object and everything under it.
- Application monitors every object in the process that object belongs to.
- Broad monitors every non-NVDA process, and asks you to confirm first.

Selected element and selected subtree need an object Keystone can recognise again when an event
arrives. Most controls provide one, including the many that expose no automation ID. When they do
not, monitoring does not quietly widen to something else: it refuses and says why, such as "no object
is selected in the Inspector hierarchy", "the Inspector is showing an offline snapshot, which reports
no live events", or "the selected object exposes no identifier that events can be matched against".
Restart with Current Inspector Selection uses exactly the same rule and, when it refuses, leaves the
running session and every captured row untouched.

### What each event row tells you

The captured events list has four columns: Event, Source, Changed value, and Time.

Changed value says what the event changed, and the selected-event details name where that value came
from:

- Reported by the provider, for a UI Automation notification carrying its own display string.
- Read after the event, for a value, name, description, or live region text read from the object.
- Compared with the previous observation, when the same identified object was seen before, reading
  as "old changed to new" or, for states, which states were added and removed.
- Caret position metadata, which is the caret offset only. Caret text is never read into a row.

When there is nothing to report, the column says so rather than going blank: Not applicable for
events that carry no value, Not exposed when the provider offers none, Unavailable when the value
could not be read, and (redacted) when redaction hid it. Remembered previous values are bounded and
are discarded whenever a monitoring session starts or ends.

## Protected values and redaction

Keystone shows protected values, including password fields, by default. Everything that reports
evidence treats them the same way: the Inspector, Events, captures, exports, Custom UIA, diffs, and
the NVDA log.

Turn on "Redact protected text" in Keystone settings to hide them instead; that one setting applies
everywhere at once. Whenever monitoring starts with redaction off, Keystone warns you that protected
text is not being hidden.

Screenshots are always unredacted. Read [settings and privacy](settings-and-privacy.md) before
capturing, exporting, or sharing evidence with protected text or visual content.

If you used a Keystone version that redacted by default, that stored preference is retired once when
you first run this version, and Keystone tells you it was reset so you can turn it back on
deliberately. Size and safety limits are unrelated to redaction and still apply.


## Runtime availability

Keystone checks each optional feature when NVDA starts. Raw UI Automation and event monitoring
require an active NVDA UIA handler. The settings interface and screenshots require NVDA's graphical
interface, sounds require the bundled sound files and NVDA audio output, and capture storage and
diagnostic outputs require a writable Keystone output directory. These features are unavailable on
the secure desktop.

Open Capability Details in Keystone settings to read the direct reason when a feature is
unavailable. Keystone does not require a separate status file.

## Closing

Close the Inspector with the Close button. Keystone announces "Inspector closed." and
returns nothing about your focus, navigator object, or selection to a different place: they stay
exactly where they were before you opened the window.
