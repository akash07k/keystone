# Keystone user guide

This guide is written to be followed from top to bottom with a keyboard and screen reader.
Keystone reads accessibility evidence without changing the inspected application's focus, navigator
object, values, caret, or selection.

## Enter the command layer

Press NVDA+slash, release both keys, and then press one command key. Keystone calls this sequence
KLS. Press KLS, then H to hear the command list. The
[keyboard reference](keyboard-reference.md) is generated from Keystone's command registry and is the
complete shortcut reference.

## Capture and compare evidence

Use these commands after entering the command layer:

- Press S to capture the foreground application with the configured limits.
- Press Shift+S to capture the foreground application with process-safety limits.
- Press F to capture the current focus-object subtree with process-safety limits.
- Press D to capture or compare the foreground diff.
- Press N to capture the navigator object with the configured limits.
- Press Shift+N to capture the navigator object with process-safety limits.
- Press Shift+O to capture the navigator-object subtree with process-safety limits.

While a capture or diff is running, press the same command again to request cancellation at the next
safe boundary. Pressing a different capture command does not cancel the running command. After a
result is committed, press the same command again quickly to copy its file path, then once more
quickly to reveal that output in Explorer.

The unlimited commands remove Keystone's user-configured collection caps. They do not make provider
data available when it is unavailable, remove fixed process-safety ceilings, or interrupt a provider
call that is already blocked. See [settings and privacy](settings-and-privacy.md) for limits and
privacy choices.

Focus-object and navigator-object subtree capture folders begin with the privacy-filtered root
element name, followed by the capture timestamp. Other capture folder names are unchanged.

## Inspect a live target

Press I to open Inspector for the current focus object, or O to open Inspector for the current
navigator object. Inspector opens a read-only native window and reports its selected target without
moving it. Use Tab and Shift+Tab to move through controls. Ctrl+F opens native Find for the loaded
hierarchy; F3 and Shift+F3 repeat the last hierarchy search.

Inspector and Event Monitor are pages in the same window. Press Ctrl+I for Inspector and Ctrl+E for
Event Monitor. The [Inspector guide](inspector.md) describes property categories, navigation,
copying, source states, and every spoken outcome. Use [advanced UIA](advanced-uia.md) only when you
need diagnostic guidance for raw UIA or Custom UIA.

## Monitor events

Press E to select the current live focus in Inspector and open Event Monitor. Press F5 after
entering the command layer to start or stop Event Monitor from any application. Within Event Monitor,
F5 provides the same start-or-stop action.

Opening Event Monitor leaves monitoring stopped and focuses Start Monitoring. Choose a scope, then
start monitoring. The report has four columns: Event, Source, Changed value, and Time. Selected-event
details explain the changed value separately; row-specific copy, source, and delete actions are in
the event context menu. Ctrl+C copies the selected event as text, and Delete removes it from retained
history.

Use Export in History actions to write the retained events. For a single-application scope, the
default name uses that executable; broad scopes use `keystone-events.json`. Export and Clear are the
only visible History actions.

## Manage Custom UIA definitions

Press C after entering the command layer to open Custom UIA Properties. The native, list-first dialog
has Add, Replace, and Export actions, with definition actions also available from the context menu,
Ctrl+C, and Delete. You can also assign an additional gesture through NVDA Preferences, Input
Gestures, Keystone. See [advanced UIA](advanced-uia.md) before using these diagnostic definitions.

## Find and manage output

Keystone announces a committed capture or export path. Use the quick-repeat behavior described above
to copy or reveal the newest matching capture output. Open NVDA Preferences, Settings, Keystone for
capture and output management. The settings panel reports the
state of optional features; use Capability Details when a feature is unavailable.

For privacy, screenshot, logging, and limit information, continue with
[settings and privacy](settings-and-privacy.md).
