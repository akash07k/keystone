# Keystone for NVDA

Keystone captures accessibility evidence, compares foreground captures, inspects the current focus
or navigator object, and monitors accessibility events. It is read-only: it does not change the
inspected application's focus, navigator object, values, caret, or selection.

## Start here

Use the [user guide](docs/user-guide.md) for a linear, keyboard-first walkthrough of captures,
Inspector, Event Monitor, exports, and output. The [keyboard reference](docs/keyboard-reference.md)
lists every command exactly as Keystone announces it.

For settings, privacy, screenshots, limits, sounds, logs, and optional capabilities, read
[settings and privacy](docs/settings-and-privacy.md). For raw UIA and Custom UIA diagnostics, read
[advanced UIA](docs/advanced-uia.md). The [Inspector guide](docs/inspector.md) gives the complete
keyboard and spoken-state reference for the Inspector and Event Monitor.

Use [troubleshooting](docs/troubleshooting.md) when a capture, export, or optional capability does
not behave as expected. The [evidence schema](docs/evidence-schema.md) defines the fields and
availability states in captured and exported evidence.

## Commands, Inspector, and Event Monitor

Press NVDA+slash, release both keys, then press a command key. Press H after NVDA+slash to hear
the complete list. Capture and diff commands produce persistent evidence; repeating the same
active capture command requests cancellation at the next safe boundary. After a committed result,
quick repeats copy its path and then reveal it in Explorer.

Open Event Monitor with NVDA+slash, then E, or NVDA+Shift+slash. Inspector and Event Monitor are
two pages in one native window. Inspector is for read-only accessibility evidence about a focus or
navigator target. Event Monitor is for live, scoped accessibility events: choose a scope, then
activate Start Monitoring. Use Event Filter to choose the event families retained in new rows.
Its report has exactly four columns: Event, Source, Changed value, and Time. Details and row
actions are separate from those columns.

Open Manage Custom UIA Properties with NVDA+slash, then C. Change Keystone settings in NVDA Preferences, Settings, Keystone. Assign gestures in NVDA Preferences, Input Gestures, Keystone.

## License

Keystone is distributed under the GNU General Public License, version 2 or later. See
[COPYING.txt](COPYING.txt).
