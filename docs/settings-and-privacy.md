# Keystone settings and privacy

Open NVDA Preferences, Settings, Keystone. The panel uses ordinary NVDA controls, follows a
keyboard order, and keeps Keystone settings global rather than applying different settings through
NVDA profiles. Choose Apply or OK to save changes. Use Restore Defaults to replace unsaved values;
nothing is saved until you choose Apply or OK.

## Capture limits

Bounded capture uses the settings in the Capture limits group:

- Maximum nodes per bounded capture.
- Maximum tree depth per bounded capture.
- Capture time budget in seconds.
- Maximum characters per text range.
- Progress announcement frequency in seconds.

The unlimited full and navigator commands remove those user-configured collection caps. They do
not make unavailable provider data appear, remove Keystone's fixed process-safety ceilings, or
interrupt one provider call that is already blocked.

Fixed ceilings remain active for visible UIA ranges (50), selection ranges (50), UIA element-array
entries (200), IA2 hyperlinks (200), focus-match nodes (150), focus-match depth (40), a work slice
(150 milliseconds), and the interval used to yield back to NVDA (10 milliseconds). If Keystone
reaches a limit, its evidence reports the limit rather than silently presenting a complete result.

## Privacy and screenshots

Redact protected-field text is off by default. With it off, new Keystone evidence can contain
sensitive text, including password-field values, in captures, exports, Event Monitor history, the
NVDA log.

Turn on Redact protected-field text in Keystone evidence to withhold protected values throughout
those evidence surfaces. It does not change the inspected application. Redaction does not alter
screenshots: screenshots are always saved unredacted and can include sensitive visual information,
including content outside the inspected control. Review a screenshot before sharing it.

## Output and published captures

Keystone writes its output under `%TEMP%\Keystone\`. The Output and screenshots group lets you use
full tab indentation in JSON output files and clear all published captures. Clear All Published
Captures asks for confirmation and deletes only validated Keystone-owned captures; suspicious or
unrecognized entries are left alone. It does not clear event exports.

Keystone announces a committed capture or export path. You can use the command's quick-repeat
behavior to copy or reveal its newest matching capture output. Event Monitor export names follow
the selected scope; see the [user guide](user-guide.md#monitor-events).

## Inspector and event settings

The Inspector and events group provides these settings:

- Maximum characters per event detail. Zero removes display truncation only.
- Maximum retained event rows. Fixed process-safety limits still apply.
- Maximum offline file size in megabytes.
- Property shortcut multi-press interval in milliseconds.
- Swap double-press and triple-press property actions.
- Force raw UI Automation for Keystone inspection, when Raw UI Automation is available.

Raw UIA is an advanced diagnostic choice. Read [advanced UIA](advanced-uia.md) before enabling it.
For the normal Inspector and Event Monitor workflow, including the verified four-column event
report, read the [Inspector guide](inspector.md).

## Sounds and diagnostics

Enable Keystone sounds controls optional sound feedback. Sounds supplement complete speech, use
NVDA or system volume, and have no separate Keystone volume control. You can choose a bundled cue
and preview it from the panel. If sound playback is unavailable, speech still reports the workflow.

Keystone emits curated diagnostics through NVDA's native log. Those records follow the same privacy boundary as other Keystone evidence.

## Capability availability

Keystone checks optional capabilities when NVDA starts. Raw UI Automation and event monitoring
need an active NVDA UIA handler. The settings interface and screenshots need NVDA's graphical
interface; sounds need bundled files and NVDA audio output; capture storage needs a writable Keystone output directory. These features are unavailable on the secure desktop.

Open Capability Details in Keystone settings to read a capability's direct status, reason, and safe
fallback.
