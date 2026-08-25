# Advanced UIA diagnostics

This guide is for diagnostic use. Normal Keystone inspection starts from NVDA-selected objects so
it can preserve richer application-specific object models and NVDA's normal backend choice. Do not
enable raw UIA just because it is available: it is not a universally better backend.

## Request raw UIA for one retarget

In Inspector, Use Raw UIA asks Keystone to use the raw UI Automation view for the next retarget
only. It does not change NVDA's global backend policy or an application's normal behavior.

When the current target has no direct raw UIA reference, Keystone asks the existing UI Automation
client for an element at that target's screen position. Keystone accepts the result only when its
accessible name matches the selected target. If raw UIA is unavailable or cannot be matched,
Keystone announces that it is using the NVDA-selected target instead. A target without a native UIA
provider stays on the NVDA-selected target; Keystone does not treat a proxy as native UIA.

Use this option when you need to compare the raw UIA surface with the normal NVDA-selected
inspection. It is a focused diagnostic request, not a replacement for normal inspection.

## Force UIA for one application

Force UIA for [application] is a separate persistent, per-application setting. It asks NVDA to use
an explicit UIA override for that executable, even when NVDA would normally select another backend.
Keystone asks for confirmation, reloads app modules, closes Inspector, and announces the result.
Reopen Inspector after returning to the application to check the available accessibility backend.

Forcing UIA can be useful when diagnosing one application, but it does not guarantee a usable
native UIA target. Some applications expose only MSAA or UIA-proxy surfaces. It can also remove an
application's NVDA-specific gestures, object model, or compatibility workarounds. Turning the same
option off restores the original app module and reloads it. The choice does not alter the inspected
application or any other executable.

The corresponding global Keystone setting is held closed unless Raw UI Automation is available.
Use Capability Details in Keystone settings when the feature is unavailable.

## Custom UIA definitions

Open Custom UIA Properties with NVDA+slash followed by C, or activate Manage Custom UIA Properties
in Inspector. The accessible manager is list-first and provides Add, Replace, and Export actions;
the context menu, Ctrl+C, and Delete provide definition actions for the selected item. You can also
assign another gesture through NVDA Preferences, Input Gestures, Keystone.

Potential property and pattern discovery is best-effort metadata. A potential result does not prove
that a property or pattern is registered, supported, complete, typed, or invocable. It does not
reveal GUIDs, declared types, custom interfaces, or method schemas. Treat discovered integer IDs as
current-runtime and capture-session information only; do not persist or compare them as durable
identity.

Known custom-property definitions are a separate, application-scoped configuration. Keystone
registers them for the selected application after it validates the complete definition set. A
definition change requires an NVDA restart: Keystone does not unregister, replace, or hot-add
effective process-lifetime registrations during the current session.

Custom-property values default to privacy `unknown`. You can increase their sensitivity, but a
definition cannot mark them public, and protected-context evidence takes precedence. Keystone
records an observed value shape separately from the declared type and preserves unavailable,
unsupported, redacted, truncated, and failed outcomes rather than presenting them as ordinary
values.

Arbitrary custom patterns remain metadata-only. Keystone does not expose a generic way to invoke
their methods or mutate the inspected application.

## Continue with normal workflows

Return to the [Inspector guide](inspector.md) for normal keyboard navigation, property states, and
Event Monitor. Read [settings and privacy](settings-and-privacy.md) before collecting or exporting
evidence that may contain protected text or unredacted screenshots.
