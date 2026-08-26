# Keystone troubleshooting

Use this guide with a keyboard and screen reader. Keystone reads accessibility evidence without
changing the inspected application's focus, navigator object, values, caret, or selection. When
reporting a problem, include the exact spoken state, the command or control you used, and whether
you were working with a live target or an offline file. Do not change the inspected application to
make evidence appear.

## Start with the reported state

Open NVDA Preferences, Settings, Keystone, then activate Capability Details. It gives the direct
reason for an optional capability's state and its safe fallback.

- Raw UI Automation and Event Monitor need an active NVDA UIA handler.
- The settings interface and screenshots need NVDA's graphical interface.
- Sounds need the bundled sound files and NVDA audio output.
- Capture storage needs a writable Keystone output directory.
- These optional capabilities are unavailable on the secure desktop.

If a capability is unavailable, keep using the stated fallback rather than repeatedly retrying it.
For example, when Raw UIA is unavailable for a target, Inspector keeps the NVDA-selected target.

## Capture and cancellation

While a capture or diff is running, repeat that same command to request cancellation at the next
safe boundary. A different capture command does not cancel the active operation. Keystone cannot
interrupt a provider call that is already blocked, so wait for the terminal spoken state before
starting another capture.

Use bounded commands first when investigating a large or slow target. Unlimited commands remove
your configured collection caps, not fixed process-safety ceilings or provider availability. A
truncated, rejected, unavailable, or failed result is evidence about what happened; it is not a
complete result with missing values. See [evidence schema](evidence-schema.md) for those states.

## Provider and raw UIA diagnostics

Inspector uses the selected NVDA target for its normal workflow. Raw UIA is an advanced diagnostic
choice, not a general replacement for the normal path. If a requested raw target cannot be found
or matched, Keystone announces that raw UIA is unavailable and retains the NVDA-selected target.

Use **Use Raw UIA** for the next retarget when you need a diagnostic comparison. **Force UIA for
[application]** is a separate persistent option that requests an explicit UIA override for one
application. It may remove application-specific NVDA gestures, object models, or compatibility
workarounds, and it does not guarantee a usable native UIA target. Review
[advanced UIA](advanced-uia.md) before enabling either option.

## Event Monitor scope and filters

Open Event Monitor, choose a scope, and start monitoring. The report always has four columns:
Event, Source, Changed value, and Time. Details and row-specific actions are available separately.

- **Selected element** and **Selected subtree** require an object Keystone can recognize again.
  If Keystone cannot identify one, it refuses instead of widening the scope.
- **Application** monitors the selected object's process.
- **Broad** monitors non-NVDA processes and asks for confirmation first.

Use Event Filter to choose which new event families are retained. Changing the filter affects new
events without clearing retained history. Include Raw UIA Events only when you need that diagnostic
source. For the keyboard workflow and each spoken state, see the [Inspector guide](inspector.md).

## Logging and output directories

Keystone emits curated diagnostics through NVDA's native log. Published captures and Event Monitor exports use their own output paths. Clear All Published Captures deletes only validated Keystone-owned captures after confirmation and never clears event exports.

## Safe problem reports

Before sharing evidence, review it for protected text and screenshots. Redaction can withhold
protected text in evidence and logs, but screenshots are always unredacted. Report the following
instead of changing the inspected application:

1. The exact spoken state or diagnostic code.
2. The command, settings choice, and target type you used.
3. Whether redaction was enabled.
4. Whether the result was live, exported, or read from an offline file.
5. Exported evidence only after reviewing it for sensitive content.

For capture settings, redaction, and output management, see
[settings and privacy](settings-and-privacy.md). For a linear operating guide, start with the
[user guide](user-guide.md).
