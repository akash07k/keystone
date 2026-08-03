from __future__ import annotations

import builtins
from collections.abc import Callable
from typing import Protocol, cast

from ..domain.commands import COMMAND_DEFINITIONS, CommandId


class TranslationCatalog(Protocol):
	def gettext(self, message: str) -> str: ...

	def pgettext(self, context: str, message: str) -> str: ...

	def ngettext(self, singular: str, plural: str, count: int) -> str: ...


def gettext(message: str) -> str:
	resolver = getattr(builtins, "_", None)
	return cast(Callable[[str], str], resolver)(message) if callable(resolver) else message


def pgettext(context: str, message: str) -> str:
	resolver = getattr(builtins, "pgettext", None)
	if callable(resolver):
		return cast(Callable[[str, str], str], resolver)(context, message)
	return gettext(message)


def ngettext(singular: str, plural: str, count: int) -> str:
	resolver = getattr(builtins, "ngettext", None)
	if callable(resolver):
		return cast(Callable[[str, str, int], str], resolver)(singular, plural, count)
	return singular if count == 1 else plural


class NvdaTranslationCatalog:
	def gettext(self, message: str) -> str:
		return gettext(message)

	def pgettext(self, context: str, message: str) -> str:
		return pgettext(context, message)

	def ngettext(self, singular: str, plural: str, count: int) -> str:
		return ngettext(singular, plural, count)


def commandLabelText(commandId: CommandId) -> str:
	"""The translatable action label for a command, extractable for the message catalog.

	The English text is the single stable label held in the command registry; a contract test
	keeps this mapping and :data:`COMMAND_DEFINITIONS` in exact agreement so dispatch, help,
	discoverability, and the generated keyboard reference all speak one identity per command.
	"""

	if commandId is CommandId.FOREGROUND_BOUNDED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture foreground with configured limits")
	if commandId is CommandId.FOREGROUND_UNLIMITED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture foreground with process-safety limits")
	if commandId is CommandId.FOCUS_UNLIMITED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture focus-object subtree with process-safety limits")
	if commandId is CommandId.DIFF:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture or compare the foreground diff")
	if commandId is CommandId.NAVIGATOR_BOUNDED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture navigator object with configured limits")
	if commandId is CommandId.NAVIGATOR_UNLIMITED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture navigator object with process-safety limits")
	if commandId is CommandId.NAVIGATOR_SUBTREE_UNLIMITED:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Capture navigator-object subtree with process-safety limits")
	if commandId is CommandId.INSPECT_FOCUS:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Open Inspector for focus")
	if commandId is CommandId.INSPECT_NAVIGATOR:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Open Inspector for navigator object")
	if commandId is CommandId.EVENT_MONITOR:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Open Event Monitor")
	if commandId is CommandId.EVENT_MONITOR_TOGGLE:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Start or stop Event Monitor")
	if commandId is CommandId.CUSTOM_UIA_PROPERTIES:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Manage Custom UIA Properties")
	if commandId is CommandId.HELP:
		# Translators: Keystone command shown in NVDA+/ help and the keyboard reference.
		return pgettext("keystone command", "Show Keystone command help")
	raise KeyError(commandId)


def commandGestureText(commandId: CommandId) -> str:
	"""The translatable keystroke phrase for a command, extractable for the message catalog."""

	if commandId is CommandId.FOREGROUND_BOUNDED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then S")
	if commandId is CommandId.FOREGROUND_UNLIMITED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then Shift+S")
	if commandId is CommandId.FOCUS_UNLIMITED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then F")
	if commandId is CommandId.DIFF:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then D")
	if commandId is CommandId.NAVIGATOR_BOUNDED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then N")
	if commandId is CommandId.NAVIGATOR_UNLIMITED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then Shift+N")
	if commandId is CommandId.NAVIGATOR_SUBTREE_UNLIMITED:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then Shift+O")
	if commandId is CommandId.INSPECT_FOCUS:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then I")
	if commandId is CommandId.INSPECT_NAVIGATOR:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then O")
	if commandId is CommandId.EVENT_MONITOR:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then E")
	if commandId is CommandId.EVENT_MONITOR_TOGGLE:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then F5")
	if commandId is CommandId.CUSTOM_UIA_PROPERTIES:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then C")
	if commandId is CommandId.HELP:
		# Translators: Keystone keystroke phrase; keep the printed keys, translate the connecting word.
		return pgettext("keystone gesture", "NVDA+/, then H")
	raise KeyError(commandId)


def commandHelpText() -> str:
	lines = [
		# Translators: Header of the NVDA+/ command help spoken and shown when H is pressed.
		pgettext(
			"keystone command help",
			"KLS means NVDA+/. Press KLS, then one of these keys:",
		),
		"",
	]
	lines.extend(
		f"{_helpGesture(definition.commandId)}: {commandLabelText(definition.commandId)}."
		for definition in COMMAND_DEFINITIONS
	)
	lines.extend(
		(
			"",
			gettext(
				"For capture and diff commands, repeat the matching command while it is running "
				+ "to request cancellation. After a committed result, repeat quickly to copy its path, "
				+ "then repeat once more to reveal it in Explorer.",
			),
			gettext(
				"Inspector includes explicit raw UIA, Event Monitor, and Custom UIA Properties controls.",
			),
		),
	)
	return "\n".join(lines)


def _helpGesture(commandId: CommandId) -> str:
	return commandGestureText(commandId).replace("NVDA+/", "KLS", 1)


def keyboardReferenceMarkdown() -> str:
	"""Render the screen-reader-first keyboard reference from the shared command registry.

	The section order, keystrokes, and action labels come straight from :data:`COMMAND_DEFINITIONS`
	so the document can never drift from what NVDA actually dispatches. The output is deliberately
	linear: one heading, a short orientation paragraph, then one list item per command in registry
	order, each reading as "keystroke: action." with no reliance on tables or visual layout.
	"""

	lines = [
		"# Keystone keyboard reference",
		"",
		(
			"Every Keystone command starts from the command layer. Press NVDA+slash, release it, then "
			"press the command key below. Keystone calls this sequence KLS. Press KLS, then H at any "
			"time to hear this list read aloud. Each entry reads as the keystroke followed by what it does."
		),
		"",
	]
	for definition in COMMAND_DEFINITIONS:
		gesture = commandGestureText(definition.commandId)
		label = commandLabelText(definition.commandId)
		lines.append(f"- {gesture}: {label}.")
	lines.extend(
		(
			"",
			(
				"While a capture or diff command is running, press the same command again to request "
				"cancellation at the next safe boundary. After a result is committed, press the same "
				"command again quickly to copy its file path, then once more to reveal it in Explorer."
			),
			"",
			(
				"Inspector and Event Monitor are two pages of the same Keystone Inspector window. "
				"NVDA+/, then E selects the current live focus before opening Event Monitor. "
				"NVDA+/, then F5 starts or stops Event Monitor from any application. Ctrl+I selects "
				"Inspector and Ctrl+E selects Event Monitor. Tab and Shift+Tab use normal native "
				"traversal, including the Close button below the pages. In Inspector, Ctrl+F opens "
				"native Find and F3 or Shift+F3 repeats the most recent hierarchy search. In the "
				"Annotations properties list, Alt+T shows the selected annotation target. Hierarchy "
				"and property context menus provide Copy, Inspect this element, Monitor this element, "
				"and Show annotation target actions where applicable."
			),
			"",
		),
	)
	return "\n".join(lines)


def _captureLabel(commandId: CommandId, *, sentenceStart: bool) -> str:
	if commandId is CommandId.FOREGROUND_BOUNDED:
		if sentenceStart:
			return gettext("Bounded foreground capture")
		return gettext("bounded foreground capture")
	if commandId is CommandId.FOREGROUND_UNLIMITED:
		if sentenceStart:
			return gettext("Unlimited foreground capture")
		return gettext("unlimited foreground capture")
	if commandId is CommandId.FOCUS_UNLIMITED:
		if sentenceStart:
			return gettext("Unlimited focus-object subtree snapshot capture")
		return gettext("unlimited focus-object subtree snapshot capture")
	if commandId is CommandId.DIFF:
		if sentenceStart:
			return gettext("Foreground diff")
		return gettext("foreground diff")
	if commandId is CommandId.NAVIGATOR_BOUNDED:
		if sentenceStart:
			return gettext("Bounded navigator capture")
		return gettext("bounded navigator capture")
	if commandId is CommandId.NAVIGATOR_UNLIMITED:
		if sentenceStart:
			return gettext("Unlimited navigator capture")
		return gettext("unlimited navigator capture")
	if commandId is CommandId.NAVIGATOR_SUBTREE_UNLIMITED:
		if sentenceStart:
			return gettext("Unlimited navigator-object subtree capture")
		return gettext("unlimited navigator-object subtree capture")
	raise KeyError(commandId)


def presentCommandStart(commandId: CommandId) -> str:
	return gettext("{command} started.").format(command=_captureLabel(commandId, sentenceStart=True))


def presentCommandBusy(requestedCommandId: CommandId, activeCommandId: CommandId) -> str:
	return gettext(
		"{requested} is busy because {active} is active. The active capture was not cancelled.",
	).format(
		requested=_captureLabel(requestedCommandId, sentenceStart=True),
		active=_captureLabel(activeCommandId, sentenceStart=False),
	)


_OUTCOME_MESSAGES = {
	"started": "Capture started.",
	"progress": "Capture is still in progress.",
	"completed": "Foreground capture completed.",
	"cancellationRequested": (
		"Cancellation requested. Keystone will stop after the current provider call reaches a safe boundary."
	),
	"cancelled": "Capture cancelled.",
	"truncated": "Capture completed with one or more limits reached.",
	"partialScreenshot": "Capture completed, but the screenshot was unavailable.",
	"failed": "Capture failed.",
	"baselineCreated": "Diff baseline created.",
	"noChange": "Diff completed. No changes were found.",
}

_COMPLETED_BY_COMMAND = {
	CommandId.INSPECT_FOCUS: "Focus Inspector opened.",
	CommandId.INSPECT_NAVIGATOR: "Navigator Inspector opened.",
	CommandId.CUSTOM_UIA_PROPERTIES: "Custom UIA Properties opened.",
}

_FAILED_BY_COMMAND = {
	CommandId.INSPECT_FOCUS: "Focus Inspector could not be opened.",
	CommandId.INSPECT_NAVIGATOR: "Navigator Inspector could not be opened.",
	CommandId.EVENT_MONITOR: "Event Monitor could not be opened.",
	CommandId.CUSTOM_UIA_PROPERTIES: "Custom UIA Properties could not be opened.",
}


def _captureOutcome(token: str, commandId: CommandId) -> str | None:
	template = {
		"started": "{command} started.",
		"progress": "{command} is still in progress.",
		"completed": "{command} completed.",
		"cancellationRequested": (
			"{command} cancellation requested. "
			+ "Keystone will stop after the current provider call reaches a safe boundary."
		),
		"cancelled": "{command} cancelled.",
		"truncated": "{command} completed with one or more limits reached.",
		"partialScreenshot": "{command} completed, but the screenshot was unavailable.",
		"failed": "{command} failed.",
	}.get(token)
	if template is None:
		return None
	try:
		subject = _captureLabel(commandId, sentenceStart=True)
	except KeyError:
		return None
	return gettext(template).format(command=subject)


def presentCaptureLimit(limitType: str, configuredLimit: int) -> str:
	"""Describe the limiting capture budget without exposing captured content."""

	if limitType == "textScalars":
		return gettext("Text limit of {limit:,} characters reached.").format(limit=configuredLimit)
	if limitType == "nodes":
		return gettext("Node limit of {limit:,} reached.").format(limit=configuredLimit)
	if limitType == "depth":
		return gettext("Depth limit of {limit:,} reached.").format(limit=configuredLimit)
	if limitType == "timeMilliseconds":
		return gettext("Time limit of {limit:,} milliseconds reached.").format(limit=configuredLimit)
	return gettext("Capture limit reached.")


def presentCaptureProgress(
	processedNodes: int,
	pendingWorkCount: int,
	elapsedMilliseconds: int,
	phase: str = "collecting",
) -> str:
	"""Describe safe, actionable capture progress without exposing captured values."""

	if processedNodes < 0 or pendingWorkCount < 0 or elapsedMilliseconds < 0:
		raise ValueError("capture progress values must be nonnegative")
	if phase not in ("collecting", "preparing", "packaging"):
		raise ValueError("capture progress phase is not supported")
	elapsedSeconds = max(1, (elapsedMilliseconds + 500) // 1_000)
	nodes = ngettext(
		"{count:,} node captured",
		"{count:,} nodes captured",
		processedNodes,
	).format(count=processedNodes)
	pending = gettext("{count:,} pending").format(count=pendingWorkCount)
	elapsed = ngettext(
		"{count:,} second",
		"{count:,} seconds",
		elapsedSeconds,
	).format(count=elapsedSeconds)
	if phase == "preparing":
		return gettext("Preparing snapshot: {nodes}, {elapsed}.").format(
			nodes=nodes,
			elapsed=elapsed,
		)
	if phase == "packaging":
		return gettext("Saving snapshot: {nodes}, {elapsed}.").format(
			nodes=nodes,
			elapsed=elapsed,
		)
	return gettext("{nodes}, {pending}, {elapsed}.").format(
		nodes=nodes,
		pending=pending,
		elapsed=elapsed,
	)


def presentCommandOutcome(
	token: str,
	detail: str | None = None,
	*,
	commandId: CommandId | None = None,
) -> str:
	commandMessage = None if commandId is None else _captureOutcome(token, commandId)
	if commandMessage is not None:
		message = commandMessage
	else:
		if commandId is not None and token == "completed":
			commandMessage = _COMPLETED_BY_COMMAND.get(commandId)
		elif commandId is not None and token == "failed":
			commandMessage = _FAILED_BY_COMMAND.get(commandId)
		message = gettext(commandMessage or _OUTCOME_MESSAGES.get(token, "Command failed."))
	return message if detail is None else f"{message} {detail}"
