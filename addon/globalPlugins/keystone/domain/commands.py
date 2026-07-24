from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from .sounds import CueAtomId, CueEventId
from .status import requireNonnegativeInteger


class CommandId(StrEnum):
	FOREGROUND_BOUNDED = "foregroundBounded"
	FOREGROUND_UNLIMITED = "foregroundUnlimited"
	FOCUS_UNLIMITED = "focusUnlimited"
	DIFF = "diff"
	NAVIGATOR_BOUNDED = "navigatorBounded"
	NAVIGATOR_UNLIMITED = "navigatorUnlimited"
	NAVIGATOR_SUBTREE_UNLIMITED = "navigatorSubtreeUnlimited"
	INSPECT_FOCUS = "inspectFocus"
	INSPECT_NAVIGATOR = "inspectNavigator"
	EVENT_MONITOR = "eventMonitor"
	EVENT_MONITOR_TOGGLE = "eventMonitorToggle"
	CUSTOM_UIA_PROPERTIES = "customUiaProperties"
	HELP = "help"


CAPTURE_COMMANDS = frozenset(
	{
		CommandId.FOREGROUND_BOUNDED,
		CommandId.FOREGROUND_UNLIMITED,
		CommandId.FOCUS_UNLIMITED,
		CommandId.DIFF,
		CommandId.NAVIGATOR_BOUNDED,
		CommandId.NAVIGATOR_UNLIMITED,
		CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
	},
)


# The closed capture-command sound map. Every capture command binds one fixed family atom and one
# typed start event; terminal outcomes bind typed events by their stable outcome token, never by the
# localized sentence spoken to the user. Inspector and Help commands are absent here because their
# cues are owned by the Inspector frame and the command-confirmation surface respectively.
_CAPTURE_FAMILY_ATOM: dict[CommandId, CueAtomId] = {
	CommandId.FOREGROUND_BOUNDED: CueAtomId.BOUNDED_FULL_FAMILY,
	CommandId.FOREGROUND_UNLIMITED: CueAtomId.UNLIMITED_FULL_FAMILY,
	CommandId.FOCUS_UNLIMITED: CueAtomId.UNLIMITED_FULL_FAMILY,
	CommandId.DIFF: CueAtomId.DIFF_FAMILY,
	CommandId.NAVIGATOR_BOUNDED: CueAtomId.BOUNDED_NAVIGATOR_FAMILY,
	CommandId.NAVIGATOR_UNLIMITED: CueAtomId.UNLIMITED_NAVIGATOR_FAMILY,
	CommandId.NAVIGATOR_SUBTREE_UNLIMITED: CueAtomId.UNLIMITED_NAVIGATOR_FAMILY,
}

_CAPTURE_START_EVENT: dict[CommandId, CueEventId] = {
	CommandId.FOREGROUND_BOUNDED: CueEventId.START_BOUNDED_FULL,
	CommandId.FOREGROUND_UNLIMITED: CueEventId.START_UNLIMITED_FULL,
	CommandId.FOCUS_UNLIMITED: CueEventId.START_UNLIMITED_FULL,
	CommandId.DIFF: CueEventId.START_DIFF,
	CommandId.NAVIGATOR_BOUNDED: CueEventId.START_BOUNDED_NAVIGATOR,
	CommandId.NAVIGATOR_UNLIMITED: CueEventId.START_UNLIMITED_NAVIGATOR,
	CommandId.NAVIGATOR_SUBTREE_UNLIMITED: CueEventId.START_UNLIMITED_NAVIGATOR,
}

# Terminal outcome tokens that speak over the running capture and carry its active family atom.
_ACTIVE_FAMILY_OUTCOME_EVENT: dict[str, CueEventId] = {
	"completed": CueEventId.CAPTURE_SUCCESS,
	"truncated": CueEventId.CAPTURE_TRUNCATED_SUCCESS,
	"partialScreenshot": CueEventId.CAPTURE_PARTIAL_SCREENSHOT,
	"cancelled": CueEventId.CAPTURE_CANCELLED,
	"failed": CueEventId.CAPTURE_FAILURE,
}

# Diff-only terminal outcomes bind the fixed diff family atom rather than an active-family atom.
_DIFF_OUTCOME_EVENT: dict[str, CueEventId] = {
	"noChange": CueEventId.DIFF_NO_CHANGE,
	"baselineCreated": CueEventId.DIFF_BASELINE_CREATED,
}


@dataclass(frozen=True, slots=True)
class CaptureCueBinding:
	"""A typed capture cue: the event to request and the active family atom it needs, if any."""

	event: CueEventId
	activeFamilyAtom: CueAtomId | None


def captureStartCue(commandId: CommandId) -> CaptureCueBinding | None:
	"""The start cue for a capture command, or ``None`` for non-capture commands.

	The start event fixes its own family atom in the cue grammar, so no active family is supplied.
	"""

	event = _CAPTURE_START_EVENT.get(commandId)
	return None if event is None else CaptureCueBinding(event, None)


def captureCancellationCue(commandId: CommandId) -> CaptureCueBinding | None:
	"""The cancellation-requested cue for an in-flight capture command."""

	family = _CAPTURE_FAMILY_ATOM.get(commandId)
	if family is None:
		return None
	return CaptureCueBinding(CueEventId.CAPTURE_CANCELLATION_REQUESTED, family)


def captureOutcomeCue(commandId: CommandId, outcomeToken: str) -> CaptureCueBinding | None:
	"""The terminal cue for a capture command outcome, or ``None`` when nothing sounds.

	Diff no-change and baseline-created bind the fixed diff family; all other terminal outcomes
	speak over the command's active family. Non-capture commands and non-terminal tokens sound
	nothing here.
	"""

	family = _CAPTURE_FAMILY_ATOM.get(commandId)
	if family is None:
		return None
	if commandId is CommandId.DIFF:
		diffEvent = _DIFF_OUTCOME_EVENT.get(outcomeToken)
		if diffEvent is not None:
			return CaptureCueBinding(diffEvent, None)
	event = _ACTIVE_FAMILY_OUTCOME_EVENT.get(outcomeToken)
	return None if event is None else CaptureCueBinding(event, family)


@dataclass(frozen=True, slots=True)
class CommandDefinition:
	commandId: CommandId
	key: str
	gestureLabel: str
	label: str
	captureKind: str | None


COMMAND_DEFINITIONS = (
	CommandDefinition(
		CommandId.FOREGROUND_BOUNDED,
		"s",
		"NVDA+/, then S",
		"Capture foreground with configured limits",
		"snapshot",
	),
	CommandDefinition(
		CommandId.FOREGROUND_UNLIMITED,
		"shift+s",
		"NVDA+/, then Shift+S",
		"Capture foreground with process-safety limits",
		"snapshot",
	),
	CommandDefinition(
		CommandId.FOCUS_UNLIMITED,
		"f",
		"NVDA+/, then F",
		"Capture focus-object subtree with process-safety limits",
		"snapshot",
	),
	CommandDefinition(
		CommandId.DIFF,
		"d",
		"NVDA+/, then D",
		"Capture or compare the foreground diff",
		"diff",
	),
	CommandDefinition(
		CommandId.NAVIGATOR_BOUNDED,
		"n",
		"NVDA+/, then N",
		"Capture navigator object with configured limits",
		"navigatorSnapshot",
	),
	CommandDefinition(
		CommandId.NAVIGATOR_UNLIMITED,
		"shift+n",
		"NVDA+/, then Shift+N",
		"Capture navigator object with process-safety limits",
		"navigatorSnapshot",
	),
	CommandDefinition(
		CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
		"shift+o",
		"NVDA+/, then Shift+O",
		"Capture navigator-object subtree with process-safety limits",
		"navigatorSnapshot",
	),
	CommandDefinition(CommandId.INSPECT_FOCUS, "i", "NVDA+/, then I", "Open Inspector for focus", None),
	CommandDefinition(
		CommandId.INSPECT_NAVIGATOR,
		"o",
		"NVDA+/, then O",
		"Open Inspector for navigator object",
		None,
	),
	CommandDefinition(
		CommandId.EVENT_MONITOR,
		"e",
		"NVDA+/, then E",
		"Open Event Monitor",
		None,
	),
	CommandDefinition(
		CommandId.EVENT_MONITOR_TOGGLE,
		"f5",
		"NVDA+/, then F5",
		"Start or stop Event Monitor",
		None,
	),
	CommandDefinition(
		CommandId.CUSTOM_UIA_PROPERTIES,
		"c",
		"NVDA+/, then C",
		"Manage Custom UIA Properties",
		None,
	),
	CommandDefinition(CommandId.HELP, "h", "NVDA+/, then H", "Show Keystone command help", None),
)
COMMAND_BY_KEY = {definition.key: definition for definition in COMMAND_DEFINITIONS}
COMMAND_BY_ID = {definition.commandId: definition for definition in COMMAND_DEFINITIONS}


type RepeatAction = Literal["run", "cancel", "busy", "copy", "reveal", "invoke"]


@dataclass(frozen=True, slots=True)
class CommandRequestDecision:
	commandId: CommandId
	action: RepeatAction


@dataclass(slots=True)
class _Cycle:
	nextAction: Literal["copy", "reveal"] = "copy"
	deadlineMilliseconds: int = -1


class CommandRepeatState:
	def __init__(self, *, repeatWindowMilliseconds: int = 1_500) -> None:
		super().__init__()
		if requireNonnegativeInteger(repeatWindowMilliseconds, "command repeat window") == 0:
			raise ValueError("command repeat window must be positive")
		self._repeatWindow = repeatWindowMilliseconds
		self._activeCommand: CommandId | None = None
		self._cycles = {commandId: _Cycle() for commandId in CAPTURE_COMMANDS}

	@property
	def activeCommand(self) -> CommandId | None:
		return self._activeCommand

	def request(self, commandId: CommandId, *, nowMilliseconds: int) -> CommandRequestDecision:
		_ = requireNonnegativeInteger(nowMilliseconds, "command clock")
		if commandId not in CAPTURE_COMMANDS:
			return CommandRequestDecision(commandId, "invoke")
		if self._activeCommand is not None:
			return CommandRequestDecision(
				commandId,
				"cancel" if commandId is self._activeCommand else "busy",
			)
		cycle = self._cycles[commandId]
		if nowMilliseconds <= cycle.deadlineMilliseconds:
			action = cycle.nextAction
			if action == "copy":
				cycle.nextAction = "reveal"
				cycle.deadlineMilliseconds = nowMilliseconds + self._repeatWindow
			else:
				cycle.nextAction = "copy"
				cycle.deadlineMilliseconds = -1
			return CommandRequestDecision(commandId, action)
		cycle.nextAction = "copy"
		cycle.deadlineMilliseconds = -1
		self._activeCommand = commandId
		return CommandRequestDecision(commandId, "run")

	def finish(self, commandId: CommandId, *, nowMilliseconds: int, committed: bool) -> None:
		_ = requireNonnegativeInteger(nowMilliseconds, "command clock")
		if self._activeCommand is not commandId:
			return
		self._activeCommand = None
		cycle = self._cycles[commandId]
		cycle.nextAction = "copy"
		cycle.deadlineMilliseconds = nowMilliseconds + self._repeatWindow if committed else -1

	def invalidate(self) -> None:
		self._activeCommand = None
		for cycle in self._cycles.values():
			cycle.nextAction = "copy"
			cycle.deadlineMilliseconds = -1


@dataclass(frozen=True, slots=True)
class LayerToken:
	layerGeneration: int
	lifecycleGeneration: int
	deadlineMilliseconds: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.layerGeneration, "command layer generation")
		_ = requireNonnegativeInteger(self.lifecycleGeneration, "lifecycle generation")
		_ = requireNonnegativeInteger(self.deadlineMilliseconds, "command layer deadline")


class CommandLayerState:
	def __init__(self, *, timeoutMilliseconds: int = 4_000) -> None:
		super().__init__()
		if requireNonnegativeInteger(timeoutMilliseconds, "command layer timeout") == 0:
			raise ValueError("command layer timeout must be positive")
		self._timeout = timeoutMilliseconds
		self._generation = 0
		self._active: LayerToken | None = None

	def enter(self, *, lifecycleGeneration: int, nowMilliseconds: int) -> LayerToken:
		_ = requireNonnegativeInteger(lifecycleGeneration, "lifecycle generation")
		_ = requireNonnegativeInteger(nowMilliseconds, "command layer clock")
		self._generation += 1
		token = LayerToken(
			self._generation,
			lifecycleGeneration,
			nowMilliseconds + self._timeout,
		)
		self._active = token
		return token

	def isCurrent(
		self,
		token: LayerToken,
		*,
		lifecycleGeneration: int,
		nowMilliseconds: int,
	) -> bool:
		_ = requireNonnegativeInteger(lifecycleGeneration, "lifecycle generation")
		_ = requireNonnegativeInteger(nowMilliseconds, "command layer clock")
		return (
			self._active == token
			and token.lifecycleGeneration == lifecycleGeneration
			and nowMilliseconds <= token.deadlineMilliseconds
		)

	def isGeneration(self, token: LayerToken) -> bool:
		return token.layerGeneration == self._generation

	def leave(self, token: LayerToken) -> None:
		if self._active == token:
			self._active = None

	def invalidate(self) -> None:
		self._generation += 1
		self._active = None
