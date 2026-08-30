# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import os
import platform
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from pathlib import Path
from time import monotonic_ns
from typing import Literal, Protocol, cast
from uuid import uuid4

from ...application.capture_service import (
	CaptureRequest,
	CaptureResult,
	CaptureService,
	CaptureTargetKind,
)
from ...application.bundle_service import BundleService, portableSubtreeDestination, writePortableBundle
from ...application.diff_service import DiffService
from ...application.inspector_service import FollowFocusEvent, InspectorService
from ...application.lifecycle import LifecycleService
from ...application.output_service import OutputService
from ...application.sound_service import WorkflowSounds
from ...domain.commands import (
	CAPTURE_COMMANDS,
	COMMAND_BY_ID,
	COMMAND_BY_KEY,
	CommandId,
	CommandLayerState,
	CommandRepeatState,
	LayerToken,
	captureCancellationCue,
	captureOutcomeCue,
	captureStartCue,
)
from ..providers.custom_uia import CustomUiaCaptureMode
from ...domain.correlation import CorrelationFactory
from ...domain.event_monitor import (
	EventRow,
	MonitorScopeUnavailable,
	ScopeUnavailableReason,
)
from ...domain.inspector import InspectorSourceIdentity, InspectorSourceKind, PropertyCategory
from ...domain.privacy import PrivacyPolicy
from ...domain.projection import ProjectionBudget, ProjectionRequest
from ...domain.settings import SettingsSnapshot
from ...domain.snapshot_bundle import (
	BundleAdmissionLimits,
	BundlePackage,
	BundleSnapshotView,
	SelectedSubtreeProjection,
)
from ...domain.sounds import (
	CUE_GRAMMAR,
	CueAtomId,
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	soundRequestFor,
)
from ...domain.state import CaptureState
from ...domain.traversal import TraversalLimits, TraversalProgress
from ...encoding.log_formats import LogScalar
from ...ports.effects import ScreenshotPort, ScreenshotTarget
from ...ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ProviderRelationRequest,
	ProviderSessionCloseRequest,
	ProviderTextRequest,
)
from ...presentation.commands import (
	commandHelpText,
	presentCaptureLimit,
	presentCaptureProgress,
	presentCommandBusy,
	presentCommandOutcome,
	presentCommandStart,
)
from ..windows.publication import CaptureKind
from ..wx.inspector_frame import (
	AppModuleOverrideOutcome,
	AppModuleOverrideState,
	InspectorRetargetOutcome,
	InspectorTargetEvidence,
	InspectorTargetKind,
	InspectorWorkspace,
	KeystoneWindow,
	WindowOwnershipCheck,
)
from .app_module_overrides import NvdaAppModuleOverrides
from .inspector_source import LiveInspectorSource, LiveSessionNodeReader, OfflineInspectorSource
from .event_sources import targetIdentityFromObject
from .selected_objects import (
	NvdaSelectedObjectSource,
	SelectedObjectReference,
	SelectedObjectSession,
	SelectedObjectSource,
)


@dataclass(frozen=True, slots=True)
class CommandExecutionResult:
	outcome: str
	committed: bool = False
	detail: str | None = None
	announcementHandled: bool = False


@dataclass(frozen=True, slots=True)
class _PendingExecution:
	generation: int
	commandId: CommandId
	lifecycleGeneration: int


type CommandSpeechPriority = Literal["normal", "next", "now"]


class CommandRuntime(Protocol):
	def execute(self, commandId: CommandId) -> CommandExecutionResult: ...

	def requestCancellation(self, commandId: CommandId) -> None: ...

	def copyNewest(self, commandId: CommandId) -> bool: ...

	def revealNewest(self, commandId: CommandId) -> bool: ...


type RuntimeLogSink = Callable[[str, tuple[tuple[str, LogScalar], ...]], None]


class CommandLifecycle(Protocol):
	@property
	def generation(self) -> int: ...

	def isCurrent(self, generation: int) -> bool: ...

	@property
	def state(self) -> str: ...


class CommandHost(Protocol):
	def installCapture(self, capture: Callable[[object], bool]) -> object: ...

	def restoreCapture(self, previous: object) -> None: ...

	def announce(self, message: str, *, priority: CommandSpeechPriority = "normal") -> None: ...

	def showHelp(self, title: str, message: str) -> None: ...

	def callLater(self, milliseconds: int, callback: Callable[[], None]) -> object: ...

	def cancelCall(self, callback: object) -> None: ...


def _clockMilliseconds() -> int:
	return monotonic_ns() // 1_000_000


_MODIFIER_KEYS = frozenset(
	{
		"alt",
		"capslock",
		"control",
		"extendedinsert",
		"insert",
		"leftalt",
		"leftcontrol",
		"leftshift",
		"leftwindows",
		"numpadinsert",
		"nvda",
		"rightalt",
		"rightcontrol",
		"rightshift",
		"rightwindows",
		"shift",
		"windows",
	},
)


class NvdaCommandHost:
	def installCapture(self, capture: Callable[[object], bool]) -> object:
		manager = import_module("inputCore").manager
		previous = manager._captureFunc
		manager._captureFunc = capture
		return previous

	def restoreCapture(self, previous: object) -> None:
		import_module("inputCore").manager._captureFunc = previous

	def announce(self, message: str, *, priority: CommandSpeechPriority = "normal") -> None:
		speech = import_module("speech")
		speechPriority = getattr(getattr(speech, "Spri"), priority.upper())
		import_module("ui").message(message, speechPriority=speechPriority)

	def showHelp(self, title: str, message: str) -> None:
		import_module("ui").browseableMessage(message, title, isHtml=False)

	def callLater(self, milliseconds: int, callback: Callable[[], None]) -> object:
		return import_module("core").callLater(milliseconds, callback)

	def cancelCall(self, callback: object) -> None:
		stop = getattr(callback, "Stop", None)
		if callable(stop):
			_ = stop()


class NvdaCommandLayer:
	def __init__(
		self,
		runtime: CommandRuntime,
		lifecycle: CommandLifecycle,
		host: CommandHost | None = None,
		*,
		nowMilliseconds: Callable[[], int] = _clockMilliseconds,
		sound: WorkflowSounds | None = None,
	) -> None:
		super().__init__()
		self._runtime = runtime
		self._lifecycle = lifecycle
		self._host = host or NvdaCommandHost()
		self._clock = nowMilliseconds
		self._sound = sound
		self._layer = CommandLayerState()
		self._repeat = CommandRepeatState()
		self._token: LayerToken | None = None
		self._previousCapture: object = None
		self._timeout: object | None = None
		self._dispatchGeneration = 0
		self._executionGeneration = 0
		self._captureSoundGeneration = 0
		self._activeCaptureSound: tuple[CommandId, SoundOwner] | None = None
		self._pendingExecution: _PendingExecution | None = None
		self._executingCommand: CommandId | None = None

	def _emit(
		self,
		event: CueEventId,
		owner: SoundOwner,
		*,
		activeFamilyAtom: CueAtomId | None = None,
	) -> None:
		# Sound is optional and additive: the caller has already spoken. A missing seam is a no-op,
		# and any failure to build or schedule the request must never disturb speech or command flow.
		if self._sound is None:
			return
		try:
			self._sound.emit(soundRequestFor(event, owner, activeFamilyAtom=activeFamilyAtom))
		except Exception:
			self._logUnexpected("Keystone sound emission failed")

	def _beginCaptureSound(self, commandId: CommandId) -> None:
		# Allocate a fresh capture owner generation so a later terminal or cancellation cue can only
		# land while this same capture is still the active one; a superseding capture bumps the owner.
		binding = captureStartCue(commandId)
		if binding is None:
			self._activeCaptureSound = None
			return
		self._captureSoundGeneration += 1
		owner = SoundOwner(SoundOwnerKind.CAPTURE, self._captureSoundGeneration)
		self._activeCaptureSound = (commandId, owner)
		self._emit(binding.event, owner, activeFamilyAtom=binding.activeFamilyAtom)

	def _emitCaptureCancellation(self, commandId: CommandId) -> None:
		active = self._activeCaptureSound
		if active is None or active[0] is not commandId:
			return
		binding = captureCancellationCue(commandId)
		if binding is not None:
			self._emit(binding.event, active[1], activeFamilyAtom=binding.activeFamilyAtom)

	def _emitCaptureOutcome(self, commandId: CommandId, outcome: str) -> None:
		active = self._activeCaptureSound
		if active is None or active[0] is not commandId:
			return
		binding = captureOutcomeCue(commandId, outcome)
		if binding is not None:
			self._emit(binding.event, active[1], activeFamilyAtom=binding.activeFamilyAtom)
		self._activeCaptureSound = None

	def emitCaptureProgressSound(self, commandId: CommandId) -> None:
		"""Play one ambient progress cue for the command's still-active capture owner."""

		active = self._activeCaptureSound
		binding = captureStartCue(commandId)
		if active is None or active[0] is not commandId or binding is None:
			return
		familyAtom = CUE_GRAMMAR[binding.event].familyAtom
		if familyAtom is None:
			return
		self._emit(CueEventId.CAPTURE_PROGRESS, active[1], activeFamilyAtom=familyAtom)

	def enter(self) -> None:
		if not self._lifecycle.isCurrent(self._lifecycle.generation):
			self._announce("Keystone commands are unavailable in the current NVDA state.")
			if self._lifecycle.state == "secure":
				# The command was denied specifically because the secure desktop is active. Speech has
				# already carried the denial, so layer the optional secure-desktop cue on the system
				# generation. Indeterminate or terminating denials speak the same line but sound nothing.
				self._emit(
					CueEventId.SECURE_DESKTOP_DENIAL,
					SoundOwner(SoundOwnerKind.SYSTEM, self._lifecycle.generation),
				)
			return
		self._leave(announce=None)
		token = self._layer.enter(
			lifecycleGeneration=self._lifecycle.generation,
			nowMilliseconds=self._clock(),
		)
		self._token = token
		self._previousCapture = self._host.installCapture(self._capture)
		self._timeout = self._host.callLater(4_000, lambda: self._onTimeout(token))
		self._announce("Keystone command layer. Press H for help or Escape to cancel.")
		self._emit(CueEventId.LAYER_ENTERED, SoundOwner(SoundOwnerKind.LAYER, token.layerGeneration))

	def _onTimeout(self, token: LayerToken) -> None:
		if self._layer.isCurrent(
			token,
			lifecycleGeneration=self._lifecycle.generation,
			nowMilliseconds=self._clock(),
		):
			self._leave(announce="Keystone command layer timed out.", sound=CueEventId.LAYER_TIMEOUT)

	def _leave(self, *, announce: str | None, sound: CueEventId | None = None) -> None:
		token = self._token
		self._token = None
		if token is not None:
			self._layer.leave(token)
			self._host.restoreCapture(self._previousCapture)
			self._previousCapture = None
		if self._timeout is not None:
			self._host.cancelCall(self._timeout)
			self._timeout = None
		if announce is not None:
			self._announce(announce)
		if sound is not None and token is not None:
			self._emit(sound, SoundOwner(SoundOwnerKind.LAYER, token.layerGeneration))

	@staticmethod
	def _keyboardIdentifierKey(identifier: object) -> str | None:
		if not isinstance(identifier, str):
			return None
		source, separator, key = identifier.casefold().partition(":")
		if not separator or not (source == "kb" or (source.startswith("kb(") and source.endswith(")"))):
			return None
		return key

	@classmethod
	def _key(cls, gesture: object) -> str | None:
		identifiers = getattr(gesture, "normalizedIdentifiers", ())
		for identifier in cast(tuple[object, ...], identifiers):
			key = cls._keyboardIdentifierKey(identifier)
			if key is None:
				continue
			if key == "escape":
				return key
			parts = tuple(sorted(key.split("+")))
			for registeredKey in COMMAND_BY_KEY:
				if parts == tuple(sorted(registeredKey.split("+"))):
					return registeredKey
		return None

	@classmethod
	def _isModifierOnly(cls, gesture: object) -> bool:
		if getattr(gesture, "isModifier", False) is True:
			return True
		identifiers = getattr(gesture, "normalizedIdentifiers", ())
		for identifier in cast(tuple[object, ...], identifiers):
			key = cls._keyboardIdentifierKey(identifier)
			if key is None:
				continue
			parts = tuple(part for part in key.split("+") if part)
			if parts and all(part in _MODIFIER_KEYS for part in parts):
				return True
		return False

	@staticmethod
	def _logUnexpected(message: str) -> None:
		try:
			import_module("logHandler").log.exception(message)
		except Exception:
			pass

	def _announce(self, message: str, *, priority: CommandSpeechPriority = "normal") -> None:
		try:
			self._host.announce(message, priority=priority)
		except Exception:
			self._logUnexpected("Keystone command announcement failed")

	def _showHelp(self, title: str, message: str) -> bool:
		try:
			self._host.showHelp(title, message)
		except Exception:
			self._logUnexpected("Keystone command help failed")
			return False
		return True

	def _capture(self, gesture: object) -> bool:
		token = self._token
		if token is None or not self._layer.isCurrent(
			token,
			lifecycleGeneration=self._lifecycle.generation,
			nowMilliseconds=self._clock(),
		):
			self._leave(announce=None)
			return True
		key = self._key(gesture)
		if key == "escape":
			self._leave(announce=None)
			self._scheduleLayerFeedback(
				"Keystone command layer cancelled.",
				lifecycleGeneration=token.lifecycleGeneration,
				layerGeneration=token.layerGeneration,
				sound=CueEventId.LAYER_EXIT,
			)
			return False
		if key is None and self._isModifierOnly(gesture):
			return False
		definition = COMMAND_BY_KEY.get(key or "")
		if definition is None:
			self._leave(announce=None)
			self._scheduleLayerFeedback(
				"Unknown Keystone command.",
				lifecycleGeneration=token.lifecycleGeneration,
				layerGeneration=token.layerGeneration,
				sound=CueEventId.LAYER_INVALID_KEY,
			)
			return False
		self._leave(announce=None)
		if definition.commandId is CommandId.HELP:
			self._scheduleHelp(token)
			return False
		self._dispatch(definition.commandId, token)
		return False

	def _scheduleLayerFeedback(
		self,
		message: str,
		*,
		lifecycleGeneration: int,
		layerGeneration: int | None = None,
		sound: CueEventId | None = None,
	) -> None:
		dispatchGeneration = self._dispatchGeneration

		def announce() -> None:
			if dispatchGeneration != self._dispatchGeneration or not self._lifecycle.isCurrent(
				lifecycleGeneration,
			):
				return
			self._announce(message)
			if sound is not None and layerGeneration is not None:
				self._emit(sound, SoundOwner(SoundOwnerKind.LAYER, layerGeneration))

		_ = self._host.callLater(0, announce)

	def _scheduleHelp(self, layerToken: LayerToken) -> None:
		def show() -> None:
			if not self._layer.isGeneration(layerToken) or not self._lifecycle.isCurrent(
				layerToken.lifecycleGeneration,
			):
				return
			if not self._showHelp("Keystone commands", commandHelpText()):
				self._announce("Keystone command help could not be opened.")
				return
			self._announce("Keystone command help opened.")
			self._emit(
				CueEventId.COMMAND_HELP_OPENED,
				SoundOwner(SoundOwnerKind.COMMAND, layerToken.layerGeneration),
			)

		_ = self._host.callLater(0, show)

	def _dispatch(self, commandId: CommandId, layerToken: LayerToken) -> None:
		decision = self._repeat.request(commandId, nowMilliseconds=self._clock())
		activeCommand = self._repeat.activeCommand
		cancellationForwarded = decision.action == "cancel" and self._executingCommand is commandId
		if cancellationForwarded:
			self._runtime.requestCancellation(commandId)
		dispatchGeneration = self._dispatchGeneration

		def dispatch() -> None:
			if dispatchGeneration != self._dispatchGeneration or not self._lifecycle.isCurrent(
				layerToken.lifecycleGeneration,
			):
				if decision.action == "run":
					self._repeat.finish(commandId, nowMilliseconds=self._clock(), committed=False)
				return
			if decision.action == "invoke":
				self._scheduleExecution(commandId, layerToken, announceStart=False)
			elif decision.action == "run":
				self._announce(presentCommandStart(commandId), priority="now")
				self._beginCaptureSound(commandId)
				self._scheduleExecution(commandId, layerToken, announceStart=True)
			elif decision.action == "cancel":
				self._announce(
					presentCommandOutcome("cancellationRequested", commandId=commandId),
					priority="now",
				)
				self._emitCaptureCancellation(commandId)
				pending = self._pendingExecution
				if pending is not None and pending.commandId is commandId:
					self._executionGeneration += 1
					self._pendingExecution = None
					self._repeat.finish(commandId, nowMilliseconds=self._clock(), committed=False)
					self._announce(
						presentCommandOutcome("cancelled", commandId=commandId),
						priority="now",
					)
					self._emitCaptureOutcome(commandId, "cancelled")
				elif not cancellationForwarded:
					self._runtime.requestCancellation(commandId)
			elif decision.action == "busy":
				assert activeCommand is not None
				self._announce(
					presentCommandBusy(commandId, activeCommand),
					priority="now",
				)
			elif decision.action == "copy":
				copied = self._runtime.copyNewest(commandId)
				self._announce(
					"Capture already finished. Newest matching output path copied."
					if copied
					else "No matching committed output is available.",
					priority="now",
				)
				if copied:
					self._emit(
						CueEventId.OUTPUT_PATH_COPY,
						SoundOwner(SoundOwnerKind.COMMAND, self._dispatchGeneration),
					)
			else:
				revealed = self._runtime.revealNewest(commandId)
				self._announce(
					"Capture already finished. Newest matching output revealed in Explorer."
					if revealed
					else "No matching committed output is available.",
					priority="now",
				)
				if revealed:
					self._emit(
						CueEventId.EXPLORER_REVEAL,
						SoundOwner(SoundOwnerKind.COMMAND, self._dispatchGeneration),
					)

		_ = self._host.callLater(0, dispatch)

	def _scheduleExecution(
		self,
		commandId: CommandId,
		layerToken: LayerToken,
		*,
		announceStart: bool,
	) -> None:
		def execute() -> None:
			if not self._lifecycle.isCurrent(layerToken.lifecycleGeneration):
				return
			self._executingCommand = commandId
			try:
				try:
					result = self._runtime.execute(commandId)
				except Exception:
					self._logUnexpected(f"Keystone command execution failed: {commandId.value}")
					result = CommandExecutionResult("failed")
			finally:
				if self._executingCommand is commandId:
					self._executingCommand = None
			if announceStart:
				self._repeat.finish(
					commandId,
					nowMilliseconds=self._clock(),
					committed=result.committed,
				)
			if result.announcementHandled:
				return
			feedbackGeneration = self._dispatchGeneration

			def announceOutcome() -> None:
				if feedbackGeneration != self._dispatchGeneration or not self._lifecycle.isCurrent(
					layerToken.lifecycleGeneration,
				):
					return
				self._announce(
					presentCommandOutcome(result.outcome, result.detail, commandId=commandId),
					priority="now",
				)
				self._emitCaptureOutcome(commandId, result.outcome)

			_ = self._host.callLater(0, announceOutcome)

		if not announceStart:
			_ = self._host.callLater(0, execute)
			return

		self._executionGeneration += 1
		pending = _PendingExecution(
			self._executionGeneration,
			commandId,
			layerToken.lifecycleGeneration,
		)
		self._pendingExecution = pending

		def executePending() -> None:
			if self._pendingExecution != pending:
				return
			if not self._lifecycle.isCurrent(pending.lifecycleGeneration):
				self._pendingExecution = None
				self._repeat.finish(commandId, nowMilliseconds=self._clock(), committed=False)
				return
			self._pendingExecution = None
			execute()

		_ = self._host.callLater(10, executePending)

	def invalidate(self) -> None:
		self._leave(announce=None)
		self._layer.invalidate()
		self._repeat.invalidate()
		self._dispatchGeneration += 1
		self._executionGeneration += 1
		self._pendingExecution = None
		self._activeCaptureSound = None
		if self._sound is not None:
			try:
				self._sound.invalidate()
			except Exception:
				self._logUnexpected("Keystone sound invalidation failed")


class _FixedSelectedObjectSource:
	def __init__(self, targetKind: str, target: object, foreground: object) -> None:
		super().__init__()
		self._targetKind = targetKind
		self._target = target
		self._foreground = foreground

	def selectedObject(self, targetKind: Literal["foreground", "focus", "navigator"]) -> object:
		if targetKind == self._targetKind:
			return self._target
		if targetKind == "foreground":
			return self._foreground
		raise RuntimeError("fixed selected-object source received the wrong target kind")


class _SessionRouter:
	def __init__(self) -> None:
		super().__init__()
		self._session: SelectedObjectSession | None = None

	def activate(self, session: SelectedObjectSession) -> None:
		if self._session is not None:
			raise RuntimeError("a selected-object session is already active")
		self._session = session

	def deactivate(self, session: SelectedObjectSession) -> None:
		if self._session is session:
			self._session = None

	def _current(self) -> SelectedObjectSession:
		if self._session is None:
			raise RuntimeError("KS.PROVIDER.SESSION_UNAVAILABLE")
		return self._session

	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult:
		return self._current().readField(request)

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		return self._current().readChildren(request)

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		return self._current().readLogicalFirstChild(request)

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult:
		return self._current().readRelation(request)

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult:
		return self._current().readText(request)

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		return self._current().readMetadata(request)

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		return self._current().compareIdentity(request)


@dataclass(frozen=True, slots=True)
class _SelectedTarget:
	session: SelectedObjectSession
	reference: SelectedObjectReference
	request: CaptureRequest


@dataclass(frozen=True, slots=True)
class _InspectorSelection:
	target: object
	foreground: object
	focusAncestors: tuple[object, ...] = ()
	inspectorOwned: bool = False


#: Win32 window classes used by Windows' own shell chrome for transient, purely-navigational
#: overlays (the Alt+Tab task-switcher, Windows 11's Task View/Snap Layouts host). These never
#: represent an application the user actually wants inspected, so focus observation ignores
#: them outright rather than treating them as a settled external target.
_SHELL_OVERLAY_WINDOW_CLASSES = ("multitaskingviewframe", "xamlexplorerhostislandwindow")


def _altPhysicallyHeld() -> bool:
	"""True while the physical Alt key is held down, so a focus signal or settle read taken
	mid Alt+Tab cycle is never treated as a genuine "user settled on a different application"
	moment - only whatever has focus once Alt is released is. Imported lazily and isolated
	from failure: any host that cannot answer (no winUser, a non-Windows test double) is
	treated as "Alt is not held" rather than blocking observation.
	"""
	try:
		winUser = import_module("winUser")
		vkMenu = getattr(winUser, "VK_MENU", 0x12)
		state = winUser.getAsyncKeyState(vkMenu)
	except Exception:
		return False
	return bool(cast(int, state) & 0x8000)


def _attribute(target: object, name: str, default: object) -> object:
	try:
		return target.__getattribute__(name)
	except Exception:
		return default


def _integer(target: object, name: str) -> int:
	value = _attribute(target, name, 0)
	return value if type(value) is int and value >= 0 else 0


def _executable(target: object) -> str:
	appModule = _attribute(target, "appModule", None)
	value = _attribute(appModule, "appName", "unknown") if appModule is not None else "unknown"
	name = value if isinstance(value, str) and value else "unknown"
	return name if name.casefold().endswith(".exe") else f"{name}.exe"


def _isTopLevelWindowWrapper(target: object, foreground: object) -> bool:
	"""Whether a navigator window wrapper should yield to its content root."""

	if target is foreground:
		return False
	if _integer(target, "windowHandle") == 0 or _integer(target, "windowHandle") != _integer(
		foreground,
		"windowHandle",
	):
		return False
	if _integer(target, "processID") != _integer(foreground, "processID"):
		return False
	role = _attribute(target, "role", None)
	name = _attribute(role, "name", role)
	if not isinstance(name, str):
		return False
	return name.casefold().rsplit(".", 1)[-1] == "window"


def _diagnosticObject(target: object) -> str:
	targetType = type(target)
	typeName = f"{targetType.__module__}.{targetType.__qualname__}"
	return (
		f"app={_executable(target)},pid={_integer(target, 'processID')},"
		f"hwnd={_integer(target, 'windowHandle')},type={typeName}"
	)


def _defaultInspectorDiagnostic(message: str) -> None:
	try:
		logger = import_module("logHandler").log
	except (AttributeError, ImportError):
		return
	logger.info(message)


def _geometry(target: object) -> tuple[int, int, int, int]:
	value = _attribute(target, "location", None)
	if value is None:
		return (0, 0, 0, 0)
	parts = tuple(_attribute(value, name, 0) for name in ("left", "top", "width", "height"))
	if len(parts) != 4 or not all(type(item) is int for item in parts):
		return (0, 0, 0, 0)
	return cast(tuple[int, int, int, int], parts)


class ProductionCommandRuntime:
	"""Production capture, diff, output, and modeless Inspector command surface."""

	def __init__(
		self,
		lifecycle: LifecycleService,
		settings: SettingsSnapshot,
		output: OutputService,
		screenshot: ScreenshotPort,
		*,
		openCustomUia: Callable[[object, str | None], None],
		openEventMonitor: Callable[[], None],
		toggleEventMonitor: Callable[[], bool] | None = None,
		eventMonitorActive: Callable[[], bool] | None = None,
		selectedSource: SelectedObjectSource | None = None,
		announceInspector: Callable[[str], None] | None = None,
		announceFollowFocus: Callable[[str], None] | None = None,
		inspectorWindowOwnership: WindowOwnershipCheck | None = None,
		scheduleInspector: Callable[[Callable[[], None]], None] | None = None,
		inspectorDiagnostic: Callable[[str], None] | None = None,
		appModuleOverrides: NvdaAppModuleOverrides | None = None,
		sound: WorkflowSounds | None = None,
		announceCaptureProgress: Callable[[str], None] | None = None,
		emitCaptureProgressSound: Callable[[CommandId], None] | None = None,
		runtimeLog: RuntimeLogSink | None = None,
	) -> None:
		super().__init__()
		self._lifecycle = lifecycle
		self._settings = settings
		self._output = output
		self._screenshot = screenshot
		self._openCustomUia = openCustomUia
		self._openEventMonitor = openEventMonitor
		self._toggleEventMonitor = toggleEventMonitor
		self._eventMonitorActive = eventMonitorActive
		self._source = selectedSource or NvdaSelectedObjectSource()
		self._inspectorSelections: dict[InspectorTargetKind, _InspectorSelection] = {}
		self._lastExternalFocusSelection: _InspectorSelection | None = None
		self._pendingFollowSelection: _InspectorSelection | None = None
		self._liveInspectorSource: LiveInspectorSource | None = None
		self._followFocusGeneration = 0
		self._focusObservationGeneration = 0
		self._pendingFocusSignal: tuple[object, tuple[object, ...]] | None = None
		self._lastInspectorRawRequested = False
		self._lastInspectorRawApplied = False
		self._lastInspectorRawReason: str | None = None
		self._eventSourceObjects: OrderedDict[str, object] = OrderedDict()
		self._eventSourceSequence = 0
		self._scheduleInspector = scheduleInspector or self._scheduleOnHost
		self._inspectorDiagnostic = inspectorDiagnostic or _defaultInspectorDiagnostic
		self._appModuleOverrides = appModuleOverrides
		self._announceCaptureProgress = announceCaptureProgress
		self._emitCaptureProgressSound = emitCaptureProgressSound
		self._runtimeLog = runtimeLog
		self._router = _SessionRouter()
		policy = PrivacyPolicy(
			settings.settingsRevision,
			settings.settingsRevision,
			settings.redactProtectedText,
		)
		self._capture = CaptureService(
			lifecycle,
			self._router,
			self._router,
			output,
			screenshot,
			settings=settings,
			privacyPolicy=policy,
			documentIdFactory=lambda: str(uuid4()),
			publicationIdFactory=lambda: os.urandom(16).hex(),
			screenshotAttemptIdFactory=lambda: os.urandom(12).hex(),
			yieldControl=self._yieldControl,
		)
		self._diff = DiffService(
			self._capture,
			output,
			privacyPolicy=policy,
			documentIdFactory=lambda: str(uuid4()),
			publicationIdFactory=lambda: os.urandom(16).hex(),
			environment=("0.0.0", self._nvdaVersion(), platform.version() or "unknown"),
		)
		self._announceInspector = announceInspector
		self._sound = sound
		self._bundles = BundleService()
		self._inspectorService = InspectorService()
		self._window = KeystoneWindow(windowOwnership=inspectorWindowOwnership)
		self._inspector = InspectorWorkspace(
			self._inspectorService,
			retarget=self._retargetInspector,
			followRetarget=self._followInspector,
			announce=announceInspector,
			announceFollowFocus=announceFollowFocus,
			copyToClipboard=self._copyInspectorText,
			copySubtreeSnapshot=self._copyInspectorSubtreeSnapshot,
			exportSubtreeSnapshot=self._exportInspectorSubtreeSnapshot,
			openSnapshot=self.openSnapshotBundle,
			openEventMonitor=self._openEventMonitor,
			openCustomUia=self._openCustomUiaForInspector,
			appModuleOverrideState=self._appModuleOverrideState,
			setAppModuleOverride=self._setAppModuleOverride,
			isCurrent=lambda: lifecycle.isCurrent(lifecycle.generation),
			windowOwnership=inspectorWindowOwnership,
			sound=sound,
			window=self._window,
		)

	@property
	def window(self) -> KeystoneWindow:
		"""The one Keystone window both top-level workspaces are pages of."""

		return self._window

	def applySettings(self, settings: SettingsSnapshot, privacyPolicy: PrivacyPolicy) -> None:
		"""Adopt a committed settings change for every command that starts after it.

		Capture and diff hold the change until their next operation begins, so an inspection or a
		diff already under way finishes under the policy it started with and the evidence it stores
		keeps describing the rule that actually produced it. The Inspector takes the change at once
		because what it caches -- the quick-property repeat interval and the swapped actions -- is
		interaction state rather than stored evidence.
		"""

		self._settings = settings
		self._capture.stageConfiguration(settings, privacyPolicy)
		self._diff.stageConfiguration(privacyPolicy)
		self._inspectorService.applySettings(settings)
		source = getattr(self, "_liveInspectorSource", None)
		if source is not None:
			# An Inspector left open keeps its selection and its already-loaded rows; only the nodes
			# and properties it reads from here on are transformed under the new policy.
			source.applyPrivacyPolicy(privacyPolicy)

	def setCaptureProgressSoundEmitter(
		self,
		emitter: Callable[[CommandId], None] | None,
	) -> None:
		"""Bind the command-layer capture owner after both runtime surfaces are constructed."""

		self._emitCaptureProgressSound = emitter

	def _appModuleOverrideState(self) -> AppModuleOverrideState:
		manager = self._appModuleOverrides
		identity = self._inspectorService.sourceIdentity()
		if (
			manager is None
			or identity is None
			or identity.kind is not InspectorSourceKind.LIVE
			or identity.executable == "unknown.exe"
		):
			return AppModuleOverrideState(None, False, False)
		state = manager.state(identity.executable)
		return AppModuleOverrideState(state.executable, state.enabled, state.available)

	def _setAppModuleOverride(self, enabled: bool) -> AppModuleOverrideOutcome:
		manager = self._appModuleOverrides
		state = self._appModuleOverrideState()
		if manager is None or not state.available:
			return AppModuleOverrideOutcome(False, state.executable, enabled, "KS.APP_MODULE.UNAVAILABLE")
		result = manager.setEnabled(state.executable, enabled)
		if result.succeeded:
			self._inspectorSelections.clear()
			self._lastExternalFocusSelection = None
			self._pendingFollowSelection = None
			self._liveInspectorSource = None
		return AppModuleOverrideOutcome(
			result.succeeded,
			result.executable,
			result.enabled,
			result.errorCode,
		)

	@staticmethod
	def _scheduleOnHost(callback: Callable[[], None]) -> None:
		try:
			core = import_module("core")
		except ImportError:
			callback()
			return
		callLater = getattr(core, "callLater", None)
		if callable(callLater):
			_ = callLater(0, callback)
		else:
			callback()

	@staticmethod
	def _nvdaVersion() -> str:
		try:
			versionInfo = import_module("versionInfo")
			return str(versionInfo.version)
		except (AttributeError, ImportError):
			return "unknown"

	@staticmethod
	def _yieldControl(_visited: int) -> None:
		try:
			import_module("api").processPendingEvents(processEventQueue=True)
		except Exception:
			return

	def _traceInspector(
		self,
		event: str,
		**fields: str | int | bool | None,
	) -> None:
		details = ", ".join(
			f"{key}={str(value).lower() if isinstance(value, bool) else value}"
			for key, value in sorted(fields.items())
		)
		message = f"Keystone Inspector: {event}"
		if details:
			message = f"{message}; {details}"
		self._inspectorDiagnostic(message)

	def _selected(
		self,
		targetKind: Literal["foreground", "focus", "navigator"],
		*,
		mode: Literal["bounded", "unlimited"] = "bounded",
		rawRequest: ProjectionRequest | None = None,
		customUiaCaptureMode: CustomUiaCaptureMode = CustomUiaCaptureMode.NORMAL,
		retargetNavigatorWindow: bool = False,
		includeRootNameInOutput: bool = False,
	) -> _SelectedTarget:
		target = self._source.selectedObject(targetKind)
		foreground = self._source.selectedObject("foreground")
		return self._selectedObjects(
			targetKind,
			target,
			foreground,
			mode=mode,
			rawRequest=rawRequest,
			customUiaCaptureMode=customUiaCaptureMode,
			retargetNavigatorWindow=retargetNavigatorWindow,
			includeRootNameInOutput=includeRootNameInOutput,
		)

	def _selectedObjects(
		self,
		targetKind: Literal["foreground", "focus", "navigator"],
		target: object,
		foreground: object,
		*,
		mode: Literal["bounded", "unlimited"] = "bounded",
		rawRequest: ProjectionRequest | None = None,
		inspectionTarget: object | None = None,
		customUiaCaptureMode: CustomUiaCaptureMode = CustomUiaCaptureMode.NORMAL,
		retargetNavigatorWindow: bool = False,
		includeRootNameInOutput: bool = False,
	) -> _SelectedTarget:
		captureTarget = (
			foreground
			if targetKind == "navigator"
			and retargetNavigatorWindow
			and _isTopLevelWindowWrapper(target, foreground)
			else target
		)
		fixed = _FixedSelectedObjectSource(targetKind, captureTarget, foreground)
		session = SelectedObjectSession(
			fixed,
			generation=self._lifecycle.generation,
			customUiaCaptureMode=customUiaCaptureMode,
			rawDiagnostic=self._inspectorDiagnostic if rawRequest is not None else None,
		)
		reference = session.acquire(targetKind, rawRequest=rawRequest)
		inspectionTargetRef = session.retain(inspectionTarget) if inspectionTarget is not None else None
		windowHandle = _integer(foreground, "windowHandle")
		request = CaptureRequest(
			CaptureTargetKind.NAVIGATOR if targetKind == "navigator" else CaptureTargetKind.FOREGROUND,
			reference.rootRef,
			ScreenshotTarget(
				"containingForeground",
				f"window-{windowHandle}",
				_geometry(foreground),
			),
			_executable(captureTarget),
			_integer(captureTarget, "processID"),
			mode,
			reference.providerScope,
			reference.processScope,
			reference.backend,
			inspectionTargetRef=inspectionTargetRef,
			includeRootNameInOutput=includeRootNameInOutput,
		)
		return _SelectedTarget(session, reference, request)

	def _inspectorSelection(self, targetKind: InspectorTargetKind) -> _InspectorSelection:
		target = self._source.selectedObject(targetKind)
		if targetKind == "focus":
			navigator = self._source.selectedObject("navigator")
			if _attribute(navigator, "hasFocus", False) is True:
				target = navigator
		foreground = self._source.selectedObject("foreground")
		focusAncestors = (
			self._cachedFocusAncestors() if targetKind == "focus" else self._objectAncestors(target)
		)
		previous = (
			self._inspectorSelections.get("focus") or self._lastExternalFocusSelection
			if targetKind == "focus"
			else self._inspectorSelections.get(targetKind) or self._lastExternalFocusSelection
		)
		targetOwned = self._inspector.ownsWindow(
			_integer(target, "processID"),
			_integer(target, "windowHandle"),
		)
		if targetOwned:
			if previous is None:
				self._traceInspector(
					"selection.rejected",
					reason="inspector-owned-without-external-selection",
					target=_diagnosticObject(target),
					targetKind=targetKind,
				)
				raise RuntimeError("Inspector has no external target to retain")
			self._traceInspector(
				"selection.retained",
				ancestorCount=len(previous.focusAncestors),
				foreground=_diagnosticObject(previous.foreground),
				reason="target-owned-by-inspector",
				target=_diagnosticObject(previous.target),
				targetKind=targetKind,
			)
			return _InspectorSelection(
				previous.target,
				previous.foreground,
				previous.focusAncestors,
				inspectorOwned=True,
			)
		foregroundOwned = self._inspector.ownsWindow(
			_integer(foreground, "processID"),
			_integer(foreground, "windowHandle"),
		)
		if foregroundOwned:
			foreground, foregroundReason = self._externalFocusForeground(target, focusAncestors)
		else:
			foregroundReason = "nvda-foreground"
		selection = _InspectorSelection(
			target,
			foreground,
			focusAncestors,
		)
		self._traceInspector(
			"selection.updated",
			ancestorCount=len(focusAncestors),
			foreground=_diagnosticObject(foreground),
			foregroundReason=foregroundReason,
			target=_diagnosticObject(target),
			targetKind=targetKind,
		)
		self._inspectorSelections[targetKind] = selection
		if targetKind == "focus":
			self._lastExternalFocusSelection = selection
		return selection

	def _objectAncestors(self, target: object, *, limit: int = 64) -> tuple[object, ...]:
		"""Read a bounded NVDA parent chain without assuming the object is focused."""

		ancestors: list[object] = []
		current = target
		seen = {id(target)}
		while len(ancestors) < limit:
			parent = _attribute(current, "simpleParent", None)
			if parent is None:
				parent = _attribute(current, "parent", None)
			if parent is None or id(parent) in seen:
				break
			seen.add(id(parent))
			ancestors.append(parent)
			current = parent
		ancestors.reverse()
		return tuple(ancestors)

	def _externalFocusForeground(
		self,
		target: object,
		focusAncestors: tuple[object, ...],
	) -> tuple[object, str]:
		targetProcessId = _integer(target, "processID")
		for ancestor in focusAncestors:
			if _integer(ancestor, "processID") != targetProcessId:
				continue
			if self._inspector.ownsWindow(
				_integer(ancestor, "processID"),
				_integer(ancestor, "windowHandle"),
			):
				continue
			return ancestor, "focus-ancestor"
		return target, "focus-target-fallback"

	def _cachedFocusAncestors(self) -> tuple[object, ...]:
		"""Retain NVDA's focus-transition ancestry before the Inspector receives focus."""

		try:
			api = import_module("api")
			ancestors = api.getFocusAncestors()
		except (AttributeError, ImportError):
			return ()
		except Exception:
			self._logUnexpected("Keystone could not read NVDA's cached focus ancestors")
			return ()
		if not isinstance(ancestors, (list, tuple)):
			self._logUnexpected("Keystone received malformed cached focus ancestors")
			return ()
		return tuple(ancestor for ancestor in ancestors if ancestor is not None)

	def _closeSession(self, selected: _SelectedTarget) -> None:
		context = CorrelationFactory().admit(generation=self._lifecycle.generation)
		_ = selected.session.closeSession(ProviderSessionCloseRequest(context))

	# -- live Inspector source and workspace lifecycle ---------------------

	def _openCustomUiaForInspector(self, parent: object) -> None:
		"""Open definitions against the retained external Inspector target, not NVDA's frame."""

		try:
			selection = self._inspectorSelection("focus")
			executable = _executable(selection.target)
		except Exception:
			executable = None
		self._openCustomUia(parent, executable)

	def _copyInspectorText(self, text: str) -> bool:
		"""Write one already-privacy-safe copy payload to the clipboard on the owner thread."""

		try:
			api = import_module("api")
		except ImportError:
			return False
		copyToClip = getattr(api, "copyToClip", None)
		if not callable(copyToClip):
			return False
		try:
			return bool(copyToClip(text))
		except Exception:
			return False

	def _inspectorSubtreePackage(self, nodeId: str) -> BundlePackage:
		"""Create a portable package from recorded data or one freshly captured live subtree."""

		identity = self._inspectorService.sourceIdentity()
		if identity is None:
			raise RuntimeError("no Inspector source is open")
		if identity.kind is InspectorSourceKind.OFFLINE:
			return self._bundles.selectSubtree(nodeId).package
		source = self._liveInspectorSource
		if source is None:
			raise RuntimeError("live Inspector source is unavailable")
		rows = self._inspectorService.hierarchy()
		if not rows:
			raise RuntimeError("live Inspector hierarchy is unavailable")
		target = source.liveObject(nodeId)
		foreground = source.liveObject(rows[0].nodeId)
		selected = self._selectedObjects("focus", target, foreground)
		self._router.activate(selected.session)
		try:
			result = self._capture.captureForInspection(selected.request)
		finally:
			self._router.deactivate(selected.session)
			self._closeSession(selected)
		if not result.committed or result.bundle is None:
			raise RuntimeError(result.errorCode or "KS.CAPTURE.SUBTREE_FAILED")
		return result.bundle

	def _copyInspectorSubtreeSnapshot(self, nodeId: str) -> bytes:
		"""Return one source-specific, privacy-safe selected subtree JSON payload."""

		package = self._inspectorSubtreePackage(nodeId)
		return SelectedSubtreeProjection(
			nodeId,
			self._inspectorService.sourceGeneration,
			package,
		).toJsonBytes()

	def _exportInspectorSubtreeSnapshot(self, nodeId: str, destination: Path) -> None:
		"""Write a source-specific subtree package outside the normal capture destination."""

		identity = self._inspectorService.sourceIdentity()
		row = next((row for row in self._inspectorService.hierarchy() if row.nodeId == nodeId), None)
		if identity is None or row is None:
			raise RuntimeError("the selected Inspector hierarchy item is unavailable")
		facet = row.node.facet
		automationId: str | None = None
		if not facet.hasName and self._liveInspectorSource is not None:
			value = _attribute(self._liveInspectorSource.liveObject(nodeId), "UIAAutomationId", None)
			automationId = value if isinstance(value, str) else None
		exportDirectory = portableSubtreeDestination(
			destination,
			applicationName=identity.executable,
			elementName=facet.name if facet.hasName else None,
			automationId=automationId,
			role=facet.role,
			now=datetime.now().astimezone(),
		)
		package = self._inspectorSubtreePackage(nodeId)
		exportDirectory.parent.mkdir(parents=True, exist_ok=True)
		_ = writePortableBundle(package, exportDirectory)

	def _buildLiveInspectorSource(
		self,
		targetKind: InspectorTargetKind,
		*,
		rawRequested: bool = False,
		selection: _InspectorSelection | None = None,
	) -> LiveInspectorSource | None:
		"""Build a live foreground hierarchy without materialising an Inspector capture."""

		selection = selection or self._inspectorSelection(targetKind)
		self._traceInspector(
			"source.build-start",
			ancestorCount=len(selection.focusAncestors),
			foreground=_diagnosticObject(selection.foreground),
			rawRequested=rawRequested,
			target=_diagnosticObject(selection.target),
			targetKind=targetKind,
		)
		rawRequest = (
			ProjectionRequest.explicit(
				f"inspector-{uuid4()}",
				ProjectionBudget(150, 600, 2_000),
				allowWindowScoped=targetKind != "focus",
			)
			if rawRequested
			else None
		)
		selected = self._selectedObjects(
			targetKind,
			selection.target,
			selection.foreground,
			rawRequest=rawRequest,
		)
		projection = selected.reference.projection
		rawApplied = bool(projection is not None and projection.applied)
		self._lastInspectorRawRequested = rawRequested
		self._lastInspectorRawApplied = rawApplied
		self._lastInspectorRawReason = None if projection is None else projection.reasonCode
		self._traceInspector(
			"source.projection",
			backend=selected.reference.backend,
			rawApplied=rawApplied,
			rawReason=self._lastInspectorRawReason,
			rawRequested=rawRequested,
			targetKind=targetKind,
		)
		context = CorrelationFactory().admit(generation=self._lifecycle.generation)
		foregroundRef = (
			selected.reference.rootRef if rawApplied else selected.session.retain(selection.foreground)
		)
		focusAncestorRefs = (
			()
			if rawApplied
			else tuple(selected.session.retain(ancestor) for ancestor in selection.focusAncestors)
		)
		reader = LiveSessionNodeReader(
			selected.session,
			context,
			InspectorSourceIdentity(
				InspectorSourceKind.LIVE,
				selected.request.executable,
				selected.request.executable,
				selected.request.processId,
				selected.reference.backend or selected.request.backend,
				rawApplied=rawApplied,
				rawReason=self._lastInspectorRawReason,
			),
			foregroundRef=foregroundRef,
			targetRef=selected.reference.rootRef,
			focusAncestorRefs=focusAncestorRefs,
			providerScope=selected.reference.providerScope,
			processScope=selected.reference.processScope,
			privacyPolicy=PrivacyPolicy(
				self._settings.settingsRevision,
				self._settings.settingsRevision,
				self._settings.redactProtectedText,
			),
			diagnostic=self._inspectorDiagnostic,
			retargetable=not rawApplied,
		)
		return LiveInspectorSource(reader)

	def _openInspectorSource(self, source: LiveInspectorSource) -> None:
		identity = source.identity()
		self._inspectorService.openSource(source, settings=self._settings)
		self._liveInspectorSource = source
		self._traceInspector(
			"source.opened",
			backend=identity.backend,
			executable=identity.executable,
			processId=identity.processId,
			sourceGeneration=self._inspectorService.sourceGeneration,
		)
		# Populate siblings for the resolved ancestry while leaving the selected target's descendants
		# branch-lazy.
		for row in tuple(self._inspectorService.hierarchy())[:-1]:
			_ = self._inspectorService.expand(row.nodeId)

	def openSnapshotBundle(
		self,
		directory: Path,
		limits: BundleAdmissionLimits | None = None,
	) -> None:
		"""Install a fully admitted offline source without disturbing a prior source on rejection."""

		selectedDirectory = Path(directory)
		nextGeneration = self._bundles.currentGeneration + 1
		view = BundleSnapshotView(
			selectedDirectory,
			sourceGeneration=nextGeneration,
			limits=self._bundles.defaultLimits if limits is None else limits,
		)
		index = view.index
		if index.snapshotKind not in ("snapshot", "navigatorSnapshot"):
			raise ValueError("snapshot kind is not supported for offline inspection")
		if not view.captureRoots:
			raise ValueError("snapshot has no capture root")
		source = OfflineInspectorSource(
			view,
			view.captureRoots[0],
			label=selectedDirectory.name,
			executable=index.executable,
			processId=index.processId,
			backend="capture",
		)
		roots = source.roots()
		if not roots:
			raise ValueError("snapshot has no inspectable root")
		_ = source.properties(roots[-1].nodeId, PropertyCategory.CORE)
		_ = self._bundles.openDirectory(selectedDirectory, limits=limits)
		self._inspectorService.openSource(source, settings=self._settings)
		self._liveInspectorSource = None
		self._traceInspector(
			"snapshot.opened",
			backend="capture",
			executable=index.executable,
			processId=index.processId,
			sourceGeneration=self._inspectorService.sourceGeneration,
		)

	def currentInspectorSelection(self) -> object:
		"""Resolve the live object selected by the Inspector's single hierarchy selection.

		The Event Monitor freezes exactly this object, so each way of having no live selection is
		reported as its own reason rather than as one generic failure the caller could widen away.
		"""

		nodeId = self._inspectorService.selectedNodeId
		if nodeId is None:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.NO_SELECTION)
		source = self._liveInspectorSource
		if source is None:
			# A snapshot opened for offline inspection has rows but no live provider behind them.
			raise MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_OFFLINE)
		try:
			selected = source.liveObject(nodeId)
		except Exception as error:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_UNRESOLVED) from error
		if selected is None:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_UNRESOLVED)
		return selected

	def retainEventSource(self, source: object) -> str | None:
		"""Retain a bounded owner-thread source reference for explicit event navigation."""

		if targetIdentityFromObject(source) is None:
			return None
		self._eventSourceSequence += 1
		sourceRef = f"event-source-{self._eventSourceSequence}"
		self._eventSourceObjects[sourceRef] = source
		while len(self._eventSourceObjects) > 2_000:
			_ = self._eventSourceObjects.popitem(last=False)
		return sourceRef

	def showEventSource(self, row: EventRow) -> bool:
		"""Open a still-live, identity-proven event source without changing the monitor target."""

		if row.sourceRef is None or row.sourceIdentity is None:
			return False
		sourceObject = self._eventSourceObjects.get(row.sourceRef)
		if sourceObject is None:
			return False
		currentIdentity = targetIdentityFromObject(sourceObject)
		if currentIdentity is None or not row.sourceIdentity.correlates(currentIdentity):
			_ = self._eventSourceObjects.pop(row.sourceRef, None)
			return False
		ancestors = self._objectAncestors(sourceObject)
		foreground = ancestors[0] if ancestors else sourceObject
		selection = _InspectorSelection(sourceObject, foreground, ancestors)
		try:
			source = self._buildLiveInspectorSource("focus", selection=selection)
			if source is None:
				return False
			self._openInspectorSource(source)
			self._inspector.show()
		except Exception:
			return False
		self._eventSourceObjects.move_to_end(row.sourceRef)
		return True

	def _openLiveInspector(
		self,
		targetKind: InspectorTargetKind,
		*,
		rawRequested: bool = False,
	) -> bool:
		selection = self._inspectorSelection(targetKind)
		if selection.inspectorOwned:
			# The global shortcut is often pressed while the Inspector tree owns focus. Retain the
			# external source rather than recapturing the Inspector itself as a new focus target.
			self._inspector.show()
			return True
		try:
			source = self._buildLiveInspectorSource(
				targetKind,
				rawRequested=rawRequested,
				selection=selection,
			)
		except Exception:
			self._logUnexpected("Keystone could not build the live Inspector source")
			self._announceInspectorFailure(targetKind)
			return False
		if source is None:
			self._announceInspectorFailure(targetKind)
			return False
		self._openInspectorSource(source)
		self._inspector.show()
		self._emitInspectorSound(self._openInspectorCue(targetKind))
		# A successful open has produced a shown workspace with browsable content: the ready cue is the
		# success counterpart to the failure cue above. It is owned by the same source generation, so
		# its urgent priority supersedes the open sequence just emitted rather than adding a second
		# voice, and it never speaks - the workspace has already announced the focused node.
		self._emitInspectorSound(CueEventId.INSPECTOR_READY)
		return True

	def _prepareFocusSelectionForEventMonitor(self) -> bool:
		"""Install the focused live object without showing the Inspector page.

		The Events command needs the same selected live object as the Focus Inspector command, but
		raising the Inspector page first would move the user through an unrelated page and make its
		open cue misleading. A retained external selection is rebuilt when Keystone already owns
		focus, so an offline source can never be reused as a monitor target.
		"""

		try:
			selection = self._inspectorSelection("focus")
			source = self._buildLiveInspectorSource("focus", selection=selection)
		except Exception:
			self._logUnexpected("Keystone could not prepare the focused object for Event Monitor")
			self._announceInspectorFailure("focus")
			return False
		if source is None:
			self._announceInspectorFailure("focus")
			return False
		self._openInspectorSource(source)
		return True

	def _retargetInspector(
		self,
		targetKind: InspectorTargetKind,
		rawRequested: bool,
	) -> InspectorRetargetOutcome:
		self._traceInspector(
			"retarget.requested",
			rawRequested=rawRequested,
			targetKind=targetKind,
		)
		try:
			selection = self._inspectorSelection(targetKind)
			if (
				targetKind == "focus"
				and selection.inspectorOwned
				and self._lastExternalFocusSelection is not None
			):
				selection = self._lastExternalFocusSelection
				self._traceInspector(
					"retarget.external-selection-restored",
					foreground=_diagnosticObject(selection.foreground),
					target=_diagnosticObject(selection.target),
					targetKind=targetKind,
				)
			source = self._buildLiveInspectorSource(
				targetKind,
				rawRequested=rawRequested,
				selection=selection,
			)
			if source is None:
				self._traceInspector(
					"retarget.failed",
					reason="source-unavailable",
					targetKind=targetKind,
				)
				return InspectorRetargetOutcome(False, rawRequested)
			self._openInspectorSource(source)
			self._traceInspector(
				"retarget.completed",
				rawApplied=self._lastInspectorRawApplied,
				rawRequested=self._lastInspectorRawRequested,
				targetKind=targetKind,
			)
			return InspectorRetargetOutcome(
				True,
				self._lastInspectorRawRequested,
				self._lastInspectorRawApplied,
				self._lastInspectorRawReason,
			)
		except Exception:
			self._traceInspector(
				"retarget.failed",
				reason="exception",
				targetKind=targetKind,
			)
			self._logUnexpected("Keystone could not retarget the live Inspector")
			return InspectorRetargetOutcome(False, rawRequested)

	def _followInspector(self, event: FollowFocusEvent) -> bool:
		selection = self._pendingFollowSelection
		if selection is None:
			self._traceInspector(
				"follow.failed",
				applicationKey=event.applicationKey,
				reason="pending-selection-missing",
			)
			return False
		try:
			current = self._liveInspectorSource
			if current is not None:
				try:
					facets = current.retarget(
						selection.target,
						selection.foreground,
						selection.focusAncestors,
					)
				except Exception:
					self._logUnexpected(
						"Keystone could not reuse the current Inspector hierarchy; rebuilding it",
					)
					facets = None
				if facets is not None and self._inspectorService.retargetWithinSource(facets):
					self._traceInspector(
						"follow.completed",
						applicationKey=event.applicationKey,
						hierarchyReused=True,
					)
					return True
			source = self._buildLiveInspectorSource(
				"focus",
				rawRequested=self._lastInspectorRawRequested,
				selection=selection,
			)
			if source is None:
				self._traceInspector(
					"follow.failed",
					applicationKey=event.applicationKey,
					reason="source-unavailable",
				)
				return False
			self._openInspectorSource(source)
			self._traceInspector(
				"follow.completed",
				applicationKey=event.applicationKey,
				hierarchyReused=False,
			)
			return True
		except Exception:
			self._traceInspector(
				"follow.failed",
				applicationKey=event.applicationKey,
				reason="exception",
			)
			self._logUnexpected("Keystone could not follow the new focus object")
			return False

	def _nvdaOwnProcessFocus(self, target: object) -> bool:
		"""True when ``target`` belongs to NVDA's own process, checked via ``appModule.processID``
		when available and falling back to the object's own ``processID``. This is intentionally
		broader than ``InspectorWorkspace.ownsWindow`` (which matches a specific frame handle): it
		also excludes NVDA-internal objects (e.g. the Inspector's own controls) that never carry
		the frame's own window handle.
		"""
		pid = os.getpid()
		if _integer(target, "processID") == pid:
			return True
		appModule = _attribute(target, "appModule", None)
		return appModule is not None and _integer(appModule, "processID") == pid

	def _inspectorOwnedFocus(self, target: object) -> bool:
		return self._inspector.ownsWindow(
			_integer(target, "processID"),
			_integer(target, "windowHandle"),
		) or self._nvdaOwnProcessFocus(target)

	@staticmethod
	def _shellOverlayFocus(target: object) -> bool:
		windowClassName = str(_attribute(target, "windowClassName", "")).casefold()
		targetType = type(target)
		typeName = f"{targetType.__module__}.{targetType.__qualname__}".casefold()
		return any(
			shellClass in windowClassName or shellClass in typeName
			for shellClass in _SHELL_OVERLAY_WINDOW_CLASSES
		)

	@staticmethod
	def _taskSwitchName(target: object) -> bool:
		name = _attribute(target, "name", "")
		return isinstance(name, str) and "task switch" in name.casefold()

	@staticmethod
	def _transientRoleFocus(target: object) -> bool:
		role = _attribute(target, "role", "")
		name = _attribute(role, "name", role)
		text = str(name).casefold().replace("_", "").replace(" ", "")
		return text in {"menu", "menuitem", "popupmenu", "tooltip"}

	@staticmethod
	def _structuralFocus(target: object) -> bool:
		targetType = type(target)
		typeName = f"{targetType.__module__}.{targetType.__qualname__}".casefold()
		return "contentgenericclient" in typeName or "uicolumnheader" in typeName

	def _ignorableFocusReason(self, target: object) -> str | None:
		"""Classify a focus/foreground candidate that observation must never commit to.

		``"inspector-owned"`` is reported separately from every other reason because only it
		invalidates a pending settle (see observeFocus); the remaining reasons are transient
		noise that observation simply steps around, leaving whatever settle is already
		scheduled free to run and independently re-check its own fresh state.
		"""
		if self._inspectorOwnedFocus(target):
			return "inspector-owned"
		if _altPhysicallyHeld():
			return "alt-held"
		if self._shellOverlayFocus(target):
			return "shell-overlay"
		if self._taskSwitchName(target):
			return "task-switch-name"
		if self._transientRoleFocus(target):
			return "transient"
		if self._structuralFocus(target):
			return "structural"
		return None

	def observeFocus(self, target: object) -> None:
		"""Treat one NVDA gainFocus object as a signal that focus may have settled, never as
		the settled target itself. A non-ignorable signal only bumps the focus-observation
		generation and arms a zero-delay host callback (``_settleFocusObservation``) that later
		reads focus, foreground, and cached ancestry fresh - so bursts of transitional objects
		(Explorer/Chromium structural children, Alt+Tab overlay frames) can never outrun or
		overwrite the object the user actually settled on.
		"""
		if not self._inspector.window.isOpen:
			return
		if not self._lifecycle.isCurrent(self._lifecycle.generation):
			self._traceInspector("focus.signal-ignored", reason="stale-lifecycle")
			return
		reason = self._ignorableFocusReason(target)
		if reason == "inspector-owned":
			# The Inspector's own controls just took focus (or NVDA's own process otherwise
			# produced this signal). Any settle already scheduled for an earlier signal is now
			# superseded - invalidate it by generation so it cannot later commit whatever
			# incidental object happened to be captured - but never touch the last stable
			# external selection: explicit Retarget depends on it staying intact while the
			# Inspector owns focus.
			self._focusObservationGeneration += 1
			self._pendingFocusSignal = None
			self._traceInspector(
				"focus.signal-ignored",
				reason=reason,
				target=_diagnosticObject(target),
			)
			return
		if reason is not None:
			self._traceInspector(
				"focus.signal-ignored",
				reason=reason,
				target=_diagnosticObject(target),
			)
			return
		focusAncestors = self._cachedFocusAncestors()
		pending = self._pendingFocusSignal
		targetTypeName = f"{type(target).__module__}.{type(target).__qualname__}".casefold()
		if (
			"chromium.document" in targetTypeName
			and pending is not None
			and _integer(pending[0], "processID") == _integer(target, "processID")
			and len(pending[1]) > len(focusAncestors)
		):
			self._traceInspector(
				"focus.signal-ignored",
				reason="structural-after-deeper-target",
				target=_diagnosticObject(target),
			)
			return
		self._focusObservationGeneration += 1
		generation = self._focusObservationGeneration
		self._pendingFocusSignal = (target, focusAncestors)
		self._traceInspector(
			"focus.signal-coalesced",
			focusObservationGeneration=generation,
			target=_diagnosticObject(target),
		)
		self._scheduleInspector(lambda: self._settleFocusObservation(generation))

	def _settleFocusObservation(self, generation: int) -> None:
		"""Drain a coalesced focus signal: only the newest scheduled generation may commit, and
		everything it commits is read fresh at drain time rather than replayed from the
		originating gainFocus event.
		"""
		if not self._inspector.window.isOpen:
			self._pendingFocusSignal = None
			return
		if generation != self._focusObservationGeneration:
			self._traceInspector(
				"focus.settle-rejected",
				focusObservationGeneration=generation,
				reason="superseded",
			)
			return
		if not self._lifecycle.isCurrent(self._lifecycle.generation):
			self._traceInspector(
				"focus.settle-rejected",
				focusObservationGeneration=generation,
				reason="stale-lifecycle",
			)
			return
		if _altPhysicallyHeld():
			self._traceInspector(
				"focus.settle-rejected",
				focusObservationGeneration=generation,
				reason="alt-held",
			)
			return
		try:
			focus = self._source.selectedObject("focus")
		except Exception:
			self._traceInspector(
				"focus.settle-rejected",
				focusObservationGeneration=generation,
				reason="focus-read-failed",
			)
			return
		focusReason = self._ignorableFocusReason(focus)
		if focusReason is not None:
			self._traceInspector(
				"focus.settle-rejected",
				focusObservationGeneration=generation,
				reason=focusReason,
				target=_diagnosticObject(focus),
			)
			return
		focusAncestors = self._cachedFocusAncestors()
		try:
			foreground = self._source.selectedObject("foreground")
		except Exception:
			foreground = focus
			foregroundReason = "focus-target-after-read-failure"
		else:
			foregroundIgnorable = self._ignorableFocusReason(foreground)
			if foregroundIgnorable is None:
				foregroundReason = "nvda-foreground"
			elif foregroundIgnorable == "inspector-owned":
				foreground, foregroundReason = self._externalFocusForeground(focus, focusAncestors)
			else:
				self._traceInspector(
					"focus.settle-rejected",
					focusObservationGeneration=generation,
					reason=f"foreground-{foregroundIgnorable}",
					target=_diagnosticObject(focus),
				)
				return
		selection = _InspectorSelection(focus, foreground, focusAncestors)
		self._pendingFocusSignal = None
		self._traceInspector(
			"focus.settled",
			ancestorCount=len(focusAncestors),
			focusObservationGeneration=generation,
			followFocus=self._inspectorService.followFocusEnabled,
			foreground=_diagnosticObject(foreground),
			foregroundReason=foregroundReason,
			target=_diagnosticObject(focus),
		)
		self._retainObservedFocus(selection)

	def _retainObservedFocus(self, selection: _InspectorSelection) -> None:
		self._lastExternalFocusSelection = selection
		self._inspectorSelections["focus"] = selection
		if not self._inspectorService.followFocusEnabled:
			self._traceInspector("focus.retained", reason="follow-focus-disabled")
			return
		self._followFocusGeneration += 1
		generation = self._followFocusGeneration
		target = selection.target
		event = FollowFocusEvent(
			applicationKey=f"{_executable(target)}\x1f{_integer(target, 'processID')}",
		)
		self._scheduleInspector(
			lambda: self._applyFollowFocus(generation, selection, event),
		)
		self._traceInspector(
			"follow.scheduled",
			applicationKey=event.applicationKey,
			followGeneration=generation,
		)

	def _applyFollowFocus(
		self,
		generation: int,
		selection: _InspectorSelection,
		event: FollowFocusEvent,
	) -> None:
		if generation != self._followFocusGeneration:
			self._traceInspector(
				"follow.skipped",
				followGeneration=generation,
				reason="superseded",
			)
			return
		if not self._lifecycle.isCurrent(self._lifecycle.generation):
			self._traceInspector(
				"follow.skipped",
				followGeneration=generation,
				reason="stale-lifecycle",
			)
			return
		self._pendingFollowSelection = selection
		try:
			outcome = self._inspector.considerFollowFocus(event)
			self._traceInspector(
				"follow.dispatched",
				applicationKey=event.applicationKey,
				followGeneration=generation,
				outcome=outcome,
			)
		finally:
			self._pendingFollowSelection = None

	def _announceInspectorFailure(self, targetKind: InspectorTargetKind) -> None:
		announce = self._announceInspector
		if announce is not None:
			try:
				announce("Inspector could not read the selected object.")
			except Exception:
				self._logUnexpected("Keystone Inspector failure announcement failed")
		self._emitInspectorSound(
			CueEventId.INSPECTOR_FAILURE,
			activeFamilyAtom=self._inspectorFamilyAtom(targetKind),
		)

	def _emitInspectorSound(
		self,
		event: CueEventId,
		*,
		activeFamilyAtom: CueAtomId | None = None,
	) -> None:
		# Optional audio layered after the Inspector has already spoken, owned by the current source
		# generation so a superseded open cannot sound. Any sink failure stays isolated from speech.
		sound = self._sound
		if sound is None:
			return
		try:
			owner = SoundOwner(SoundOwnerKind.INSPECTOR, self._inspectorService.sourceGeneration)
			sound.emit(soundRequestFor(event, owner, activeFamilyAtom=activeFamilyAtom))
		except Exception:
			self._logUnexpected("Keystone inspector sound failed")

	@staticmethod
	def _openInspectorCue(targetKind: InspectorTargetKind) -> CueEventId:
		if targetKind == "navigator":
			return CueEventId.OPEN_NAVIGATOR_INSPECTOR
		return CueEventId.OPEN_FOCUS_INSPECTOR

	@staticmethod
	def _inspectorFamilyAtom(targetKind: InspectorTargetKind) -> CueAtomId:
		if targetKind == "navigator":
			return CueAtomId.NAVIGATOR_INSPECTOR_FAMILY
		return CueAtomId.FOCUS_INSPECTOR_FAMILY

	@staticmethod
	def _logUnexpected(message: str) -> None:
		try:
			import_module("logHandler").log.exception(message)
		except Exception:
			pass

	def _captureCommand(self, commandId: CommandId) -> CommandExecutionResult:
		targetKind: Literal["foreground", "focus", "navigator"] = (
			"navigator"
			if commandId
			in {
				CommandId.NAVIGATOR_BOUNDED,
				CommandId.NAVIGATOR_UNLIMITED,
				CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
			}
			else "focus"
			if commandId is CommandId.FOCUS_UNLIMITED
			else "foreground"
		)
		mode: Literal["bounded", "unlimited"] = (
			"unlimited"
			if commandId
			in {
				CommandId.FOREGROUND_UNLIMITED,
				CommandId.FOCUS_UNLIMITED,
				CommandId.NAVIGATOR_UNLIMITED,
				CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
			}
			else "bounded"
		)
		selected = self._selected(
			targetKind,
			mode=mode,
			retargetNavigatorWindow=commandId is CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
			includeRootNameInOutput=commandId
			in {CommandId.FOCUS_UNLIMITED, CommandId.NAVIGATOR_SUBTREE_UNLIMITED},
		)
		self._router.activate(selected.session)
		try:
			if commandId is CommandId.DIFF:
				diff = self._diff.diff(selected.request)
				return CommandExecutionResult(
					"baselineCreated"
					if diff.outcome == "baselineCreated"
					else "noChange"
					if diff.outcome == "noChange"
					else "completed"
					if diff.outcome == "changed"
					else "failed",
					committed=diff.outcome in {"baselineCreated", "changed", "noChange"},
					detail=diff.errorCode,
				)
			limits = TraversalLimits.fromSettings(self._settings, mode)
			self._recordCapture(
				"KS.CAPTURE.STARTED",
				(
					("captureKind", targetKind),
					("boundedMode", mode == "bounded"),
					("configuredNodeLimit", limits.maximumNodes),
					("configuredDepthLimit", limits.maximumDepth),
					("configuredTimeMs", limits.maximumMilliseconds),
				),
			)
			capture = (
				self._capture.captureSubtree
				if commandId is CommandId.FOCUS_UNLIMITED
				else self._capture.capture
			)
			result = capture(selected.request, progress=self._captureProgressReporter(commandId, targetKind))
			self._recordCaptureResult(targetKind, result)
			return self._captureResult(result)
		except RuntimeError as error:
			code = str(error)
			self._recordCapture(
				"KS.CAPTURE.CANCELLED" if code == "KS.CAPTURE.CANCELLED" else "KS.CAPTURE.FAILED",
				(
					("captureKind", targetKind),
					("terminalState", "cancelled"),
					("processedNodes", 0),
					("elapsedMs", 0),
				)
				if code == "KS.CAPTURE.CANCELLED"
				else (
					("captureKind", targetKind),
					("phase", "execution"),
					("reasonCode", code),
					("processedNodes", 0),
					("elapsedMs", 0),
				),
			)
			return CommandExecutionResult(
				"cancelled" if code == "KS.CAPTURE.CANCELLED" else "failed",
				detail=None if code == "KS.CAPTURE.CANCELLED" else code,
			)
		finally:
			self._router.deactivate(selected.session)
			self._closeSession(selected)

	def exportCustomUiaDiagnostics(self) -> CommandExecutionResult:
		"""Publish a discovery capture only after the user asks for diagnostics."""
		selected = self._selected(
			"foreground",
			customUiaCaptureMode=CustomUiaCaptureMode.DIAGNOSTIC_EXPORT,
		)
		self._router.activate(selected.session)
		try:
			return self._captureResult(self._capture.exportCustomUiaDiagnostics(selected.request))
		except RuntimeError as error:
			code = str(error)
			return CommandExecutionResult(
				"cancelled" if code == "KS.CAPTURE.CANCELLED" else "failed",
				detail=None if code == "KS.CAPTURE.CANCELLED" else code,
			)
		finally:
			self._router.deactivate(selected.session)
			self._closeSession(selected)

	@staticmethod
	def _captureResult(result: CaptureResult) -> CommandExecutionResult:
		state = result.lifecycle.state
		outcome = (
			"cancelled"
			if state is CaptureState.CANCELLED
			else "truncated"
			if state is CaptureState.COMPLETED_TRUNCATED
			else "partialScreenshot"
			if state is CaptureState.COMPLETED_PARTIAL_SCREENSHOT
			else "completed"
			if state is CaptureState.COMPLETED
			else "failed"
		)
		return CommandExecutionResult(
			outcome,
			committed=result.committed,
			detail=(
				None
				if state is CaptureState.CANCELLED
				else ProductionCommandRuntime._truncationDetail(result)
				if state is CaptureState.COMPLETED_TRUNCATED
				else result.errorCode
			),
		)

	@staticmethod
	def _truncationDetail(result: CaptureResult) -> str | None:
		limit = next((item for item in result.traversal.limits if item.reached), None)
		return None if limit is None else presentCaptureLimit(limit.limitType, limit.configuredLimit)

	def _captureProgressReporter(
		self,
		commandId: CommandId,
		captureKind: str,
	) -> Callable[[TraversalProgress], None]:
		nextAnnouncementMilliseconds = self._settings.progressIntervalSeconds * 1_000

		def report(progress: TraversalProgress) -> None:
			nonlocal nextAnnouncementMilliseconds
			if progress.elapsedMilliseconds < nextAnnouncementMilliseconds:
				return
			nextAnnouncementMilliseconds = (
				progress.elapsedMilliseconds + self._settings.progressIntervalSeconds * 1_000
			)
			self._recordCapture(
				"KS.CAPTURE.PROGRESS",
				(
					("captureKind", captureKind),
					("processedNodes", progress.processedNodes),
					("elapsedMs", progress.elapsedMilliseconds),
					("pendingWorkCount", progress.pendingWorkCount),
					("phase", progress.phase),
				),
			)
			announce = self._announceCaptureProgress
			if announce is not None:
				try:
					announce(
						presentCaptureProgress(
							progress.processedNodes,
							progress.pendingWorkCount,
							progress.elapsedMilliseconds,
							progress.phase,
						),
					)
				except Exception:
					self._logUnexpected("Keystone capture progress announcement failed")
			emitSound = self._emitCaptureProgressSound
			if emitSound is not None:
				emitSound(commandId)

		return report

	def _recordCaptureResult(self, captureKind: str, result: CaptureResult) -> None:
		nodeCount = len(result.traversal.nodes)
		elapsed = next(
			(item.observedCount for item in result.traversal.limits if item.limitType == "timeMilliseconds"),
			0,
		)
		if result.lifecycle.state is CaptureState.CANCELLED:
			self._recordCapture(
				"KS.CAPTURE.CANCELLED",
				(
					("captureKind", captureKind),
					("terminalState", result.lifecycle.state.value),
					("processedNodes", nodeCount),
					("elapsedMs", elapsed),
				),
			)
			return
		if result.lifecycle.state is CaptureState.COMPLETED_TRUNCATED:
			limit = next((item for item in result.traversal.limits if item.reached), None)
			if limit is None:
				return
			self._recordCapture(
				"KS.CAPTURE.COMPLETED_TRUNCATED",
				(
					("captureKind", captureKind),
					("nodeCount", nodeCount),
					("limitType", limit.limitType),
					("configuredLimit", limit.configuredLimit),
					("actualCount", limit.observedCount),
					("elapsedMs", elapsed),
				),
			)
			return
		if result.lifecycle.state is CaptureState.COMPLETED_PARTIAL_SCREENSHOT:
			self._recordCapture(
				"KS.CAPTURE.COMPLETED_PARTIAL_SCREENSHOT",
				(
					("nodeCount", nodeCount),
					(
						"screenshotCode",
						result.screenshot.errorCode or "unavailable" if result.screenshot else "unavailable",
					),
					("captureKind", captureKind),
					("elapsedMs", elapsed),
				),
			)
			return
		if result.lifecycle.state is CaptureState.COMPLETED:
			self._recordCapture(
				"KS.CAPTURE.COMPLETED",
				(
					("captureKind", captureKind),
					("nodeCount", nodeCount),
					("publicationStatus", "committed" if result.committed else "failed"),
					("elapsedMs", elapsed),
					("cycleCount", sum(node.cycleDetected for node in result.traversal.nodes)),
				),
			)

	def _recordCapture(self, code: str, fields: tuple[tuple[str, LogScalar], ...]) -> None:
		record = self._runtimeLog
		if record is not None:
			record(code, fields)

	def _inspectTarget(
		self,
		targetKind: InspectorTargetKind,
		rawRequested: bool,
	) -> InspectorTargetEvidence:
		raw = (
			ProjectionRequest.explicit(
				f"inspector-{uuid4()}",
				ProjectionBudget(150, 600, 2_000),
			)
			if rawRequested
			else None
		)
		selection = self._inspectorSelection(targetKind)
		selected = self._selectedObjects(
			targetKind,
			selection.target,
			selection.foreground,
			rawRequest=raw,
		)
		try:
			projection = selected.reference.projection
			return InspectorTargetEvidence(
				targetKind,
				selected.request.executable,
				selected.request.processId,
				_integer(selection.target, "windowHandle"),
				selected.reference.backend,
				rawRequested,
				bool(projection is not None and projection.applied),
				None if projection is None else projection.reasonCode,
			)
		finally:
			self._closeSession(selected)

	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		if commandId in {
			CommandId.FOREGROUND_BOUNDED,
			CommandId.FOREGROUND_UNLIMITED,
			CommandId.FOCUS_UNLIMITED,
			CommandId.DIFF,
			CommandId.NAVIGATOR_BOUNDED,
			CommandId.NAVIGATOR_UNLIMITED,
			CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
		}:
			return self._captureCommand(commandId)
		if commandId is CommandId.INSPECT_FOCUS:
			opened = self._openLiveInspector("focus")
			return CommandExecutionResult("completed" if opened else "failed", announcementHandled=not opened)
		if commandId is CommandId.INSPECT_NAVIGATOR:
			opened = self._openLiveInspector("navigator")
			return CommandExecutionResult("completed" if opened else "failed", announcementHandled=not opened)
		if commandId is CommandId.EVENT_MONITOR:
			_ = self._prepareFocusSelectionForEventMonitor()
			self._openEventMonitor()
			# Events announces its current monitoring state when the workspace opens.
			return CommandExecutionResult("completed", announcementHandled=True)
		if commandId is CommandId.EVENT_MONITOR_TOGGLE:
			active = self._eventMonitorActive is not None and self._eventMonitorActive()
			if not active:
				_ = self._prepareFocusSelectionForEventMonitor()
			if self._toggleEventMonitor is not None:
				active = self._toggleEventMonitor()
				# The monitor lifecycle owns the detailed transition announcement.
				return CommandExecutionResult(
					"eventMonitorStarted" if active else "eventMonitorStopped",
					announcementHandled=True,
				)
			self._openEventMonitor()
			# Opening Events announces its current state when no toggle result is available.
			return CommandExecutionResult("completed", announcementHandled=True)
		if commandId is CommandId.CUSTOM_UIA_PROPERTIES:
			self._openCustomUia(None, None)
			return CommandExecutionResult("completed")
		return CommandExecutionResult("failed")

	def requestCancellation(self, commandId: CommandId) -> None:
		if commandId in CAPTURE_COMMANDS:
			self._capture.requestCancellation()

	def _actNewest(self, commandId: CommandId, operation: Literal["copy", "reveal"]) -> bool:
		captureKind = COMMAND_BY_ID[commandId].captureKind
		if captureKind not in {"snapshot", "navigatorSnapshot", "diff"}:
			return False
		admission = self._lifecycle.admit(f"output.{operation}.{commandId.value}")
		if not admission.accepted or admission.context is None:
			return False
		return self._output.actOnNewest(
			cast(CaptureKind, captureKind),
			operation,
			lifecycleGeneration=admission.generation,
			context=admission.context,
		)

	def copyNewest(self, commandId: CommandId) -> bool:
		return self._actNewest(commandId, "copy")

	def revealNewest(self, commandId: CommandId) -> bool:
		return self._actNewest(commandId, "reveal")

	def openInspectorForReview(self, targetKind: InspectorTargetKind = "focus") -> None:
		_ = self._openLiveInspector(targetKind)

	def runRawInspectorRetargetDiagnostic(self) -> dict[str, object]:
		"""Exercise the production Inspector raw-retarget path without showing or moving its window."""

		outcome = self._retargetInspector("focus", True)
		return {
			"succeeded": outcome.succeeded,
			"requested": outcome.rawRequested,
			"applied": outcome.rawApplied,
			"sourceGeneration": self._inspectorService.sourceGeneration,
		}

	def close(self) -> None:
		self._followFocusGeneration += 1
		self._pendingFollowSelection = None
		self._eventSourceObjects.clear()
		self._inspector.close()
