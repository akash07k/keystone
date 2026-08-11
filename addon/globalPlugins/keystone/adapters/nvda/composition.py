# pyright: reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUninitializedInstanceVariable=false, reportUnusedCallResult=false

from __future__ import annotations

import builtins
from collections.abc import Callable, MutableSequence
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Protocol, cast, override

from ...application.lifecycle import LifecycleService
from ...application.logging_service import (
	LogCandidate,
	LogContext,
	LogFieldCandidate,
	LoggingService,
)
from ...application.output_service import OutputService
from ...application.event_monitor_service import EventMonitorService
from ...application.settings_service import SettingsService
from ...application.sound_service import SoundRuntimeLog, SoundService, WorkflowSounds
from ...application.custom_uia_service import CustomUiaService
from ...capability import (
	CapabilitySnapshot as PanelCapabilitySnapshot,
	CapabilityState,
	defaultCapabilitySnapshot,
)
from ...domain.capability_status import (
	CAPABILITY_REGISTRY,
	CapabilityRow,
	CapabilitySnapshot,
	CapabilityStatus,
)
from ...encoding.log_formats import LogScalar, LogicalRecord, SequenceAllocator
from ...domain.correlation import CorrelationContext
from ...domain.event_monitor import EventFilter, MonitorScope, RawUiaFamily
from ...domain.privacy import FieldGroup, PrivacyClass, PrivacyPolicy, ProtectionEvidence
from ...domain.settings import SETTING_DEFINITIONS, SettingsSnapshot, validateCandidate
from ...domain.sounds import CueAtomId, SOUND_ASSETS, SoundScheduler
from ...ports.effects import (
	CaptureManagementPort,
	ClipboardRequest,
	EffectResult,
	FeedbackRequest,
	PortError,
	PortOutcome,
	PortStatus,
	SettingsPort,
	SettingsWriteRequest,
	ScreenshotPort,
	ShellRequest,
)
from ...ports.event_sources import EventSource
from ..windows.capability_registry import CapabilityStatusLoader, RuntimeCapabilityChecks
from ..windows.path_ops import fixedOutputRoot, snapshotOutputRoot
from ..windows.publication import LocalPublicationBackend, PublicationManager
from ..windows.raw_uia_events import RawUiaEventSource, RawUiaNotification
from ..windows.screenshot import ScreenshotAdapter, WxModule, WxScreenshotBackend
from ..export_names import defaultExportFilename
from ..wx.inspector_frame import EventsWorkspace
from ..wx.settings_panel import (
	KeystoneSettingsPanel,
	NativeControlDefinition,
	PREVIEW_CUE_ORDER,
	PreviewPort,
	SettingsAppliedPort,
	SettingsPanelController,
	ValidationDialogPresentation,
	clearCapturesConfirmation,
	panelMessages,
)
from ..wx.custom_uia_dialog import CustomUiaDialogController, showCustomUiaDialog
from .audio import NvdaWaveAudioPort, SoundThemeManifest
from .app_module_overrides import NvdaAppModuleOverrides
from .nvda_log import NvdaLogAdapter
from .commands import NvdaCommandHost, NvdaCommandLayer, ProductionCommandRuntime
from .custom_uia_registry import buildNvdaCustomUiaRegistry
from .event_monitor_session import EventMonitorSession
from .event_sources import NvdaEventSource
from .settings import (
	NvdaSettingsAdapter,
	RedactionMigrationOutcome,
	SettingsLoadResult,
	initializeKeystoneBaseSection,
	initializeLegacyKeystoneBaseSection,
)


class PanelRegistry(Protocol):
	def add(
		self,
		panelClass: type[object],
		controllerFactory: Callable[[], SettingsPanelController],
	) -> None: ...

	def remove(self, panelClass: type[object]) -> None: ...


class StatusLoader(Protocol):
	def load(self) -> CapabilitySnapshot: ...


class SettingsAdapter(Protocol):
	def readSnapshot(self) -> SettingsLoadResult: ...

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult: ...


@dataclass(frozen=True, slots=True)
class _Release:
	name: str
	callback: Callable[[], None]


_FOLLOW_FOCUS_ANNOUNCEMENT_DELAY_MS = 700


class _PoliteFollowFocusAnnouncer:
	"""Delay application changes behind focus speech and discard superseded messages."""

	def __init__(self, host: NvdaCommandHost) -> None:
		super().__init__()
		self._host = host
		self._generation = 0
		self._pending: object | None = None

	def announce(self, message: str) -> None:
		self._generation += 1
		generation = self._generation
		if self._pending is not None:
			self._host.cancelCall(self._pending)

		def deliver() -> None:
			if generation != self._generation:
				return
			self._pending = None
			self._host.announce(message, priority="normal")

		self._pending = self._host.callLater(_FOLLOW_FOCUS_ANNOUNCEMENT_DELAY_MS, deliver)

	def cancel(self) -> None:
		self._generation += 1
		if self._pending is not None:
			self._host.cancelCall(self._pending)
			self._pending = None


class CompositionRoot:
	def __init__(
		self,
		*,
		lifecycle: LifecycleService,
		panelRegistry: PanelRegistry,
		settingsService: SettingsService,
		capabilities: PanelCapabilitySnapshot,
		captureManagement: CaptureManagementPort,
		onPanelClose: Callable[[], None] | None = None,
		preview: PreviewPort | None = None,
		settingsApplied: SettingsAppliedPort | None = None,
	) -> None:
		super().__init__()
		self._lifecycle = lifecycle
		self._panelRegistry = panelRegistry
		self._settingsService = settingsService
		self._capabilities = capabilities
		self._captureManagement = captureManagement
		self._onPanelClose = onPanelClose
		self._preview = preview
		self._settingsApplied = settingsApplied
		self._panelController: SettingsPanelController | None = None
		self._started = False
		self._panelClosed = False

	@property
	def lifecycle(self) -> LifecycleService:
		return self._lifecycle

	@property
	def captureManagement(self) -> CaptureManagementPort:
		return self._captureManagement

	@property
	def capabilities(self) -> PanelCapabilitySnapshot:
		return self._capabilities

	def start(self, settings: SettingsSnapshot) -> None:
		if self._started:
			raise RuntimeError("Keystone composition has already started")
		self._started = True
		panelAdmission = self._lifecycle.admit("settings-panel")
		panelContext = panelAdmission.context
		if not panelAdmission.accepted or panelContext is None:
			raise RuntimeError("settings panel correlation admission was rejected")

		def controllerFactory() -> SettingsPanelController:
			if self._panelController is None:
				self._panelController = SettingsPanelController(
					snapshot=settings,
					settingsService=self._settingsService,
					capabilities=self._capabilities,
					captureManagement=self._captureManagement,
					lifecycleGeneration=panelAdmission.generation,
					context=panelContext,
					preview=self._preview,
					settingsApplied=self._settingsApplied,
				)
			return self._panelController

		def closePanel() -> None:
			if self._panelClosed:
				return
			self._panelClosed = True
			try:
				if self._panelController is not None:
					self._panelController.close()
				if self._onPanelClose is not None:
					self._onPanelClose()
			finally:
				self._panelRegistry.remove(KeystoneSettingsPanel)

		try:
			self._panelRegistry.add(KeystoneSettingsPanel, controllerFactory)
			self._lifecycle.registerUi("settings-panel", closePanel)
		except Exception:
			closePanel()
			self._lifecycle.transition("terminating")
			raise

	def transition(self, state: str) -> None:
		self._lifecycle.transition(state)

	def close(self) -> None:
		self._lifecycle.transition("terminating")


def _announceViaUi(message: str) -> None:
	"""Speak one Events-workspace status line through NVDA; silent off-host or on failure."""

	try:
		import_module("ui").message(message)
	except Exception:
		pass


def _pickEventExportDestination(application: str | None = None) -> Path | None:
	"""Prompt for an Events export path via the host save dialog; ``None`` when cancelled or off-host."""

	try:
		wx = import_module("wx")
	except ImportError:
		return None
	gui = import_module("gui")
	parent = getattr(gui, "mainFrame", None)
	# Translators: Title of the save dialog for exporting captured events to a JSON file.
	title = "Export captured events"
	# Translators: File-type filter in the events export save dialog.
	wildcard = "JSON files (*.json)|*.json|All files (*.*)|*.*"
	dialog = wx.FileDialog(
		parent,
		message=title,
		defaultFile=defaultExportFilename(application, "events", ".json"),
		wildcard=wildcard,
		style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
	)
	try:
		if dialog.ShowModal() != wx.ID_OK:
			return None
		path = dialog.GetPath()
	finally:
		dialog.Destroy()
	return Path(path) if path else None


class _ObservationClipboard:
	"""Clipboard port used during installed observation; copy/export are not exercised."""

	def copyText(self, request: ClipboardRequest) -> EffectResult:
		_ = request
		return EffectResult(PortStatus("ready", 0), PortOutcome("copied"))


class _ObservationFeedback:
	"""Feedback port used during installed observation; announcements are suppressed."""

	def announce(self, request: FeedbackRequest) -> EffectResult:
		_ = request
		return EffectResult(PortStatus("ready", 0), PortOutcome("announced"))


class _WxMainThreadMarshal:
	"""Deliver audio completions on the host UI thread; wx is imported only when a sound plays."""

	def __init__(self) -> None:
		super().__init__()
		self._timers: set[Any] = set()

	def callLater(self, delayMilliseconds: int, action: Callable[[], None]) -> None:
		wx = import_module("wx")
		if delayMilliseconds <= 0:
			wx.CallAfter(action)
			return
		self._retainTimer(wx, delayMilliseconds, action)

	def _retainTimer(self, wx: Any, delayMilliseconds: int, action: Callable[[], None]) -> None:
		holder: list[Any] = []

		def invoke() -> None:
			self._timers.discard(holder[0])
			action()

		timer = wx.CallLater(delayMilliseconds, invoke)
		holder.append(timer)
		self._timers.add(timer)

	def close(self) -> None:
		timers = tuple(self._timers)
		self._timers.clear()
		for timer in timers:
			try:
				stop = getattr(timer, "Stop")
				if callable(stop):
					stop()
			except Exception:
				pass


class _WxSoundHost:
	"""Monotonic clock and deferral seam for the sound scheduler on the installed host."""

	def __init__(self) -> None:
		super().__init__()
		self._timers: set[Any] = set()

	def nowMilliseconds(self) -> int:
		return int(time.monotonic() * 1000)

	def callLater(self, delayMilliseconds: int, action: Callable[[], None]) -> None:
		wx = import_module("wx")
		holder: list[Any] = []

		def invoke() -> None:
			self._timers.discard(holder[0])
			action()

		timer = wx.CallLater(max(0, delayMilliseconds), invoke)
		holder.append(timer)
		self._timers.add(timer)

	def close(self) -> None:
		timers = tuple(self._timers)
		self._timers.clear()
		for timer in timers:
			try:
				stop = getattr(timer, "Stop")
				if callable(stop):
					stop()
			except Exception:
				pass


class _ManagedSoundService(SoundService):
	"""Close delayed host callbacks together with the sound service that owns them."""

	def __init__(
		self,
		*,
		feedback: _NvdaFeedbackAdapter,
		audio: NvdaWaveAudioPort,
		scheduler: SoundScheduler,
		host: _WxSoundHost,
		enabled: bool,
		runtimeLog: SoundRuntimeLog | None,
		timerOwners: tuple[_WxMainThreadMarshal | _WxSoundHost, ...],
	) -> None:
		super().__init__(
			feedback=feedback,
			audio=audio,
			scheduler=scheduler,
			host=host,
			enabled=enabled,
			runtimeLog=runtimeLog,
		)
		self._timerOwners = timerOwners

	@override
	def close(self) -> None:
		try:
			super().close()
		finally:
			for owner in self._timerOwners:
				owner.close()


def _buildSoundService(
	settings: SettingsSnapshot,
	runtimeLog: _RuntimeLog | None = None,
) -> SoundService | None:
	"""Assemble the live sound service over the closed theme, or ``None`` when unavailable.

	Construction touches no host runtime: the manifest only resolves bundled paths and the wave
	port imports its output seam lazily on first playback, so this is safe off-host and during
	headless observation. Any unexpected assembly failure degrades to silent, speech-only operation.
	"""

	try:
		root = Path(__file__).resolve().parents[2] / "sounds" / "rich"
		manifest = SoundThemeManifest(root=root, paths=dict(SOUND_ASSETS))
		marshal = _WxMainThreadMarshal()
		host = _WxSoundHost()
		audio = NvdaWaveAudioPort(
			manifest=manifest,
			marshal=marshal,
			failureReporter=lambda atom, reason: _recordSoundFailure(runtimeLog, atom, reason),
		)
		return _ManagedSoundService(
			feedback=_NvdaFeedbackAdapter(),
			audio=audio,
			scheduler=SoundScheduler(),
			host=host,
			enabled=bool(settings.soundsEnabled),
			runtimeLog=None if runtimeLog is None else runtimeLog.record,
			timerOwners=(marshal, host),
		)
	except (AttributeError, ImportError, OSError, ValueError):
		_recordSoundFailure(runtimeLog, CueAtomId.SHARED_WARNING, "serviceAssemblyFailed")
		return None


def _recordSoundFailure(
	runtimeLog: _RuntimeLog | None,
	atom: CueAtomId,
	reasonCode: str,
) -> None:
	if runtimeLog is None:
		return
	runtimeLog.record(
		"KS.SOUND.PLAY_FAILED",
		(
			("transitionId", atom.value),
			("reasonCode", reasonCode),
			("assetId", atom.value),
		),
	)


class ProductionComposition:
	def __init__(
		self,
		*,
		root: CompositionRoot,
		settings: SettingsSnapshot,
		operationalEligible: bool,
		startupIssueCode: str | None,
		releaseCallbacks: tuple[tuple[str, Callable[[], None]], ...] = (),
		customUiaService: CustomUiaService | None = None,
		appModuleOverrides: NvdaAppModuleOverrides | None = None,
		workflowSound: WorkflowSounds | None = None,
		runtimeLog: _RuntimeLog | None = None,
	) -> None:
		super().__init__()
		self._root = root
		self._settings = settings
		self._operationalEligible = operationalEligible
		self._startupIssueCode = startupIssueCode
		self._customUiaService = customUiaService
		self._appModuleOverrides = appModuleOverrides
		self._workflowSound = workflowSound
		self._runtimeLog = runtimeLog
		self._releases = tuple(_Release(name, callback) for name, callback in releaseCallbacks)
		self._started = False
		self._closed = False
		self._released = False
		self._commandLayer: NvdaCommandLayer | None = None
		self._commandRuntime: ProductionCommandRuntime | None = None
		self._eventSource: NvdaEventSource | None = None
		self._eventMonitorSession: EventMonitorSession | None = None
		self._followFocusAnnouncer: _PoliteFollowFocusAnnouncer | None = None
		# The policy revision starts from the settings it was built for, so it only ever moves
		# forward as changes are committed.
		self._policyRevision = settings.settingsRevision

	@property
	def started(self) -> bool:
		return self._started

	@property
	def closed(self) -> bool:
		return self._closed

	@property
	def operationalEligible(self) -> bool:
		return self._operationalEligible and self._started and not self._closed

	@property
	def startupIssueCode(self) -> str | None:
		return self._startupIssueCode

	def start(self) -> None:
		if self._started:
			raise RuntimeError("Keystone production composition has already started")
		if self._closed:
			raise RuntimeError("Keystone production composition has already closed")
		self._root.start(self._settings)
		if self._customUiaService is not None:
			_ = self._customUiaService.registerAtStartup()
		if self._appModuleOverrides is not None:
			_ = self._appModuleOverrides.activateStored()
		self._started = True
		if self._commandRuntime is not None:
			# Events is a page of the same window as Inspector, so it is built with the window rather
			# than on first use: Ctrl+E must reach a workspace that already exists. Building it starts
			# no monitoring and subscribes no source.
			with contextlib.suppress(Exception):
				_ = self._ensureEventMonitorSession()

	def configureCommands(
		self,
		layer: NvdaCommandLayer,
		runtime: ProductionCommandRuntime,
	) -> None:
		if self._started or self._closed or self._commandLayer is not None:
			raise RuntimeError("Keystone command surface must be configured exactly once before startup")
		self._commandLayer = layer
		self._commandRuntime = runtime

	def configureDefaultCommands(self) -> None:
		output = self._root.captureManagement
		if not isinstance(output, OutputService):
			return
		screenshot = output.screenshotPort
		if screenshot is None:
			return

		def openCustomUia(parent: object, currentExecutable: str | None = None) -> None:
			_ = self.openCustomUiaProperties(
				parent=parent,
				currentExecutable=currentExecutable,
			)

		host = NvdaCommandHost()
		followFocusAnnouncer = _PoliteFollowFocusAnnouncer(host)
		self._followFocusAnnouncer = followFocusAnnouncer
		runtime = ProductionCommandRuntime(
			self._root.lifecycle,
			self._settings,
			output,
			screenshot,
			openCustomUia=openCustomUia,
			openEventMonitor=self.openEventMonitor,
			toggleEventMonitor=self.toggleEventMonitor,
			eventMonitorActive=self.eventMonitorActive,
			announceInspector=lambda message: host.announce(message, priority="now"),
			announceFollowFocus=followFocusAnnouncer.announce,
			appModuleOverrides=self._appModuleOverrides,
			sound=self._workflowSound,
			announceCaptureProgress=lambda message: host.announce(message, priority="normal"),
			runtimeLog=None if self._runtimeLog is None else self._runtimeLog.record,
		)
		layer = NvdaCommandLayer(runtime, self._root.lifecycle, host, sound=self._workflowSound)
		setProgressSoundEmitter = getattr(runtime, "setCaptureProgressSoundEmitter", None)
		if callable(setProgressSoundEmitter):
			setProgressSoundEmitter(layer.emitCaptureProgressSound)
		self.configureCommands(layer, runtime)

	def enterCommandLayer(self) -> None:
		if self._closed or not self._started or self._commandLayer is None:
			raise RuntimeError("Keystone command layer is not active")
		self._commandLayer.enter()

	def useEventSource(self, source: NvdaEventSource) -> None:
		"""Adopt the global plugin's own ``NvdaEventSource`` before startup.

		The plugin's forwarders feed this exact source, so the production monitor must subscribe it -
		never a disconnected duplicate. Configuration is refused once the composition has closed.
		"""

		if self._closed:
			raise RuntimeError("Keystone composition is closed")
		self._eventSource = source

	def openEventMonitor(self) -> None:
		"""Open (or re-activate) the stopped singleton Events workspace.

		Builds the one production monitoring session on first use, wiring the plugin's own NVDA event
		source and a raw-UIA bridge into a single ``EventMonitorService`` rendered by a single
		``EventsWorkspace``. Monitoring begins only through its explicit Start action. Refused outside
		an active composition.
		"""

		if self._closed or not self._started:
			raise RuntimeError("Keystone Event Monitor is not active")
		session = self._ensureEventMonitorSession()
		session.open()

	def eventMonitorActive(self) -> bool:
		"""Whether the singleton monitoring session is currently subscribed."""

		session = self._eventMonitorSession
		return session is not None and session.service.active

	def toggleEventMonitor(self) -> bool:
		"""Stop an active monitor or start one from the current Inspector selection."""

		if self._closed or not self._started:
			raise RuntimeError("Keystone Event Monitor is not active")
		return self._ensureEventMonitorSession().toggle()

	def forwardRawUiaEvent(
		self,
		family: RawUiaFamily,
		obj: object,
		*,
		notification: RawUiaNotification | None = None,
		activeTextRange: object | None = None,
	) -> bool:
		"""Bridge one forwarded NVDA ``event_UIA_*`` object into the live raw source, if monitoring.

		A no-op returning ``False`` when no monitoring session exists yet, so the plugin's thin UIA
		forwarders can call unconditionally without gating on monitor state.
		"""

		session = self._eventMonitorSession
		if session is None:
			return False
		return session.forwardRaw(
			family,
			obj,
			notification=notification,
			activeTextRange=activeTextRange,
		)

	def _ensureEventMonitorSession(self) -> EventMonitorSession:
		session = self._eventMonitorSession
		if session is not None:
			return session
		source = self._eventSource or NvdaEventSource()
		service = self._buildLiveEventMonitorService()
		runtime = self._commandRuntime
		workspace = EventsWorkspace(
			service,
			announce=_announceViaUi,
			sound=self._workflowSound,
			window=None if runtime is None else runtime.window,
		)
		rawSource = RawUiaEventSource(clientFactory=None)
		if runtime is None:
			session = EventMonitorSession(
				service=service,
				workspace=workspace,
				nvdaSource=source,
				rawSource=rawSource,
			)
		else:
			source.configureSourceNavigation(runtime.retainEventSource)
			rawSource.configureSourceNavigation(runtime.retainEventSource)
			session = EventMonitorSession(
				service=service,
				workspace=workspace,
				nvdaSource=source,
				rawSource=rawSource,
				selectionResolver=runtime.currentInspectorSelection,
				showSource=runtime.showEventSource,
			)
		self._eventMonitorSession = session
		return session

	@property
	def eventMonitorSession(self) -> EventMonitorSession | None:
		"""The single production monitoring session, once opened; ``None`` before first open."""

		return self._eventMonitorSession

	def _buildLiveEventMonitorService(self) -> EventMonitorService:
		return EventMonitorService(
			lifecycle=self._root.lifecycle,
			settings=lambda: self._settings,
			policy=self._privacyPolicy,
			clipboard=_NvdaClipboardAdapter(),
			feedback=_NvdaFeedbackAdapter(),
			monotonic=lambda: time.monotonic() * 1000.0,
			wallClock=lambda: int(time.time() * 1000),
			destinationPicker=lambda: _pickEventExportDestination(self._eventMonitorExportApplication()),
			sound=self._workflowSound,
			runtimeLog=None if self._runtimeLog is None else self._runtimeLog.record,
		)

	def _eventMonitorExportApplication(self) -> str | None:
		session = self._eventMonitorSession
		scope = None if session is None else session.service.scope
		if scope is None or scope.broad:
			return None
		return scope.application

	@property
	def privacyPolicy(self) -> PrivacyPolicy:
		"""The privacy policy every surface records against right now.

		Derived rather than stored, so a committed change reaches the next row read, the next
		capture, the next diff, and the next log boundary without any of them holding a stale copy.
		"""

		return self._privacyPolicy()

	def _privacyPolicy(self) -> PrivacyPolicy:
		return PrivacyPolicy(
			policyRevision=self._policyRevision,
			settingsRevision=self._settings.settingsRevision,
			redactProtectedText=self._settings.redactProtectedText,
		)

	def applySettings(self, settings: SettingsSnapshot) -> None:
		"""Adopt a committed settings change for work that starts after it.

		Rows already retained keep the policy they were captured under, which is what makes their
		recorded provenance true. Everything read from settings afterwards -- the retained-row cap,
		the detail character limit, redaction, and the session-risk warnings a new session speaks --
		follows the new snapshot.
		"""

		if self._closed:
			return
		if settings.settingsRevision == self._settings.settingsRevision:
			return
		self._settings = settings
		self._policyRevision = max(self._policyRevision + 1, settings.settingsRevision)
		runtime = self._commandRuntime
		policy = self._privacyPolicy()
		if self._runtimeLog is not None:
			self._runtimeLog.reconfigure(settings, policy)
		if runtime is not None:
			runtime.applySettings(settings, policy)

	def _closeEventMonitorSession(self) -> None:
		session = self._eventMonitorSession
		self._eventMonitorSession = None
		if session is not None:
			try:
				session.dispose()
			except Exception:
				pass

	def observeFocus(self, target: object) -> None:
		"""Offer one NVDA focus object to the active Inspector without blocking the event handler."""

		if self._closed or not self._started or self._commandRuntime is None:
			return
		self._commandRuntime.observeFocus(target)

	def openInspectorForReview(self) -> None:
		if self._closed or not self._started or self._commandRuntime is None:
			raise RuntimeError("Keystone Inspector invocation is not active")
		self._commandRuntime.openInspectorForReview()

	def runInstalledReview(self, outputPath: Path) -> dict[str, object]:
		if self._closed or not self._started:
			raise RuntimeError("Keystone installed review requires an active composition")
		from .review_hook import runPackagedReview

		return runPackagedReview(outputPath, openInspector=self.openInspectorForReview)

	def runAutomatedRuntimeReview(self, outputPath: Path) -> dict[str, object]:
		if self._closed or not self._started:
			raise RuntimeError("Keystone automated runtime review requires an active composition")
		from .review_hook import runAutomatedRuntimeReview

		return runAutomatedRuntimeReview(
			outputPath,
			enabledCapabilities=self.enabledCapabilityIds(),
			inspectorRawRetarget=self._commandRuntime.runRawInspectorRetargetDiagnostic()
			if self._commandRuntime is not None
			else {},
		)

	def enabledCapabilityIds(self) -> frozenset[str]:
		"""Product capability IDs whose current runtime prerequisites are available."""

		return frozenset(
			record.capabilityId for record in self._root.capabilities.records if record.status == "enabled"
		)

	def runInstalledEventSourceObservation(
		self,
		*,
		scope: MonitorScope,
		sources: tuple[EventSource, ...],
		stimulus: Callable[[EventMonitorService], dict[str, object]],
		activeFilter: EventFilter | None = None,
	) -> dict[str, object]:
		"""Start the shipped event monitor through production composition and observe ``stimulus``.

		The monitor only runs when the current runtime provides both event monitoring and raw UIA
		inspection; otherwise the observation is reported unavailable without starting any source.
		``stimulus`` drives the started service and returns the observation fields to merge into the
		result.
		"""

		if self._closed or not self._started:
			raise RuntimeError("Keystone installed event source observation requires an active composition")
		enabled = self.enabledCapabilityIds()
		identities = tuple(
			{
				"module": type(source).__module__,
				"type": type(source).__qualname__,
				"backend": source.backend.value,
			}
			for source in sources
		)
		if not {"eventMonitoring", "rawUiaInspection"}.issubset(enabled):
			return {
				"status": "unavailable",
				"enabledCapabilities": sorted(enabled),
				"productionCompositionStarted": self._started,
				"monitorStarted": False,
				"monitorStopped": False,
				"sourceIdentities": identities,
			}
		service = self._buildEventMonitorService()
		service.start(scope, sources, activeFilter=activeFilter)
		observation = stimulus(service)
		service.stop()
		result: dict[str, object] = {
			"status": "observed",
			"enabledCapabilities": sorted(enabled),
			"productionCompositionStarted": self._started,
			"monitorStarted": True,
			"monitorStopped": not service.active,
			"sourceIdentities": identities,
		}
		result.update(observation)
		return result

	def _buildEventMonitorService(self) -> EventMonitorService:
		settings = self._settings
		policy = PrivacyPolicy(
			policyRevision=1,
			settingsRevision=settings.settingsRevision,
			redactProtectedText=settings.redactProtectedText,
		)
		return EventMonitorService(
			lifecycle=self._root.lifecycle,
			settings=lambda: self._settings,
			policy=lambda: policy,
			clipboard=_ObservationClipboard(),
			feedback=_ObservationFeedback(),
			monotonic=lambda: time.monotonic() * 1000.0,
			wallClock=lambda: int(time.time() * 1000),
			sound=self._workflowSound,
		)

	def openCustomUiaProperties(
		self,
		*,
		parent: object = None,
		currentExecutable: str | None = None,
	) -> CustomUiaDialogController:
		if self._closed or not self._started:
			raise RuntimeError("Keystone production composition is not active")
		if self._customUiaService is None:
			raise RuntimeError("Custom UIA configuration is unavailable outside the NVDA host")
		executable = currentExecutable or self._currentExecutable()
		controller = CustomUiaDialogController(
			self._customUiaService,
			currentExecutable=executable,
			exportCustomUiaDiagnostics=self.exportCustomUiaDiagnostics,
		)
		showCustomUiaDialog(parent, controller)
		return controller

	def exportCustomUiaDiagnostics(self) -> bool:
		"""Run the separate discovery capture; ordinary Inspector and capture paths never call it."""
		if self._closed or not self._started or self._commandRuntime is None:
			return False
		return self._commandRuntime.exportCustomUiaDiagnostics().committed

	@staticmethod
	def _currentExecutable() -> str:
		try:
			api = import_module("api")
			focus = api.getFocusObject()
			appName = str(focus.appModule.appName)
		except (AttributeError, ImportError):
			return "unknown.exe"
		return appName if appName.lower().endswith(".exe") else f"{appName}.exe"

	def _releaseOwned(self) -> None:
		if self._released:
			return
		self._released = True
		for release in reversed(self._releases):
			try:
				release.callback()
			except Exception:
				continue

	def _invalidateSound(self) -> None:
		# Discard any pending or in-flight cue synchronously at a lifecycle boundary so a stale
		# generation can never sound after the owning surface is gone. Speech is untouched.
		if self._workflowSound is not None:
			try:
				self._workflowSound.invalidate()
			except Exception:
				pass

	def _cancelFollowFocusAnnouncement(self) -> None:
		if self._followFocusAnnouncer is not None:
			self._followFocusAnnouncer.cancel()

	def _closeSound(self) -> None:
		if isinstance(self._workflowSound, SoundService):
			self._workflowSound.close()
		else:
			self._invalidateSound()

	def _teardownCommandSurface(self) -> None:
		if self._commandLayer is not None:
			try:
				self._commandLayer.invalidate()
			except Exception:
				pass
		if self._commandRuntime is not None:
			try:
				self._commandRuntime.close()
			except Exception:
				pass

	def _teardownTerminalResources(self) -> None:
		try:
			self._cancelFollowFocusAnnouncement()
		except Exception:
			pass
		try:
			self._closeSound()
		except Exception:
			pass
		self._closeEventMonitorSession()
		self._teardownCommandSurface()

	def transition(self, state: str) -> None:
		if self._closed:
			return
		try:
			self._root.transition(state)
		finally:
			if state in ("secure", "indeterminate", "terminating"):
				try:
					self._teardownTerminalResources()
				finally:
					self._operationalEligible = False
					self._releaseOwned()
					if state == "terminating":
						self._closed = True

	def close(self) -> None:
		if self._closed:
			return
		self._closed = True
		self._operationalEligible = False
		try:
			self._teardownTerminalResources()
			self._root.close()
		finally:
			self._releaseOwned()


@dataclass(frozen=True, slots=True)
class _ProjectedCapabilitySnapshot:
	records: tuple[CapabilityState, ...]


def _projectCapabilities(
	snapshot: CapabilitySnapshot,
) -> PanelCapabilitySnapshot:
	records: list[CapabilityState] = []
	for row in snapshot.rows:
		records.append(
			CapabilityState(
				capabilityId=row.capabilityId,
				status=row.status.value,
				gateId=row.capabilityId,
				reasonCode=row.reason,
				fallbackCode="capabilityDisabled",
			),
		)
	return _ProjectedCapabilitySnapshot(tuple(records))


def _settingsOperational(snapshot: CapabilitySnapshot) -> bool:
	return any(
		row.capabilityId == "userInterface" and row.status is CapabilityStatus.ENABLED
		for row in snapshot.rows
	)


def _unavailableCapabilityStatus(
	reason: str = "Runtime availability check failed.",
) -> CapabilitySnapshot:
	rows = tuple(
		CapabilityRow(
			capabilityId=definition.capabilityId,
			status=CapabilityStatus.UNAVAILABLE,
			reason=reason,
		)
		for definition in CAPABILITY_REGISTRY
	)
	return CapabilitySnapshot(rows)


def _nvdaConfigurationRoot() -> Path:
	globalVars = import_module("globalVars")
	root = Path(str(globalVars.appArgs.configPath))
	if not root.is_absolute():
		raise ValueError("NVDA configuration root must be absolute")
	return root


def _productionStatusLoader() -> StatusLoader:
	return CapabilityStatusLoader(
		RuntimeCapabilityChecks(
			secureDesktop=lambda: bool(import_module("globalVars").appArgs.secure),
			uiaHandlerAvailable=lambda: import_module("UIAHandler").handler is not None,
			userInterfaceAvailable=lambda: all(
				hasattr(import_module("gui.settingsDialogs"), name)
				for name in ("NVDASettingsDialog", "SettingsPanel")
			),
			outputDirectoryWritable=lambda: _outputDirectoryWritable(),
			soundPlaybackAvailable=lambda: _soundPlaybackAvailable(),
			screenshotAvailable=lambda: _screenshotAvailable(),
		),
	)


def _outputDirectoryWritable() -> bool:
	root = snapshotOutputRoot()
	existing = root if root.exists() else root.parent
	return existing.is_dir() and os.access(existing, os.W_OK)


def _soundPlaybackAvailable() -> bool:
	_ = import_module("nvwave")
	root = Path(__file__).resolve().parents[2] / "sounds" / "rich"
	return all((root / relativePath).is_file() for relativePath in SOUND_ASSETS.values())


def _screenshotAvailable() -> bool:
	wx = import_module("wx")
	return hasattr(wx, "ScreenDC") and hasattr(wx, "Bitmap")


def _migrateStoredRedactionPolicy(
	settingsAdapter: SettingsAdapter,
) -> RedactionMigrationOutcome | None:
	"""Run the one-time redaction migration when the adapter supports it."""

	migrate = getattr(settingsAdapter, "migrateRedactionPolicy", None)
	if not callable(migrate):
		return None
	try:
		outcome = migrate()
	except Exception:
		return None
	return outcome if isinstance(outcome, RedactionMigrationOutcome) else None


def _announceRedactionMigration(outcome: RedactionMigrationOutcome) -> None:
	"""Tell the user their stored redaction preference was retired, and how to get it back."""

	if outcome.previousValue is not True:
		return
	resolver = getattr(builtins, "_", None)
	template = (
		"Keystone now shows protected values by default. Your saved setting to hide them was reset; "
		"turn Redact protected text back on in Keystone settings to hide them again."
	)
	message = cast(Callable[[str], str], resolver)(template) if callable(resolver) else template
	try:
		import_module("ui").message(message)
	except Exception:
		return


def _assembleProductionComposition(
	*,
	statusLoader: StatusLoader,
	settingsAdapter: SettingsAdapter,
	panelRegistry: PanelRegistry,
	captureManagement: CaptureManagementPort | None,
	releaseCallbacks: tuple[tuple[str, Callable[[], None]], ...] = (),
	customUiaService: CustomUiaService | None = None,
	appModuleOverrides: NvdaAppModuleOverrides | None = None,
) -> ProductionComposition:
	status: CapabilitySnapshot | None
	try:
		status = statusLoader.load()
	except (OSError, ValueError):
		status = None
		statusIssue = "KS.CAPABILITY.RUNTIME_CHECK_FAILED"
	else:
		statusIssue = None

	try:
		settingsResult = settingsAdapter.readSnapshot()
	except (OSError, ValueError):
		settingsResult = SettingsLoadResult("failed", None, "KS.SETTINGS.READ_FAILED")
	settingsIssue = settingsResult.errorCode
	redactionMigration = _migrateStoredRedactionPolicy(settingsAdapter)
	if redactionMigration is not None and redactionMigration.migrated:
		try:
			settingsResult = settingsAdapter.readSnapshot()
		except (OSError, ValueError):
			settingsResult = SettingsLoadResult("failed", None, "KS.SETTINGS.READ_FAILED")
		settingsIssue = settingsResult.errorCode
		_announceRedactionMigration(redactionMigration)

	startupIssue = statusIssue or settingsIssue
	if status is None:
		panelCapabilities = defaultCapabilitySnapshot
	else:
		panelCapabilities = _projectCapabilities(status)
	settings = settingsResult.snapshot or SettingsSnapshot.defaults(settingsRevision=1)
	operational = startupIssue is None and status is not None and _settingsOperational(status)
	lifecycle = LifecycleService()
	ownedReleases = list(releaseCallbacks)
	runtimeLog: _RuntimeLog | None = None
	settingsRelay = _RuntimeSettingsRelay()
	if captureManagement is None:
		concrete = _buildConcreteManagementServices(
			lifecycle=lifecycle,
			capabilities=status or _unavailableCapabilityStatus(),
			settings=settings,
			policyProvider=settingsRelay.currentPolicy,
		)
		captureManagement = concrete.captureManagement
		runtimeLog = concrete.runtimeLog
		ownedReleases.extend(concrete.releaseCallbacks)
	sound = _buildSoundService(settings, runtimeLog)
	root = CompositionRoot(
		lifecycle=lifecycle,
		panelRegistry=panelRegistry,
		settingsService=SettingsService(cast(SettingsPort, settingsAdapter)),
		capabilities=panelCapabilities,
		captureManagement=captureManagement,
		preview=sound,
		settingsApplied=settingsRelay,
	)
	composition = ProductionComposition(
		root=root,
		settings=settings,
		operationalEligible=operational,
		startupIssueCode=startupIssue,
		releaseCallbacks=tuple(ownedReleases),
		customUiaService=customUiaService,
		appModuleOverrides=appModuleOverrides,
		workflowSound=sound,
		runtimeLog=runtimeLog,
	)
	settingsRelay.attach(composition)
	return composition


class _ClosedSettingsAdapter:
	def readSnapshot(self) -> SettingsLoadResult:
		return SettingsLoadResult("failed", None, "KS.SETTINGS.READ_FAILED")

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		raise RuntimeError("settings are unavailable outside the NVDA host")


class _NvdaFeedbackAdapter:
	def announce(self, request: FeedbackRequest) -> EffectResult:
		revision = request.context.generation if request.context.generation is not None else 0
		try:
			import_module("ui").message(self._render(request))
		except Exception:
			return EffectResult(PortStatus("failed", revision), error=PortError("feedbackUnavailable"))
		return EffectResult(
			PortStatus("ready", revision),
			PortOutcome("feedbackAnnounced"),
		)

	def _render(self, request: FeedbackRequest) -> str:
		resolver = getattr(builtins, "_", None)

		def translate(template: str) -> str:
			return cast(Callable[[str], str], resolver)(template) if callable(resolver) else template

		if request.messageId == "output.committed":
			return translate("Capture output saved.")
		if request.messageId == "sound.preview":
			name = str(request.arguments[0]) if request.arguments else ""
			return translate("Previewing %s.") % name
		if request.messageId == "sound.preview.failed":
			name = str(request.arguments[0]) if request.arguments else ""
			return translate("The %s sound could not be played. Speech remains available.") % name
		if request.messageId == "events.monitor.started":
			target = str(request.arguments[0]) if request.arguments else ""
			scope = str(request.arguments[1]) if len(request.arguments) > 1 else ""
			rawIncluded = bool(request.arguments[2]) if len(request.arguments) > 2 else False
			scopeText = {
				"element": translate("selected element"),
				"subtree": translate("selected subtree"),
				"application": translate("application"),
				"broad": translate("broad scope"),
			}.get(scope, translate("selected element"))
			rawText = translate("included") if rawIncluded else translate("excluded")
			if target:
				return translate(
					"Monitoring active. For {target}. Scope: {scope}. Raw UIA events {raw}.",
				).format(target=target, scope=scopeText, raw=rawText)
			return translate(
				"Monitoring active. Scope: {scope}. Raw UIA events {raw}.",
			).format(scope=scopeText, raw=rawText)
		if request.messageId == "events.monitor.stopped":
			return translate("Event monitoring stopped.")
		if request.messageId == "events.monitor.failed":
			return translate("Event monitoring could not start. Speech remains available.")
		if request.messageId == "events.risk.broadScope":
			return translate("Warning: broad event scope monitors other applications.")
		if request.messageId == "events.risk.rawUia":
			return translate("Warning: raw UIA events are included in this session.")
		if request.messageId == "events.risk.redactionDisabled":
			return translate("Warning: protected text redaction is disabled.")
		message = request.messageId
		if request.arguments:
			message = f"{message}: {', '.join(str(value) for value in request.arguments)}"
		return message


class _NvdaClipboardAdapter:
	def copyText(self, request: ClipboardRequest) -> EffectResult:
		revision = request.context.generation if request.context.generation is not None else 0
		try:
			copied = import_module("api").copyToClip(request.text)
			if copied is False:
				raise OSError("clipboard rejected text")
		except Exception:
			return EffectResult(PortStatus("failed", revision), error=PortError("clipboardUnavailable"))
		return EffectResult(
			PortStatus("ready", revision),
			PortOutcome("clipboardUpdated"),
		)


class _NvdaShellAdapter:
	def _path(self, request: ShellRequest) -> Path:
		return Path(request.targetId)

	def openFolder(self, request: ShellRequest) -> EffectResult:
		try:
			path = self._path(request)
			folder = path if path.is_dir() else path.parent
			os.startfile(folder)
		except Exception:
			return EffectResult(
				PortStatus("failed", request.statusRevision),
				error=PortError("openFolderFailed"),
			)
		return EffectResult(PortStatus("ready", request.statusRevision), PortOutcome("folderOpened"))

	def revealFile(self, request: ShellRequest) -> EffectResult:
		try:
			path = self._path(request)
			_ = subprocess.Popen(("explorer.exe", f"/select,{path}"), close_fds=True)
		except Exception:
			return EffectResult(
				PortStatus("failed", request.statusRevision),
				error=PortError("revealFileFailed"),
			)
		return EffectResult(PortStatus("ready", request.statusRevision), PortOutcome("fileRevealed"))


class _RuntimeSettingsRelay:
	"""Carries a committed settings change into the running composition.

	The panel exists before the composition it configures, so the relay is handed to the panel at
	construction and pointed at the composition once there is one. Before that, and after teardown,
	applying settings is a silent no-op rather than a failure.
	"""

	def __init__(self) -> None:
		super().__init__()
		self._composition: ProductionComposition | None = None

	def attach(self, composition: ProductionComposition) -> None:
		self._composition = composition

	def applySettings(self, settings: SettingsSnapshot) -> None:
		composition = self._composition
		if composition is None:
			return
		with contextlib.suppress(Exception):
			composition.applySettings(settings)

	def currentPolicy(self, settings: SettingsSnapshot) -> PrivacyPolicy:
		"""The evidence policy in force, so the log records agree with every other surface.

		Before a composition is attached there is nothing running to agree with, so the policy is
		derived from the settings being applied.
		"""

		composition = self._composition
		if composition is not None:
			return composition.privacyPolicy
		return PrivacyPolicy(
			policyRevision=settings.settingsRevision,
			settingsRevision=settings.settingsRevision,
			redactProtectedText=settings.redactProtectedText,
		)


class _HostNvdaLogSink:
	"""Writes curated records to NVDA's own log, and stays quiet when there is no host to write to."""

	def __init__(self) -> None:
		super().__init__()
		self._adapter: NvdaLogAdapter | None = None

	def emit(self, record: LogicalRecord) -> None:
		if self._adapter is None:
			self._adapter = NvdaLogAdapter()
		self._adapter.emit(record)


class _RuntimeLog:
	"""Turns curated runtime moments into records for NVDA's native log.

	Only events the schema already names are recorded, and only with fields the runtime genuinely
	knows: a monitoring session starting and stopping, an approved broad scope, and a committed
	settings change. Everything else stays out of the log rather than filling it with noise.
	"""

	def __init__(self, service: LoggingService, context: CorrelationContext) -> None:
		super().__init__()
		self._service = service
		self._context = LogContext(
			sessionCorrelationId=context.sessionId.value,
			operationId=None,
			jobId=None,
			windowGeneration=None,
			inspectorGeneration=None,
			monitorGeneration=None,
			nvdaPid=os.getpid(),
			# Every curated record is produced on the owner thread that drives the workspaces and the
			# settings panel. The record contract admits a closed set of thread names, so naming the
			# thread honestly is also what keeps these records from being rejected outright.
			threadIdentity="gui",
		)

	def record(self, code: str, fields: tuple[tuple[str, LogScalar], ...]) -> None:
		with contextlib.suppress(Exception):
			_ = self._service.emit(self._candidate(code, fields))

	def reconfigure(self, settings: SettingsSnapshot, policy: PrivacyPolicy) -> None:
		self._service.replacePrivacyPolicy(policy)
		self.record(
			"KS.SETTINGS.GLOBAL_CHANGED",
			(("settingsRevision", settings.settingsRevision), ("policyRevision", policy.policyRevision)),
		)

	def _candidate(self, code: str, fields: tuple[tuple[str, LogScalar], ...]) -> LogCandidate:
		return LogCandidate(
			timestamp=datetime.now(UTC),
			code=code,
			context=self._context,
			fields=tuple(
				LogFieldCandidate(
					name=name,
					value=value,
					fieldGroup=FieldGroup.LOG,
					privacyClass=PrivacyClass.PUBLIC,
					protection=ProtectionEvidence.allClear(),
					sourceId=f"runtime-{name}",
				)
				for name, value in fields
			),
		)


@dataclass(frozen=True, slots=True)
class _ConcreteManagementServices:
	captureManagement: CaptureManagementPort
	screenshot: ScreenshotPort
	runtimeLog: _RuntimeLog
	releaseCallbacks: tuple[tuple[str, Callable[[], None]], ...]


def _buildConcreteManagementServices(
	*,
	lifecycle: LifecycleService,
	capabilities: CapabilitySnapshot,
	settings: SettingsSnapshot,
	policyProvider: Callable[[SettingsSnapshot], PrivacyPolicy] | None = None,
) -> _ConcreteManagementServices:
	admission = lifecycle.admit("production-management")
	context = admission.context
	if not admission.accepted or context is None:
		raise RuntimeError("production management correlation admission was rejected")
	feedback = _NvdaFeedbackAdapter()
	clipboard = _NvdaClipboardAdapter()
	startupPolicy = PrivacyPolicy(
		policyRevision=settings.settingsRevision,
		settingsRevision=settings.settingsRevision,
		redactProtectedText=settings.redactProtectedText,
	)
	runtimeLog = _RuntimeLog(
		LoggingService(
			nvdaSink=_HostNvdaLogSink(),
			sequenceAllocator=SequenceAllocator(),
			privacyPolicy=startupPolicy,
		),
		context,
	)
	outputShell = _NvdaShellAdapter()
	runtimeDirectory = fixedOutputRoot() / "runtime"
	runtimeDirectory.mkdir(parents=True, exist_ok=True)
	screenshotEnabled = any(
		row.capabilityId == "screenCapture" and row.status is CapabilityStatus.ENABLED
		for row in capabilities.rows
	)
	screenshotBackend: WxScreenshotBackend | None = None
	if screenshotEnabled:
		try:
			screenshotBackend = WxScreenshotBackend(cast(WxModule, import_module("wx")), runtimeDirectory)
		except ImportError:
			screenshotEnabled = False
	screenshot = ScreenshotAdapter(
		screenshotBackend,
		enabled=screenshotEnabled,
		clock=lambda: datetime.now(UTC).isoformat(),
	)
	publicationBackend = LocalPublicationBackend(snapshotOutputRoot())
	captureManagement = OutputService(
		PublicationManager(publicationBackend),
		feedback,
		clipboard,
		outputShell,
		actionIdFactory=lambda: os.urandom(16).hex(),
		screenshot=screenshot,
		screenshotAttemptIdFactory=lambda: os.urandom(12).hex(),
		lifecycleGeneration=admission.generation,
	)
	return _ConcreteManagementServices(
		captureManagement,
		screenshot,
		runtimeLog,
		(("publication-backend", publicationBackend.close),),
	)


class _ClosedPanelRegistry:
	def add(
		self,
		panelClass: type[object],
		controllerFactory: Callable[[], SettingsPanelController],
	) -> None:
		return

	def remove(self, panelClass: type[object]) -> None:
		return


class _NativePanelBuilder:
	def __init__(self, panel: object, sizer: object) -> None:
		super().__init__()
		self._panel = panel
		self._sizer = sizer
		self._helper: object | None = None
		self.controls: dict[str, object] = {}
		self.choiceTokens: dict[str, tuple[str, ...]] = {}

	def beginGroup(self, label: str) -> None:
		wx = import_module("wx")
		guiHelper = import_module("gui.guiHelper")
		box = wx.StaticBoxSizer(wx.VERTICAL, self._panel, label=label)
		box.GetStaticBox().DisableFocusFromKeyboard()
		self._sizer.Add(box, flag=wx.EXPAND | wx.ALL, border=self._panel.scaleSize(8))
		self._helper = guiHelper.BoxSizerHelper(self._panel, sizer=box)

	def _addHelp(self, text: str) -> None:
		wx = import_module("wx")
		assert self._helper is not None
		label = wx.StaticText(self._panel, label=text)
		label.Wrap(self._panel.scaleSize(700))
		self._helper.addItem(label)

	def _decorate(self, control: object, definition: NativeControlDefinition) -> object:
		control.SetName(f"{definition.label.replace('&', '')}. {definition.helpText}")
		control.SetHelpText(definition.helpText)
		self.controls[definition.controlId] = control
		self._addHelp(definition.helpText)
		return control

	def addSpin(
		self,
		definition: NativeControlDefinition,
		value: int,
		minimum: int,
		maximum: int,
	) -> None:
		assert self._helper is not None
		nvdaControls = import_module("gui.nvdaControls")
		control = self._helper.addLabeledControl(
			definition.label,
			nvdaControls.SelectOnFocusSpinCtrl,
			min=minimum,
			max=maximum,
			initial=value,
		)
		self._decorate(control, definition)

	def addCheckBox(self, definition: NativeControlDefinition, value: bool, enabled: bool) -> None:
		wx = import_module("wx")
		assert self._helper is not None
		control = wx.CheckBox(self._panel, label=definition.label)
		control.SetValue(value)
		control.Enable(enabled)
		self._helper.addItem(control)
		self._decorate(control, definition)

	def addChoice(
		self,
		definition: NativeControlDefinition,
		value: str,
		choices: tuple[str, ...],
		enabled: bool,
	) -> None:
		wx = import_module("wx")
		assert self._helper is not None
		control = self._helper.addLabeledControl(definition.label, wx.Choice, choices=choices)
		if definition.controlId == "soundPreviewCue":
			# The preview cue is not a stored setting; its stable tokens are the atom identifiers in
			# manifest order, matched to the localized labels by position.
			tokens = tuple(atom.value for atom in PREVIEW_CUE_ORDER)
			if value not in choices or len(tokens) != len(choices):
				raise ValueError(f"choice values drifted for {definition.controlId}")
			self.choiceTokens[definition.controlId] = tokens
			control.SetSelection(choices.index(value))
		else:
			setting = next(
				setting for setting in SETTING_DEFINITIONS if setting.settingId.value == definition.controlId
			)
			if value not in setting.choices or len(setting.choices) != len(choices):
				raise ValueError(f"choice values drifted for {definition.controlId}")
			self.choiceTokens[definition.controlId] = setting.choices
			control.SetSelection(setting.choices.index(value))
		control.Enable(enabled)
		self._decorate(control, definition)

	def addButton(self, definition: NativeControlDefinition, enabled: bool) -> None:
		wx = import_module("wx")
		assert self._helper is not None
		control = wx.Button(self._panel, label=definition.label)
		control.Enable(enabled)
		control.Bind(wx.EVT_BUTTON, lambda event: self._panel.onKeystoneAction(definition))
		self._helper.addItem(control)
		self._decorate(control, definition)


def _nativePanelClass(
	baseClass: type[object],
	controllerFactory: Callable[[], SettingsPanelController],
) -> type[object]:
	class NativeKeystoneSettingsPanel(baseClass):
		title = KeystoneSettingsPanel.title
		panelDescription = KeystoneSettingsPanel.panelDescription

		def makeSettings(self, sizer: object) -> None:
			self._keystoneController = controllerFactory()
			self._keystoneBuilder = _NativePanelBuilder(self, sizer)
			KeystoneSettingsPanel(self._keystoneController).makeSettings(self._keystoneBuilder)

		def _syncCandidate(self) -> None:
			wx = import_module("wx")
			for definition in SETTING_DEFINITIONS:
				control = self._keystoneBuilder.controls.get(definition.settingId.value)
				if control is None:
					continue
				if isinstance(control, wx.Choice):
					tokens = self._keystoneBuilder.choiceTokens[definition.settingId.value]
					selection = control.GetSelection()
					value = tokens[selection] if 0 <= selection < len(tokens) else ""
				else:
					value = control.GetValue()
				self._keystoneController.setValue(definition.settingId, value)

		def isValid(self) -> bool:
			self._syncCandidate()
			validation = validateCandidate(self._keystoneController.candidate())
			if validation.isValid:
				return True
			first = validation.issues[0]
			self._showValidation(self._keystoneController.validationDialog(validation))
			control = self._keystoneBuilder.controls.get(first.settingId.value)
			if control is not None:
				control.SetFocus()
				selectAll = getattr(control, "SelectAll", None)
				if callable(selectAll):
					selectAll()
			return False

		def onSave(self) -> None:
			self._syncCandidate()
			result = self._keystoneController.apply()
			if result.status.value != "updated":
				self._showValidation(self._keystoneController.saveFailureDialog(result))
				raise ValueError("Keystone settings were not saved")

		def onDiscard(self) -> None:
			self._keystoneController.cancel()

		def _showValidation(self, presentation: ValidationDialogPresentation) -> None:
			wx = import_module("wx")
			dialog = wx.RichMessageDialog(
				self,
				presentation.message,
				presentation.title,
				style=wx.OK | wx.ICON_ERROR,
			)
			dialog.ShowDetailedText(presentation.details)
			dialog.SetEscapeId(wx.ID_OK)
			try:
				_ = dialog.ShowModal()
			finally:
				dialog.Destroy()

		def _showCapabilityDetails(self, details: str) -> None:
			wx = import_module("wx")
			messages = panelMessages()
			dialog = wx.Dialog(self, title=messages.capabilityDetailsTitle)
			detailsText = wx.TextCtrl(
				dialog,
				value=details,
				style=wx.TE_MULTILINE | wx.TE_READONLY,
			)
			detailsText.SetName(messages.capabilityDetailsTitle)
			copyButton = wx.Button(dialog, label=messages.capabilityDetailsCopy)
			closeButton = wx.Button(
				dialog,
				wx.ID_CLOSE,
				label=messages.capabilityDetailsClose,
			)

			def onCopy(_event: object) -> None:
				detailsText.SelectAll()
				detailsText.Copy()
				detailsText.SetFocus()

			def onClose(_event: object) -> None:
				dialog.EndModal(wx.ID_CLOSE)

			copyButton.Bind(wx.EVT_BUTTON, onCopy)
			closeButton.Bind(wx.EVT_BUTTON, onClose)
			closeButton.SetDefault()
			dialog.SetEscapeId(wx.ID_CLOSE)
			dialog.SetAffirmativeId(wx.ID_CLOSE)
			content = wx.BoxSizer(wx.VERTICAL)
			content.Add(detailsText, 1, wx.EXPAND | wx.ALL, 12)
			buttons = wx.BoxSizer(wx.HORIZONTAL)
			buttons.AddStretchSpacer()
			buttons.Add(copyButton, 0, wx.RIGHT, 8)
			buttons.Add(closeButton)
			content.Add(buttons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
			dialog.SetSizer(content)
			dialog.SetSize((640, 420))
			dialog.CentreOnParent()
			try:
				detailsText.SetFocus()
				_ = dialog.ShowModal()
			finally:
				dialog.Destroy()

		def _confirm(self, title: str, message: str, affirmativeLabel: str) -> bool:
			wx = import_module("wx")
			dialog = wx.MessageDialog(
				self,
				message,
				title,
				style=wx.OK | wx.CANCEL | wx.CANCEL_DEFAULT | wx.ICON_WARNING,
			)
			if hasattr(dialog, "SetOKCancelLabels"):
				dialog.SetOKCancelLabels(affirmativeLabel, panelMessages().cancelLabel)
			try:
				return dialog.ShowModal() == wx.ID_OK
			finally:
				dialog.Destroy()

		def onKeystoneAction(self, definition: NativeControlDefinition) -> None:
			controlId = definition.controlId
			if controlId in ("rawUiaDetails", "soundDetails"):
				self._showCapabilityDetails(self._keystoneController.capabilityDetails(controlId))
				return
			if controlId == "restoreDefaults":
				messages = panelMessages()
				confirmed = self._confirm(
					messages.restoreDefaultsTitle,
					messages.restoreDefaultsConfirmation,
					messages.restoreDefaultsAction,
				)
				_ = self._keystoneController.restoreDefaults(confirmed=confirmed)
				if confirmed:
					wx = import_module("wx")
					for setting in SETTING_DEFINITIONS:
						control = self._keystoneBuilder.controls.get(setting.settingId.value)
						if control is not None:
							value = self._keystoneController.candidate().value(setting.settingId)
							if isinstance(control, wx.Choice):
								tokens = self._keystoneBuilder.choiceTokens[setting.settingId.value]
								control.SetSelection(tokens.index(str(value)))
							else:
								control.SetValue(value)
				return
			if controlId == "clearPublishedCaptures":
				status = self._keystoneController.refreshCaptures()
				if status is None:
					return
				if status.recognizedCount == 0:
					import_module("ui").message(panelMessages().noCapturesBody)
					return
				confirmed = self._confirm(
					panelMessages().clearCapturesTitle,
					clearCapturesConfirmation(status.recognizedCount),
					panelMessages().clearCapturesAction,
				)
				_ = self._keystoneController.clearPublishedCaptures(confirmed=confirmed)
				return

			if controlId == "previewSound":
				choice = self._keystoneBuilder.controls.get("soundPreviewCue")
				if choice is not None:
					selection = choice.GetSelection()
					if 0 <= selection < len(PREVIEW_CUE_ORDER):
						self._keystoneController.setPreviewCue(PREVIEW_CUE_ORDER[selection])
				self._keystoneController.previewSelectedCue()
				return
			import_module("ui").message(definition.helpText)

	NativeKeystoneSettingsPanel.__name__ = "KeystoneSettingsPanel"
	NativeKeystoneSettingsPanel.__qualname__ = "KeystoneSettingsPanel"
	return NativeKeystoneSettingsPanel


class NvdaPanelRegistry:
	def __init__(self) -> None:
		super().__init__()
		settingsDialogs = import_module("gui.settingsDialogs")
		self._categories = cast(
			MutableSequence[type[object]],
			settingsDialogs.NVDASettingsDialog.categoryClasses,
		)
		self._baseClass = cast(type[object], settingsDialogs.SettingsPanel)
		self._nativeClass: type[object] | None = None

	def add(
		self,
		panelClass: type[object],
		controllerFactory: Callable[[], SettingsPanelController],
	) -> None:
		if panelClass is not KeystoneSettingsPanel or self._nativeClass is not None:
			raise RuntimeError("Keystone settings panel registration drifted")
		nativeClass = _nativePanelClass(self._baseClass, controllerFactory)
		self._categories.append(nativeClass)
		self._nativeClass = nativeClass

	def remove(self, panelClass: type[object]) -> None:
		if panelClass is not KeystoneSettingsPanel:
			raise RuntimeError("Keystone settings panel removal drifted")
		nativeClass = self._nativeClass
		self._nativeClass = None
		if nativeClass is not None and nativeClass in self._categories:
			self._categories.remove(nativeClass)


def buildProductionComposition() -> ProductionComposition:
	statusLoader = _productionStatusLoader()
	try:
		config = import_module("config")
	except (AttributeError, ImportError):
		settingsAdapter = _ClosedSettingsAdapter()
	else:
		try:
			_ = import_module("config.configSections")
		except ModuleNotFoundError as error:
			if error.name != "config.configSections":
				raise
			registration = initializeLegacyKeystoneBaseSection(config.conf)
		else:
			registration = initializeKeystoneBaseSection(config.conf)
		if not registration.available:
			raise RuntimeError("Keystone settings registration is unavailable")
		settingsAdapter = NvdaSettingsAdapter(config.conf)
	# Building the panel registry imports NVDA's GUI runtime (gui.settingsDialogs) and reads its
	# settings-dialog attributes, both legitimately absent off-host and during headless production
	# observation. Only those expected unavailable-GUI conditions degrade to the shipped closed
	# registry: ImportError (including ModuleNotFoundError) from the missing GUI module, and
	# AttributeError from a GUI surface that lacks the expected settings-dialog attributes. Any other
	# error is a real panel-initialization defect and must propagate instead of being masked into a
	# silently closed panel.
	try:
		panelRegistry: PanelRegistry = NvdaPanelRegistry()
	except (AttributeError, ImportError):
		panelRegistry = _ClosedPanelRegistry()
	try:
		userConfigurationRoot = _nvdaConfigurationRoot()
	except (AttributeError, ImportError, ValueError):
		customUiaService = None
		appModuleOverrides = None
	else:
		try:
			customUiaService = CustomUiaService(
				userConfigurationRoot,
				registry=buildNvdaCustomUiaRegistry(),
			)
		except (AttributeError, ImportError, ValueError):
			customUiaService = None
		try:
			appModuleOverrides = NvdaAppModuleOverrides(userConfigurationRoot)
		except (AttributeError, ImportError, ValueError):
			appModuleOverrides = None
	composition = _assembleProductionComposition(
		statusLoader=statusLoader,
		settingsAdapter=settingsAdapter,
		panelRegistry=panelRegistry,
		captureManagement=None,
		customUiaService=customUiaService,
		appModuleOverrides=appModuleOverrides,
	)
	composition.configureDefaultCommands()
	return composition
