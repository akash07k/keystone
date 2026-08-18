# pyright: reportPrivateUsage=false
"""Focused tests for the production event-monitor session, wiring, and live capture behaviour.

These cover the repaired parity gaps end to end: the production composition subscribes the plugin's
own ``NvdaEventSource`` (never a duplicate), forwarded events drain into the rendered history through
a bounded owner-thread pump, the workspace is a torn-down singleton, raw UIA families forward through
the shipped source, a live filter change takes effect without Stop/Start, per-type detail extraction
is privacy-safe, and no pump tick survives a stop.
"""

from __future__ import annotations

from collections.abc import Callable
from collections import OrderedDict
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, override
import unittest

from addon.globalPlugins.keystone.adapters.nvda.composition import ProductionComposition
from addon.globalPlugins.keystone.adapters.nvda.commands import ProductionCommandRuntime
from addon.globalPlugins.keystone.adapters.nvda import event_monitor_session as sessionModule
from addon.globalPlugins.keystone.adapters.nvda.event_monitor_session import EventMonitorSession
from addon.globalPlugins.keystone.adapters.nvda.event_sources import (
	NvdaEventSource,
	targetIdentityFromObject,
)
from addon.globalPlugins.keystone.adapters.windows.raw_uia_events import RawUiaEventSource
from addon.globalPlugins.keystone.adapters.wx.inspector_frame import KeystoneWindow
from addon.globalPlugins.keystone.application.event_monitor_service import EventMonitorService
from addon.globalPlugins.keystone.application.lifecycle import LifecycleService
from addon.globalPlugins.keystone.domain.event_monitor import (
	BoundaryReason,
	EventFilter,
	MonitorScope,
	MonitorScopeKind,
	MonitorScopeUnavailable,
	NvdaEventType,
	RawUiaFamily,
	ScopeUnavailableReason,
	TargetIdentity,
	TargetLifecycleReason,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.ports.effects import (
	EffectResult,
	PortOutcome,
	PortStatus,
)

from .test_production_composition import _composition


class _Clock:
	def __init__(self) -> None:
		super().__init__()
		self._value = 1_000.0

	def ms(self) -> float:
		self._value += 1.0
		return self._value


class _SilentClipboard:
	def copyText(self, request: object) -> EffectResult:
		_ = request
		return EffectResult(PortStatus("ready", 0), PortOutcome("copied"))


class _SilentFeedback:
	def announce(self, request: object) -> EffectResult:
		_ = request
		return EffectResult(PortStatus("ready", 0), PortOutcome("announced"))


class _FakeWorkspace:
	"""A workspace double that records show/refresh/close and tracks the open frame state."""

	def __init__(self) -> None:
		super().__init__()
		self.shows = 0
		self.refreshes = 0
		self.closes = 0
		self._open = False
		self.startMonitoring: Callable[..., bool] | None = None
		self.stopMonitoring: Callable[[], None] | None = None
		self.restartMonitoring: Callable[[MonitorScopeKind | None], bool] | None = None
		self.scopeFailure: Callable[[], ScopeUnavailableReason | None] | None = None

	def configureMonitoring(
		self,
		*,
		start: Callable[..., bool],
		stop: Callable[[], None],
		restart: Callable[[MonitorScopeKind | None], bool] | None = None,
		showSource: Callable[..., bool] | None = None,
		scopeFailure: Callable[[], ScopeUnavailableReason | None] | None = None,
	) -> None:
		_ = showSource
		self.startMonitoring = start
		self.stopMonitoring = stop
		self.restartMonitoring = restart
		self.scopeFailure = scopeFailure

	def show(self) -> None:
		self.shows += 1
		self._open = True

	@property
	def isOpen(self) -> bool:
		return self._open

	def refresh(self) -> None:
		self.refreshes += 1

	def close(self) -> None:
		self.closes += 1
		self._open = False


class _FakeTimer:
	def __init__(self) -> None:
		super().__init__()
		self.stopped = False

	def Stop(self) -> None:
		self.stopped = True


class _FakeScheduler:
	"""Records pending owner-thread callbacks and fires them on demand, like ``wx.CallLater``."""

	def __init__(self, *, armFailures: int = 0) -> None:
		super().__init__()
		self._pending: list[tuple[_FakeTimer, object]] = []
		self._armFailures = armFailures

	def schedule(self, delayMs: int, callback: object) -> _FakeTimer:
		_ = delayMs
		if self._armFailures:
			self._armFailures -= 1
			raise RuntimeError("scheduler unavailable")
		timer = _FakeTimer()
		self._pending.append((timer, callback))
		return timer

	@property
	def armed(self) -> bool:
		return any(not timer.stopped for timer, _ in self._pending)

	def tick(self) -> bool:
		while self._pending:
			timer, callback = self._pending.pop(0)
			if timer.stopped:
				continue
			callback()  # type: ignore[operator]
			return True
		return False


class _ComError(Exception):
	def __init__(self) -> None:
		super().__init__("element unavailable")
		self.hresult = -2147220991


class _StaleUiaObject:
	def __init__(self) -> None:
		super().__init__()
		self.processID = 4242
		self.windowHandle = 101
		self.appModule = SimpleNamespace(appName="firefox")
		self.UIAElement = object()
		self.stale = False

	@property
	def UIAAutomationId(self) -> str:
		if self.stale:
			raise _ComError()
		return "target"


class _TrackedEventObject:
	def __init__(
		self,
		automationId: str,
		*,
		parent: _TrackedEventObject | None = None,
	) -> None:
		super().__init__()
		self.name = automationId
		self.role = SimpleNamespace(name="button")
		self.processID = 4242
		self.windowHandle = 101
		self.appModule = SimpleNamespace(appName="firefox")
		self.value = ""
		self.isProtected = False
		self.UIAAutomationId = automationId
		self._parent = parent
		self.parentReads = 0

	@property
	def parent(self) -> _TrackedEventObject | None:
		self.parentReads += 1
		return self._parent


class _UiaElementFailureObject(_StaleUiaObject):
	def __init__(self) -> None:
		self._uiaElementFails = False
		super().__init__()

	@property
	@override
	def UIAElement(self) -> object:
		if self._uiaElementFails:
			raise _ComError()
		return object()

	@UIAElement.setter
	def UIAElement(self, _value: object) -> None:
		return


def _fakeObject(
	*,
	name: str = "Search",
	role: str = "editableText",
	pid: int = 4242,
	app: str = "firefox",
	value: str = "",
	protected: bool = False,
	states: tuple[str, ...] = (),
	description: str = "",
	politeness: str | None = None,
) -> object:
	return SimpleNamespace(
		name=name,
		role=SimpleNamespace(name=role),
		processID=pid,
		appModule=SimpleNamespace(appName=app),
		value=value,
		isProtected=protected,
		states=tuple(SimpleNamespace(name=state) for state in states),
		description=description,
		liveRegionPoliteness=None if politeness is None else SimpleNamespace(name=politeness),
	)


def _service(*, redact: bool = True) -> EventMonitorService:
	snapshot = replace(
		SettingsSnapshot.defaults(settingsRevision=3),
		eventDetailCharacters=100,
		redactProtectedText=redact,
	)
	policy = PrivacyPolicy(policyRevision=1, settingsRevision=3, redactProtectedText=redact)
	return EventMonitorService(
		lifecycle=LifecycleService(),
		settings=lambda: snapshot,
		policy=lambda: policy,
		clipboard=_SilentClipboard(),
		feedback=_SilentFeedback(),
		monotonic=_Clock().ms,
		wallClock=lambda: 1_700_000_000_000,
	)


def _session(
	*,
	service: EventMonitorService,
	nvdaSource: NvdaEventSource,
	rawSource: RawUiaEventSource | None,
	workspace: _FakeWorkspace,
	scheduler: _FakeScheduler,
	selection: object | None = None,
	toggleDebounceMs: int = 0,
) -> EventMonitorSession:
	selected = _TrackedEventObject("monitored-target") if selection is None else selection
	return EventMonitorSession(
		service=service,
		workspace=workspace,  # type: ignore[arg-type]
		nvdaSource=nvdaSource,
		rawSource=rawSource,
		selectionResolver=lambda: selected,
		scheduleLater=scheduler.schedule,
		toggleDebounceMs=toggleDebounceMs,
	)


class ProductionWiringTests(unittest.TestCase):
	def test_command_runtime_resolves_the_browsed_live_node(self) -> None:
		selected = object()

		def liveObject(_nodeId: str) -> object:
			return selected

		runtime: Any = ProductionCommandRuntime.__new__(ProductionCommandRuntime)
		runtime._liveInspectorSource = SimpleNamespace(liveObject=liveObject)
		runtime._inspectorService = SimpleNamespace(selectedNodeId="selected-1")

		self.assertIs(ProductionCommandRuntime.currentInspectorSelection(runtime), selected)

	def test_show_source_revalidates_identity_before_opening_inspector(self) -> None:
		sourceObject = SimpleNamespace(
			processID=4242,
			windowHandle=101,
			UIAAutomationId="event-control",
		)
		opened: list[object] = []
		shows: list[bool] = []

		def ancestors(_source: object) -> tuple[object, ...]:
			return ()

		def build(_kind: str, *, selection: object) -> object:
			return selection

		runtime: Any = ProductionCommandRuntime.__new__(ProductionCommandRuntime)
		runtime._eventSourceObjects = OrderedDict((("source-1", sourceObject),))
		runtime._objectAncestors = ancestors
		runtime._buildLiveInspectorSource = build
		runtime._openInspectorSource = opened.append
		runtime._inspector = SimpleNamespace(show=lambda: shows.append(True))
		row: Any = SimpleNamespace(
			sourceRef="source-1",
			sourceIdentity=TargetIdentity(
				4242,
				101,
				(("providerIdentifier", "event-control"),),
			),
		)

		self.assertTrue(ProductionCommandRuntime.showEventSource(runtime, row))
		self.assertEqual(len(opened), 1)
		self.assertEqual(shows, [True])

	def test_composition_wires_the_command_runtime_as_selection_and_navigation_authority(self) -> None:
		composition, _, _, _ = _composition()
		composition.start()
		selected = object()
		retained: list[object] = []
		shown: list[object] = []

		def retain(source: object) -> str:
			retained.append(source)
			return "source-1"

		def show(row: object) -> bool:
			shown.append(row)
			return True

		runtime = SimpleNamespace(
			currentInspectorSelection=lambda: selected,
			retainEventSource=retain,
			showEventSource=show,
			window=KeystoneWindow(),
		)
		composition._commandRuntime = runtime  # type: ignore[assignment]
		pluginSource = NvdaEventSource()
		composition.useEventSource(pluginSource)

		session = composition._ensureEventMonitorSession()

		self.assertIs(session._selectionResolver(), selected)
		self.assertIsNotNone(pluginSource._sourceRetainer)
		self.assertIs(session.workspace._showSource, runtime.showEventSource)

	def test_composition_subscribes_the_plugin_source_and_drains_into_history(self) -> None:
		composition, _, _, _ = _composition()
		composition.start()
		pluginSource = NvdaEventSource()
		composition.useEventSource(pluginSource)

		session = composition._ensureEventMonitorSession()
		# The production session reuses the plugin's exact source rather than a disconnected duplicate.
		self.assertIs(session.nvdaSource, pluginSource)
		self.assertIn(pluginSource, session.sources)

		# Drive the built session off-host by swapping in a fake frame and scheduler.
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session._workspace = workspace  # type: ignore[assignment]
		session._scheduleLater = scheduler.schedule
		session._selectionResolver = lambda: _TrackedEventObject("monitored-target")

		session.open()
		self.assertTrue(session.start(MonitorScopeKind.APPLICATION))
		self.assertTrue(pluginSource.active)
		self.assertGreaterEqual(session.service.subscriptionCount, 1)

		self.assertTrue(pluginSource.forward(NvdaEventType.FOCUS, _fakeObject(name="hit")))
		self.assertTrue(scheduler.tick())

		rows = session.service.retainedRows()
		self.assertEqual(1, len(rows))
		self.assertEqual("hit", rows[0].objectName)
		self.assertGreaterEqual(workspace.refreshes, 1)

		composition.transition("terminating")
		self.assertFalse(pluginSource.active)
		self.assertFalse(session.pumpRunning)

	def test_open_event_monitor_builds_one_singleton_session(self) -> None:
		composition, _, _, _ = _composition()
		composition.start()
		first = composition._ensureEventMonitorSession()
		second = composition._ensureEventMonitorSession()
		self.assertIs(first, second)
		self.assertIs(composition.eventMonitorSession, first)


class DrainPumpTests(unittest.TestCase):
	def _open(self) -> tuple[EventMonitorSession, NvdaEventSource, _FakeWorkspace, _FakeScheduler]:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
		)
		session.open()
		self.assertIsNotNone(workspace.startMonitoring)
		assert workspace.startMonitoring is not None
		# The pump and history tests forward objects from across the selected application, so they
		# monitor the application the Inspector selection belongs to rather than that one element.
		self.assertTrue(workspace.startMonitoring(MonitorScopeKind.APPLICATION))
		return session, source, workspace, scheduler

	def test_open_stays_stopped_until_explicit_start_and_stop_keeps_the_workspace_open(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
		)

		session.open()

		self.assertTrue(workspace.isOpen)
		self.assertFalse(service.active)
		self.assertFalse(session.pumpRunning)
		self.assertIsNotNone(workspace.startMonitoring)
		self.assertIsNotNone(workspace.stopMonitoring)
		assert workspace.startMonitoring is not None
		assert workspace.stopMonitoring is not None

		self.assertTrue(workspace.startMonitoring())
		self.assertTrue(service.active)
		self.assertTrue(session.pumpRunning)
		self.assertTrue(source.active)

		workspace.stopMonitoring()
		self.assertTrue(workspace.isOpen)
		self.assertFalse(service.active)
		self.assertFalse(session.pumpRunning)
		self.assertFalse(source.active)

	def test_repeated_start_rearms_pump_after_scheduler_arm_failure(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler(armFailures=1)
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
		)

		self.assertTrue(session.start(MonitorScopeKind.APPLICATION))
		scope = service.scope
		self.assertIsNotNone(scope)
		self.assertTrue(service.active)
		self.assertTrue(source.active)
		self.assertFalse(session.pumpRunning)
		self.assertFalse(scheduler.armed)

		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))

		self.assertIs(scope, service.scope)
		self.assertTrue(service.active)
		self.assertTrue(source.active)
		self.assertTrue(session.pumpRunning)
		self.assertTrue(scheduler.armed)

	def test_toggle_stops_then_restarts_the_last_selected_scope(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
		)

		self.assertTrue(session.start(MonitorScopeKind.SUBTREE))
		self.assertFalse(session.toggle())
		self.assertFalse(service.active)
		self.assertFalse(source.active)

		self.assertTrue(session.toggle())
		self.assertTrue(service.active)
		self.assertTrue(source.active)
		scope = service.scope
		assert scope is not None
		self.assertIs(MonitorScopeKind.SUBTREE, scope.kind)

	def test_toggle_ignores_a_duplicate_delivery_before_stopping(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		clock = [1_000.0]
		session = EventMonitorSession(
			service=service,
			workspace=workspace,  # type: ignore[arg-type]
			nvdaSource=source,
			selectionResolver=lambda: _TrackedEventObject("monitored-target"),
			scheduleLater=scheduler.schedule,
			monotonicMs=lambda: clock[0],
		)

		self.assertTrue(session.toggle())
		clock[0] += 112.0
		self.assertTrue(session.toggle())
		self.assertTrue(service.active)

		clock[0] += 500.0
		self.assertFalse(session.toggle())
		self.assertFalse(service.active)

	def test_global_toggle_keeps_monitoring_active_without_an_open_events_page(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
		)

		self.assertTrue(session.toggle())
		self.assertFalse(workspace.isOpen)
		self.assertTrue(scheduler.tick())
		self.assertTrue(service.active)
		self.assertTrue(source.active)

	def test_start_feedback_name_omits_protected_target_text(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		protected = _TrackedEventObject("account number")
		protected.isProtected = True
		session = _session(
			service=service,
			nvdaSource=NvdaEventSource(),
			rawSource=None,
			workspace=workspace,
			scheduler=scheduler,
			selection=protected,
		)

		self.assertIsNone(session._announcementTargetName())

	def test_forwarded_events_drain_into_history_and_refresh_the_open_frame(self) -> None:
		session, source, workspace, scheduler = self._open()
		self.assertTrue(workspace.isOpen)
		self.assertTrue(session.pumpRunning)

		for index in range(3):
			self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name=f"row-{index}")))
		self.assertEqual(0, len(session.service.retainedRows()))

		self.assertTrue(scheduler.tick())
		self.assertEqual(3, len(session.service.retainedRows()))
		self.assertGreaterEqual(workspace.refreshes, 1)
		self.assertTrue(scheduler.armed)

	def test_no_pump_tick_survives_a_stop(self) -> None:
		session, source, workspace, scheduler = self._open()
		self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name="kept")))
		self.assertTrue(scheduler.tick())
		self.assertEqual(1, len(session.service.retainedRows()))

		session.close()
		self.assertFalse(session.pumpRunning)
		self.assertFalse(session.service.active)
		self.assertEqual(1, workspace.closes)
		# Any queued tick is refused: it neither drains nor re-arms the pump.
		self.assertFalse(scheduler.armed)
		self.assertFalse(scheduler.tick())

	def test_closing_the_window_ends_monitoring_from_within_the_pump(self) -> None:
		session, source, workspace, scheduler = self._open()
		self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name="live")))
		self.assertTrue(scheduler.tick())

		# The user closes the Events frame; the next pump tick observes it and tears the session down.
		workspace.close()
		self.assertTrue(scheduler.tick())
		self.assertFalse(session.service.active)
		self.assertFalse(session.pumpRunning)
		self.assertFalse(scheduler.armed)

	def test_history_survives_close_and_reopen(self) -> None:
		session, source, _workspace, scheduler = self._open()
		self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name="kept")))
		self.assertTrue(scheduler.tick())
		retained = session.service.retainedRows()
		self.assertEqual(1, len(retained))

		session.close()
		session.open()
		self.assertEqual(retained, session.service.retainedRows())

	def test_restart_re_resolves_current_element_and_inserts_scope_boundary(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		current = [
			SimpleNamespace(
				processID=4242,
				windowHandle=101,
				UIAAutomationId="first",
				appModule=SimpleNamespace(appName="firefox"),
			),
		]
		sessionType: Any = EventMonitorSession
		session: Any = sessionType(
			service=service,
			workspace=workspace,
			nvdaSource=source,
			selectionResolver=lambda: current[0],
			scheduleLater=scheduler.schedule,
		)

		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		firstScope = service.scope
		assert firstScope is not None
		firstIdentity = firstScope.targetIdentity
		assert firstIdentity is not None
		self.assertIn(("providerIdentifier", "first"), firstIdentity.providerEvidence)
		current[0] = SimpleNamespace(
			processID=4242,
			windowHandle=101,
			UIAAutomationId="second",
			appModule=SimpleNamespace(appName="firefox"),
		)

		self.assertTrue(session.restartWithCurrentInspectorSelection())

		secondScope = service.scope
		assert secondScope is not None
		secondIdentity = secondScope.targetIdentity
		assert secondIdentity is not None
		self.assertIn(("providerIdentifier", "second"), secondIdentity.providerEvidence)
		self.assertNotEqual(firstIdentity, secondIdentity)
		self.assertIs(service.historySnapshot().boundaries[-1].reason, BoundaryReason.SWITCHED)
		self.assertIn("Selected element", service.historySnapshot().boundaries[-1].detail)

	def test_restart_with_shared_source_instances_keeps_forwarding(self) -> None:
		service = _service()
		source = NvdaEventSource()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		current = [_TrackedEventObject("first")]
		sessionType: Any = EventMonitorSession
		session: Any = sessionType(
			service=service,
			workspace=workspace,
			nvdaSource=source,
			selectionResolver=lambda: current[0],
			scheduleLater=scheduler.schedule,
		)
		session.open()
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		current[0] = _TrackedEventObject("second")

		self.assertTrue(session.restartWithCurrentInspectorSelection())
		self.assertTrue(source.active)
		self.assertTrue(source.forward(NvdaEventType.FOCUS, current[0]))
		self.assertEqual(1, service.drain())
		self.assertEqual("second", service.retainedRows()[-1].objectName)

	def test_element_and_subtree_resolution_never_widens_to_broad(self) -> None:
		for kind in (MonitorScopeKind.ELEMENT, MonitorScopeKind.SUBTREE, MonitorScopeKind.APPLICATION):
			with self.subTest(kind=kind):
				service = _service()
				session = EventMonitorSession(
					service=service,
					workspace=_FakeWorkspace(),  # type: ignore[arg-type]
					nvdaSource=NvdaEventSource(),
					selectionResolver=lambda: (_ for _ in ()).throw(LookupError("no selection")),
					scheduleLater=_FakeScheduler().schedule,
				)

				self.assertFalse(session.start(kind))
				self.assertFalse(service.active)
				self.assertIsNone(service.scope)
				self.assertEqual(ScopeUnavailableReason.NO_SELECTION, session.lastScopeFailure())

	def test_each_unusable_selection_reports_its_own_reason(self) -> None:
		cases: tuple[tuple[Callable[[], object], ScopeUnavailableReason], ...] = (
			(
				lambda: (_ for _ in ()).throw(MonitorScopeUnavailable(ScopeUnavailableReason.NO_SELECTION)),
				ScopeUnavailableReason.NO_SELECTION,
			),
			(
				lambda: (_ for _ in ()).throw(
					MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_OFFLINE),
				),
				ScopeUnavailableReason.SELECTION_OFFLINE,
			),
			(lambda: None, ScopeUnavailableReason.SELECTION_UNRESOLVED),
			(
				lambda: SimpleNamespace(processID=-1, appModule=SimpleNamespace(appName="firefox")),
				ScopeUnavailableReason.NO_PROCESS,
			),
			(
				lambda: SimpleNamespace(processID=4242, appModule=SimpleNamespace(appName="firefox")),
				ScopeUnavailableReason.NO_IDENTITY,
			),
		)
		for resolver, expected in cases:
			with self.subTest(reason=expected):
				service = _service()
				session = EventMonitorSession(
					service=service,
					workspace=_FakeWorkspace(),  # type: ignore[arg-type]
					nvdaSource=NvdaEventSource(),
					selectionResolver=resolver,
					scheduleLater=_FakeScheduler().schedule,
				)

				self.assertFalse(session.start(MonitorScopeKind.ELEMENT))
				self.assertFalse(service.active)
				self.assertEqual(expected, session.lastScopeFailure())

	def test_a_refused_restart_retains_rows_and_the_frozen_target(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		selection: list[object] = [_TrackedEventObject("first-target")]
		session = EventMonitorSession(
			service=service,
			workspace=workspace,  # type: ignore[arg-type]
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: selection[0],
			scheduleLater=scheduler.schedule,
		)
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		self.assertTrue(session.nvdaSource.forward(NvdaEventType.FOCUS, selection[0]))
		self.assertEqual(1, service.drain())
		frozenScope = service.scope

		selection[0] = SimpleNamespace(processID=4242, appModule=SimpleNamespace(appName="firefox"))
		self.assertFalse(session.restartWithCurrentInspectorSelection())

		self.assertEqual(ScopeUnavailableReason.NO_IDENTITY, session.lastScopeFailure())
		self.assertTrue(service.active)
		self.assertIs(frozenScope, service.scope)
		self.assertEqual(1, len(service.retainedRows()))

	def test_stale_uia_com_failure_stops_the_frozen_target(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		target = _StaleUiaObject()
		session = EventMonitorSession(
			service=service,
			workspace=workspace,  # type: ignore[arg-type]
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: target,
			scheduleLater=scheduler.schedule,
		)
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))

		target.stale = True
		session._pump(session._pumpGeneration)

		self.assertFalse(service.active)
		self.assertIs(
			service.historySnapshot().boundaries[-1].targetLifecycleReason,
			TargetLifecycleReason.COM_FAILURE,
		)

	def test_uia_element_property_com_failure_stops_the_frozen_target(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		target = _UiaElementFailureObject()
		session = EventMonitorSession(
			service=service,
			workspace=workspace,  # type: ignore[arg-type]
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: target,
			scheduleLater=scheduler.schedule,
		)
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		target._uiaElementFails = True

		session._pump(session._pumpGeneration)

		self.assertFalse(service.active)
		self.assertIs(
			service.historySnapshot().boundaries[-1].targetLifecycleReason,
			TargetLifecycleReason.COM_FAILURE,
		)

	def test_com_liveness_reads_are_throttled_through_the_watchdog_seam(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		target = _TrackedEventObject("target")
		now = [0.0]
		watchdogCalls: list[object] = []

		def cancellable(action: Callable[[], bool]) -> bool:
			watchdogCalls.append(action)
			return action()

		def windowIsValid(_hwnd: int) -> bool:
			return True

		def windowIsHung(_hwnd: int) -> bool:
			return False

		sessionType: Any = EventMonitorSession
		session: Any = sessionType(
			service=service,
			workspace=workspace,
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: target,
			scheduleLater=scheduler.schedule,
			monotonicMs=lambda: now[0],
			cancellableExecute=cancellable,
			windowIsValid=windowIsValid,
			windowIsHung=windowIsHung,
		)
		session.open()
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))

		session._pump(session._pumpGeneration)
		interval = int(getattr(sessionModule, "TARGET_LIVENESS_INTERVAL_MS", 1_000))
		now[0] = interval - 1
		session._pump(session._pumpGeneration)
		now[0] = interval
		session._pump(session._pumpGeneration)

		self.assertEqual(2, len(watchdogCalls))

	def test_hung_window_evidence_stops_before_any_provider_read(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		target = _StaleUiaObject()
		session = EventMonitorSession(
			service=service,
			workspace=workspace,  # type: ignore[arg-type]
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: target,
			scheduleLater=scheduler.schedule,
		)
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		session._targetIsHung = lambda: True
		target.stale = True

		session._pump(session._pumpGeneration)

		self.assertFalse(service.active)
		self.assertIs(
			service.historySnapshot().boundaries[-1].targetLifecycleReason,
			TargetLifecycleReason.HUNG,
		)

	def test_destroyed_window_evidence_stops_before_any_provider_read(self) -> None:
		service = _service()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		target = _StaleUiaObject()
		watchdogCalls: list[object] = []

		def cancellable(action: Callable[[], bool]) -> bool:
			watchdogCalls.append(action)
			return action()

		def windowIsValid(_hwnd: int) -> bool:
			return False

		def windowIsHung(_hwnd: int) -> bool:
			return False

		sessionType: Any = EventMonitorSession
		session: Any = sessionType(
			service=service,
			workspace=workspace,
			nvdaSource=NvdaEventSource(),
			selectionResolver=lambda: target,
			scheduleLater=scheduler.schedule,
			cancellableExecute=cancellable,
			windowIsValid=windowIsValid,
			windowIsHung=windowIsHung,
		)
		session.open()
		self.assertTrue(session.start(MonitorScopeKind.ELEMENT))
		target.stale = True

		session._pump(session._pumpGeneration)

		self.assertFalse(service.active)
		self.assertEqual([], watchdogCalls)
		self.assertIs(
			service.historySnapshot().boundaries[-1].targetLifecycleReason,
			TargetLifecycleReason.DESTROYED,
		)

	def test_dispose_is_terminal_and_refuses_reopen(self) -> None:
		session, _source, workspace, _scheduler = self._open()
		session.dispose()
		self.assertFalse(session.service.active)
		session.open()
		self.assertFalse(workspace.isOpen)
		self.assertFalse(session.forwardRaw(RawUiaFamily.ALERT, _fakeObject()))


class RawFamilyForwardingTests(unittest.TestCase):
	def test_subtree_matching_short_circuits_exact_targets_and_first_matching_ancestor(self) -> None:
		for sourceKind in ("nvda", "raw"):
			with self.subTest(source=sourceKind, match="exact"):
				root = _TrackedEventObject("root")
				identity = targetIdentityFromObject(root)
				assert identity is not None
				service = _service()
				scope = MonitorScope.subtree("firefox", 4242, identity)
				if sourceKind == "nvda":
					source: Any = NvdaEventSource()
					service.start(scope, (source,))
					self.assertTrue(source.forward(NvdaEventType.FOCUS, root))
				else:
					source = RawUiaEventSource(clientFactory=None)
					service.start(
						scope,
						(source,),
						activeFilter=EventFilter(
							nvdaTypes=frozenset({NvdaEventType.FOCUS}),
							rawFamilies=frozenset({RawUiaFamily.ALERT}),
						),
					)
					self.assertTrue(source.forward(RawUiaFamily.ALERT, root))
				self.assertEqual(0, root.parentReads)

			with self.subTest(source=sourceKind, match="first-ancestor"):
				aboveRoot = _TrackedEventObject("above-root")
				root = _TrackedEventObject("root", parent=aboveRoot)
				child = _TrackedEventObject("child", parent=root)
				identity = targetIdentityFromObject(root)
				assert identity is not None
				service = _service()
				scope = MonitorScope.subtree("firefox", 4242, identity)
				if sourceKind == "nvda":
					source = NvdaEventSource()
					service.start(scope, (source,))
					self.assertTrue(source.forward(NvdaEventType.FOCUS, child))
				else:
					source = RawUiaEventSource(clientFactory=None)
					service.start(
						scope,
						(source,),
						activeFilter=EventFilter(
							nvdaTypes=frozenset({NvdaEventType.FOCUS}),
							rawFamilies=frozenset({RawUiaFamily.ALERT}),
						),
					)
					self.assertTrue(source.forward(RawUiaFamily.ALERT, child))
				self.assertEqual(1, child.parentReads)
				self.assertEqual(0, root.parentReads)

	def test_selected_raw_family_forwards_live_events(self) -> None:
		service = _service()
		source = NvdaEventSource()
		raw = RawUiaEventSource(clientFactory=None)
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=raw,
			workspace=workspace,
			scheduler=scheduler,
		)
		session.open()
		self.assertTrue(session.start(MonitorScopeKind.APPLICATION))

		# Default filter excludes every raw family, so a raw event is not retained yet.
		self.assertFalse(session.forwardRaw(RawUiaFamily.ALERT, _fakeObject(name="alarm")))
		self.assertTrue(scheduler.tick())
		self.assertEqual(0, len(service.retainedRows()))

		# Enable one raw family live; the change propagates into the subscribed raw source at once.
		service.changeFilter(
			EventFilter(
				nvdaTypes=frozenset({NvdaEventType.FOCUS}),
				rawFamilies=frozenset({RawUiaFamily.ALERT}),
			),
		)
		self.assertTrue(session.forwardRaw(RawUiaFamily.ALERT, _fakeObject(name="alarm")))
		self.assertTrue(scheduler.tick())
		rows = service.retainedRows()
		self.assertEqual(1, len(rows))
		self.assertTrue(rows[0].rawEvent)
		self.assertEqual("alert", rows[0].eventType)

	def test_every_declared_family_has_a_bridge_and_forwards(self) -> None:
		service = _service()
		raw = RawUiaEventSource(clientFactory=None)
		allRaw = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset(RawUiaFamily),
		)
		service.start(MonitorScope.pinned("firefox", 4242), (raw,), activeFilter=allRaw)
		for family in RawUiaFamily:
			self.assertTrue(
				raw.forward(family, _fakeObject(name=family.value)),
				msg=f"{family.value} should forward",
			)
		self.assertEqual(len(tuple(RawUiaFamily)), service.drain())


class LiveFilterChangeTests(unittest.TestCase):
	def test_disabled_type_stops_being_retained_and_enabled_type_begins(self) -> None:
		service = _service()
		source = NvdaEventSource()
		service.start(MonitorScope.pinned("firefox", 4242), (source,))

		self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name="one")))
		self.assertEqual(1, service.drain())

		# Narrow to value changes only, live, with no Stop/Start.
		service.changeFilter(
			EventFilter(nvdaTypes=frozenset({NvdaEventType.VALUE_CHANGE}), rawFamilies=frozenset()),
		)
		# The now-disabled focus type is refused at the source and never retained again.
		self.assertFalse(source.forward(NvdaEventType.FOCUS, _fakeObject(name="two")))
		self.assertEqual(0, service.drain())
		# The newly enabled value type begins immediately.
		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, _fakeObject(name="three", value="v")))
		self.assertEqual(1, service.drain())
		self.assertEqual(2, len(service.retainedRows()))

	def test_queued_receipt_of_a_disabled_type_is_dropped_at_drain(self) -> None:
		service = _service()
		source = NvdaEventSource()
		service.start(MonitorScope.pinned("firefox", 4242), (source,))
		# A focus receipt is admitted and queued under the default filter.
		self.assertTrue(source.forward(NvdaEventType.FOCUS, _fakeObject(name="queued")))
		self.assertEqual(1, service.pendingReceipts())
		# The filter drops focus before the pump drains; the queued receipt is not retained.
		service.changeFilter(
			EventFilter(nvdaTypes=frozenset({NvdaEventType.VALUE_CHANGE}), rawFamilies=frozenset()),
		)
		self.assertEqual(0, service.drain())
		self.assertEqual(0, len(service.retainedRows()))


class DetailExtractionTests(unittest.TestCase):
	def _rowDetail(
		self,
		eventType: NvdaEventType,
		obj: object,
		*,
		redact: bool = True,
	) -> str | None:
		service = _service(redact=redact)
		source = NvdaEventSource()
		service.start(MonitorScope.pinned("firefox", 4242), (source,))
		self.assertTrue(source.forward(eventType, obj))
		self.assertEqual(1, service.drain())
		return service.retainedRows()[0].detail

	def test_value_change_reports_the_value(self) -> None:
		detail = self._rowDetail(NvdaEventType.VALUE_CHANGE, _fakeObject(value="hello"))
		self.assertEqual("value=hello", detail)

	def test_protected_value_change_is_redacted_not_leaked(self) -> None:
		detail = self._rowDetail(
			NvdaEventType.VALUE_CHANGE,
			_fakeObject(value="secret", protected=True),
		)
		self.assertIsNone(detail)

	def test_state_change_reports_sorted_states_and_is_never_protected(self) -> None:
		detail = self._rowDetail(
			NvdaEventType.STATE_CHANGE,
			_fakeObject(value="secret", protected=True, states=("focused", "checked")),
		)
		# States are a public structural summary: even on a protected object they are not redacted.
		self.assertEqual("states=[checked, focused]", detail)

	def test_description_change_reports_the_description(self) -> None:
		detail = self._rowDetail(
			NvdaEventType.DESCRIPTION_CHANGE,
			_fakeObject(description="a helpful hint"),
		)
		self.assertEqual("description=a helpful hint", detail)

	def test_live_region_reports_politeness_and_is_never_protected(self) -> None:
		detail = self._rowDetail(
			NvdaEventType.LIVE_REGION,
			_fakeObject(protected=True, politeness="polite"),
		)
		self.assertEqual("politeness=polite", detail)

	def test_name_change_reports_the_name(self) -> None:
		detail = self._rowDetail(NvdaEventType.NAME_CHANGE, _fakeObject(name="Renamed"))
		self.assertEqual("name=Renamed", detail)

	def test_navigator_object_reports_focus_flag_only_when_focused(self) -> None:
		service = _service()
		source = NvdaEventSource()
		service.start(MonitorScope.pinned("firefox", 4242), (source,))
		self.assertTrue(
			source.forward(NvdaEventType.NAVIGATOR_OBJECT, _fakeObject(name="nav"), isFocus=True),
		)
		self.assertEqual(1, service.drain())
		self.assertEqual("isFocus=True", service.retainedRows()[0].detail)

	def test_plain_focus_carries_no_detail(self) -> None:
		detail = self._rowDetail(NvdaEventType.FOCUS, _fakeObject(name="focused", value="ignored"))
		self.assertEqual("", detail)


class TeardownSafetyTests(unittest.TestCase):
	def test_forward_raw_is_safe_when_no_raw_source(self) -> None:
		service = _service()
		source = NvdaEventSource()
		session = _session(
			service=service,
			nvdaSource=source,
			rawSource=None,
			workspace=_FakeWorkspace(),
			scheduler=_FakeScheduler(),
		)
		session.open()
		self.assertFalse(session.forwardRaw(RawUiaFamily.ALERT, _fakeObject()))

	def test_secure_transition_closes_the_session_pump(self) -> None:
		composition: ProductionComposition
		composition, _, _, _ = _composition()
		composition.start()
		composition.useEventSource(NvdaEventSource())
		session = composition._ensureEventMonitorSession()
		workspace = _FakeWorkspace()
		scheduler = _FakeScheduler()
		session._workspace = workspace  # type: ignore[assignment]
		session._scheduleLater = scheduler.schedule
		session._selectionResolver = lambda: _TrackedEventObject("monitored-target")
		session.open()
		self.assertTrue(session.start())
		self.assertTrue(session.pumpRunning)

		composition.transition("secure")
		self.assertFalse(session.pumpRunning)
		self.assertFalse(session.service.active)
		self.assertFalse(scheduler.armed)


if __name__ == "__main__":  # pragma: no cover
	_ = unittest.main()
