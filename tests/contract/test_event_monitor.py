# pyright: reportPrivateUsage=false
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from typing import Any
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.domain import event_monitor as eventMonitorDomain
from addon.globalPlugins.keystone.application import event_monitor_service as eventMonitorServiceModule
from addon.globalPlugins.keystone.adapters.nvda.event_sources import NvdaEventSource
from addon.globalPlugins.keystone.adapters.windows.raw_uia_events import RawUiaEventSource
from addon.globalPlugins.keystone.adapters.wx.inspector_frame import EventsWorkspace
from addon.globalPlugins.keystone.application.event_monitor_service import (
	EventActionOutcome,
	EventMonitorService,
)
from addon.globalPlugins.keystone.application.lifecycle import LifecycleService
from addon.globalPlugins.keystone.domain.event_monitor import (
	BoundaryReason,
	EventBackend,
	EventCopyFormat,
	EventFilter,
	MonitorScope,
	NvdaEventType,
	RawUiaFamily,
	RetentionPolicy,
	renderSelectedEvents,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy
from addon.globalPlugins.keystone.domain.settings import (
	SettingId,
	SettingsSnapshot,
	validateCandidate,
)
from addon.globalPlugins.keystone.domain.sounds import (
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	SoundRequest,
)
from addon.globalPlugins.keystone.ports.effects import (
	ClipboardRequest,
	EffectResult,
	FeedbackRequest,
	PortError,
	PortOutcome,
	PortStatus,
)
from addon.globalPlugins.keystone.ports.event_sources import (
	EventSink,
	SubscriptionRequest,
)
from tests.live import probe_installed_event_sources as installedProbe
from tests.live import probe_raw_uia_subscription as rawProbe


class _Clock:
	def __init__(self, start: float = 1_000.0, step: float = 1.0) -> None:
		super().__init__()
		self._value = start
		self._step = step

	def ms(self) -> float:
		self._value += self._step
		return self._value


class _WallClock:
	def __init__(self) -> None:
		super().__init__()
		self._value = 1_700_000_000_000

	def now(self) -> int:
		self._value += 1_000
		return self._value


class _RecordingClipboard:
	def __init__(self, *, fail: bool = False) -> None:
		super().__init__()
		self.requests: list[ClipboardRequest] = []
		self._fail = fail

	def copyText(self, request: ClipboardRequest) -> EffectResult:
		self.requests.append(request)
		if self._fail:
			return EffectResult(PortStatus("failed", 1), error=PortError("KS.CLIPBOARD.FAILED"))
		return EffectResult(PortStatus("ready", request.context.generation or 0), PortOutcome("copied"))


class _SilentFeedback:
	def __init__(self) -> None:
		super().__init__()
		self.messages: list[str] = []
		self.requests: list[FeedbackRequest] = []

	def announce(self, request: FeedbackRequest) -> EffectResult:
		self.requests.append(request)
		messageId = getattr(request, "messageId", "")
		self.messages.append(messageId if isinstance(messageId, str) else "")
		return EffectResult(PortStatus("ready", 1), PortOutcome("announced"))


class _RecordingSounds:
	"""A ``WorkflowSounds`` seam that records requests instead of scheduling audio.

	Every monitor assertion reduces to "which typed event, owned by which generation, coalesced on
	which milestone" - never to sound. The recorder never raises, so a passing test proves the
	service reached the seam after it spoke, not that anything played.
	"""

	def __init__(self) -> None:
		super().__init__()
		self.requests: list[SoundRequest] = []
		self.ticks = 0
		self.invalidations: list[SoundOwner | None] = []

	def emit(self, request: SoundRequest) -> None:
		self.requests.append(request)

	def tick(self) -> None:
		self.ticks += 1

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		self.invalidations.append(owner)

	def events(self) -> list[CueEventId]:
		return [request.event for request in self.requests]


class _FailingSounds:
	"""A seam whose every operation raises, proving sound failures never reach speech or history."""

	def emit(self, request: SoundRequest) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and history")

	def tick(self) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and history")

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and history")


class _FailingSource:
	"""An event source whose subscription always raises, proving a failed start sounds its cue."""

	@property
	def backend(self) -> EventBackend:
		return EventBackend.NVDA

	@property
	def families(self) -> tuple[str, ...]:
		return ()

	@property
	def active(self) -> bool:
		return False

	@property
	def subscriptionCount(self) -> int:
		return 0

	def subscribe(self, sink: EventSink, request: SubscriptionRequest) -> None:
		raise RuntimeError("a source that cannot subscribe must fail the monitor start")

	def unsubscribe(self) -> None:
		return None

	def updateFilter(self, activeFilter: EventFilter) -> None:
		_ = activeFilter
		return None


class _ResubscribeFailingSource:
	"""A shared source that can fail a candidate subscription and its restoration."""

	def __init__(self, *, failRestoration: bool = False) -> None:
		super().__init__()
		self._failRestoration = failRestoration
		self.requests: list[SubscriptionRequest] = []
		self.unsubscribeCalls = 0
		self._active = False

	@property
	def backend(self) -> EventBackend:
		return EventBackend.NVDA

	@property
	def families(self) -> tuple[str, ...]:
		return ()

	@property
	def active(self) -> bool:
		return self._active

	@property
	def subscriptionCount(self) -> int:
		return int(self._active)

	def subscribe(self, sink: EventSink, request: SubscriptionRequest) -> None:
		_ = sink
		self.requests.append(request)
		self._active = False
		if len(self.requests) == 2 or (self._failRestoration and len(self.requests) == 3):
			raise RuntimeError("shared source subscription failed")
		self._active = True

	def unsubscribe(self) -> None:
		self.unsubscribeCalls += 1
		self._active = False

	def updateFilter(self, activeFilter: EventFilter) -> None:
		_ = activeFilter


class _Settings:
	def __init__(self, *, eventRows: int = 2_000, detail: int = 100, redact: bool = True) -> None:
		super().__init__()
		self.eventRows = eventRows
		self.detail = detail
		self.redact = redact

	def snapshot(self) -> SettingsSnapshot:
		return replace(
			SettingsSnapshot.defaults(settingsRevision=3),
			eventRows=self.eventRows,
			eventDetailCharacters=self.detail,
			redactProtectedText=self.redact,
		)

	def policy(self) -> PrivacyPolicy:
		return PrivacyPolicy(policyRevision=5, settingsRevision=3, redactProtectedText=self.redact)


def _fakeObject(
	*,
	name: str = "Search",
	roleName: str = "editableText",
	pid: int = 4242,
	app: str = "firefox",
	value: str = "",
	protected: bool = False,
) -> object:
	return SimpleNamespace(
		name=name,
		role=SimpleNamespace(name=roleName),
		processID=pid,
		appModule=SimpleNamespace(appName=app),
		value=value,
		isProtected=protected,
	)


class _Harness:
	def __init__(
		self,
		*,
		settings: _Settings | None = None,
		clipboard: _RecordingClipboard | None = None,
		picker: Callable[[], Path | None] | None = None,
		sound: _RecordingSounds | _FailingSounds | None = None,
		runtimeLog: Callable[[str, tuple[tuple[str, str | int | bool], ...]], None] | None = None,
	) -> None:
		super().__init__()
		self.settings = settings or _Settings()
		self.clipboard = clipboard or _RecordingClipboard()
		self.feedback = _SilentFeedback()
		self.lifecycle = LifecycleService()
		self.clock = _Clock()
		self.wall = _WallClock()
		self.histories: list[object] = []
		self.service = EventMonitorService(
			lifecycle=self.lifecycle,
			settings=self.settings.snapshot,
			policy=self.settings.policy,
			clipboard=self.clipboard,
			feedback=self.feedback,
			monotonic=self.clock.ms,
			wallClock=self.wall.now,
			destinationPicker=picker,
			historyListener=self.histories.append,
			sound=sound,
			runtimeLog=runtimeLog,
		)
		self.source = NvdaEventSource(monotonicMs=self.clock.ms)

	def start(
		self,
		*,
		pid: int = 4242,
		app: str = "firefox",
		targetName: str | None = None,
	) -> None:
		self.service.start(MonitorScope.pinned(app, pid), (self.source,), targetName=targetName)

	def forwardFocus(self, **kwargs: object) -> bool:
		return self.source.forward(NvdaEventType.FOCUS, _fakeObject(**kwargs))  # type: ignore[arg-type]


class EventMonitorRuntimeLogTests(unittest.TestCase):
	def test_default_timestamp_uses_the_host_local_timezone(self) -> None:
		wallClockMs = 1_700_000_000_123

		moment = eventMonitorServiceModule.datetime.fromtimestamp(wallClockMs / 1_000).astimezone()
		expected = (
			moment.strftime("%I:%M:%S.") + f"{moment.microsecond // 1_000:03d} " + moment.strftime("%p")
		)

		self.assertEqual(expected, eventMonitorServiceModule._defaultTimestamp(wallClockMs))

	def test_a_monitoring_session_records_its_own_start_and_stop(self) -> None:
		records: list[tuple[str, dict[str, str | int | bool]]] = []
		harness = _Harness(runtimeLog=lambda code, fields: records.append((code, dict(fields))))

		harness.start()
		self.assertTrue(harness.forwardFocus(name="Search"))
		self.assertEqual(1, harness.service.drain())
		harness.service.stop()

		codes = [code for code, _fields in records]
		self.assertEqual(["KS.EVENT.MONITOR_STARTED", "KS.EVENT.MONITOR_STOPPED"], codes)
		started = records[0][1]
		self.assertEqual("application", started["scopeKind"])
		self.assertIs(False, started["rawEventsEnabled"])
		stopped = records[1][1]
		self.assertEqual("stopped", stopped["stopReason"])
		self.assertEqual(1, stopped["retainedCount"])

	def test_a_broad_scope_is_recorded_as_its_own_warning(self) -> None:
		records: list[str] = []
		harness = _Harness(runtimeLog=lambda code, _fields: records.append(code))

		harness.service.start(MonitorScope.broadScope(), (harness.source,))

		self.assertIn("KS.EVENT.BROAD_SCOPE_ENABLED", records)

	def test_a_failing_log_sink_never_interrupts_monitoring(self) -> None:
		def explode(_code: str, _fields: tuple[tuple[str, str | int | bool], ...]) -> None:
			raise OSError("the log is unavailable")

		harness = _Harness(runtimeLog=explode)

		harness.start()

		self.assertTrue(harness.service.active)
		self.assertTrue(harness.forwardFocus(name="Search"))
		self.assertEqual(1, harness.service.drain())


class EventMonitorScopeSwitchTests(unittest.TestCase):
	def test_switch_reannounces_active_risks_and_records_a_session_start(self) -> None:
		records: list[str] = []
		sounds = _RecordingSounds()
		harness = _Harness(
			settings=_Settings(redact=False),
			sound=sounds,
			runtimeLog=lambda code, _fields: records.append(code),
		)
		rawFilter = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.ALERT}),
		)
		harness.service.start(MonitorScope.pinned("firefox", 4242), (harness.source,), activeFilter=rawFilter)
		harness.feedback.messages.clear()
		sounds.requests.clear()
		records.clear()

		self.assertTrue(harness.service.switchScope(MonitorScope.broadScope(), (harness.source,)))

		self.assertEqual(
			[
				"events.risk.broadScope",
				"events.risk.rawUia",
				"events.risk.redactionDisabled",
			],
			harness.feedback.messages,
		)
		self.assertEqual(
			[
				CueEventId.BROAD_EVENT_SCOPE,
				CueEventId.RAW_UIA_FALLBACK,
				CueEventId.REDACTION_DISABLED,
			],
			sounds.events(),
		)
		self.assertEqual(
			["KS.EVENT.MONITOR_STARTED", "KS.EVENT.BROAD_SCOPE_ENABLED"],
			records,
		)

	def test_failed_shared_resubscription_cleans_up_then_restores_old_session(self) -> None:
		harness = _Harness()
		source = _ResubscribeFailingSource()
		oldScope = MonitorScope.pinned("firefox", 4242)
		harness.service.start(oldScope, (source,))
		oldGeneration = harness.service.generation

		self.assertFalse(harness.service.switchScope(MonitorScope.pinned("chrome", 4321), (source,)))

		self.assertTrue(harness.service.active)
		self.assertEqual(oldScope, harness.service.scope)
		self.assertEqual(oldGeneration, harness.service.generation)
		self.assertTrue(source.active)
		self.assertEqual(oldScope, source.requests[-1].scope)
		self.assertEqual(oldGeneration, source.requests[-1].generation)
		self.assertGreaterEqual(source.unsubscribeCalls, 1)

	def test_failed_shared_resubscription_stops_when_rollback_cannot_restore(self) -> None:
		records: list[str] = []
		harness = _Harness(runtimeLog=lambda code, _fields: records.append(code))
		source = _ResubscribeFailingSource(failRestoration=True)
		harness.service.start(MonitorScope.pinned("firefox", 4242), (source,))

		self.assertFalse(harness.service.switchScope(MonitorScope.pinned("chrome", 4321), (source,)))

		self.assertFalse(harness.service.active)
		self.assertFalse(source.active)
		self.assertEqual(0, harness.service.subscriptionCount)
		self.assertIn("events.monitor.failed", harness.feedback.messages)
		self.assertIn("KS.EVENT.MONITOR_SWITCH_ROLLBACK_FAILED", records)


class EventMonitorTracerTests(unittest.TestCase):
	def test_selected_events_copy_json_text_markdown_with_context(self) -> None:
		harness = _Harness()
		harness.start()
		self.assertTrue(harness.forwardFocus(name="Search", value="query text"))
		self.assertEqual(harness.service.drain(), 1)

		rows = harness.service.retainedRows()
		self.assertEqual(len(rows), 1)
		row = rows[0]
		self.assertEqual(row.eventType, "focus")
		self.assertEqual(row.objectName, "Search")
		self.assertEqual(row.processId, 4242)
		self.assertEqual(row.application, "firefox")
		self.assertFalse(row.redacted)

		selection = harness.service.buildSelection(rows)
		jsonText = renderSelectedEvents(selection, EventCopyFormat.JSON)
		plainText = renderSelectedEvents(selection, EventCopyFormat.TEXT)
		markdownText = renderSelectedEvents(selection, EventCopyFormat.MARKDOWN)

		payload = json.loads(jsonText)
		self.assertEqual(payload["provenance"]["application"], "firefox")
		self.assertEqual(payload["provenance"]["processId"], 4242)
		self.assertFalse(payload["provenance"]["broadScope"])
		self.assertEqual(len(payload["events"]), 1)
		self.assertEqual(payload["events"][0]["event"], "focus")
		self.assertEqual(payload["events"][0]["object"], "Search")
		self.assertIn("focus", payload["provenance"]["filter"])

		for text in (plainText, markdownText):
			self.assertIn("firefox", text)
			self.assertIn("focus", text)
			self.assertIn("Search", text)
		self.assertIn("Scope:", plainText)
		self.assertIn("| Time | Event |", markdownText)

	def test_selected_events_copy_redacts_protected_content(self) -> None:
		harness = _Harness()
		harness.start()
		self.assertTrue(harness.forwardFocus(name="secret account", value="hunter2", protected=True))
		self.assertEqual(harness.service.drain(), 1)
		row = harness.service.retainedRows()[0]
		self.assertTrue(row.redacted)
		self.assertIsNone(row.objectName)

		jsonText = harness.service.renderSelection((row,), EventCopyFormat.JSON)
		self.assertNotIn("secret account", jsonText)
		self.assertNotIn("hunter2", jsonText)

		outcome = harness.service.copySelectedEvents((row,), EventCopyFormat.TEXT)
		self.assertEqual(outcome.status, "copied")
		self.assertTrue(outcome.clipboardRequested)
		self.assertNotIn("secret account", harness.clipboard.requests[0].text)

	def test_selected_events_keep_protected_content_unless_redaction_is_opted_into(self) -> None:
		harness = _Harness(settings=_Settings(redact=False))
		harness.start()
		self.assertTrue(harness.forwardFocus(name="secret account", value="hunter2", protected=True))
		self.assertEqual(harness.service.drain(), 1)
		row = harness.service.retainedRows()[0]

		self.assertFalse(row.redacted)
		self.assertEqual("secret account", row.objectName)
		self.assertIn("secret account", harness.service.renderSelection((row,), EventCopyFormat.JSON))

	def test_a_shortened_detail_leaves_an_empty_changed_value_reported_as_empty(self) -> None:
		harness = _Harness(settings=_Settings(detail=8))
		harness.start()
		# A live region with a long politeness detail whose announced name reads as empty.
		liveRegion = SimpleNamespace(
			name="",
			role=SimpleNamespace(name="alert"),
			processID=4242,
			appModule=SimpleNamespace(appName="firefox"),
			value="",
			isProtected=False,
			liveRegionPoliteness=SimpleNamespace(name="assertive"),
		)
		self.assertTrue(harness.source.forward(NvdaEventType.LIVE_REGION, liveRegion))
		self.assertEqual(1, harness.service.drain())

		row = harness.service.retainedRows()[0]

		self.assertTrue(row.truncated)
		self.assertFalse(row.changedValueTruncated)
		self.assertEqual("(empty)", row.changedValueText)

	def test_a_shortened_changed_value_says_so_on_its_own(self) -> None:
		harness = _Harness(settings=_Settings(detail=4))
		harness.start()
		self.assertTrue(
			harness.source.forward(
				NvdaEventType.VALUE_CHANGE,
				_fakeObject(value="a value far past the configured limit"),
			),
		)
		self.assertEqual(1, harness.service.drain())

		row = harness.service.retainedRows()[0]

		self.assertTrue(row.changedValueTruncated)
		self.assertEqual("a va", row.changedValueText)

	def test_export_copies_path_only_after_atomic_commit(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			destination = Path(directory) / "events.json"
			harness = _Harness(picker=lambda: destination)
			harness.start()
			self.assertTrue(harness.forwardFocus())
			self.assertEqual(harness.service.drain(), 1)

			outcome = harness.service.exportEventHistory()
			self.assertEqual(outcome.status, "published")
			self.assertEqual(outcome.committedPath, str(destination))
			self.assertTrue(outcome.clipboardRequested)
			self.assertEqual(len(harness.clipboard.requests), 1)
			self.assertEqual(harness.clipboard.requests[0].text, str(destination))
			self.assertTrue(destination.exists())
			exported = json.loads(destination.read_text(encoding="utf-8"))
			self.assertEqual(exported["metadata"]["exportedEventCount"], 1)

	def test_export_cancellation_writes_nothing_and_copies_nothing(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			destination = Path(directory) / "events.json"
			harness = _Harness(picker=lambda: None)
			harness.start()
			self.assertTrue(harness.forwardFocus())
			self.assertEqual(harness.service.drain(), 1)

			outcome = harness.service.exportEventHistory()
			self.assertEqual(outcome.status, "cancelled")
			self.assertFalse(outcome.clipboardRequested)
			self.assertEqual(harness.clipboard.requests, [])
			self.assertFalse(destination.exists())

	def test_export_write_failure_copies_nothing(self) -> None:
		missing = Path("Z:/keystone-nonexistent-directory-xyz") / "events.json"
		harness = _Harness(picker=lambda: missing)
		harness.start()
		self.assertTrue(harness.forwardFocus())
		self.assertEqual(harness.service.drain(), 1)

		outcome = harness.service.exportEventHistory()
		self.assertEqual(outcome.status, "failed")
		self.assertFalse(outcome.clipboardRequested)
		self.assertEqual(harness.clipboard.requests, [])

	def test_export_stale_generation_writes_nothing(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			destination = Path(directory) / "events.json"
			state: dict[str, LifecycleService] = {}

			def picker() -> Path | None:
				state["lifecycle"].transition("secure")
				return destination

			harness = _Harness(picker=picker)
			state["lifecycle"] = harness.lifecycle
			harness.start()
			self.assertTrue(harness.forwardFocus())
			self.assertEqual(harness.service.drain(), 1)

			outcome = harness.service.exportEventHistory()
			self.assertEqual(outcome.status, "stale")
			self.assertFalse(outcome.clipboardRequested)
			self.assertEqual(harness.clipboard.requests, [])
			self.assertFalse(destination.exists())

	def test_export_clipboard_failure_does_not_claim_publication(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			destination = Path(directory) / "events.json"
			harness = _Harness(
				clipboard=_RecordingClipboard(fail=True),
				picker=lambda: destination,
			)
			harness.start()
			self.assertTrue(harness.forwardFocus())
			self.assertEqual(harness.service.drain(), 1)

			outcome = harness.service.exportEventHistory()
			self.assertEqual(outcome.status, "failed")
			self.assertFalse(outcome.clipboardRequested)
			self.assertEqual(outcome.committedPath, str(destination))

	def test_export_metadata_includes_scope_drops_settings_and_sessions(self) -> None:
		harness = _Harness(settings=_Settings(eventRows=2))
		harness.start(pid=4242, app="firefox")
		self.assertTrue(harness.forwardFocus(name="first"))
		self.assertTrue(harness.forwardFocus(name="second"))
		self.assertEqual(harness.service.drain(), 2)

		metadata = harness.service.exportMetadata()
		self.assertEqual(metadata.application, "firefox")
		self.assertEqual(metadata.processId, 4242)
		self.assertFalse(metadata.broadScope)
		self.assertIn("4242", metadata.scopeText)
		self.assertFalse(metadata.rawEventsEnabled)
		self.assertTrue(metadata.redactionEnabled)
		self.assertEqual(metadata.exportedEventCount, 1)
		self.assertEqual(metadata.retainedRowDrops, 1)
		self.assertEqual(metadata.pendingQueueDrops, 0)
		self.assertEqual(metadata.queueCapacity, 1_000)
		self.assertEqual(metadata.drainLimit, 100)
		self.assertEqual(metadata.retentionCap, 2)
		self.assertEqual(metadata.retentionCeiling, 1_000_000)
		self.assertEqual(metadata.detailCharacters, 100)
		self.assertIn("focus", metadata.filterSummary)
		self.assertEqual(metadata.settingsRevision, 3)
		self.assertEqual(metadata.policyRevision, 5)
		self.assertTrue(metadata.sessionBoundaries)
		self.assertEqual(metadata.sessionBoundaries[0].reason.value, "started")

	def test_export_metadata_reports_broad_scope(self) -> None:
		harness = _Harness()
		harness.service.start(MonitorScope.broadScope(), (harness.source,))
		metadata = harness.service.exportMetadata()
		self.assertTrue(metadata.broadScope)
		self.assertIsNone(metadata.processId)
		self.assertIn("Broad scope", metadata.scopeText)


def _passingInstalledObservations() -> installedProbe.InstalledEventSourceObservations:
	return installedProbe.InstalledEventSourceObservations(
		callbackMaxMs=5.0,
		forwardingMaxMs=2.0,
		burst100MaxMs=50.0,
		receiptToProcessingMaxMs=10.0,
		receiptToPropertyReadMaxMs=8.0,
		eventFamiliesObserved=tuple(rawProbe.EXPECTED_EVENT_FAMILIES),
		pidMismatchAccepted=0,
		forwardingCount=1_011,
		receiptCount=1_011,
		retainedRowDrops=0,
		ownershipViolations=0,
		lateCallbacksAccepted=0,
		subscriptionsAfterTeardown=0,
		retainedMutationsAfterTeardown=0,
		secureMutations=0,
		observationWindowMs=rawProbe.OBSERVATION_WINDOW_MS,
		enabledCapabilities=("eventMonitoring", "rawUiaInspection"),
		configSectionRegistered=True,
		installedTreeReady=True,
		scopeKindsExercised=("element", "subtree", "application", "broad"),
		productionNvdaForwarded=1,
		outOfSubtreeAccepted=0,
		rawSourceModule=RawUiaEventSource.__module__,
		rawSourceType=RawUiaEventSource.__qualname__,
		nvdaSourceModule=NvdaEventSource.__module__,
		nvdaSourceType=NvdaEventSource.__qualname__,
		productionCompositionStarted=True,
		monitorStarted=True,
		monitorStopped=True,
		callbacksObservedAfterTeardown=0,
		providerAccessesAfterTeardown=0,
	)


class EventSourceAndStormTests(unittest.TestCase):
	def test_installed_archive_drives_shipped_sources_and_stops_cleanly(self) -> None:
		baseline = _passingInstalledObservations()
		passResult = installedProbe.evaluate(baseline)
		self.assertEqual(passResult.status, "pass")
		self.assertEqual(passResult.exitCode, rawProbe.EXIT_PASS)

		# The installed run reuses every fixed event-safety threshold and window; none is inferred here.
		self.assertEqual(installedProbe.CALLBACK_MAX_MS, rawProbe.CALLBACK_MAX_MS)
		self.assertEqual(installedProbe.FORWARDING_MAX_MS, rawProbe.FORWARDING_MAX_MS)
		self.assertEqual(installedProbe.BURST100_MAX_MS, rawProbe.BURST100_MAX_MS)
		self.assertEqual(installedProbe.RECEIPT_TO_PROCESSING_MAX_MS, rawProbe.RECEIPT_TO_PROCESSING_MAX_MS)
		self.assertEqual(
			installedProbe.RECEIPT_TO_PROPERTY_READ_MAX_MS,
			rawProbe.RECEIPT_TO_PROPERTY_READ_MAX_MS,
		)
		self.assertEqual(installedProbe.OBSERVATION_WINDOW_MS, rawProbe.OBSERVATION_WINDOW_MS)

		# The result schema names every required installed and shared raw-probe field.
		payload = passResult.payload
		for key in (
			"status",
			"enabledCapabilities",
			"configSectionRegistered",
			"installedTreeReady",
			"scopeKindsExercised",
			"productionNvdaForwarded",
			"outOfSubtreeAccepted",
			"rawSourceModule",
			"rawSourceType",
			"nvdaSourceModule",
			"nvdaSourceType",
			"productionCompositionStarted",
			"monitorStarted",
			"monitorStopped",
			"callbacksObservedAfterTeardown",
			"providerAccessesAfterTeardown",
			"unavailableObservations",
			"skippedObservations",
			"missingObservations",
			"callbackMaxMs",
			"forwardingMaxMs",
			"burst100MaxMs",
			"receiptToProcessingMaxMs",
			"receiptToPropertyReadMaxMs",
			"eventFamiliesObserved",
			"pidMismatchAccepted",
			"forwardingCount",
			"receiptCount",
			"retainedRowDrops",
			"ownershipViolations",
			"lateCallbacksAccepted",
			"subscriptionsAfterTeardown",
			"retainedMutationsAfterTeardown",
			"secureMutations",
			"observationWindowMs",
		):
			self.assertIn(key, payload)

		# Exact shipped identities: the probe's expected module suffix and type match the real classes.
		self.assertEqual(RawUiaEventSource.__qualname__, installedProbe.EXPECTED_RAW_SOURCE_TYPE)
		self.assertTrue(RawUiaEventSource.__module__.endswith(installedProbe.RAW_SOURCE_MODULE_SUFFIX))
		self.assertEqual(NvdaEventSource.__qualname__, installedProbe.EXPECTED_NVDA_SOURCE_TYPE)
		self.assertTrue(NvdaEventSource.__module__.endswith(installedProbe.NVDA_SOURCE_MODULE_SUFFIX))

		# Any failure of identity, capability binding, enablement, start/stop, or storm arithmetic fails.
		failing: dict[str, installedProbe.InstalledEventSourceObservations] = {
			"wrong raw module": replace(baseline, rawSourceModule="keystone.adapters.nvda.event_sources"),
			"wrong raw type": replace(baseline, rawSourceType="NvdaEventSource"),
			"wrong nvda type": replace(baseline, nvdaSourceType="RawUiaEventSource"),
			"missing raw capability": replace(baseline, enabledCapabilities=("eventMonitoring",)),
			"missing event capability": replace(baseline, enabledCapabilities=("rawUiaInspection",)),
			"missing config section": replace(baseline, configSectionRegistered=False),
			"missing installed tree": replace(baseline, installedTreeReady=False),
			"scope drift": replace(baseline, scopeKindsExercised=("application",)),
			"missing production forward": replace(baseline, productionNvdaForwarded=0),
			"out of subtree accepted": replace(baseline, outOfSubtreeAccepted=1),
			"production not started": replace(baseline, productionCompositionStarted=False),
			"monitor not started": replace(baseline, monitorStarted=False),
			"monitor not stopped": replace(baseline, monitorStopped=False),
			"family drift": replace(
				baseline,
				eventFamiliesObserved=tuple(rawProbe.EXPECTED_EVENT_FAMILIES[:-1]),
			),
			"arithmetic drift": replace(baseline, forwardingCount=1_010),
			"zero receipts": replace(baseline, forwardingCount=0, receiptCount=0),
			"pid mismatch accepted": replace(baseline, pidMismatchAccepted=1),
			"ownership violation": replace(baseline, ownershipViolations=1),
			"over callback budget": replace(baseline, callbackMaxMs=rawProbe.CALLBACK_MAX_MS + 1.0),
			"over burst budget": replace(baseline, burst100MaxMs=rawProbe.BURST100_MAX_MS + 1.0),
			"wrong window": replace(baseline, observationWindowMs=200),
		}
		for label, observations in failing.items():
			with self.subTest(failure=label):
				self.assertEqual(installedProbe.evaluate(observations).exitCode, rawProbe.EXIT_FAILED)

		retained = replace(baseline, receiptCount=100, retainedRowDrops=911)
		self.assertEqual(installedProbe.evaluate(retained).exitCode, rawProbe.EXIT_PASS)

		# Every post-teardown no-effect count must be zero, or the run is an unsafe teardown breach.
		teardown: dict[str, installedProbe.InstalledEventSourceObservations] = {
			"late callbacks": replace(baseline, lateCallbacksAccepted=1),
			"subscriptions after teardown": replace(baseline, subscriptionsAfterTeardown=1),
			"retained mutations after teardown": replace(baseline, retainedMutationsAfterTeardown=1),
			"secure mutations": replace(baseline, secureMutations=1),
			"callbacks observed after teardown": replace(baseline, callbacksObservedAfterTeardown=1),
			"provider accesses after teardown": replace(baseline, providerAccessesAfterTeardown=1),
		}
		for label, observations in teardown.items():
			with self.subTest(teardown=label):
				self.assertEqual(installedProbe.evaluate(observations).exitCode, rawProbe.EXIT_TEARDOWN)

		# An observation that could not be established outranks every other verdict.
		self.assertEqual(
			installedProbe.evaluate(replace(baseline, missingObservations=("no host",))).exitCode,
			rawProbe.EXIT_UNAVAILABLE,
		)
		self.assertEqual(
			installedProbe.evaluate(
				replace(baseline, unavailableObservations=("no host",), lateCallbacksAccepted=1),
			).exitCode,
			rawProbe.EXIT_UNAVAILABLE,
		)


class EventRetentionAndLifecycleTests(unittest.TestCase):
	"""Retention, filter, boundary, and teardown behaviour proven through the live service.

	These drive the real ``EventMonitorService`` ingest/drain/retention/lifecycle path (not the
	domain helpers in isolation) so the wiring between the shared setting layer, the retention
	policy, session boundaries, and the ordered lifecycle release is verified end to end.
	"""

	def _pump(self, harness: _Harness, count: int, *, start: int) -> None:
		"""Forward ``count`` uniquely named focus events, draining in sub-queue-capacity batches.

		Batches stay well under the 1,000-slot queue so every event becomes a retained row rather
		than a pending-queue drop, isolating retained-row cap behaviour from queue-pressure drops.
		"""

		pending = 0
		for offset in range(count):
			self.assertTrue(harness.forwardFocus(name=f"evt-{start + offset:06d}"))
			pending += 1
			if pending >= 90:
				self.assertEqual(harness.service.drain(), pending)
				pending = 0
		if pending:
			self.assertEqual(harness.service.drain(), pending)

	def test_retention_default_zero_ceiling_and_oldest_row(self) -> None:
		harness = _Harness(settings=_Settings(eventRows=2_000))
		harness.start()

		# Below the cap: every forwarded event is retained with no drops.
		self._pump(harness, 1_999, start=1)
		self.assertEqual(len(harness.service.retainedRows()), 1_999)
		self.assertEqual(harness.service.historySnapshot().drops.retainedRowDrops, 0)

		# A session marker is retained alongside rows, so it occupies one record of the total cap.
		self._pump(harness, 1, start=2_000)
		rows = harness.service.retainedRows()
		self.assertEqual(len(rows), 1_999)
		self.assertEqual(harness.service.historySnapshot().drops.retainedRowDrops, 1)
		self.assertEqual(rows[0].objectName, "evt-000002")
		self.assertEqual(rows[-1].objectName, "evt-002000")

		# One more event evicts the next oldest row while total history remains bounded.
		self._pump(harness, 1, start=2_001)
		snapshot = harness.service.historySnapshot()
		rows = snapshot.rows
		self.assertEqual(len(rows), 1_999)
		self.assertEqual(snapshot.drops.retainedRowDrops, 2)
		self.assertLessEqual(len(snapshot.items), 2_000)
		self.assertEqual(rows[0].objectName, "evt-000003")
		self.assertEqual(rows[-1].objectName, "evt-002001")
		self.assertGreater(rows[-1].sequence, rows[0].sequence)

		# Boundary preservation: the started boundary still interprets the survivors, so it stays.
		startedBoundaries = tuple(
			boundary for boundary in snapshot.boundaries if boundary.reason is BoundaryReason.STARTED
		)
		self.assertEqual(len(startedBoundaries), 1)
		self.assertEqual(startedBoundaries[0].session, rows[0].session)

		# Zero removes the user cap but never disables the hard million-record process ceiling.
		unbounded = RetentionPolicy.fromSetting(0)
		self.assertTrue(unbounded.unbounded)
		self.assertEqual(unbounded.processCeiling, 1_000_000)
		self.assertEqual(unbounded.effectiveCap, 1_000_000)
		zeroHarness = _Harness(settings=_Settings(eventRows=0))
		zeroHarness.start()
		self._pump(zeroHarness, 5, start=1)
		self.assertEqual(len(zeroHarness.service.retainedRows()), 5)
		self.assertEqual(zeroHarness.service.historySnapshot().drops.retainedRowDrops, 0)

	def test_invalid_retention_rejected_through_shared_setting_layer(self) -> None:
		defaults = SettingsSnapshot.defaults(settingsRevision=1).asCandidate()
		for rejected in (-1, 1_000_001):
			result = validateCandidate(defaults.withValue(SettingId.EVENT_ROWS, rejected))
			self.assertFalse(result.isValid)
			self.assertEqual(result.firstInvalidSettingId, SettingId.EVENT_ROWS)
		for accepted in (0, 2_000, 1_000_000):
			candidate = defaults.withValue(SettingId.EVENT_ROWS, accepted)
			self.assertTrue(validateCandidate(candidate).isValid)

	def test_filter_change_affects_future_capture_only(self) -> None:
		harness = _Harness()
		harness.start()
		self.assertTrue(harness.forwardFocus(name="before-filter"))
		self.assertEqual(harness.service.drain(), 1)
		retainedBefore = harness.service.retainedRows()

		narrowed = EventFilter(nvdaTypes=frozenset({NvdaEventType.FOCUS}), rawFamilies=frozenset())
		harness.service.changeFilter(narrowed)

		self.assertEqual(harness.service.activeFilter, narrowed)
		self.assertEqual(harness.service.retainedRows(), retainedBefore)

	def test_raw_master_switch_drops_already_queued_raw_receipts(self) -> None:
		harness = _Harness()
		raw = RawUiaEventSource(clientFactory=None)
		activeFilter = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.ALERT}),
		)
		harness.service.start(
			MonitorScope.pinned("firefox", 4242),
			(raw,),
			activeFilter=activeFilter,
		)
		self.assertTrue(
			raw.forward(
				RawUiaFamily.ALERT,
				SimpleNamespace(
					processID=4242,
					appModule=SimpleNamespace(appName="firefox"),
					name="alert",
					role=SimpleNamespace(name="alert"),
					isProtected=False,
				),
			),
		)

		harness.service.setRawEventsEnabled(False)

		self.assertEqual(0, harness.service.drain())
		self.assertEqual((), harness.service.retainedRows())

	def test_disabling_raw_only_filter_unsubscribes_the_raw_source(self) -> None:
		harness = _Harness()
		raw = RawUiaEventSource(clientFactory=None)
		harness.service.start(
			MonitorScope.pinned("firefox", 4242),
			(raw,),
			activeFilter=EventFilter(
				nvdaTypes=frozenset(),
				rawFamilies=frozenset({RawUiaFamily.ALERT}),
			),
		)

		self.assertTrue(raw.active)
		harness.service.setRawEventsEnabled(False)

		self.assertFalse(raw.active)
		self.assertEqual(0, raw.subscriptionCount)
		self.assertFalse(harness.service.rawEventsEnabled)
		self.assertIn("raw UIA off", harness.service.statusText)

		harness.service.setRawEventsEnabled(True)

		self.assertTrue(raw.active)
		self.assertEqual(1, raw.subscriptionCount)
		self.assertIn("raw UIA included", harness.service.statusText)

	def test_raw_toggle_rejects_queued_receipt_from_prior_subscription(self) -> None:
		harness = _Harness()
		raw = RawUiaEventSource(clientFactory=None)
		harness.service.start(
			MonitorScope.pinned("firefox", 4242),
			(raw,),
			activeFilter=EventFilter(
				nvdaTypes=frozenset(),
				rawFamilies=frozenset({RawUiaFamily.ALERT}),
			),
		)
		target = SimpleNamespace(
			processID=4242,
			appModule=SimpleNamespace(appName="firefox"),
			name="old alert",
			role=SimpleNamespace(name="alert"),
			isProtected=False,
		)
		self.assertTrue(raw.forward(RawUiaFamily.ALERT, target))

		harness.service.setRawEventsEnabled(False)
		harness.service.setRawEventsEnabled(True)

		target.name = "new alert"
		self.assertTrue(
			raw.forward(
				RawUiaFamily.ALERT,
				target,
			),
		)
		self.assertEqual(1, harness.service.drain())
		self.assertEqual(("new alert",), tuple(row.objectName for row in harness.service.retainedRows()))
		self.assertEqual(1, harness.service.lateReceiptsRejected)

	def test_disabling_raw_in_mixed_filter_unsubscribes_raw_and_reports_off(self) -> None:
		harness = _Harness()
		raw = RawUiaEventSource(clientFactory=None)
		activeFilter = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.ALERT}),
		)
		harness.service.start(
			MonitorScope.pinned("firefox", 4242),
			(harness.source, raw),
			activeFilter=activeFilter,
		)

		harness.service.setRawEventsEnabled(False)

		self.assertTrue(harness.source.active)
		self.assertFalse(raw.active)
		self.assertFalse(harness.service.rawEventsEnabled)
		self.assertIn("raw UIA off", harness.service.statusText)

	def test_one_drain_batch_applies_retention_once(self) -> None:
		harness = _Harness(settings=_Settings(eventRows=10))
		harness.start()
		for index in range(100):
			self.assertTrue(harness.forwardFocus(name=f"event-{index}"))

		with patch.object(
			eventMonitorServiceModule,
			"applyRetention",
			wraps=eventMonitorServiceModule.applyRetention,
		) as retention:
			self.assertEqual(100, harness.service.drain())

		self.assertEqual(1, retention.call_count)
		self.assertEqual(9, len(harness.service.retainedRows()))
		self.assertEqual(91, harness.service.historySnapshot().drops.retainedRowDrops)

	def test_stop_adds_one_boundary_and_retains_history_across_reopen(self) -> None:
		harness = _Harness()
		harness.start()
		self.assertTrue(harness.forwardFocus(name="kept"))
		self.assertEqual(harness.service.drain(), 1)
		boundariesBeforeStop = harness.service.historySnapshot().boundaries
		retainedBeforeStop = harness.service.retainedRows()

		harness.service.stop()

		self.assertFalse(harness.service.active)
		boundariesAfterStop = harness.service.historySnapshot().boundaries
		self.assertEqual(len(boundariesAfterStop), len(boundariesBeforeStop) + 1)
		self.assertIs(boundariesAfterStop[-1].reason, BoundaryReason.STOPPED)
		# Retained history survives the stop so a reopened frame rehydrates the same rows.
		self.assertEqual(harness.service.retainedRows(), retainedBeforeStop)

	def test_target_unavailability_reasons_remain_distinct_in_status_and_export(self) -> None:
		reasonType: Any = getattr(eventMonitorDomain, "TargetLifecycleReason")
		for reason in (reasonType.DESTROYED, reasonType.COM_FAILURE, reasonType.HUNG):
			with self.subTest(reason=reason):
				harness = _Harness()
				harness.start()
				service: Any = harness.service

				service.targetUnavailable(reason)

				self.assertFalse(harness.service.active)
				boundary: Any = harness.service.historySnapshot().boundaries[-1]
				self.assertEqual(boundary.targetLifecycleReason, reason)
				metadata: Any = harness.service.exportMetadata()
				self.assertEqual(metadata.targetLifecycleReason, reason)
				self.assertIn(reason.value, service.statusText)

	def test_lifecycle_release_runs_in_registered_order(self) -> None:
		lifecycle = LifecycleService()
		order: list[str] = []
		lifecycle.registerInvalidator("inv", lambda: order.append("invalidator"))
		lifecycle.registerSource("src", lambda: order.append("source"))
		lifecycle.registerQueue("queue", lambda: order.append("queue"))
		lifecycle.registerUi("ui", lambda: order.append("ui"))
		lifecycle.registerResource("resource", lambda: order.append("resource"))

		lifecycle.transition("terminating")

		self.assertEqual(order, ["invalidator", "source", "queue", "ui", "resource"])

	def test_post_close_callbacks_are_rejected_before_effects(self) -> None:
		harness = _Harness()
		harness.service.registerLifecycle()
		harness.start()
		self.assertTrue(harness.forwardFocus(name="kept"))
		self.assertEqual(harness.service.drain(), 1)
		retained = harness.service.retainedRows()
		self.assertEqual(len(retained), 1)

		harness.lifecycle.transition("secure")

		self.assertFalse(harness.service.active)
		# A copy admitted after shutdown is refused before it can reach the clipboard.
		outcome = harness.service.copySelectedEvents(retained, EventCopyFormat.JSON)
		self.assertEqual(outcome.status, "failed")
		self.assertEqual(outcome.errorCode, "KS.EVENTS.COPY.UNAVAILABLE")
		self.assertEqual(harness.clipboard.requests, [])
		# A late forward after invalidation adds no retained row.
		_ = harness.forwardFocus(name="late")
		self.assertEqual(harness.service.drain(), 0)
		self.assertEqual(harness.service.retainedRows(), retained)


class EventMonitorDropSoundTests(unittest.TestCase):
	"""Drop milestones emit their typed cue after speech, owned by the live monitor generation.

	The monitor is the single owner of retained history, so every pending-queue and retained-row
	drop the service already speaks also reaches the optional sound seam - keyed on the current
	generation and coalesced on the crossed milestone - without altering the drop count or the
	spoken milestone. A missing seam stays silent; a raising seam stays isolated from both.
	"""

	def test_retained_row_drop_emits_cue_after_speech(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(settings=_Settings(eventRows=2), sound=sounds)
		harness.start()
		generation = harness.service.generation
		self.assertTrue(harness.forwardFocus(name="first"))
		self.assertEqual(harness.service.drain(), 1)
		# The start cue sounded on entry; no drop has crossed a milestone yet.
		self.assertEqual(sounds.events(), [CueEventId.EVENT_MONITOR_START])
		self.assertTrue(harness.forwardFocus(name="second"))
		self.assertEqual(harness.service.drain(), 1)
		# The total cap evicts the oldest data row once the marker and two rows would exceed it.
		self.assertEqual(harness.service.historySnapshot().drops.retainedRowDrops, 1)
		# Speech announced the milestone; the cue followed it on the same monitor generation.
		self.assertIn("events.drop.retained", harness.feedback.messages)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.RETAINED_ROW_DROP],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.MONITOR)
		self.assertEqual(request.owner.generation, generation)
		self.assertEqual(request.coalescingKey, "retainedRowDrop:1")

	def test_pending_queue_drop_emits_cue_after_speech(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		generation = harness.service.generation
		# Fill the bounded queue without draining, then overflow it by one to force a pending drop.
		for offset in range(1_001):
			_ = harness.forwardFocus(name=f"evt-{offset:06d}")
		self.assertEqual(harness.service.historySnapshot().drops.pendingQueueDrops, 1)
		self.assertIn("events.drop.pending", harness.feedback.messages)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.PENDING_QUEUE_DROP],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.MONITOR)
		self.assertEqual(request.owner.generation, generation)
		self.assertEqual(request.coalescingKey, "pendingQueueDrop:1")

	def test_pending_drop_effects_run_after_the_ingestion_lock_is_released(self) -> None:
		harness = _Harness()
		harness.start()
		lockStates: list[bool] = []

		def observeLock(_before: int, _after: int, *, pending: bool) -> None:
			self.assertTrue(pending)
			lockStates.append(harness.service._lock.locked())

		with patch.object(harness.service, "_announceDropMilestones", side_effect=observeLock):
			for offset in range(1_001):
				_ = harness.forwardFocus(name=f"evt-{offset:06d}")

		self.assertEqual([False], lockStates)

	def test_drop_sound_failure_stays_isolated_from_speech_and_history(self) -> None:
		harness = _Harness(settings=_Settings(eventRows=1), sound=_FailingSounds())
		harness.start()
		self.assertTrue(harness.forwardFocus(name="first"))
		self.assertEqual(harness.service.drain(), 1)
		self.assertTrue(harness.forwardFocus(name="second"))
		# The retained drop is counted and spoken even though every sound emit raises.
		self.assertEqual(harness.service.drain(), 1)
		self.assertEqual(harness.service.historySnapshot().drops.retainedRowDrops, 1)
		self.assertIn("events.drop.retained", harness.feedback.messages)

	def test_absent_sound_seam_leaves_drops_silent_but_spoken(self) -> None:
		harness = _Harness(settings=_Settings(eventRows=1))
		harness.start()
		self.assertTrue(harness.forwardFocus(name="first"))
		self.assertEqual(harness.service.drain(), 1)
		self.assertTrue(harness.forwardFocus(name="second"))
		# Without a seam the drop is still counted and announced; nothing is scheduled.
		self.assertEqual(harness.service.drain(), 1)
		self.assertEqual(harness.service.historySnapshot().drops.retainedRowDrops, 1)
		self.assertIn("events.drop.retained", harness.feedback.messages)


class EventMonitorLifecycleSoundTests(unittest.TestCase):
	"""Start, stop, and a failed start each speak their localized transition before the optional cue.

	The monitor owns its own lifecycle, so a genuine start sounds the standard start cue, a user stop
	sounds the urgent stop cue, and a start that cannot subscribe sounds the critical failure cue and
	still propagates - each owned by the monitor generation it ran under and each only after speech. A
	lifecycle-boundary stop (secure screen) invalidates the pending cue on that generation instead of
	sounding a stop. A missing seam stays silent but still speaks; a raising seam never disturbs speech
	or the propagated failure.
	"""

	def test_start_sounds_the_start_cue_after_speech(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		generation = harness.service.generation
		self.assertIn("events.monitor.started", harness.feedback.messages)
		self.assertEqual(sounds.events(), [CueEventId.EVENT_MONITOR_START])
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.MONITOR)
		self.assertEqual(request.owner.generation, generation)

	def test_start_feedback_carries_the_selected_target_and_active_configuration(self) -> None:
		harness = _Harness()

		harness.start(targetName="Search")

		request = harness.feedback.requests[-1]
		self.assertEqual("events.monitor.started", request.messageId)
		self.assertEqual(("Search", "application", False), request.arguments)

	def test_user_stop_sounds_the_stop_cue_after_speech(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		generation = harness.service.generation
		harness.service.stop()
		self.assertIn("events.monitor.stopped", harness.feedback.messages)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.EVENT_MONITOR_STOP],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.MONITOR)
		self.assertEqual(request.owner.generation, generation)

	def test_failed_start_sounds_the_failure_cue_after_speech_and_propagates(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		with self.assertRaises(RuntimeError):
			harness.service.start(MonitorScope.broadScope(), (_FailingSource(),))
		generation = harness.service.generation
		self.assertFalse(harness.service.active)
		self.assertIn("events.monitor.failed", harness.feedback.messages)
		self.assertEqual(sounds.events(), [CueEventId.EVENT_MONITOR_FAILURE])
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.MONITOR)
		self.assertEqual(request.owner.generation, generation)

	def test_secure_stop_invalidates_the_monitor_cue_without_sounding_a_stop(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		generation = harness.service.generation
		harness.service.stop(reason=BoundaryReason.SECURE)
		# No stop cue sounds at a lifecycle boundary; the pending monitor generation is invalidated.
		self.assertEqual(sounds.events(), [CueEventId.EVENT_MONITOR_START])
		self.assertTrue(
			any(
				owner is not None and owner.kind is SoundOwnerKind.MONITOR and owner.generation == generation
				for owner in sounds.invalidations
			),
		)

	def test_failed_start_sound_stays_isolated_from_speech(self) -> None:
		harness = _Harness(sound=_FailingSounds())
		with self.assertRaises(RuntimeError):
			harness.service.start(MonitorScope.broadScope(), (_FailingSource(),))
		# The failure is still spoken and still propagates even though every sound operation raises.
		self.assertIn("events.monitor.failed", harness.feedback.messages)
		self.assertFalse(harness.service.active)

	def test_absent_seam_leaves_lifecycle_silent_but_spoken(self) -> None:
		harness = _Harness()
		harness.start()
		harness.service.stop()
		# Without a seam the start and stop are still spoken; nothing is scheduled.
		self.assertIn("events.monitor.started", harness.feedback.messages)
		self.assertIn("events.monitor.stopped", harness.feedback.messages)


class EventMonitorSessionRiskSoundTests(unittest.TestCase):
	"""Starting a session speaks each active privacy risk before its shared-warning cue.

	The event monitor's own provenance treats broad scope, raw UIA event families, and disabled
	redaction as session risks. Each active risk speaks its own localized, stable-ID warning after the
	started transition and then layers the shared-warning cue owned by the system generation. A risk
	that is not active stays silent. Speech is mandatory; the cue is optional, so a missing seam still
	speaks every risk and a raising seam never disturbs speech or the started session.
	"""

	@staticmethod
	def _rawFilter() -> EventFilter:
		return EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.NOTIFICATION}),
		)

	def test_broad_scope_start_speaks_then_sounds_the_broad_warning(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.service.start(MonitorScope.broadScope(), (harness.source,))
		generation = harness.service.generation
		self.assertEqual(
			harness.feedback.messages,
			["events.monitor.started", "events.risk.broadScope"],
		)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.BROAD_EVENT_SCOPE],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.SYSTEM)
		self.assertEqual(request.owner.generation, generation)

	def test_narrow_scope_start_emits_no_broad_warning(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		self.assertNotIn("events.risk.broadScope", harness.feedback.messages)
		self.assertNotIn(CueEventId.BROAD_EVENT_SCOPE, sounds.events())

	def test_raw_uia_filter_start_speaks_then_sounds_the_raw_warning(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.service.start(
			MonitorScope.pinned("firefox", 4242),
			(harness.source,),
			activeFilter=self._rawFilter(),
		)
		generation = harness.service.generation
		self.assertEqual(
			harness.feedback.messages,
			["events.monitor.started", "events.risk.rawUia"],
		)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.RAW_UIA_FALLBACK],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.SYSTEM)
		self.assertEqual(request.owner.generation, generation)

	def test_default_filter_start_emits_no_raw_warning(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(sound=sounds)
		harness.start()
		self.assertNotIn("events.risk.rawUia", harness.feedback.messages)
		self.assertNotIn(CueEventId.RAW_UIA_FALLBACK, sounds.events())

	def test_redaction_disabled_start_speaks_then_sounds_the_redaction_warning(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(settings=_Settings(redact=False), sound=sounds)
		harness.start()
		generation = harness.service.generation
		self.assertFalse(harness.settings.redact)
		self.assertEqual(
			harness.feedback.messages,
			["events.monitor.started", "events.risk.redactionDisabled"],
		)
		self.assertEqual(
			sounds.events(),
			[CueEventId.EVENT_MONITOR_START, CueEventId.REDACTION_DISABLED],
		)
		request = sounds.requests[-1]
		self.assertEqual(request.owner.kind, SoundOwnerKind.SYSTEM)
		self.assertEqual(request.owner.generation, generation)

	def test_every_active_monitor_risk_speaks_a_distinct_warning_after_the_start(self) -> None:
		sounds = _RecordingSounds()
		harness = _Harness(settings=_Settings(redact=False), sound=sounds)
		harness.service.start(
			MonitorScope.broadScope(),
			(harness.source,),
			activeFilter=self._rawFilter(),
		)
		# Every active risk speaks its own stable-ID text; no two risks share speech text.
		self.assertEqual(
			harness.feedback.messages,
			[
				"events.monitor.started",
				"events.risk.broadScope",
				"events.risk.rawUia",
				"events.risk.redactionDisabled",
			],
		)
		self.assertEqual(
			sounds.events(),
			[
				CueEventId.EVENT_MONITOR_START,
				CueEventId.BROAD_EVENT_SCOPE,
				CueEventId.RAW_UIA_FALLBACK,
				CueEventId.REDACTION_DISABLED,
			],
		)

	def test_risk_warning_failure_stays_isolated_from_speech(self) -> None:
		harness = _Harness(settings=_Settings(redact=False), sound=_FailingSounds())
		harness.service.start(
			MonitorScope.broadScope(),
			(harness.source,),
			activeFilter=self._rawFilter(),
		)
		# Every active monitor risk is still spoken and the session stays active despite sound failures.
		self.assertEqual(
			harness.feedback.messages,
			[
				"events.monitor.started",
				"events.risk.broadScope",
				"events.risk.rawUia",
				"events.risk.redactionDisabled",
			],
		)
		self.assertTrue(harness.service.active)

	def test_absent_seam_leaves_risks_silent_but_spoken(self) -> None:
		harness = _Harness(settings=_Settings(redact=False))
		harness.service.start(
			MonitorScope.broadScope(),
			(harness.source,),
			activeFilter=self._rawFilter(),
		)
		# Without a seam every active risk is still spoken; nothing is scheduled.
		self.assertIn("events.risk.broadScope", harness.feedback.messages)
		self.assertIn("events.risk.rawUia", harness.feedback.messages)
		self.assertIn("events.risk.redactionDisabled", harness.feedback.messages)


class EventsWorkspaceExportSoundTests(unittest.TestCase):
	"""The Events workspace sounds a terminal export cue after it speaks the outcome.

	Export is the only Events-workspace transition with a cue. Success and genuine failure each
	emit their typed cue - owned by the export generation the service actually ran under - only
	after the spoken outcome. Copy carries no cue; cancelled and stale exports stay silent; a
	missing seam or a raising seam never disturbs speech, the clipboard, or the exported file.
	"""

	def _workspace(
		self,
		sound: _RecordingSounds | _FailingSounds | None,
	) -> tuple[EventsWorkspace, list[str]]:
		announcements: list[str] = []
		workspace = EventsWorkspace(_Harness().service, announce=announcements.append, sound=sound)
		return workspace, announcements

	def test_real_export_publishes_and_sounds_success_end_to_end(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			destination = Path(tmp) / "events.json"
			harness = _Harness(picker=lambda: destination)
			harness.start()
			self.assertTrue(harness.forwardFocus(name="Search"))
			self.assertEqual(harness.service.drain(), 1)
			sounds = _RecordingSounds()
			announcements: list[str] = []
			workspace = EventsWorkspace(
				harness.service,
				announce=announcements.append,
				sound=sounds,
			)
			workspace._export()
			# The real export wrote its file and spoke completion; the cue followed that speech.
			self.assertTrue(destination.exists())
			self.assertEqual(announcements, ["Export complete."])
			self.assertEqual(sounds.events(), [CueEventId.EVENT_EXPORT_SUCCESS])
			request = sounds.requests[-1]
			self.assertEqual(request.owner.kind, SoundOwnerKind.EXPORT)
			# The cue is owned by the export generation the service admitted the operation under.
			self.assertIsInstance(request.owner.generation, int)
			self.assertIsNone(request.coalescingKey)

	def test_failed_export_emits_failure_cue_after_speech(self) -> None:
		sounds = _RecordingSounds()
		workspace, announcements = self._workspace(sounds)
		outcome = EventActionOutcome("failed", errorCode="KS.EVENTS.EXPORT.WRITE", generation=9)
		workspace._announceOutcome(outcome, action="export")
		self.assertEqual(announcements, ["Export failed."])
		self.assertEqual(sounds.events(), [CueEventId.EVENT_EXPORT_FAILURE])
		self.assertEqual(sounds.requests[-1].owner, SoundOwner(SoundOwnerKind.EXPORT, 9))

	def test_copy_outcome_carries_no_export_cue(self) -> None:
		sounds = _RecordingSounds()
		workspace, announcements = self._workspace(sounds)
		# Copy reuses the same outcome shape and completion verb but has no cue in the matrix.
		workspace._announceOutcome(EventActionOutcome("copied", clipboardRequested=True), action="copy")
		self.assertEqual(announcements, ["Copy complete."])
		self.assertEqual(sounds.requests, [])

	def test_nonterminal_exports_stay_silent(self) -> None:
		sounds = _RecordingSounds()
		workspace, announcements = self._workspace(sounds)
		for outcome in (
			EventActionOutcome("cancelled", generation=3),
			EventActionOutcome("stale", errorCode="KS.EVENTS.EXPORT.STALE", generation=4),
		):
			workspace._announceOutcome(outcome, action="export")
		# A cancelled or stale export is still spoken, but neither reaches the cue seam.
		self.assertEqual(
			announcements,
			["Export cancelled.", "Export skipped because monitoring changed."],
		)
		self.assertEqual(sounds.requests, [])

	def test_published_export_without_generation_stays_silent(self) -> None:
		sounds = _RecordingSounds()
		workspace, announcements = self._workspace(sounds)
		# Defensive: a published status with no captured generation owns nothing, so it stays silent.
		workspace._announceOutcome(EventActionOutcome("published", committedPath="x"), action="export")
		self.assertEqual(announcements, ["Export complete."])
		self.assertEqual(sounds.requests, [])

	def test_export_cue_failure_stays_isolated_from_speech(self) -> None:
		workspace, announcements = self._workspace(_FailingSounds())
		outcome = EventActionOutcome(
			"published",
			committedPath="x",
			clipboardRequested=True,
			generation=1,
		)
		workspace._announceOutcome(outcome, action="export")
		# The raising seam is swallowed; the spoken outcome is untouched.
		self.assertEqual(announcements, ["Export complete."])

	def test_absent_seam_leaves_export_silent_but_spoken(self) -> None:
		workspace, announcements = self._workspace(None)
		outcome = EventActionOutcome(
			"published",
			committedPath="x",
			clipboardRequested=True,
			generation=1,
		)
		workspace._announceOutcome(outcome, action="export")
		self.assertEqual(announcements, ["Export complete."])


if __name__ == "__main__":
	_ = unittest.main()
