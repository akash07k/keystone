"""Runtime-owned event monitor service.

The service is the sink every event source delivers to and the single owner of retained history. It
pins one scope per session, admits receipts only for the current monitor generation, enqueues without
blocking a callback, drains at most one hundred receipts per GUI turn, transforms each receipt through
the privacy pipeline before retention, enforces the retention policy, and exposes copy/export
projections. History lives on the runtime, not on any wx frame, so it survives frame close until a
manual Clear or runtime shutdown.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
import contextlib
import os
from pathlib import Path
import tempfile
import threading
from typing import cast, override
from uuid import uuid4

from ..domain.correlation import CorrelationContext
from ..domain.event_monitor import (
	DRAIN_LIMIT,
	QUEUE_CAPACITY,
	BoundaryReason,
	ChangeEvidence,
	DropCounters,
	EventBackend,
	EventCopyFormat,
	EventExportMetadata,
	EventFilter,
	EventHistory,
	EventProvenance,
	EventReceipt,
	EventRow,
	EventSelection,
	HistoryItem,
	MonitorProvenance,
	MonitorScope,
	RetentionPolicy,
	SessionBoundary,
	TargetLifecycleReason,
	applyRetention,
	crossedDropMilestones,
	renderSelectedEvents,
	serializeEventExport,
)
from ..domain.privacy import (
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	transformValue,
)
from ..domain.settings import SettingsSnapshot
from ..domain.sounds import (
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	soundRequestFor,
)
from ..ports.effects import ClipboardPort, ClipboardRequest, FeedbackPort, FeedbackRequest
from ..ports.event_sources import EventSink, EventSource, SubscriptionRequest
from .lifecycle import LifecycleService
from .sound_service import WorkflowSounds


type MonotonicClock = Callable[[], float]
type WallClock = Callable[[], int]
type SettingsProvider = Callable[[], SettingsSnapshot]
type PolicyProvider = Callable[[], PrivacyPolicy]
type DestinationPicker = Callable[[], Path | None]
type HistoryListener = Callable[[EventHistory], None]
type RuntimeLogSink = Callable[[str, tuple[tuple[str, str | int | bool], ...]], None]


@dataclass(frozen=True, slots=True)
class EventActionOutcome:
	"""Result of a copy or export action, with an honest publication/clipboard record."""

	status: str
	committedPath: str | None = None
	clipboardRequested: bool = False
	errorCode: str | None = None
	generation: int | None = None

	def __post_init__(self) -> None:
		if self.status not in ("published", "copied", "cancelled", "failed", "stale", "empty"):
			raise ValueError(f"unknown event action status {self.status!r}")


def _defaultTimestamp(wallClockMs: int) -> str:
	moment = datetime.fromtimestamp(wallClockMs / 1_000).astimezone()
	return moment.strftime("%I:%M:%S.") + f"{moment.microsecond // 1_000:03d} " + moment.strftime("%p")


class _SubscriptionSink(EventSink):
	"""Bind deliveries to one source subscription lifetime."""

	def __init__(self, monitor: EventMonitorService, token: int) -> None:
		super().__init__()
		self._monitor = monitor
		self._token = token

	@override
	def deliver(self, receipt: EventReceipt) -> None:
		self._monitor.deliverFromSubscription(self._token, receipt)


class EventMonitorService(EventSink):
	"""Owns history, drains receipts safely, and produces privacy-safe copy/export projections."""

	def __init__(
		self,
		*,
		lifecycle: LifecycleService,
		settings: SettingsProvider,
		policy: PolicyProvider,
		clipboard: ClipboardPort,
		feedback: FeedbackPort,
		monotonic: MonotonicClock,
		wallClock: WallClock,
		destinationPicker: DestinationPicker | None = None,
		timestampFormatter: Callable[[int], str] = _defaultTimestamp,
		historyListener: HistoryListener | None = None,
		sound: WorkflowSounds | None = None,
		runtimeLog: RuntimeLogSink | None = None,
	) -> None:
		super().__init__()
		self._lifecycle = lifecycle
		self._sound = sound
		self._settings = settings
		self._policy = policy
		self._clipboard = clipboard
		self._feedback = feedback
		self._monotonic = monotonic
		self._wallClock = wallClock
		self._pickDestination = destinationPicker
		self._formatTimestamp = timestampFormatter
		self._historyListener = historyListener
		self._runtimeLog = runtimeLog
		self._lock = threading.Lock()
		self._queue: deque[tuple[int | None, EventReceipt]] = deque()
		self._items: list[HistoryItem] = []
		self._drops = DropCounters()
		self._capturedCount = 0
		self._order = 0
		self._session = 0
		self._generation = 0
		self._nextSubscriptionToken = 0
		self._sourceSubscriptionTokens: dict[int, int] = {}
		self._activeSubscriptionTokens: set[int] = set()
		self._active = False
		self._scope: MonitorScope | None = None
		self._filter: EventFilter = EventFilter.default()
		self._rawEventsEnabled = False
		self._sources: tuple[EventSource, ...] = ()
		self._lateReceiptsRejected = 0
		self._lastTargetLifecycleReason: TargetLifecycleReason | None = None

	# -- observable state --------------------------------------------------

	@property
	def active(self) -> bool:
		with self._lock:
			return self._active

	@property
	def generation(self) -> int:
		with self._lock:
			return self._generation

	@property
	def activeFilter(self) -> EventFilter:
		with self._lock:
			return self._filter

	@property
	def rawEventsEnabled(self) -> bool:
		with self._lock:
			return self._rawEventsEnabled

	@property
	def scope(self) -> MonitorScope | None:
		with self._lock:
			return self._scope

	@property
	def lateReceiptsRejected(self) -> int:
		with self._lock:
			return self._lateReceiptsRejected

	@property
	def subscriptionCount(self) -> int:
		with self._lock:
			sources = self._sources
		return sum(source.subscriptionCount for source in sources)

	@property
	def statusText(self) -> str:
		snapshot = self.historySnapshot()
		with self._lock:
			state = "active" if self._active else "stopped"
			scope = self._scope.scopeText if self._scope is not None else "Selected element proposed"
			raw = "included" if self._rawEventsEnabled else "off"
			reason = (
				""
				if self._lastTargetLifecycleReason is None
				else f"; target {self._lastTargetLifecycleReason.value}"
			)
		return (
			f"Monitoring {state}; {scope}; raw UIA {raw}; events {snapshot.rowCount}; "
			f"pending drops {snapshot.drops.pendingQueueDrops}; "
			f"retained drops {snapshot.drops.retainedRowDrops}{reason}."
		)

	# -- session lifecycle -------------------------------------------------

	def start(
		self,
		scope: MonitorScope,
		sources: tuple[EventSource, ...],
		*,
		activeFilter: EventFilter | None = None,
		targetName: str | None = None,
	) -> None:
		"""Pin ``scope`` and subscribe ``sources`` for a new monitoring session."""

		with self._lock:
			active = self._active
		if active:
			self._stopSources(BoundaryReason.SWITCHED)
		redactionEnabled = self._policy().redactProtectedText
		with self._lock:
			if activeFilter is not None:
				self._filter = activeFilter
				self._rawEventsEnabled = activeFilter.rawEnabled
			self._scope = scope
			self._lastTargetLifecycleReason = None
			self._session += 1
			self._generation += 1
			self._active = True
			self._sources = sources
			generation = self._generation
		self._appendBoundary(BoundaryReason.STARTED, scope, "Monitoring started")
		effective = self._effectiveFilter()
		subscribed: list[EventSource] = []
		try:
			if effective is not None:
				for source in self._subscribableSources(sources, effective):
					self._subscribeSource(source, scope, effective, generation)
					subscribed.append(source)
		except Exception:
			# A source that cannot subscribe leaves no half-open session: unwind the sources that did
			# subscribe, mark the monitor inactive, and speak the failure before the optional cue. The
			# original error still propagates so the caller learns monitoring never started.
			for started in subscribed:
				with contextlib.suppress(Exception):
					self._unsubscribeSource(started)
			with self._lock:
				self._active = False
				self._sources = ()
			self._announceMonitorLifecycle("events.monitor.failed", CueEventId.EVENT_MONITOR_FAILURE)
			self._notify()
			raise
		self._announceMonitorLifecycle(
			"events.monitor.started",
			CueEventId.EVENT_MONITOR_START,
			targetName=targetName,
		)
		self._announceSessionRisks(scope, redactionEnabled=redactionEnabled)
		self._recordSessionStart(scope)
		self._notify()

	def stop(
		self,
		*,
		reason: BoundaryReason = BoundaryReason.STOPPED,
		targetLifecycleReason: TargetLifecycleReason | None = None,
	) -> None:
		"""Stop the active session, unsubscribe sources, and record a boundary."""

		with self._lock:
			active = self._active
			scope = self._scope or MonitorScope.broadScope()
			sessionGeneration = self._generation
		if not active and reason is BoundaryReason.STOPPED:
			return
		self._stopSources(reason)
		with self._lock:
			self._lastTargetLifecycleReason = targetLifecycleReason
		self._appendBoundary(
			reason,
			scope,
			self._boundaryDetail(reason),
			targetLifecycleReason=targetLifecycleReason,
		)
		if reason is BoundaryReason.STOPPED:
			self._announceMonitorLifecycle(
				"events.monitor.stopped",
				CueEventId.EVENT_MONITOR_STOP,
				generation=sessionGeneration,
			)
		else:
			# Secure, closed, switched, and process-exit stops are lifecycle boundaries, not a user
			# stop: drop any pending cue on the session generation instead of sounding a stop.
			self._invalidateMonitorSound(generation=sessionGeneration)
		snapshot = self.historySnapshot()
		self._recordRuntime(
			"KS.EVENT.MONITOR_STOPPED",
			(
				("stopReason", reason.value),
				("retainedCount", snapshot.rowCount),
				("pendingDropCount", snapshot.drops.pendingQueueDrops),
				("rowDropCount", snapshot.drops.retainedRowDrops),
			),
		)
		self._notify()

	def targetUnavailable(self, reason: TargetLifecycleReason) -> None:
		"""Stop a frozen element or subtree after a distinct provider lifecycle failure."""

		with self._lock:
			active = self._active
		if not active:
			return
		boundaryReason = {
			TargetLifecycleReason.DESTROYED: BoundaryReason.TARGET_DESTROYED,
			TargetLifecycleReason.COM_FAILURE: BoundaryReason.TARGET_COM_FAILURE,
			TargetLifecycleReason.HUNG: BoundaryReason.TARGET_HUNG,
		}[reason]
		self.stop(reason=boundaryReason, targetLifecycleReason=reason)

	def switchScope(self, scope: MonitorScope, sources: tuple[EventSource, ...]) -> bool:
		"""Transactionally move to a new pinned scope, keeping the old session on failure."""

		with self._lock:
			previousSources = self._sources
			previousScope = self._scope
			previousGeneration = self._generation
		if previousScope is None:
			return False
		effective = self._effectiveFilter()
		with self._lock:
			previousSubscribed = tuple(
				source for source in previousSources if id(source) in self._sourceSubscriptionTokens
			)
		candidateSources = self._subscribableSources(sources, effective)
		previousRequest = (
			None
			if effective is None
			else SubscriptionRequest(
				scope=previousScope,
				activeFilter=effective,
				generation=previousGeneration,
			)
		)
		sharedSources: list[EventSource] = []
		for source in candidateSources:
			if any(source is previous for previous in previousSubscribed):
				sharedSources.append(source)
		touchedShared: list[EventSource] = []
		touchedNew: list[EventSource] = []
		try:
			with self._lock:
				self._generation += 1
				candidateGeneration = self._generation
			if effective is not None:
				for source in candidateSources:
					if any(source is shared for shared in sharedSources):
						touchedShared.append(source)
					else:
						touchedNew.append(source)
					self._subscribeSource(source, scope, effective, candidateGeneration)
		except Exception:  # noqa: BLE001 - candidate failure must preserve old monitoring
			return self._rollbackScopeSwitch(
				previousScope,
				previousGeneration,
				previousRequest,
				previousSubscribed,
				touchedShared,
				touchedNew,
			)
		for source in previousSubscribed:
			if any(source is candidate for candidate in candidateSources):
				continue
			with contextlib.suppress(Exception):
				self._unsubscribeSource(source)
		with self._lock:
			self._session += 1
			self._scope = scope
			self._lastTargetLifecycleReason = None
			self._sources = sources
			self._active = True
		self._appendBoundary(
			BoundaryReason.SWITCHED,
			scope,
			(
				f"Restarted with {scope.scopeText}; previous target "
				f"{previousScope.scopeText if previousScope else 'none'}"
			),
		)
		redactionEnabled = self._policy().redactProtectedText
		self._announceSessionRisks(scope, redactionEnabled=redactionEnabled)
		self._recordSessionStart(scope)
		self._notify()
		return True

	def _rollbackScopeSwitch(
		self,
		previousScope: MonitorScope,
		previousGeneration: int,
		previousRequest: SubscriptionRequest | None,
		previousSubscribed: tuple[EventSource, ...],
		touchedShared: list[EventSource],
		touchedNew: list[EventSource],
	) -> bool:
		"""Clean an interrupted candidate subscription before restoring the prior session."""

		for source in (*touchedNew, *touchedShared):
			with contextlib.suppress(Exception):
				self._unsubscribeSource(source)
		restored = True
		if previousRequest is not None:
			for source in touchedShared:
				try:
					self._subscribeSource(
						source,
						previousRequest.scope,
						previousRequest.activeFilter,
						previousRequest.generation,
					)
				except Exception:
					restored = False
		if restored:
			with self._lock:
				self._generation = previousGeneration
			return False

		with self._lock:
			self._active = False
			self._generation = max(self._generation, previousGeneration + 1)
			self._activeSubscriptionTokens.clear()
			self._sourceSubscriptionTokens.clear()
			self._sources = ()
			self._scope = previousScope
			self._queue.clear()
		for source in {
			id(source): source for source in (*previousSubscribed, *touchedNew, *touchedShared)
		}.values():
			with contextlib.suppress(Exception):
				source.unsubscribe()
		self._announceMonitorLifecycle("events.monitor.failed", CueEventId.EVENT_MONITOR_FAILURE)
		self._recordRuntime(
			"KS.EVENT.MONITOR_SWITCH_ROLLBACK_FAILED",
			(("scopeKind", previousScope.kind.value),),
		)
		self._notify()
		return False

	def changeFilter(self, activeFilter: EventFilter, *, preserveRawState: bool = False) -> None:
		"""Apply a new filter to future capture immediately; retained rows are untouched.

		The change propagates into every live source at once (a disabled type stops forwarding, an
		enabled type resumes) and is enforced service-side on both ingestion and drain, so a type
		disabled here can never be retained again and a type enabled here begins on its next event -
		all without a Stop/Start cycle. Rows already retained under the previous filter are preserved.
		"""

		with self._lock:
			self._filter = activeFilter
			if not preserveRawState and activeFilter.rawEnabled:
				self._rawEventsEnabled = True
			scope = self._scope
		self._synchronizeSourceSubscriptions()
		if scope is not None:
			self._appendBoundary(
				BoundaryReason.FILTER_CHANGED,
				scope,
				f"Event filter changed: {', '.join(activeFilter.summary())}",
			)
		self._notify()

	def setRawEventsEnabled(self, enabled: bool) -> None:
		"""Toggle raw capture while retaining the dialog's selected raw families."""

		with self._lock:
			if self._rawEventsEnabled == enabled:
				return
			self._rawEventsEnabled = enabled
			scope = self._scope
		self._synchronizeSourceSubscriptions()
		if scope is not None:
			state = "enabled" if enabled else "disabled"
			self._appendBoundary(
				BoundaryReason.FILTER_CHANGED,
				scope,
				f"Raw UIA events {state}",
			)
		if enabled:
			self._announceSessionRisk("events.risk.rawUia", CueEventId.RAW_UIA_FALLBACK)
		self._notify()

	def _effectiveFilter(self) -> EventFilter | None:
		with self._lock:
			activeFilter = self._filter
			rawEventsEnabled = self._rawEventsEnabled
		return self._effectiveFilterFor(activeFilter, rawEventsEnabled)

	@staticmethod
	def _effectiveFilterFor(
		activeFilter: EventFilter,
		rawEventsEnabled: bool,
	) -> EventFilter | None:
		if rawEventsEnabled or not activeFilter.rawFamilies:
			return activeFilter
		if activeFilter.nvdaTypes:
			return EventFilter(nvdaTypes=activeFilter.nvdaTypes, rawFamilies=frozenset())
		return None

	@staticmethod
	def _subscribableSources(
		sources: tuple[EventSource, ...],
		activeFilter: EventFilter | None,
	) -> tuple[EventSource, ...]:
		if activeFilter is None:
			return ()
		return tuple(
			source
			for source in sources
			if (source.backend is EventBackend.NVDA and bool(activeFilter.nvdaTypes))
			or (source.backend is EventBackend.RAW_UIA and bool(activeFilter.rawFamilies))
		)

	def _synchronizeSourceSubscriptions(self) -> None:
		"""Keep each backend subscribed only while its effective filter selects an event kind."""

		with self._lock:
			scope = self._scope
			sources = self._sources
			generation = self._generation
			effective = self._effectiveFilterFor(self._filter, self._rawEventsEnabled)
		if effective is None:
			for source in sources:
				if source.active:
					with contextlib.suppress(Exception):
						self._unsubscribeSource(source)
			return
		subscribed = self._subscribableSources(sources, effective)
		for source in sources:
			if any(source is candidate for candidate in subscribed):
				if source.active:
					updateFilter = getattr(source, "updateFilter", None)
					if callable(updateFilter):
						with contextlib.suppress(Exception):
							_ = updateFilter(effective)
				elif scope is not None:
					with contextlib.suppress(Exception):
						self._subscribeSource(source, scope, effective, generation)
			elif source.active:
				with contextlib.suppress(Exception):
					self._unsubscribeSource(source)

	def clear(self) -> None:
		"""Discard all retained history and drop counters after explicit confirmation."""

		with self._lock:
			self._items.clear()
			self._queue.clear()
			self._drops = DropCounters()
			self._capturedCount = 0
		self._notify()

	def deleteHistoryItem(self, item: HistoryItem) -> bool:
		"""Delete one retained event or session boundary selected by the Event Monitor."""
		with self._lock:
			try:
				self._items.remove(item)
			except ValueError:
				return False
		self._notify()
		return True

	def _stopSources(self, reason: BoundaryReason) -> None:
		with self._lock:
			self._active = False
			self._generation += 1
			self._activeSubscriptionTokens.clear()
			self._sourceSubscriptionTokens.clear()
			sources = self._sources
		for source in sources:
			with contextlib.suppress(Exception):
				source.unsubscribe()
		with self._lock:
			self._sources = ()
			if reason is not BoundaryReason.SWITCHED:
				self._queue.clear()

	# -- ingestion ---------------------------------------------------------

	@override
	def deliver(self, receipt: EventReceipt) -> None:
		"""Enqueue one receipt without blocking the callback; drop-and-count when full."""

		self.deliverFromSubscription(None, receipt)

	def deliverFromSubscription(self, token: int | None, receipt: EventReceipt) -> None:
		"""Enqueue a receipt only while its source subscription remains current."""

		pendingDrop: tuple[int, int] | None = None
		with self._lock:
			if (
				not self._active
				or receipt.generation != self._generation
				or (token is not None and token not in self._activeSubscriptionTokens)
			):
				self._lateReceiptsRejected += 1
				return
			effective = self._effectiveFilterFor(self._filter, self._rawEventsEnabled)
			if effective is None or not effective.admits(receipt.backend, receipt.eventType):
				return
			scope = self._scope
			if scope is not None and not scope.acceptsProcess(receipt.processId, receipt.executable):
				return
			if len(self._queue) >= QUEUE_CAPACITY:
				before = self._drops.pendingQueueDrops
				self._drops = self._drops.withPendingDrop()
				pendingDrop = (before, self._drops.pendingQueueDrops)
			else:
				self._queue.append((token, receipt))
		if pendingDrop is not None:
			self._announceDropMilestones(*pendingDrop, pending=True)

	def drain(self) -> int:
		"""Drain at most :data:`DRAIN_LIMIT` receipts into retained rows; return the count drained."""

		drained: list[tuple[int | None, EventReceipt]] = []
		with self._lock:
			while self._queue and len(drained) < DRAIN_LIMIT:
				drained.append(self._queue.popleft())
		rows: list[EventRow] = []
		for token, receipt in drained:
			with self._lock:
				current = (
					self._active
					and receipt.generation == self._generation
					and (token is None or token in self._activeSubscriptionTokens)
				)
				if not current:
					self._lateReceiptsRejected += 1
					continue
			effective = self._effectiveFilter()
			if effective is None or not effective.admits(receipt.backend, receipt.eventType):
				# A receipt enqueued under the previous filter whose type has since been disabled is
				# dropped here rather than retained, so a live filter change stops retaining at once.
				continue
			rows.append(self._rowFromReceipt(receipt))
		if rows:
			self._appendRows(rows)
		if drained:
			self._notify()
		return len(rows)

	def pendingReceipts(self) -> int:
		with self._lock:
			return len(self._queue)

	# -- history snapshots and projections ---------------------------------

	def historySnapshot(self) -> EventHistory:
		with self._lock:
			return EventHistory(
				items=tuple(self._items),
				drops=self._drops,
				capturedCount=self._capturedCount,
			)

	def retainedRows(self) -> tuple[EventRow, ...]:
		return self.historySnapshot().rows

	def buildSelection(self, rows: tuple[EventRow, ...]) -> EventSelection:
		snapshot = self.historySnapshot()
		return EventSelection(
			rows=tuple(rows),
			boundaries=snapshot.boundaries,
			provenance=self._provenance(),
		)

	def renderSelection(self, rows: tuple[EventRow, ...], copyFormat: EventCopyFormat) -> str:
		return renderSelectedEvents(self.buildSelection(rows), copyFormat)

	def copySelectedEvents(
		self,
		rows: tuple[EventRow, ...],
		copyFormat: EventCopyFormat,
	) -> EventActionOutcome:
		if not rows:
			return EventActionOutcome("empty")
		admission = self._lifecycle.admit("events.copy")
		if not admission.accepted or admission.context is None:
			return EventActionOutcome("failed", errorCode="KS.EVENTS.COPY.UNAVAILABLE")
		text = renderSelectedEvents(self.buildSelection(rows), copyFormat)
		outcome = self._sendClipboard(text, admission.context, prefix="events-copy")
		if outcome is not None:
			return EventActionOutcome("failed", errorCode=outcome)
		return EventActionOutcome("copied", clipboardRequested=True)

	def exportMetadata(self) -> EventExportMetadata:
		snapshot = self.historySnapshot()
		rows = snapshot.rows
		return EventExportMetadata.build(
			self._provenance(),
			exportedEventCount=len(rows),
			drops=snapshot.drops,
			truncated=any(row.truncated for row in rows),
			boundaries=snapshot.boundaries,
		)

	def exportEventHistory(self) -> EventActionOutcome:
		"""Atomically export history, copying the committed path only after a successful replace."""

		if self._pickDestination is None:
			return EventActionOutcome("failed", errorCode="KS.EVENTS.EXPORT.NOPICKER")
		admission = self._lifecycle.admit("events.export")
		if not admission.accepted or admission.context is None:
			return EventActionOutcome("failed", errorCode="KS.EVENTS.EXPORT.UNAVAILABLE")
		generation = admission.generation
		snapshot = self.historySnapshot()
		rows = snapshot.rows
		metadata = EventExportMetadata.build(
			self._provenance(),
			exportedEventCount=len(rows),
			drops=snapshot.drops,
			truncated=any(row.truncated for row in rows),
			boundaries=snapshot.boundaries,
		)
		payload = serializeEventExport(metadata, rows)
		destination = self._pickDestination()
		if destination is None:
			return EventActionOutcome("cancelled")
		if not self._lifecycle.isCurrent(generation):
			return EventActionOutcome("stale", errorCode="KS.EVENTS.EXPORT.STALE")
		try:
			committed = self._stageAndReplace(destination, payload)
		except OSError:
			return EventActionOutcome(
				"failed",
				errorCode="KS.EVENTS.EXPORT.WRITE",
				generation=generation,
			)
		outcome = self._sendClipboard(str(committed), admission.context, prefix="events-export")
		if outcome is not None:
			return EventActionOutcome(
				"failed",
				committedPath=str(committed),
				errorCode=outcome,
				generation=generation,
			)
		return EventActionOutcome(
			"published",
			committedPath=str(committed),
			clipboardRequested=True,
			generation=generation,
		)

	# -- lifecycle registration -------------------------------------------

	def registerLifecycle(self) -> None:
		self._lifecycle.registerInvalidator("events.generation", self._invalidate)
		self._lifecycle.registerSource("events.sources", self._releaseSources)
		self._lifecycle.registerQueue("events.queue", self._releaseQueue)
		self._lifecycle.registerUi("events.ui", self._closeUi)
		self._lifecycle.registerResource("events.resources", self._releaseResources)

	def _invalidate(self) -> None:
		with self._lock:
			self._active = False
			self._generation += 1
			self._activeSubscriptionTokens.clear()
			self._sourceSubscriptionTokens.clear()

	def _releaseSources(self) -> None:
		with self._lock:
			sources = self._sources
		for source in sources:
			with contextlib.suppress(Exception):
				self._unsubscribeSource(source)
		with self._lock:
			self._sources = ()

	def _releaseQueue(self) -> None:
		with self._lock:
			self._queue.clear()

	def _closeUi(self) -> None:
		if self._historyListener is not None:
			with contextlib.suppress(Exception):
				self._historyListener(self.historySnapshot())

	def _releaseResources(self) -> None:
		return None

	# -- internals ---------------------------------------------------------

	def _subscribeSource(
		self,
		source: EventSource,
		scope: MonitorScope,
		activeFilter: EventFilter,
		generation: int,
	) -> None:
		"""Subscribe one source under a token unique to this subscription lifetime."""

		sourceId = id(source)
		with self._lock:
			previousToken = self._sourceSubscriptionTokens.pop(sourceId, None)
			if previousToken is not None:
				self._activeSubscriptionTokens.discard(previousToken)
			self._nextSubscriptionToken += 1
			token = self._nextSubscriptionToken
			self._sourceSubscriptionTokens[sourceId] = token
			self._activeSubscriptionTokens.add(token)
		try:
			source.subscribe(
				_SubscriptionSink(self, token),
				SubscriptionRequest(scope=scope, activeFilter=activeFilter, generation=generation),
			)
		except Exception:
			with self._lock:
				if self._sourceSubscriptionTokens.get(sourceId) == token:
					del self._sourceSubscriptionTokens[sourceId]
					self._activeSubscriptionTokens.discard(token)
			raise

	def _unsubscribeSource(self, source: EventSource) -> None:
		"""Invalidate callbacks before releasing a source subscription."""

		with self._lock:
			token = self._sourceSubscriptionTokens.pop(id(source), None)
			if token is not None:
				self._activeSubscriptionTokens.discard(token)
		source.unsubscribe()

	def _appendRows(self, rows: list[EventRow]) -> None:
		policy = RetentionPolicy.fromSetting(self._settings().eventRows)
		with self._lock:
			self._items.extend(rows)
			self._capturedCount += len(rows)
			before = self._drops.retainedRowDrops
			items, drops = applyRetention(tuple(self._items), self._drops, policy)
			self._items = list(items)
			self._drops = drops
			after = self._drops.retainedRowDrops
		self._announceDropMilestones(before, after, pending=False)

	def _appendBoundary(
		self,
		reason: BoundaryReason,
		scope: MonitorScope,
		detail: str,
		*,
		targetLifecycleReason: TargetLifecycleReason | None = None,
	) -> None:
		wall = self._wallClock()
		timestamp = self._formatTimestamp(wall)
		policy = RetentionPolicy.fromSetting(self._settings().eventRows)
		boundary = SessionBoundary(
			sequence=0,
			session=0,
			application=scope.application,
			processId=scope.processId,
			broad=scope.broad,
			reason=reason,
			startTimeText=timestamp,
			wallClockMs=wall,
			detail=detail,
			targetLifecycleReason=targetLifecycleReason,
		)
		with self._lock:
			self._order += 1
			boundary = replace(boundary, sequence=self._order, session=self._session)
			self._items.append(boundary)
			items, drops = applyRetention(tuple(self._items), self._drops, policy)
			if boundary not in items:
				working = list(items)
				working.append(boundary)
				while len(working) > policy.effectiveCap:
					for index, item in enumerate(working):
						if isinstance(item, EventRow):
							del working[index]
							drops = drops.withRetainedDrop()
							break
					sessionsWithRows = {item.session for item in working if isinstance(item, EventRow)}
					working = [
						item
						for item in working
						if item is boundary
						or not isinstance(item, SessionBoundary)
						or item.session in sessionsWithRows
					]
				items = tuple(working)
			self._items = list(items)
			self._drops = drops

	def _nextOrder(self) -> int:
		with self._lock:
			self._order += 1
			return self._order

	def _rowFromReceipt(self, receipt: EventReceipt) -> EventRow:
		policy = self._policy()
		settings = self._settings()
		with self._lock:
			self._order += 1
			order = self._order
			session = self._session
			rawEventsEnabled = self._rawEventsEnabled
		name, nameRedacted = self._transformField(
			receipt.objectName,
			receipt.protectedName,
			f"event-{order}-name",
			policy,
		)
		detail, detailRedacted = self._transformField(
			receipt.detail,
			receipt.protectedDetail,
			f"event-{order}-detail",
			policy,
		)
		truncated = False
		if detail is not None and len(detail) > settings.eventDetailCharacters:
			detail = detail[: settings.eventDetailCharacters]
			truncated = True
		changedValue, changeEvidence = self._transformChangedValue(receipt, order, policy)
		changedValueTruncated = False
		if changedValue is not None and len(changedValue) > settings.eventDetailCharacters:
			changedValue = changedValue[: settings.eventDetailCharacters]
			changedValueTruncated = True
		drainMs = self._monotonic()
		wall = self._wallClock()
		return EventRow(
			sequence=order,
			session=session,
			backend=receipt.backend,
			eventType=receipt.eventType,
			processId=receipt.processId,
			application=receipt.application,
			objectName=name,
			objectRole=receipt.objectRole,
			detail=detail,
			timestampText=self._formatTimestamp(wall),
			wallClockMs=wall,
			receiptToProcessingMs=max(0.0, drainMs - receipt.receivedAtMs),
			receiptToPropertyReadMs=max(0.0, receipt.readAtMs - receipt.receivedAtMs),
			redacted=nameRedacted or detailRedacted or changeEvidence is ChangeEvidence.REDACTED,
			rawEvent=receipt.backend is EventBackend.RAW_UIA,
			truncated=truncated or changedValueTruncated,
			provenance=EventProvenance(
				backend=receipt.backend,
				rawEventsEnabled=rawEventsEnabled,
				redactionEnabled=policy.redactProtectedText,
				settingsRevision=settings.settingsRevision,
				policyRevision=policy.policyRevision,
			),
			sourceRef=receipt.sourceRef,
			sourceIdentity=receipt.sourceIdentity,
			changedValue=changedValue,
			changeEvidence=changeEvidence,
			changedValueTruncated=changedValueTruncated,
		)

	def _transformField(
		self,
		value: str,
		protected: bool,
		sourceId: str,
		policy: PrivacyPolicy,
	) -> tuple[str | None, bool]:
		observed = ObservedValue(
			fieldGroup=FieldGroup.EVENT,
			value=value,
			privacyClass=PrivacyClass.PROTECTED if protected else PrivacyClass.PUBLIC,
			protection=ProtectionEvidence(True) if protected else ProtectionEvidence.allClear(),
			sourceId=sourceId,
		)
		transformed = transformValue(observed, SinkId.EVENT, policy)
		if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
			return None, True
		return cast(str, transformed.value), False

	def _transformChangedValue(
		self,
		receipt: EventReceipt,
		order: int,
		policy: PrivacyPolicy,
	) -> tuple[str | None, ChangeEvidence]:
		"""Carry a source's change evidence into the row, replacing it when policy withholds it.

		A withheld value becomes the stated ``redacted`` outcome rather than a blank cell, so the
		Changed value column always distinguishes "nothing was reported" from "something was".
		"""

		if not receipt.changeEvidence.carriesValue:
			return None, receipt.changeEvidence
		value, redacted = self._transformField(
			receipt.changedValue,
			receipt.protectedChangedValue,
			f"event-{order}-changed-value",
			policy,
		)
		if redacted:
			return None, ChangeEvidence.REDACTED
		return value, receipt.changeEvidence

	def _provenance(self) -> MonitorProvenance:
		settings = self._settings()
		policy = self._policy()
		with self._lock:
			scope = self._scope or MonitorScope.broadScope()
			rawEventsEnabled = self._rawEventsEnabled
			activeFilter = self._filter
		return MonitorProvenance(
			scope=scope,
			rawEventsEnabled=rawEventsEnabled,
			redactionEnabled=policy.redactProtectedText,
			settingsRevision=settings.settingsRevision,
			policyRevision=policy.policyRevision,
			queueCapacity=QUEUE_CAPACITY,
			drainLimit=DRAIN_LIMIT,
			retention=RetentionPolicy.fromSetting(settings.eventRows),
			detailCharacters=settings.eventDetailCharacters,
			filterSummary=activeFilter.summary(),
		)

	def _stageAndReplace(self, destination: Path, payload: bytes) -> Path:
		parent = destination.parent
		handle = tempfile.NamedTemporaryFile(
			dir=parent,
			prefix=".keystone-events-",
			suffix=".tmp",
			delete=False,
		)
		staging = Path(handle.name)
		try:
			with handle:
				_ = handle.write(payload)
				handle.flush()
				os.fsync(handle.fileno())
			os.replace(staging, destination)
		except OSError:
			with contextlib.suppress(OSError):
				staging.unlink()
			raise
		return destination

	def _sendClipboard(self, text: str, context: CorrelationContext, *, prefix: str) -> str | None:
		request = ClipboardRequest(text=text, requestId=f"{prefix}-{uuid4().hex}", context=context)
		result = self._clipboard.copyText(request)
		if result.status.token == "failed":
			return f"KS.EVENTS.{prefix.upper().replace('-', '.')}.CLIPBOARD"
		return None

	def _announceDropMilestones(self, before: int, after: int, *, pending: bool) -> None:
		milestones = crossedDropMilestones(before, after)
		if not milestones:
			return
		admission = self._lifecycle.admit("events.drop")
		if not admission.accepted or admission.context is None:
			return
		messageId = "events.drop.pending" if pending else "events.drop.retained"
		request = FeedbackRequest(
			messageId=messageId,
			arguments=(milestones[-1],),
			context=admission.context,
		)
		with contextlib.suppress(Exception):
			_ = self._feedback.announce(request)
		event = CueEventId.PENDING_QUEUE_DROP if pending else CueEventId.RETAINED_ROW_DROP
		self._emitMonitorSound(event, coalescingKey=str(milestones[-1]))

	def _emitMonitorSound(
		self,
		event: CueEventId,
		*,
		coalescingKey: str | None = None,
		generation: int | None = None,
	) -> None:
		# Sound is optional and additive: the drop milestone has already been spoken. A missing
		# seam is a no-op, and any failure to build or schedule the cue must never disturb speech.
		sound = self._sound
		if sound is None:
			return
		with self._lock:
			currentGeneration = self._generation
		owner = SoundOwner(SoundOwnerKind.MONITOR, currentGeneration if generation is None else generation)
		with contextlib.suppress(Exception):
			sound.emit(soundRequestFor(event, owner, coalescingKey=coalescingKey))

	def _announceMonitorLifecycle(
		self,
		messageId: str,
		event: CueEventId,
		*,
		generation: int | None = None,
		targetName: str | None = None,
	) -> None:
		# Speech-first monitor lifecycle: admit and speak the localized transition, then layer the
		# optional cue on the owning monitor generation. No admission means no speech and no cue, so
		# the sound can never precede or replace speech.
		admission = self._lifecycle.admit("events.monitor")
		if not admission.accepted or admission.context is None:
			return
		arguments: tuple[str | bool, ...] = ()
		if messageId == "events.monitor.started":
			with self._lock:
				scope = self._scope
				rawEventsEnabled = self._rawEventsEnabled
			arguments = (
				targetName or "",
				"" if scope is None else scope.kind.value,
				rawEventsEnabled,
			)
		request = FeedbackRequest(messageId=messageId, arguments=arguments, context=admission.context)
		with contextlib.suppress(Exception):
			_ = self._feedback.announce(request)
		self._emitMonitorSound(event, generation=generation)

	def _invalidateMonitorSound(self, *, generation: int | None = None) -> None:
		# Synchronously discard any pending cue on the owning monitor generation at a lifecycle
		# boundary so a stale generation can never sound after the session is gone. Speech and history
		# are untouched, and a missing or raising seam stays isolated.
		sound = self._sound
		if sound is None:
			return
		with self._lock:
			currentGeneration = self._generation
		target = currentGeneration if generation is None else generation
		with contextlib.suppress(Exception):
			sound.invalidate(SoundOwner(SoundOwnerKind.MONITOR, target))

	def _announceSessionRisks(self, scope: MonitorScope, *, redactionEnabled: bool) -> None:
		# After the started transition, speak each privacy risk this session actually carries. The
		# monitor's own provenance treats a broad scope, raw UIA event families, and disabled redaction
		# as the session risks, so each active one speaks its distinct localized warning before the
		# shared-warning cue. A risk that is not active stays silent, so a cautious session warns of
		# nothing.
		if scope.broad:
			self._announceSessionRisk("events.risk.broadScope", CueEventId.BROAD_EVENT_SCOPE)
		with self._lock:
			rawEventsEnabled = self._rawEventsEnabled
		if rawEventsEnabled:
			self._announceSessionRisk("events.risk.rawUia", CueEventId.RAW_UIA_FALLBACK)
		if not redactionEnabled:
			self._announceSessionRisk("events.risk.redactionDisabled", CueEventId.REDACTION_DISABLED)

	def _announceSessionRisk(self, messageId: str, event: CueEventId) -> None:
		# Speech-first session risk: admit and speak the localized warning, then layer the optional
		# shared-warning cue owned by the system generation. Speech is mandatory and the sound optional,
		# so a missing or raising seam still speaks the risk and never disturbs the started session.
		admission = self._lifecycle.admit("events.risk")
		if not admission.accepted or admission.context is None:
			return
		request = FeedbackRequest(messageId=messageId, arguments=(), context=admission.context)
		with contextlib.suppress(Exception):
			_ = self._feedback.announce(request)
		self._emitSystemWarningSound(event)

	def _emitSystemWarningSound(self, event: CueEventId) -> None:
		# The warning cue is optional and additive: the risk has already been spoken. A missing seam is
		# a no-op, and any failure to build or schedule the shared-warning cue must never disturb speech.
		sound = self._sound
		if sound is None:
			return
		with self._lock:
			generation = self._generation
		owner = SoundOwner(SoundOwnerKind.SYSTEM, generation)
		with contextlib.suppress(Exception):
			sound.emit(soundRequestFor(event, owner))

	def _recordRuntime(self, code: str, fields: tuple[tuple[str, str | int | bool], ...]) -> None:
		# The log is an optional, additive record of what the monitor did. A missing or failing sink
		# never interrupts monitoring, speech, or retained history.
		sink = self._runtimeLog
		if sink is None:
			return
		with contextlib.suppress(Exception):
			sink(code, fields)

	def _recordSessionStart(self, scope: MonitorScope) -> None:
		"""Log the same session-start facts after a start or successful scope switch."""

		settings = self._settings()
		with self._lock:
			rawEventsEnabled = self._rawEventsEnabled
		self._recordRuntime(
			"KS.EVENT.MONITOR_STARTED",
			(
				("scopeKind", scope.kind.value),
				("rawEventsEnabled", rawEventsEnabled),
				("retainedLimit", RetentionPolicy.fromSetting(settings.eventRows).effectiveCap),
				("pendingLimit", QUEUE_CAPACITY),
			),
		)
		if scope.broad:
			self._recordRuntime(
				"KS.EVENT.BROAD_SCOPE_ENABLED",
				(("scopeKind", scope.kind.value), ("warningId", "events.risk.broadScope")),
			)

	def _boundaryDetail(self, reason: BoundaryReason) -> str:
		return {
			BoundaryReason.STOPPED: "Monitoring stopped",
			BoundaryReason.SWITCHED: "Monitoring switched",
			BoundaryReason.FILTER_CHANGED: "Event filter changed",
			BoundaryReason.PROCESS_EXITED: "Monitored process exited",
			BoundaryReason.TARGET_DESTROYED: "Monitored target was destroyed",
			BoundaryReason.TARGET_COM_FAILURE: "Monitored target became stale",
			BoundaryReason.TARGET_HUNG: "Monitored target is not responding",
			BoundaryReason.CLOSED: "Events workspace closed",
			BoundaryReason.SECURE: "Secure screen entered",
			BoundaryReason.STARTED: "Monitoring started",
		}[reason]

	def _notify(self) -> None:
		if self._historyListener is None:
			return
		with contextlib.suppress(Exception):
			self._historyListener(self.historySnapshot())
