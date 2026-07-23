"""Typed, immutable event-monitor domain.

This module owns every value type the process-pinned event monitor retains, copies, and
exports: the pinned monitoring scope, the immutable future filter, the minimal cross-thread
receipt, the privacy-safe retained row, session boundaries, exact drop counters, the retention
policy, an immutable history snapshot, and the copy/export projections. Nothing here performs
input/output, threading, or privacy classification; the application service transforms observed
values through :mod:`..domain.privacy` before building a row, so a retained row is already
privacy-safe and the copy/export renderers never re-derive protected content.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
import json


QUEUE_CAPACITY = 1_000
DRAIN_LIMIT = 100
DEFAULT_RETENTION_ROWS = 2_000
RETENTION_CEILING_RECORDS = 1_000_000
MINIMUM_RETENTION_ROWS = 0
MAXIMUM_RETENTION_ROWS = 1_000_000


class EventBackend(StrEnum):
	NVDA = "nvda"
	RAW_UIA = "rawUia"


class NvdaEventType(StrEnum):
	FOCUS = "focus"
	FOREGROUND = "foreground"
	NAME_CHANGE = "nameChange"
	VALUE_CHANGE = "valueChange"
	STATE_CHANGE = "stateChange"
	DESCRIPTION_CHANGE = "descriptionChange"
	LIVE_REGION = "liveRegion"
	SELECTION = "selection"
	CARET = "caret"
	CONTROLLER = "controller"
	NAVIGATOR_OBJECT = "navigatorObject"


class RawUiaFamily(StrEnum):
	NOTIFICATION = "notification"
	SELECTION = "selection"
	LAYOUT = "layout"
	WINDOW = "window"
	RELATION = "relation"
	DRAG_DROP = "dragDrop"
	ALERT = "alert"
	ITEM_STATUS = "itemStatus"
	TOOLTIP = "tooltip"
	ACTIVE_TEXT_POSITION = "activeTextPosition"


class ChangeEvidence(StrEnum):
	"""How much a retained row can honestly say about the value an event changed.

	Every event carries exactly one of these. The four value-carrying kinds each name where the text
	came from; the four remaining kinds are stated outright rather than left blank, so an empty
	Changed value cell can never be misread as "the value became empty".
	"""

	PROVIDER_REPORTED = "providerReported"
	READ_AFTER_EVENT = "readAfterEvent"
	PRIOR_OBSERVATION_DELTA = "priorObservationDelta"
	CARET_METADATA = "caretMetadata"
	NOT_APPLICABLE = "notApplicable"
	NOT_EXPOSED = "notExposed"
	UNAVAILABLE = "unavailable"
	REDACTED = "redacted"

	@property
	def carriesValue(self) -> bool:
		return self in _VALUE_CARRYING_EVIDENCE


_VALUE_CARRYING_EVIDENCE = frozenset(
	{
		ChangeEvidence.PROVIDER_REPORTED,
		ChangeEvidence.READ_AFTER_EVENT,
		ChangeEvidence.PRIOR_OBSERVATION_DELTA,
		ChangeEvidence.CARET_METADATA,
	},
)
# A field that was read and found empty is an observation worth keeping, so only the three kinds
# that describe something a provider actually reported must be non-empty.
_NONEMPTY_EVIDENCE = frozenset(
	{
		ChangeEvidence.PROVIDER_REPORTED,
		ChangeEvidence.PRIOR_OBSERVATION_DELTA,
		ChangeEvidence.CARET_METADATA,
	},
)
EMPTY_VALUE_TEXT = "(empty)"
TRUNCATED_VALUE_TEXT = "(truncated)"

CHANGE_EVIDENCE_WORDS: dict[ChangeEvidence, str] = {
	ChangeEvidence.PROVIDER_REPORTED: "reported by the provider",
	ChangeEvidence.READ_AFTER_EVENT: "read after the event",
	ChangeEvidence.PRIOR_OBSERVATION_DELTA: "compared with the previous observation",
	ChangeEvidence.CARET_METADATA: "caret position metadata",
	ChangeEvidence.NOT_APPLICABLE: "not applicable",
	ChangeEvidence.NOT_EXPOSED: "not exposed",
	ChangeEvidence.UNAVAILABLE: "unavailable",
	ChangeEvidence.REDACTED: "withheld for privacy",
}

_CHANGE_STATE_TEXT: dict[ChangeEvidence, str] = {
	ChangeEvidence.NOT_APPLICABLE: "Not applicable",
	ChangeEvidence.NOT_EXPOSED: "Not exposed",
	ChangeEvidence.UNAVAILABLE: "Unavailable",
	ChangeEvidence.REDACTED: "(redacted)",
}


class EventCopyFormat(StrEnum):
	JSON = "json"
	TEXT = "text"
	MARKDOWN = "markdown"


class BoundaryReason(StrEnum):
	STARTED = "started"
	STOPPED = "stopped"
	SWITCHED = "switched"
	FILTER_CHANGED = "filterChanged"
	PROCESS_EXITED = "processExited"
	TARGET_DESTROYED = "targetDestroyed"
	TARGET_COM_FAILURE = "targetComFailure"
	TARGET_HUNG = "targetHung"
	CLOSED = "closed"
	SECURE = "secure"


class TargetLifecycleReason(StrEnum):
	DESTROYED = "destroyed"
	COM_FAILURE = "comFailure"
	HUNG = "hung"


class MonitorScopeKind(StrEnum):
	ELEMENT = "element"
	SUBTREE = "subtree"
	APPLICATION = "application"
	BROAD = "broad"


class ScopeUnavailableReason(StrEnum):
	"""Why one requested monitoring scope could not be frozen from the Inspector selection."""

	NO_SELECTION = "noSelection"
	SELECTION_OFFLINE = "selectionOffline"
	SELECTION_UNRESOLVED = "selectionUnresolved"
	NO_PROCESS = "noProcess"
	NO_IDENTITY = "noIdentity"
	UNSUPPORTED_SCOPE = "unsupportedScope"


class MonitorScopeUnavailable(Exception):
	"""Raised instead of widening a selected scope that cannot be frozen.

	Element, subtree, and application monitoring all describe the object the user is browsing in the
	Inspector. When that object cannot be resolved there is no honest way to keep monitoring: a
	silent widening to the focused application or to every process would observe events the user
	never asked for. The requested kind and the exact reason travel with the refusal so the Events
	workspace can say which one applied.
	"""

	def __init__(
		self,
		reason: ScopeUnavailableReason,
		kind: MonitorScopeKind | None = None,
	) -> None:
		super().__init__(reason.value)
		self.reason = reason
		self.kind = kind


type ProviderIdentityEvidence = tuple[str, str | int]


@dataclass(frozen=True, slots=True)
class TargetIdentity:
	"""Immutable provider evidence used to correlate one live accessibility object."""

	processId: int
	windowHandle: int
	providerEvidence: tuple[ProviderIdentityEvidence, ...]

	def __post_init__(self) -> None:
		if self.processId < 0:
			raise ValueError("target process id must be nonnegative")
		if self.windowHandle <= 0:
			raise ValueError("target window handle must be positive")
		if not self.providerEvidence:
			raise ValueError("target identity requires strong provider evidence")
		if any(not key or isinstance(value, bool) for key, value in self.providerEvidence):
			raise ValueError("target provider evidence must be named and scalar")
		if len(set(self.providerEvidence)) != len(self.providerEvidence):
			raise ValueError("target provider evidence must not contain duplicates")

	def correlates(self, candidate: TargetIdentity) -> bool:
		"""Require process, window, and at least one shared strong provider identifier."""

		return (
			self.processId == candidate.processId
			and self.windowHandle == candidate.windowHandle
			and not frozenset(self.providerEvidence).isdisjoint(candidate.providerEvidence)
		)

	@property
	def stableKey(self) -> str:
		"""One deterministic key for this exact identity, used to remember prior observations."""

		evidence = ",".join(f"{name}={value}" for name, value in sorted(self.providerEvidence))
		return f"{self.processId}:{self.windowHandle}:{evidence}"


# The eleven default NVDA events, each paired with the host handler NVDA invokes. The thin
# forwarders in the global plugin project these one-to-one; the order is the canonical filter and
# summary order used everywhere a deterministic sequence is required.
NVDA_EVENT_METHODS: tuple[tuple[NvdaEventType, str], ...] = (
	(NvdaEventType.FOCUS, "event_gainFocus"),
	(NvdaEventType.FOREGROUND, "event_foreground"),
	(NvdaEventType.NAME_CHANGE, "event_nameChange"),
	(NvdaEventType.VALUE_CHANGE, "event_valueChange"),
	(NvdaEventType.STATE_CHANGE, "event_stateChange"),
	(NvdaEventType.DESCRIPTION_CHANGE, "event_descriptionChange"),
	(NvdaEventType.LIVE_REGION, "event_liveRegionChange"),
	(NvdaEventType.SELECTION, "event_selection"),
	(NvdaEventType.CARET, "event_caret"),
	(NvdaEventType.CONTROLLER, "event_controllerForChange"),
	(NvdaEventType.NAVIGATOR_OBJECT, "event_becomeNavigatorObject"),
)
NVDA_EVENT_TYPES: tuple[NvdaEventType, ...] = tuple(eventType for eventType, _method in NVDA_EVENT_METHODS)
NVDA_METHOD_BY_TYPE: dict[NvdaEventType, str] = {
	eventType: method for eventType, method in NVDA_EVENT_METHODS
}
NVDA_TYPE_BY_METHOD: dict[str, NvdaEventType] = {
	method: eventType for eventType, method in NVDA_EVENT_METHODS
}
RAW_UIA_FAMILIES: tuple[RawUiaFamily, ...] = tuple(RawUiaFamily)

# Every raw UIA family that has a reliable NVDA ``event_UIA_*`` callback, paired with the NVDA
# event-method suffix (the ``event_`` prefix is added by NVDA). NVDA already hosts these UIA
# automation-event callbacks on its own UIA thread and hands the plugin a settled ``NVDAObject``, so
# the shipped raw source bridges those forwarded objects rather than owning fragile COM handlers.
# ``dragDrop`` intentionally has two source methods (drag effect and drop-target effect); both project
# onto the one declared family. Every declared family appears at least once, so the closed
# ``RawUiaFamily`` set is fully covered by a real NVDA callback.
RAW_UIA_EVENT_METHODS: tuple[tuple[str, RawUiaFamily], ...] = (
	("event_UIA_notification", RawUiaFamily.NOTIFICATION),
	("event_UIA_elementSelected", RawUiaFamily.SELECTION),
	("event_UIA_layoutInvalidated", RawUiaFamily.LAYOUT),
	("event_UIA_window_windowOpen", RawUiaFamily.WINDOW),
	("event_UIA_controllerFor", RawUiaFamily.RELATION),
	("event_UIA_dragDropEffect", RawUiaFamily.DRAG_DROP),
	("event_UIA_dropTargetEffect", RawUiaFamily.DRAG_DROP),
	("event_UIA_systemAlert", RawUiaFamily.ALERT),
	("event_UIA_itemStatus", RawUiaFamily.ITEM_STATUS),
	("event_UIA_toolTipOpened", RawUiaFamily.TOOLTIP),
	("event_UIA_activeTextPositionChanged", RawUiaFamily.ACTIVE_TEXT_POSITION),
)
RAW_UIA_FAMILY_BY_METHOD: dict[str, RawUiaFamily] = {
	method: family for method, family in RAW_UIA_EVENT_METHODS
}

# Applications Keystone never monitors, regardless of scope: its own inspector process and NVDA. Both
# the executable form (raw UIA) and the NVDA appModule name form (object events) are excluded.
EXCLUDED_EXECUTABLES: frozenset[str] = frozenset(
	{"nvda.exe", "nvda_uiaccess.exe", "nvda", "nvda_uiaccess"},
)

_DROP_MILESTONE_BASE: tuple[int, ...] = (1, 10, 100, 1_000, 10_000, 100_000, 1_000_000)


def crossedDropMilestones(previous: int, current: int) -> tuple[int, ...]:
	"""Return the announcement milestones strictly above ``previous`` and at or below ``current``.

	The first drop (crossing 1) is always a milestone; later milestones are 10, 100, 1,000, and each
	following power of ten. Repeated identical announcements are the caller's responsibility to
	coalesce; this returns each crossed milestone exactly once in ascending order.
	"""

	if current <= previous:
		return ()
	milestones = [value for value in _DROP_MILESTONE_BASE if previous < value <= current]
	ceiling = _DROP_MILESTONE_BASE[-1]
	multiple = ceiling * 10
	while multiple <= current:
		if multiple > previous:
			milestones.append(multiple)
		multiple *= 10
	return tuple(milestones)


@dataclass(frozen=True, slots=True)
class MonitorScope:
	"""One frozen event-monitor target, from an element through an explicitly approved broad scope."""

	application: str
	processId: int | None
	broad: bool = False
	kind: MonitorScopeKind = MonitorScopeKind.APPLICATION
	targetIdentity: TargetIdentity | None = None

	def __post_init__(self) -> None:
		if self.broad and self.processId is not None:
			raise ValueError("broad scope cannot pin a process id")
		if not self.broad and self.processId is None:
			raise ValueError("pinned scope requires a process id")
		if self.processId is not None and self.processId < 0:
			raise ValueError("process id must be nonnegative")
		if self.broad:
			object.__setattr__(self, "kind", MonitorScopeKind.BROAD)
		if self.kind is MonitorScopeKind.BROAD and not self.broad:
			raise ValueError("broad kind requires broad scope")
		requiresIdentity = self.kind in (MonitorScopeKind.ELEMENT, MonitorScopeKind.SUBTREE)
		if requiresIdentity != (self.targetIdentity is not None):
			raise ValueError("element and subtree scopes require one frozen target identity")
		if self.targetIdentity is not None and self.targetIdentity.processId != self.processId:
			raise ValueError("target identity process must match the monitored process")

	@classmethod
	def pinned(cls, application: str, processId: int) -> MonitorScope:
		return cls(
			application=application,
			processId=processId,
			broad=False,
			kind=MonitorScopeKind.APPLICATION,
		)

	@classmethod
	def element(cls, application: str, processId: int, identity: TargetIdentity) -> MonitorScope:
		return cls(
			application=application,
			processId=processId,
			kind=MonitorScopeKind.ELEMENT,
			targetIdentity=identity,
		)

	@classmethod
	def subtree(cls, application: str, processId: int, rootIdentity: TargetIdentity) -> MonitorScope:
		return cls(
			application=application,
			processId=processId,
			kind=MonitorScopeKind.SUBTREE,
			targetIdentity=rootIdentity,
		)

	@classmethod
	def broadScope(cls) -> MonitorScope:
		return cls(
			application="Broad scope: non-NVDA processes",
			processId=None,
			broad=True,
			kind=MonitorScopeKind.BROAD,
		)

	def acceptsProcess(self, processId: int, executable: str) -> bool:
		"""Apply the cheap executable and process gate before any provider ancestry reads."""

		if executable.casefold() in EXCLUDED_EXECUTABLES:
			return False
		if self.broad:
			return True
		return processId == self.processId

	def accepts(
		self,
		processId: int,
		executable: str,
		*,
		candidateIdentity: TargetIdentity | None = None,
		ancestorIdentities: Sequence[TargetIdentity] = (),
	) -> bool:
		if not self.acceptsProcess(processId, executable):
			return False
		if self.kind in (MonitorScopeKind.APPLICATION, MonitorScopeKind.BROAD):
			return True
		target = self.targetIdentity
		if target is None or candidateIdentity is None:
			return False
		if target.correlates(candidateIdentity):
			return True
		if self.kind is MonitorScopeKind.ELEMENT:
			return False
		return any(target.correlates(ancestor) for ancestor in ancestorIdentities[:40])

	@property
	def scopeText(self) -> str:
		if self.broad:
			return "Broad scope: non-NVDA processes"
		if self.kind is MonitorScopeKind.ELEMENT:
			return f"Selected element in {self.application}, process {self.processId}"
		if self.kind is MonitorScopeKind.SUBTREE:
			return f"Selected subtree in {self.application}, process {self.processId}"
		return f"{self.application}, process {self.processId}"


@dataclass(frozen=True, slots=True)
class EventFilter:
	"""One immutable set of event types captured for future events only."""

	nvdaTypes: frozenset[NvdaEventType]
	rawFamilies: frozenset[RawUiaFamily]

	def __post_init__(self) -> None:
		if not self.nvdaTypes and not self.rawFamilies:
			raise ValueError("an event filter must select at least one event type")

	@classmethod
	def default(cls) -> EventFilter:
		return cls(nvdaTypes=frozenset(NVDA_EVENT_TYPES), rawFamilies=frozenset())

	@property
	def selectedCount(self) -> int:
		return len(self.nvdaTypes) + len(self.rawFamilies)

	@property
	def rawEnabled(self) -> bool:
		return bool(self.rawFamilies)

	def orderedNvda(self) -> tuple[NvdaEventType, ...]:
		return tuple(eventType for eventType in NVDA_EVENT_TYPES if eventType in self.nvdaTypes)

	def orderedRaw(self) -> tuple[RawUiaFamily, ...]:
		return tuple(family for family in RAW_UIA_FAMILIES if family in self.rawFamilies)

	def summary(self) -> tuple[str, ...]:
		nvda = tuple(eventType.value for eventType in self.orderedNvda())
		raw = tuple(f"rawUia.{family.value}" for family in self.orderedRaw())
		return nvda + raw

	def admits(self, backend: EventBackend, eventType: str) -> bool:
		if backend is EventBackend.NVDA:
			return any(candidate.value == eventType for candidate in self.nvdaTypes)
		return any(candidate.value == eventType for candidate in self.rawFamilies)


@dataclass(frozen=True, slots=True)
class EventFilterChoice:
	"""One selectable event type for the Events workspace filter dialog.

	The ordered tuple from :func:`eventFilterChoices` is the single source of truth the native
	multi-choice dialog renders and the reverse mapping in :func:`selectionToFilter` reads, so
	dialog indices can never drift from the canonical NVDA-then-raw ordering.
	"""

	label: str
	backend: EventBackend
	nvdaType: NvdaEventType | None
	rawFamily: RawUiaFamily | None


def eventFilterChoices() -> tuple[EventFilterChoice, ...]:
	"""Return every filterable event type in canonical order: NVDA events, then raw UIA families."""

	nvda = tuple(
		EventFilterChoice(f"NVDA: {eventType.value}", EventBackend.NVDA, eventType, None)
		for eventType in NVDA_EVENT_TYPES
	)
	raw = tuple(
		EventFilterChoice(f"Raw UIA: {family.value}", EventBackend.RAW_UIA, None, family)
		for family in RAW_UIA_FAMILIES
	)
	return nvda + raw


def selectionToFilter(
	choices: Sequence[EventFilterChoice],
	selectedIndices: Sequence[int],
) -> EventFilter | None:
	"""Build an :class:`EventFilter` from chosen dialog indices, or ``None`` for an empty selection.

	A ``None`` result means the user selected nothing; the caller keeps the current filter rather
	than constructing the empty filter the domain forbids. Out-of-range indices are ignored so a
	stale dialog result can never raise.
	"""

	nvdaTypes: set[NvdaEventType] = set()
	rawFamilies: set[RawUiaFamily] = set()
	for index in selectedIndices:
		if not 0 <= index < len(choices):
			continue
		choice = choices[index]
		if choice.nvdaType is not None:
			nvdaTypes.add(choice.nvdaType)
		elif choice.rawFamily is not None:
			rawFamilies.add(choice.rawFamily)
	if not nvdaTypes and not rawFamilies:
		return None
	return EventFilter(nvdaTypes=frozenset(nvdaTypes), rawFamilies=frozenset(rawFamilies))


def filterToSelection(
	choices: Sequence[EventFilterChoice],
	activeFilter: EventFilter,
) -> tuple[int, ...]:
	"""Return the dialog indices pre-checked to reflect ``activeFilter``."""

	selected: list[int] = []
	for index, choice in enumerate(choices):
		if choice.nvdaType is not None and choice.nvdaType in activeFilter.nvdaTypes:
			selected.append(index)
		elif choice.rawFamily is not None and choice.rawFamily in activeFilter.rawFamilies:
			selected.append(index)
	return tuple(selected)


def monitoringScopeStatus(scope: MonitorScope | None, activeFilter: EventFilter) -> str:
	"""One persistent line describing pinned or broad scope and whether raw UIA is included.

	Broad scope is called out because it widens observation beyond one process; raw UIA is called
	out because it is an independent opt-in. Both are the mismatch/broad/raw signals the Events
	workspace keeps visible at all times.
	"""

	if scope is None or scope.broad:
		scopeText = "all applications (broad scope)"
	else:
		scopeText = scope.scopeText
	rawText = "raw UIA included" if activeFilter.rawEnabled else "raw UIA off"
	return f"Monitoring {scopeText}; {rawText}."


@dataclass(frozen=True, slots=True)
class EventReceipt:
	"""Minimal immutable primitives crossing from a callback into the runtime history.

	A receipt never carries a live COM/NVDA reference. ``objectName`` and ``detail`` hold the raw
	observed text plus its privacy classification so the service can transform them once before the
	value enters retained history; nothing downstream reads the raw fields again.
	"""

	backend: EventBackend
	eventType: str
	processId: int
	executable: str
	application: str
	sequence: int
	receivedAtMs: float
	readAtMs: float
	generation: int
	objectName: str
	objectRole: str
	detail: str
	protectedName: bool = False
	protectedDetail: bool = False
	changedValue: str = ""
	changeEvidence: ChangeEvidence = ChangeEvidence.NOT_APPLICABLE
	protectedChangedValue: bool = False
	sourceRef: str | None = None
	sourceIdentity: TargetIdentity | None = None

	def __post_init__(self) -> None:
		if self.processId < 0:
			raise ValueError("receipt process id must be nonnegative")
		if self.sequence < 0:
			raise ValueError("receipt sequence must be nonnegative")
		if self.generation < 0:
			raise ValueError("receipt generation must be nonnegative")
		if self.readAtMs < self.receivedAtMs:
			raise ValueError("property read cannot precede callback entry")
		if self.changeEvidence is ChangeEvidence.REDACTED:
			raise ValueError("a source never classifies its own reading as redacted")
		if self.changeEvidence in _NONEMPTY_EVIDENCE and not self.changedValue:
			raise ValueError("reported, compared, and caret change evidence require an observed value")
		if not self.changeEvidence.carriesValue and self.changedValue:
			raise ValueError("a stated change outcome cannot also carry a value")


@dataclass(frozen=True, slots=True)
class EventProvenance:
	"""Effective source and settings provenance retained with every row."""

	backend: EventBackend
	rawEventsEnabled: bool
	redactionEnabled: bool
	settingsRevision: int
	policyRevision: int

	def __post_init__(self) -> None:
		for value in (self.settingsRevision, self.policyRevision):
			if value <= 0:
				raise ValueError("provenance revisions must be positive")


@dataclass(frozen=True, slots=True)
class EventRow:
	"""One retained, privacy-safe event.

	``objectName`` and ``detail`` are ``None`` when the effective policy redacted or omitted them;
	``redacted`` records that at least one field was withheld so no consumer can misread a blank as
	an observed empty value.
	"""

	sequence: int
	session: int
	backend: EventBackend
	eventType: str
	processId: int
	application: str
	objectName: str | None
	objectRole: str
	detail: str | None
	timestampText: str
	wallClockMs: int
	receiptToProcessingMs: float
	receiptToPropertyReadMs: float
	redacted: bool
	rawEvent: bool
	truncated: bool
	provenance: EventProvenance
	exceptionalStatus: str | None = None
	changedValue: str | None = None
	changeEvidence: ChangeEvidence = ChangeEvidence.NOT_APPLICABLE
	changedValueTruncated: bool = False
	sourceRef: str | None = None
	sourceIdentity: TargetIdentity | None = None

	def __post_init__(self) -> None:
		if self.changeEvidence.carriesValue and self.changedValue is None:
			raise ValueError("value-carrying change evidence requires a retained value")
		if not self.changeEvidence.carriesValue and self.changedValue is not None:
			raise ValueError("a stated change outcome cannot also retain a value")
		if self.changedValueTruncated and self.changedValue is None:
			raise ValueError("a withheld or absent changed value cannot also be truncated")

	@property
	def isBoundary(self) -> bool:
		return False

	@property
	def changedValueText(self) -> str:
		"""The exact Changed value cell: an observed value, or why there is none.

		Truncation is tracked per field: a row whose detail was shortened says nothing about whether
		the changed value was, so an observed empty value still reads as empty here.
		"""

		if self.changedValue is None:
			return _CHANGE_STATE_TEXT[self.changeEvidence]
		if self.changedValue:
			return self.changedValue
		return TRUNCATED_VALUE_TEXT if self.changedValueTruncated else EMPTY_VALUE_TEXT


@dataclass(frozen=True, slots=True)
class SessionBoundary:
	"""A focusable, exported chronological marker separating monitoring sessions."""

	sequence: int
	session: int
	application: str
	processId: int | None
	broad: bool
	reason: BoundaryReason
	startTimeText: str
	wallClockMs: int
	detail: str
	targetLifecycleReason: TargetLifecycleReason | None = None

	@property
	def isBoundary(self) -> bool:
		return True


type HistoryItem = EventRow | SessionBoundary


@dataclass(frozen=True, slots=True)
class DropCounters:
	"""Exact, separate pending-queue and retained-row drop totals."""

	pendingQueueDrops: int = 0
	retainedRowDrops: int = 0

	def __post_init__(self) -> None:
		if self.pendingQueueDrops < 0 or self.retainedRowDrops < 0:
			raise ValueError("drop counters cannot be negative")

	def withPendingDrop(self, count: int = 1) -> DropCounters:
		return DropCounters(self.pendingQueueDrops + count, self.retainedRowDrops)

	def withRetainedDrop(self, count: int = 1) -> DropCounters:
		return DropCounters(self.pendingQueueDrops, self.retainedRowDrops + count)


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
	"""The validated retained-row policy derived from the ``eventRows`` setting.

	A positive ``userCap`` drops the oldest data row first, then bounds all retained records to that
	same limit. A zero cap removes the user limit but never disables safety: a hard
	``processCeiling`` of one million total retained records still applies. In both modes, boundaries
	without a retained row from their session are removed.
	"""

	userCap: int
	processCeiling: int = RETENTION_CEILING_RECORDS

	def __post_init__(self) -> None:
		if not MINIMUM_RETENTION_ROWS <= self.userCap <= MAXIMUM_RETENTION_ROWS:
			raise ValueError("retention user cap is outside the validated range")
		if self.processCeiling != RETENTION_CEILING_RECORDS:
			raise ValueError("retention process ceiling is fixed")

	@classmethod
	def fromSetting(cls, eventRows: int) -> RetentionPolicy:
		if isinstance(eventRows, bool):
			raise TypeError("event rows setting must be an integer, not a boolean")
		if not MINIMUM_RETENTION_ROWS <= eventRows <= MAXIMUM_RETENTION_ROWS:
			raise ValueError("event rows setting is outside the validated range")
		return cls(userCap=eventRows)

	@property
	def unbounded(self) -> bool:
		return self.userCap == 0

	@property
	def effectiveCap(self) -> int:
		return self.processCeiling if self.unbounded else self.userCap


@dataclass(frozen=True, slots=True)
class EventHistory:
	"""An immutable snapshot the workspace renders: ordered items plus exact totals."""

	items: tuple[HistoryItem, ...]
	drops: DropCounters
	capturedCount: int

	def __post_init__(self) -> None:
		if self.capturedCount < 0:
			raise ValueError("captured count cannot be negative")

	@classmethod
	def empty(cls) -> EventHistory:
		return cls(items=(), drops=DropCounters(), capturedCount=0)

	@property
	def rows(self) -> tuple[EventRow, ...]:
		return tuple(item for item in self.items if isinstance(item, EventRow))

	@property
	def boundaries(self) -> tuple[SessionBoundary, ...]:
		return tuple(item for item in self.items if isinstance(item, SessionBoundary))

	@property
	def rowCount(self) -> int:
		return sum(1 for item in self.items if isinstance(item, EventRow))

	def matchingFilter(self, activeFilter: EventFilter) -> tuple[HistoryItem, ...]:
		result: list[HistoryItem] = []
		for item in self.items:
			if isinstance(item, SessionBoundary):
				result.append(item)
				continue
			if activeFilter.admits(item.backend, item.eventType):
				result.append(item)
		return tuple(result)


@dataclass(frozen=True, slots=True)
class MonitorProvenance:
	"""Effective scope and monitor settings shared by copy and export projections."""

	scope: MonitorScope
	rawEventsEnabled: bool
	redactionEnabled: bool
	settingsRevision: int
	policyRevision: int
	queueCapacity: int
	drainLimit: int
	retention: RetentionPolicy
	detailCharacters: int
	filterSummary: tuple[str, ...]

	@property
	def broadScope(self) -> bool:
		return self.scope.broad


@dataclass(frozen=True, slots=True)
class EventSelection:
	"""One immutable, already privacy-transformed projection rendered to every copy format."""

	rows: tuple[EventRow, ...]
	boundaries: tuple[SessionBoundary, ...]
	provenance: MonitorProvenance


@dataclass(frozen=True, slots=True)
class EventExportMetadata:
	"""Complete export provenance: scope, settings, drops, truncation, and session boundaries."""

	scopeText: str
	broadScope: bool
	application: str
	processId: int | None
	rawEventsEnabled: bool
	redactionEnabled: bool
	exportedEventCount: int
	pendingQueueDrops: int
	retainedRowDrops: int
	truncated: bool
	queueCapacity: int
	drainLimit: int
	retentionCap: int
	retentionCeiling: int
	detailCharacters: int
	filterSummary: tuple[str, ...]
	settingsRevision: int
	policyRevision: int
	sessionBoundaries: tuple[SessionBoundary, ...]
	targetLifecycleReason: TargetLifecycleReason | None = None

	@classmethod
	def build(
		cls,
		provenance: MonitorProvenance,
		*,
		exportedEventCount: int,
		drops: DropCounters,
		truncated: bool,
		boundaries: tuple[SessionBoundary, ...],
	) -> EventExportMetadata:
		targetLifecycleReason = next(
			(
				boundary.targetLifecycleReason
				for boundary in reversed(boundaries)
				if boundary.targetLifecycleReason is not None
			),
			None,
		)
		return cls(
			scopeText=provenance.scope.scopeText,
			broadScope=provenance.broadScope,
			application=provenance.scope.application,
			processId=provenance.scope.processId,
			rawEventsEnabled=provenance.rawEventsEnabled,
			redactionEnabled=provenance.redactionEnabled,
			exportedEventCount=exportedEventCount,
			pendingQueueDrops=drops.pendingQueueDrops,
			retainedRowDrops=drops.retainedRowDrops,
			truncated=truncated,
			queueCapacity=provenance.queueCapacity,
			drainLimit=provenance.drainLimit,
			retentionCap=provenance.retention.userCap,
			retentionCeiling=provenance.retention.processCeiling,
			detailCharacters=provenance.detailCharacters,
			filterSummary=provenance.filterSummary,
			settingsRevision=provenance.settingsRevision,
			policyRevision=provenance.policyRevision,
			sessionBoundaries=boundaries,
			targetLifecycleReason=targetLifecycleReason,
		)


_REDACTED_PLACEHOLDER = "(redacted)"


def _rowValue(value: str | None) -> str:
	return _REDACTED_PLACEHOLDER if value is None else value


def _rowMapping(row: EventRow) -> dict[str, object]:
	return {
		"sequence": row.sequence,
		"session": row.session,
		"backend": row.backend.value,
		"event": row.eventType,
		"object": None if row.objectName is None else row.objectName,
		"role": row.objectRole,
		"detail": None if row.detail is None else row.detail,
		"changedValue": row.changedValue,
		"changedValueText": row.changedValueText,
		"changedValueTruncated": row.changedValueTruncated,
		"changeEvidence": row.changeEvidence.value,
		"time": row.timestampText,
		"processId": row.processId,
		"application": row.application,
		"backendName": row.backend.value,
		"rawEvent": row.rawEvent,
		"redacted": row.redacted,
		"truncated": row.truncated,
		"receiptToProcessingMs": round(row.receiptToProcessingMs, 3),
		"receiptToPropertyReadMs": round(row.receiptToPropertyReadMs, 3),
		"exceptionalStatus": row.exceptionalStatus,
	}


def _boundaryMapping(boundary: SessionBoundary) -> dict[str, object]:
	mapping: dict[str, object] = {
		"sequence": boundary.sequence,
		"session": boundary.session,
		"application": boundary.application,
		"processId": boundary.processId,
		"broadScope": boundary.broad,
		"reason": boundary.reason.value,
		"startTime": boundary.startTimeText,
		"detail": boundary.detail,
	}
	if boundary.targetLifecycleReason is not None:
		mapping["targetLifecycleReason"] = boundary.targetLifecycleReason.value
	return mapping


def _provenanceMapping(provenance: MonitorProvenance) -> dict[str, object]:
	return {
		"scope": provenance.scope.scopeText,
		"broadScope": provenance.broadScope,
		"application": provenance.scope.application,
		"processId": provenance.scope.processId,
		"rawEventsEnabled": provenance.rawEventsEnabled,
		"redactionEnabled": provenance.redactionEnabled,
		"settingsRevision": provenance.settingsRevision,
		"policyRevision": provenance.policyRevision,
		"queueCapacity": provenance.queueCapacity,
		"drainLimit": provenance.drainLimit,
		"retentionCap": provenance.retention.userCap,
		"retentionCeiling": provenance.retention.processCeiling,
		"detailCharacters": provenance.detailCharacters,
		"filter": list(provenance.filterSummary),
	}


def renderSelectedEvents(selection: EventSelection, copyFormat: EventCopyFormat) -> str:
	"""Render one immutable transformed selection to JSON, plain text, or Markdown.

	Every format carries the complete selected event set, the privacy state of each row, and the
	session/source/settings provenance so a copied fragment is never mistaken for a complete,
	unredacted history.
	"""

	if copyFormat is EventCopyFormat.JSON:
		payload: dict[str, object] = {
			"schema": "keystone.events.copy.v1",
			"provenance": _provenanceMapping(selection.provenance),
			"boundaries": [_boundaryMapping(boundary) for boundary in selection.boundaries],
			"events": [_rowMapping(row) for row in selection.rows],
		}
		return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent="\t")
	if copyFormat is EventCopyFormat.MARKDOWN:
		return _renderMarkdown(selection)
	return _renderText(selection)


def _renderProvenanceLines(provenance: MonitorProvenance) -> tuple[str, ...]:
	return (
		f"Scope: {provenance.scope.scopeText}",
		f"Raw UIA events: {'on' if provenance.rawEventsEnabled else 'off'}",
		f"Redaction: {'on' if provenance.redactionEnabled else 'off'}",
		f"Filter: {', '.join(provenance.filterSummary)}",
		f"Settings revision: {provenance.settingsRevision}",
	)


def _renderText(selection: EventSelection) -> str:
	lines: list[str] = ["Keystone captured events"]
	lines.extend(_renderProvenanceLines(selection.provenance))
	for boundary in selection.boundaries:
		lines.append(f"-- Session {boundary.session}: {boundary.detail}")
	for row in selection.rows:
		lines.append(
			f"[{row.timestampText}] {row.eventType} | {_rowValue(row.objectName)} "
			+ f"| {row.objectRole} | {_rowValue(row.detail)} "
			+ f"| {row.changedValueText} ({CHANGE_EVIDENCE_WORDS[row.changeEvidence]}) "
			+ f"| {row.application} ({row.processId}) | {row.backend.value}"
			+ ("" if not row.redacted else " | redacted")
			+ ("" if not row.truncated else " | truncated"),
		)
	return "\n".join(lines)


def _renderMarkdown(selection: EventSelection) -> str:
	lines: list[str] = ["# Keystone captured events", ""]
	for line in _renderProvenanceLines(selection.provenance):
		lines.append(f"- {line}")
	lines.append("")
	if selection.boundaries:
		lines.append("## Sessions")
		for boundary in selection.boundaries:
			lines.append(f"- Session {boundary.session}: {boundary.detail}")
		lines.append("")
	lines.append(
		"| Time | Event | Object | Role | Details | Changed value | Change evidence | Process | Backend |",
	)
	lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for row in selection.rows:
		lines.append(
			f"| {row.timestampText} | {row.eventType} | {_rowValue(row.objectName)} "
			+ f"| {row.objectRole} | {_rowValue(row.detail)} | {row.changedValueText} "
			+ f"| {CHANGE_EVIDENCE_WORDS[row.changeEvidence]} | {row.application} ({row.processId}) "
			+ f"| {row.backend.value} |",
		)
	return "\n".join(lines)


def _metadataMapping(metadata: EventExportMetadata) -> dict[str, object]:
	mapping: dict[str, object] = {
		"scope": metadata.scopeText,
		"broadScope": metadata.broadScope,
		"application": metadata.application,
		"processId": metadata.processId,
		"rawEventsEnabled": metadata.rawEventsEnabled,
		"redactionEnabled": metadata.redactionEnabled,
		"exportedEventCount": metadata.exportedEventCount,
		"pendingQueueDrops": metadata.pendingQueueDrops,
		"retainedRowDrops": metadata.retainedRowDrops,
		"truncated": metadata.truncated,
		"queueCapacity": metadata.queueCapacity,
		"drainLimit": metadata.drainLimit,
		"retentionCap": metadata.retentionCap,
		"retentionCeiling": metadata.retentionCeiling,
		"detailCharacters": metadata.detailCharacters,
		"filter": list(metadata.filterSummary),
		"settingsRevision": metadata.settingsRevision,
		"policyRevision": metadata.policyRevision,
		"sessionBoundaries": [_boundaryMapping(boundary) for boundary in metadata.sessionBoundaries],
	}
	if metadata.targetLifecycleReason is not None:
		mapping["targetLifecycleReason"] = metadata.targetLifecycleReason.value
	return mapping


def serializeEventExport(metadata: EventExportMetadata, rows: Sequence[EventRow]) -> bytes:
	"""Serialize one atomic export payload: metadata, ordered boundaries, and privacy-safe rows."""

	payload: dict[str, object] = {
		"schema": "keystone.events.export.v1",
		"metadata": _metadataMapping(metadata),
		"events": [_rowMapping(row) for row in rows],
	}
	text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
	return (text + "\n").encode("utf-8")


def _rowCountIn(items: list[HistoryItem]) -> int:
	return sum(1 for item in items if isinstance(item, EventRow))


def _removeOldestDataRow(items: list[HistoryItem]) -> bool:
	for index, item in enumerate(items):
		if isinstance(item, EventRow):
			del items[index]
			return True
	return False


def applyPositiveCap(
	items: Sequence[HistoryItem],
	drops: DropCounters,
	cap: int,
) -> tuple[tuple[HistoryItem, ...], DropCounters]:
	"""Bound retained data rows to ``cap`` and discard boundaries no retained row needs."""

	if cap < 0:
		raise ValueError("retention cap cannot be negative")
	working = list(items)
	while _rowCountIn(working) > cap:
		if not _removeOldestDataRow(working):
			break
		drops = drops.withRetainedDrop()
	sessionsWithRows = {item.session for item in working if isinstance(item, EventRow)}
	return (
		tuple(
			item
			for item in working
			if not isinstance(item, SessionBoundary) or item.session in sessionsWithRows
		),
		drops,
	)


def applyCeiling(
	items: Sequence[HistoryItem],
	drops: DropCounters,
	ceiling: int,
) -> tuple[tuple[HistoryItem, ...], DropCounters]:
	"""Bound total records to ``ceiling``, evicting rows then their no-longer-needed boundaries."""

	if ceiling < 0:
		raise ValueError("retention ceiling cannot be negative")
	working: list[HistoryItem | None] = list(items)
	rowIndexes: deque[int] = deque()
	rowsBySession: dict[int, int] = {}
	boundaryIndexesBySession: dict[int, list[int]] = {}
	for index, item in enumerate(working):
		if isinstance(item, EventRow):
			rowIndexes.append(index)
			rowsBySession[item.session] = rowsBySession.get(item.session, 0) + 1
		else:
			assert isinstance(item, SessionBoundary)
			boundaryIndexesBySession.setdefault(item.session, []).append(index)

	retainedCount = len(working)

	def removeBoundaries(session: int) -> None:
		nonlocal retainedCount
		for index in boundaryIndexesBySession.pop(session, ()):
			if working[index] is not None:
				working[index] = None
				retainedCount -= 1

	for session in tuple(boundaryIndexesBySession):
		if rowsBySession.get(session, 0) == 0:
			removeBoundaries(session)
	while retainedCount > ceiling:
		workingIndex = rowIndexes.popleft()
		row = working[workingIndex]
		assert isinstance(row, EventRow)
		working[workingIndex] = None
		retainedCount -= 1
		drops = drops.withRetainedDrop()
		rowsBySession[row.session] -= 1
		if rowsBySession[row.session] == 0:
			removeBoundaries(row.session)
	return tuple(item for item in working if item is not None), drops


def applyRetention(
	items: Sequence[HistoryItem],
	drops: DropCounters,
	policy: RetentionPolicy,
) -> tuple[tuple[HistoryItem, ...], DropCounters]:
	"""Apply row-first eviction and a total-record ceiling in every retention mode."""

	if policy.unbounded:
		return applyCeiling(items, drops, policy.processCeiling)
	items, drops = applyPositiveCap(items, drops, policy.userCap)
	return applyCeiling(items, drops, policy.effectiveCap)
