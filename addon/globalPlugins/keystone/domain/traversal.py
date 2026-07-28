from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
from time import monotonic_ns
from typing import Literal, Protocol
from ..ports.providers import (
	IdentityComparisonPort,
	IdentityComparisonRequest,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderReadResult,
	ReadBudget,
	ReadOnlyNodePort,
)
from .correlation import CorrelationContext, requireCompleteCorrelation
from .document_records import COMMON_NODE_FIELDS
from .provider_measurement import (
	CONTRACT_DIGEST,
	BackendId,
	MeasurementAggregate,
	MeasurementObservation,
	MeasurementOutcome,
	MeasurementProvenance,
	aggregateMeasurements,
)
from .settings import SettingsSnapshot


type CaptureMode = Literal["bounded", "unlimited"]
type ProviderOperation = Literal["fieldRead", "childrenRead", "identityCompare"]
type CaptureProgressPhase = Literal["collecting", "preparing", "packaging"]

_MEASUREMENT_PROVENANCE = MeasurementProvenance(
	hashlib.sha256(b"keystone.capture.provider-timing").hexdigest(),
	CONTRACT_DIGEST,
)

PROCESS_MAXIMUM_NODES = 1_000_000
PROCESS_MAXIMUM_DEPTH = 10_000
PROCESS_MAXIMUM_MILLISECONDS = 3_600_000
PROCESS_MAXIMUM_TEXT_SCALARS = 100_000_000
PROCESS_MAXIMUM_RANGES = 100_000
PROCESS_MAXIMUM_RELATIONS = 100_000
PROCESS_MAXIMUM_ANCESTRY = 10_000
PROCESS_MAXIMUM_HYPERLINKS = 100_000
PROCESS_MAXIMUM_IDENTITY_COMPARISONS = 1_000_000
ANCESTOR_IDENTITY_SCAN_WINDOW = 40


def _automaticIdentityComparisonBudget(maximumNodes: int, maximumDepth: int) -> int:
	"""Cover bounded cycle and logical-child checks without ordinary sibling all-pairs work."""

	required = maximumNodes * maximumDepth + maximumNodes
	return min(PROCESS_MAXIMUM_IDENTITY_COMPARISONS, required)


class MonotonicMilliseconds(Protocol):
	def __call__(self) -> int: ...


def _milliseconds() -> int:
	return monotonic_ns() // 1_000_000


def _noYield(_milliseconds: int) -> None:
	return None


@dataclass(frozen=True, slots=True)
class TraversalLimits:
	maximumNodes: int
	maximumDepth: int
	maximumMilliseconds: int
	maximumTextScalars: int
	maximumRanges: int = 50
	maximumRelations: int = 200
	maximumAncestry: int = 40
	maximumHyperlinks: int = 200
	workSliceMilliseconds: int = 150
	yieldMilliseconds: int = 10
	mode: CaptureMode = "bounded"
	maximumIdentityComparisons: int | None = None

	def __post_init__(self) -> None:
		for name in (
			"maximumNodes",
			"maximumDepth",
			"maximumMilliseconds",
			"maximumTextScalars",
			"maximumRanges",
			"maximumRelations",
			"maximumAncestry",
			"maximumHyperlinks",
			"workSliceMilliseconds",
		):
			value = getattr(self, name)
			if type(value) is not int or value <= 0:
				raise ValueError(f"{name} must be a positive integer")
		if self.maximumIdentityComparisons is None:
			object.__setattr__(
				self,
				"maximumIdentityComparisons",
				_automaticIdentityComparisonBudget(self.maximumNodes, self.maximumDepth),
			)
		elif (
			type(self.maximumIdentityComparisons) is not int
			or not 0 < self.maximumIdentityComparisons <= PROCESS_MAXIMUM_IDENTITY_COMPARISONS
		):
			raise ValueError("maximumIdentityComparisons must be within the process safety ceiling")
		if type(self.yieldMilliseconds) is not int or self.yieldMilliseconds < 0:
			raise ValueError("yieldMilliseconds must be a nonnegative integer")
		if self.mode not in ("bounded", "unlimited"):
			raise ValueError("capture mode is not supported")

	@classmethod
	def fromSettings(cls, settings: SettingsSnapshot, mode: CaptureMode) -> TraversalLimits:
		fixed = dict(settings.fixedCaptureLimits())
		if mode == "unlimited":
			return cls(
				PROCESS_MAXIMUM_NODES,
				PROCESS_MAXIMUM_DEPTH,
				PROCESS_MAXIMUM_MILLISECONDS,
				PROCESS_MAXIMUM_TEXT_SCALARS,
				PROCESS_MAXIMUM_RANGES,
				PROCESS_MAXIMUM_RELATIONS,
				PROCESS_MAXIMUM_ANCESTRY,
				PROCESS_MAXIMUM_HYPERLINKS,
				fixed["workSliceMilliseconds"],
				fixed["yieldMilliseconds"],
				mode,
			)
		return cls(
			settings.maximumNodes,
			settings.maximumDepth,
			settings.captureTimeSeconds * 1_000,
			settings.maximumTextCharacters,
			fixed["visibleUiaRanges"],
			fixed["uiaElementArrayEntries"],
			fixed["focusMatchDepth"],
			fixed["ia2Hyperlinks"],
			fixed["workSliceMilliseconds"],
			fixed["yieldMilliseconds"],
			mode,
		)


@dataclass(frozen=True, slots=True)
class LimitEvidence:
	limitType: str
	configuredLimit: int
	observedCount: int
	reached: bool
	processSafetyCeiling: bool


@dataclass(frozen=True, slots=True)
class TraversalProgress:
	processedNodes: int
	elapsedMilliseconds: int
	pendingWorkCount: int
	phase: CaptureProgressPhase = "collecting"


@dataclass(frozen=True, slots=True)
class ProviderTiming:
	backend: str
	operation: ProviderOperation
	durationMilliseconds: int
	outcome: str
	degradedAfterCall: bool


@dataclass(frozen=True, slots=True)
class ProviderDegradation:
	state: Literal["closed", "open"]
	consecutiveStalls: int
	skippedReads: int
	resetAfterSkippedReads: int


@dataclass(frozen=True, slots=True)
class TraversedField:
	fieldId: str
	result: ProviderReadResult


@dataclass(frozen=True, slots=True)
class TraversedNode:
	key: str
	nodeRef: str
	parentKey: str | None
	depth: int
	fields: tuple[TraversedField, ...]
	childKeys: tuple[str, ...]
	cycleDetected: bool
	truncated: bool
	childFetchFailed: bool
	referenceKey: str | None = None

	def field(self, fieldId: str) -> ProviderReadResult:
		try:
			return next(item.result for item in self.fields if item.fieldId == fieldId)
		except StopIteration as error:
			raise KeyError(fieldId) from error


@dataclass(frozen=True, slots=True)
class TraversalResult:
	rootKeys: tuple[str, ...]
	nodes: tuple[TraversedNode, ...]
	limits: tuple[LimitEvidence, ...]
	timings: tuple[ProviderTiming, ...]
	timingAggregates: tuple[MeasurementAggregate, ...]
	degradation: ProviderDegradation
	truncated: bool
	cancelled: bool
	errorCode: str | None = None


@dataclass(slots=True)
class _NodeBuilder:
	key: str
	nodeRef: str
	parentKey: str | None
	depth: int
	fields: tuple[TraversedField, ...]
	childKeys: list[str] = field(default_factory=list[str])
	cycleDetected: bool = False
	truncated: bool = False
	childFetchFailed: bool = False
	referenceKey: str | None = None

	def freeze(self) -> TraversedNode:
		return TraversedNode(
			self.key,
			self.nodeRef,
			self.parentKey,
			self.depth,
			self.fields,
			tuple(self.childKeys),
			self.cycleDetected,
			self.truncated,
			self.childFetchFailed,
			self.referenceKey,
		)


@dataclass(frozen=True, slots=True)
class _Frame:
	nodeRef: str
	depth: int
	ancestors: tuple[_NodeBuilder, ...]


class _Cancelled(Exception):
	pass


class IterativeTraversal:
	"""Owner-thread, explicit-stack traversal over opaque provider references."""

	def __init__(
		self,
		provider: ReadOnlyNodePort,
		identity: IdentityComparisonPort,
		*,
		clock: MonotonicMilliseconds = _milliseconds,
		yieldControl: Callable[[int], None] | None = None,
		cancelRequested: Callable[[], bool] | None = None,
		generationCurrent: Callable[[], bool] | None = None,
		stallThresholdMilliseconds: int = 1_000,
		stallsBeforeOpen: int = 2,
		resetAfterSkippedReads: int = 3,
	) -> None:
		super().__init__()
		self._provider = provider
		self._identity = identity
		self._clock = clock
		self._yieldControl = yieldControl or _noYield
		self._cancelRequested = cancelRequested or (lambda: False)
		self._generationCurrent = generationCurrent or (lambda: True)
		self._stallThreshold = stallThresholdMilliseconds
		self._stallsBeforeOpen = stallsBeforeOpen
		self._resetAfterSkippedReads = resetAfterSkippedReads
		self._timings: list[ProviderTiming] = []
		self._measurements: list[MeasurementObservation] = []
		self._consecutiveStalls = 0
		self._circuitOpen = False
		self._skippedReads = 0
		self._sliceStarted = 0

	def _boundary(self, limits: TraversalLimits) -> None:
		if self._cancelRequested():
			raise _Cancelled
		if not self._generationCurrent():
			raise RuntimeError("KS.CAPTURE.STALE_GENERATION")
		now = self._clock()
		if now - self._sliceStarted >= limits.workSliceMilliseconds:
			self._yieldControl(limits.yieldMilliseconds)
			self._sliceStarted = self._clock()
			if self._cancelRequested():
				raise _Cancelled

	def _observe(self, backend: BackendId, operation: ProviderOperation, started: int, outcome: str) -> None:
		duration = max(0, self._clock() - started)
		stalled = duration >= self._stallThreshold or outcome in ("slow", "blocked")
		measurementOutcome: MeasurementOutcome
		if stalled:
			measurementOutcome = "slow"
		elif outcome == "value":
			measurementOutcome = "success"
		elif outcome == "empty":
			measurementOutcome = "empty"
		elif outcome == "unsupported":
			measurementOutcome = "unsupported"
		elif outcome == "stale":
			measurementOutcome = "stale"
		else:
			measurementOutcome = "failed"
		self._measurements.append(
			MeasurementObservation(
				backend,
				operation,
				measurementOutcome,
				duration * 1_000,
				0,
				0,
				_MEASUREMENT_PROVENANCE,
			),
		)
		self._consecutiveStalls = self._consecutiveStalls + 1 if stalled else 0
		if self._consecutiveStalls >= self._stallsBeforeOpen:
			self._circuitOpen = True
			self._skippedReads = 0
			self._consecutiveStalls = 0
			self._timings.append(ProviderTiming(backend, operation, duration, outcome, True))
		else:
			self._timings.append(ProviderTiming(backend, operation, duration, outcome, False))

	def _allowRead(self) -> bool:
		if not self._circuitOpen:
			return True
		self._skippedReads += 1
		if self._skippedReads >= self._resetAfterSkippedReads:
			self._circuitOpen = False
			self._skippedReads = 0
			return True
		return False

	def _readField(
		self,
		request: ProviderFieldRequest,
		backend: BackendId,
		limits: TraversalLimits,
	) -> ProviderReadResult:
		self._boundary(limits)
		if not self._allowRead():
			return ProviderReadResult("unavailable", errorCode="KS.PROVIDER.CIRCUIT_OPEN")
		started = self._clock()
		try:
			result = self._provider.readField(request)
		except Exception:
			result = ProviderReadResult("failed", errorCode="KS.PROVIDER.FIELD_EXCEPTION")
		self._observe(backend, "fieldRead", started, result.status)
		self._boundary(limits)
		return result

	def _readChildren(
		self,
		request: ProviderChildrenRequest,
		backend: BackendId,
		limits: TraversalLimits,
		*,
		logical: bool,
	) -> ProviderChildBatch:
		self._boundary(limits)
		if not self._allowRead():
			return ProviderChildBatch("unavailable", (), 0, False, "KS.PROVIDER.CIRCUIT_OPEN")
		started = self._clock()
		try:
			result = (
				self._provider.readLogicalFirstChild(request)
				if logical
				else self._provider.readChildren(request)
			)
		except Exception:
			result = ProviderChildBatch("failed", (), 0, False, "KS.PROVIDER.CHILDREN_EXCEPTION")
		if len(result.nodeRefs) > request.budget.maximumItems:
			result = ProviderChildBatch(
				result.status,
				result.nodeRefs[: request.budget.maximumItems],
				result.observedCount,
				True,
				result.errorCode,
			)
		self._observe(backend, "childrenRead", started, result.status)
		self._boundary(limits)
		return result

	def _same(
		self,
		first: str,
		second: str,
		providerScope: str,
		processScope: str,
		readBudget: ReadBudget,
		context: CorrelationContext,
		backend: BackendId,
		limits: TraversalLimits,
	) -> bool:
		self._boundary(limits)
		if not self._allowRead():
			return False
		started = self._clock()
		try:
			result = self._identity.compareIdentity(
				IdentityComparisonRequest(
					first,
					second,
					providerScope,
					processScope,
					readBudget,
					context,
				),
			)
			outcome = result.status
			same = result.status == "value" and result.decision == "same"
		except Exception:
			outcome = "failed"
			same = False
		self._observe(backend, "identityCompare", started, outcome)
		self._boundary(limits)
		return same

	def walk(
		self,
		rootRef: str,
		*,
		providerScope: str,
		processScope: str,
		backend: BackendId,
		context: CorrelationContext,
		limits: TraversalLimits,
		includeDescendants: bool = True,
		progress: Callable[[TraversalProgress], None] | None = None,
	) -> TraversalResult:
		_ = requireCompleteCorrelation(context)
		self._timings = []
		self._measurements = []
		self._consecutiveStalls = 0
		self._circuitOpen = False
		self._skippedReads = 0
		started = self._clock()
		self._sliceStarted = started
		readBudget = ReadBudget(
			max(1, min(limits.maximumNodes, 2_147_483_647)),
			max(1, min(limits.maximumTextScalars, 2_147_483_647)),
			max(1, min(limits.maximumMilliseconds, 2_147_483_647)),
		)
		identityComparisonBudget = limits.maximumIdentityComparisons
		assert identityComparisonBudget is not None
		builders: list[_NodeBuilder] = []
		rootKeys: list[str] = []
		stack = [_Frame(rootRef, 0, ())]
		observedDepth = 0
		observedText = 0
		observedAncestry = 0
		identityComparisons = 0
		identityBudgetReached = False
		nodeCapacityTruncated = False
		timeReached = False
		cancelled = False

		def sameWithinBudget(first: str, second: str) -> tuple[bool, bool]:
			nonlocal identityComparisons, identityBudgetReached
			if identityComparisons >= identityComparisonBudget:
				identityBudgetReached = True
				return False, True
			identityComparisons += 1
			return (
				self._same(
					first,
					second,
					providerScope,
					processScope,
					readBudget,
					context,
					backend,
					limits,
				),
				False,
			)

		try:
			while stack:
				self._boundary(limits)
				elapsed = max(0, self._clock() - started)
				if progress is not None:
					progress(TraversalProgress(len(builders), elapsed, len(stack)))
				if elapsed >= limits.maximumMilliseconds:
					timeReached = True
					frame = stack[-1]
					if frame.ancestors:
						frame.ancestors[-1].truncated = True
					break
				frame = stack.pop()
				parent = frame.ancestors[-1] if frame.ancestors else None
				observedDepth = max(observedDepth, frame.depth)
				observedAncestry = max(observedAncestry, len(frame.ancestors))
				if frame.depth > limits.maximumDepth or len(frame.ancestors) > limits.maximumAncestry:
					if parent is not None:
						parent.truncated = True
					continue
				if len(builders) >= limits.maximumNodes:
					nodeCapacityTruncated = True
					if parent is not None:
						parent.truncated = True
					continue

				reference: _NodeBuilder | None = None
				identityExhausted = False
				for ancestor in reversed(frame.ancestors):
					if frame.nodeRef == ancestor.nodeRef:
						reference = ancestor
						break
				if reference is None:
					for ancestor in reversed(frame.ancestors[-ANCESTOR_IDENTITY_SCAN_WINDOW:]):
						same, identityExhausted = sameWithinBudget(frame.nodeRef, ancestor.nodeRef)
						if identityExhausted:
							break
						if same:
							reference = ancestor
							break

				key = f"n{len(builders) + 1}"
				if reference is not None:
					fields = tuple(
						TraversedField(
							fieldId,
							ProviderReadResult(
								"value",
								("reference", reference.key) if fieldId == "stableIds" else "",
							),
						)
						for fieldId in COMMON_NODE_FIELDS
						if fieldId != "children"
					)
					builder = _NodeBuilder(
						key,
						frame.nodeRef,
						None if parent is None else parent.key,
						frame.depth,
						fields,
						cycleDetected=True,
						referenceKey=reference.key,
					)
					builders.append(builder)
					if parent is None:
						rootKeys.append(key)
					else:
						parent.childKeys.append(key)
					continue

				fieldResults: list[TraversedField] = []
				nodeTruncated = False
				for fieldId in (*COMMON_NODE_FIELDS[:-1], "protection"):
					result = self._readField(
						ProviderFieldRequest(frame.nodeRef, fieldId, readBudget, context),
						backend,
						limits,
					)
					if result.status == "value" and isinstance(result.value, str):
						originalLength = len(result.value)
						remainingText = max(0, limits.maximumTextScalars - observedText)
						observedText += originalLength
						if originalLength > remainingText:
							result = ProviderReadResult(
								"value",
								result.value[:remainingText],
								truncated=True,
							)
							nodeTruncated = True
					fieldResults.append(TraversedField(fieldId, result))
				builder = _NodeBuilder(
					key,
					frame.nodeRef,
					None if parent is None else parent.key,
					frame.depth,
					tuple(fieldResults),
					truncated=nodeTruncated,
				)
				builders.append(builder)
				if parent is None:
					rootKeys.append(key)
				else:
					parent.childKeys.append(key)

				remaining = limits.maximumNodes - len(builders) - len(stack)
				if remaining <= 0:
					if stack:
						nodeCapacityTruncated = True
						continue
					probeBudget = ReadBudget(
						1,
						readBudget.maximumTextLength,
						readBudget.maximumMilliseconds,
					)
					logical = self._readChildren(
						ProviderChildrenRequest(frame.nodeRef, probeBudget, context),
						backend,
						limits,
						logical=True,
					)
					children = self._readChildren(
						ProviderChildrenRequest(frame.nodeRef, probeBudget, context),
						backend,
						limits,
						logical=False,
					)
					builder.childFetchFailed = children.status in ("unavailable", "stale", "failed")
					if (
						logical.nodeRefs
						or logical.observedCount
						or logical.truncated
						or children.nodeRefs
						or children.observedCount
						or children.truncated
					):
						nodeCapacityTruncated = True
						builder.truncated = True
					continue
				childBudget = ReadBudget(
					remaining,
					readBudget.maximumTextLength,
					readBudget.maximumMilliseconds,
				)
				logical = self._readChildren(
					ProviderChildrenRequest(
						frame.nodeRef,
						ReadBudget(1, childBudget.maximumTextLength, childBudget.maximumMilliseconds),
						context,
					),
					backend,
					limits,
					logical=True,
				)
				ordinaryCapacity = remaining - len(logical.nodeRefs)
				if ordinaryCapacity <= 0:
					children = ProviderChildBatch("value", (), 0, False)
				else:
					children = self._readChildren(
						ProviderChildrenRequest(
							frame.nodeRef,
							ReadBudget(
								ordinaryCapacity,
								childBudget.maximumTextLength,
								childBudget.maximumMilliseconds,
							),
							context,
						),
						backend,
						limits,
						logical=False,
					)
					nodeCapacityTruncated = nodeCapacityTruncated or children.truncated
				builder.childFetchFailed = children.status in ("unavailable", "stale", "failed")
				builder.truncated = builder.truncated or children.truncated or logical.truncated
				if not includeDescendants:
					self._boundary(limits)
					continue
				candidates: list[str] = []
				candidateRefs: set[str] = set()
				for candidate in children.nodeRefs:
					if candidate not in candidateRefs:
						candidates.append(candidate)
						candidateRefs.add(candidate)
				for candidate in logical.nodeRefs[:1]:
					if candidate in candidateRefs:
						continue
					duplicate = False
					identityExhausted = False
					for existing in candidates:
						same, identityExhausted = sameWithinBudget(candidate, existing)
						if identityExhausted:
							builder.truncated = True
							break
						if same:
							duplicate = True
							break
					if identityExhausted:
						continue
					if not duplicate:
						candidates.insert(0, candidate)
				ancestors = (*frame.ancestors, builder)
				stack.extend(_Frame(child, frame.depth + 1, ancestors) for child in reversed(candidates))
				self._boundary(limits)
		except _Cancelled:
			cancelled = True
		except RuntimeError as error:
			return TraversalResult(
				tuple(rootKeys),
				tuple(item.freeze() for item in builders),
				(),
				tuple(self._timings),
				aggregateMeasurements(self._measurements),
				ProviderDegradation(
					"open" if self._circuitOpen else "closed",
					self._consecutiveStalls,
					self._skippedReads,
					self._resetAfterSkippedReads,
				),
				False,
				False,
				str(error),
			)

		elapsed = max(0, self._clock() - started)
		truncated = (
			timeReached
			or identityBudgetReached
			or any(item.truncated for item in builders)
			or nodeCapacityTruncated
			or observedText > limits.maximumTextScalars
		)
		limitRows = (
			("nodes", limits.maximumNodes, len(builders), nodeCapacityTruncated),
			(
				"identityComparisons",
				identityComparisonBudget,
				identityComparisons,
				identityBudgetReached,
			),
			("depth", limits.maximumDepth, observedDepth, observedDepth > limits.maximumDepth),
			("timeMilliseconds", limits.maximumMilliseconds, elapsed, timeReached),
			(
				"textScalars",
				limits.maximumTextScalars,
				observedText,
				observedText > limits.maximumTextScalars,
			),
			("ancestry", limits.maximumAncestry, observedAncestry, observedAncestry > limits.maximumAncestry),
		)
		return TraversalResult(
			tuple(rootKeys),
			tuple(item.freeze() for item in builders),
			tuple(
				LimitEvidence(name, configured, observed, reached, limits.mode == "unlimited")
				for name, configured, observed, reached in limitRows
			),
			tuple(self._timings),
			aggregateMeasurements(self._measurements),
			ProviderDegradation(
				"open" if self._circuitOpen else "closed",
				self._consecutiveStalls,
				self._skippedReads,
				self._resetAfterSkippedReads,
			),
			truncated,
			cancelled,
		)
