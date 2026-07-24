"""Pure Inspector domain: immutable source, node, property, search, and repeat models.

This module is the screen-reader-first Inspector's functional core. It owns the immutable
records the workspace renders and the pure decisions the application service and native frame
depend on, with no host, wx, provider, or file object ever entering its state:

* the eleven stable property categories and their direct-shortcut order;
* privacy-safe hierarchy and property row records whose status stays explicit instead of blank;
* ``StructuredPropertyNode`` plus ``expandAllPropertiesOneLevel`` for the All Properties tab, which
  reveals exactly one structured level on a fresh selection;
* ``normalizeQuickPropertyDigit`` and ``QuickPropertyRepeatState`` for layout-tolerant numeric
  quick-property cycles bounded by the validated property interval;
* ``matchInspectorTarget`` and ``FocusMatchEvidence`` for the closed retarget/Follow Focus identity
  ladder under fixed node and depth budgets;
* ``searchLoadedNodes`` for loaded-only hierarchy search that never triggers a source read.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import hashlib
import re
from typing import Literal, cast

from .evidence import ErrorReference
from .settings import SETTING_DEFINITIONS, SettingId, SettingsSnapshot
from .status import Confidence, requireNonnegativeInteger, requireToken


# ---------------------------------------------------------------------------
# Source identity and property taxonomy.
# ---------------------------------------------------------------------------


class InspectorSourceKind(StrEnum):
	LIVE = "live"
	OFFLINE = "offline"


class PropertyCategory(StrEnum):
	"""The eleven stable property tabs in their fixed presentation order."""

	QUICK = "quick"
	CORE = "core"
	SUPPORTED_UIA_PATTERNS = "supportedUiaPatterns"
	UIA = "uia"
	IA2_MSAA = "ia2Msaa"
	JAB = "jab"
	OTHER_API = "otherApi"
	DEVELOPER_INFO = "developerInfo"
	ALL_PROPERTIES = "allProperties"
	ANNOTATIONS = "annotations"
	DIAGNOSTICS = "diagnostics"


PROPERTY_CATEGORY_ORDER: tuple[PropertyCategory, ...] = (
	PropertyCategory.QUICK,
	PropertyCategory.CORE,
	PropertyCategory.SUPPORTED_UIA_PATTERNS,
	PropertyCategory.UIA,
	PropertyCategory.IA2_MSAA,
	PropertyCategory.JAB,
	PropertyCategory.OTHER_API,
	PropertyCategory.DEVELOPER_INFO,
	PropertyCategory.ALL_PROPERTIES,
	PropertyCategory.ANNOTATIONS,
	PropertyCategory.DIAGNOSTICS,
)


def propertyCategoryForShortcut(digit: int, *, shift: bool = False) -> PropertyCategory:
	"""Map Ctrl+1..9, Ctrl+0, and Ctrl+Shift+0 to their stable property tabs."""

	if digit not in range(10):
		raise ValueError("property tab shortcut digit must be 0..9")
	if digit == 0:
		return PropertyCategory.DIAGNOSTICS if shift else PropertyCategory.ANNOTATIONS
	if shift:
		raise ValueError("Shift is reserved for the Diagnostics shortcut")
	index = 9 if digit == 0 else digit - 1
	return PROPERTY_CATEGORY_ORDER[index]


def shortcutForPropertyCategory(category: PropertyCategory, *, shift: bool = False) -> int:
	if category is PropertyCategory.DIAGNOSTICS:
		if not shift:
			raise ValueError("Diagnostics requires the shifted zero shortcut")
		return 0
	if shift:
		raise ValueError("Shift is reserved for the Diagnostics shortcut")
	index = PROPERTY_CATEGORY_ORDER.index(category)
	return 0 if index == 9 else index + 1


class PropertyStatus(StrEnum):
	"""Every explicit property outcome; missing evidence is never a blank cell or ``null``."""

	VALUE = "value"
	EMPTY = "empty"
	UNSUPPORTED = "unsupported"
	NOT_APPLICABLE = "notApplicable"
	UNAVAILABLE = "unavailable"
	REDACTED = "redacted"
	TRUNCATED = "truncated"
	STALE = "stale"
	REJECTED = "rejected"
	FAILED = "failed"


class AnnotationStatus(StrEnum):
	"""Explicit availability state for captured annotation and relationship metadata."""

	NO_DATA = "noData"
	UNSUPPORTED = "unsupported"
	UNAVAILABLE = "unavailable"
	TRUNCATED = "truncated"
	STALE = "stale"
	FAILED = "failed"
	VALUE = "value"


ANNOTATION_CONVERSION_FAILED = "KS.ANNOTATION.CONVERSION_FAILED"


@dataclass(frozen=True, slots=True)
class AnnotationRecord:
	"""One annotation or semantic relationship, kept separate from source property evidence."""

	key: str
	status: AnnotationStatus
	typeName: str
	source: str
	typeId: str | None = None
	summary: str | None = None
	author: str | None = None
	dateTime: str | None = None
	targetName: str | None = None
	targetRole: str | None = None
	targetIdentity: str | None = None
	targetNodeId: str | None = None
	targetIdentityProven: bool = False
	relationship: str | None = None
	errorRef: ErrorReference | None = None
	related: tuple[AnnotationRecord, ...] = ()

	def __post_init__(self) -> None:
		object.__setattr__(self, "key", requireToken(self.key, "annotation key"))
		object.__setattr__(self, "typeName", requireToken(self.typeName, "annotation type name"))
		object.__setattr__(self, "source", requireToken(self.source, "annotation source"))
		for name in (
			"typeId",
			"summary",
			"author",
			"dateTime",
			"targetName",
			"targetRole",
			"targetIdentity",
			"targetNodeId",
			"relationship",
		):
			value = getattr(self, name)
			if value is not None:
				object.__setattr__(self, name, requireToken(value, f"annotation {name}"))
		if self.status is AnnotationStatus.VALUE:
			if not any(
				(
					self.typeId,
					self.summary,
					self.author,
					self.dateTime,
					self.targetName,
					self.targetRole,
					self.targetIdentity,
					self.relationship,
					self.related,
				),
			):
				raise ValueError("value annotations require captured metadata")
		elif self.related:
			raise ValueError("non-value annotation states cannot contain related annotations")
		if self.errorRef is not None and self.status is not AnnotationStatus.FAILED:
			raise ValueError("only failed annotations can carry an error reference")
		if self.targetIdentityProven and (self.targetIdentity is None or self.targetNodeId is None):
			raise ValueError("proven annotation targets require identity and a source node")
		relatedKeys = tuple(record.key for record in self.related)
		if len(set(relatedKeys)) != len(relatedKeys):
			raise ValueError("related annotation keys must be unique")

	@property
	def canNavigate(self) -> bool:
		return (
			self.status is AnnotationStatus.VALUE
			and self.targetIdentityProven
			and self.targetNodeId is not None
		)


def validateAnnotationKeys(records: tuple[AnnotationRecord, ...]) -> None:
	"""Require one globally unique key for every record in an annotation tree."""

	seen: set[str] = set()

	def visit(children: tuple[AnnotationRecord, ...]) -> None:
		for record in children:
			if record.key in seen:
				raise ValueError("annotation keys must be globally unique")
			seen.add(record.key)
			visit(record.related)

	visit(records)


def annotationRecordsPlain(records: tuple[AnnotationRecord, ...]) -> tuple[object, ...]:
	"""Encode annotation records for the existing immutable provider-value transport."""

	validateAnnotationKeys(records)

	def optional(value: str | None) -> tuple[object, ...]:
		return ("value", value) if value is not None else ("none",)

	def encode(record: AnnotationRecord) -> tuple[object, ...]:
		return (
			record.key,
			record.status.value,
			record.typeName,
			record.source,
			optional(record.typeId),
			optional(record.summary),
			optional(record.author),
			optional(record.dateTime),
			optional(record.targetName),
			optional(record.targetRole),
			optional(record.targetIdentity),
			optional(record.targetNodeId),
			record.targetIdentityProven,
			optional(record.relationship),
			(
				("value", record.errorRef.code, record.errorRef.diagnosticId)
				if record.errorRef is not None
				else ("none",)
			),
			tuple(encode(related) for related in record.related),
		)

	return tuple(encode(record) for record in records)


def annotationRecordsFromPlain(value: object) -> tuple[AnnotationRecord, ...]:
	"""Decode the closed provider-value transport back into validated annotation records."""

	def optionalText(item: object, label: str) -> str | None:
		if not isinstance(item, tuple):
			raise ValueError(f"{label} marker must be a tuple")
		marker = cast(tuple[object, ...], item)
		if marker == ("none",):
			return None
		if len(marker) != 2 or marker[0] != "value" or not isinstance(marker[1], str):
			raise ValueError(f"{label} marker must contain text or none")
		return marker[1]

	def decode(item: object) -> AnnotationRecord:
		if not isinstance(item, tuple):
			raise ValueError("annotation transport record must contain sixteen fields")
		parts = cast(tuple[object, ...], item)
		if len(parts) != 16:
			raise ValueError("annotation transport record must contain sixteen fields")
		key, status, typeName, source = parts[:4]
		if not all(isinstance(field, str) for field in (key, status, typeName, source)):
			raise ValueError("annotation transport identity fields must be text")
		if not isinstance(parts[12], bool):
			raise ValueError("annotation target proof must be boolean")
		if not isinstance(parts[15], tuple):
			raise ValueError("related annotation transport must be a tuple")
		errorMarker = parts[14]
		if not isinstance(errorMarker, tuple):
			raise ValueError("annotation error marker must be a tuple")
		errorParts = cast(tuple[object, ...], errorMarker)
		if errorParts == ("none",):
			errorRef = None
		elif (
			len(errorParts) == 3
			and errorParts[0] == "value"
			and isinstance(errorParts[1], str)
			and isinstance(errorParts[2], str)
		):
			errorRef = ErrorReference(errorParts[1], errorParts[2])
		else:
			raise ValueError("annotation error marker must contain a safe error reference or none")
		return AnnotationRecord(
			key=cast(str, key),
			status=AnnotationStatus(cast(str, status)),
			typeName=cast(str, typeName),
			source=cast(str, source),
			typeId=optionalText(parts[4], "annotation type ID"),
			summary=optionalText(parts[5], "annotation summary"),
			author=optionalText(parts[6], "annotation author"),
			dateTime=optionalText(parts[7], "annotation date/time"),
			targetName=optionalText(parts[8], "annotation target name"),
			targetRole=optionalText(parts[9], "annotation target role"),
			targetIdentity=optionalText(parts[10], "annotation target identity"),
			targetNodeId=optionalText(parts[11], "annotation target node"),
			targetIdentityProven=parts[12],
			relationship=optionalText(parts[13], "annotation relationship"),
			errorRef=errorRef,
			related=tuple(decode(related) for related in cast(tuple[object, ...], parts[15])),
		)

	if not isinstance(value, tuple):
		raise ValueError("annotation transport must be a tuple")
	records = tuple(decode(item) for item in cast(tuple[object, ...], value))
	validateAnnotationKeys(records)
	return records


def annotationConversionFailure(nodeIdentity: str, *, source: str) -> AnnotationRecord:
	"""Build a deterministic, safe annotation conversion failure without retaining exception text."""
	digest = hashlib.sha256(nodeIdentity.encode("utf-8")).hexdigest()[:16]
	return AnnotationRecord(
		key="annotations-failed",
		status=AnnotationStatus.FAILED,
		typeName="Annotations",
		source=source,
		errorRef=ErrorReference(
			ANNOTATION_CONVERSION_FAILED,
			f"annotation-conversion-{digest}",
		),
	)


_VALUE_BEARING_STATUS = frozenset((PropertyStatus.VALUE, PropertyStatus.TRUNCATED))
_RETRYABLE_STATUS = frozenset(
	(PropertyStatus.UNAVAILABLE, PropertyStatus.FAILED, PropertyStatus.STALE),
)


@dataclass(frozen=True, slots=True)
class InspectorSourceIdentity:
	"""Privacy-safe identity of whatever backs the current Inspector view."""

	kind: InspectorSourceKind
	label: str
	executable: str
	processId: int
	backend: str
	rawApplied: bool = False
	rawReason: str | None = None
	nodeCount: int | None = None

	def __post_init__(self) -> None:
		object.__setattr__(self, "label", requireToken(self.label, "source label"))
		object.__setattr__(self, "executable", requireToken(self.executable, "executable"))
		object.__setattr__(self, "backend", requireToken(self.backend, "backend"))
		_ = requireNonnegativeInteger(self.processId, "process id")
		if self.rawReason is not None:
			object.__setattr__(self, "rawReason", requireToken(self.rawReason, "raw reason"))
		if self.nodeCount is not None:
			_ = requireNonnegativeInteger(self.nodeCount, "node count")
		if self.kind is InspectorSourceKind.OFFLINE and self.nodeCount is None:
			raise ValueError("an offline source must report an indexed node count")

	@property
	def isLive(self) -> bool:
		return self.kind is InspectorSourceKind.LIVE

	@property
	def followFocusAvailable(self) -> bool:
		return self.isLive


# ---------------------------------------------------------------------------
# Hierarchy nodes and lazy child enumeration state.
# ---------------------------------------------------------------------------


class ChildState(StrEnum):
	"""How one node's child enumeration currently stands, kept distinct from an empty leaf."""

	UNKNOWN = "unknown"
	HINT = "hint"
	LOADING = "loading"
	EMPTY = "empty"
	LOADED = "loaded"
	FAILED = "failed"
	TRUNCATED = "truncated"
	CANCELLED = "cancelled"
	REJECTED = "rejected"


_CHILD_BEARING_STATE = frozenset((ChildState.HINT, ChildState.LOADED, ChildState.TRUNCATED))


@dataclass(frozen=True, slots=True)
class NodeFacet:
	"""One node's structural identity as a source presents it, already privacy-safe."""

	nodeId: str
	parentId: str | None
	depth: int
	name: str
	hasName: bool
	role: str
	childHint: bool = False

	def __post_init__(self) -> None:
		object.__setattr__(self, "nodeId", requireToken(self.nodeId, "node id"))
		if self.parentId is not None:
			object.__setattr__(self, "parentId", requireToken(self.parentId, "parent id"))
		_ = requireNonnegativeInteger(self.depth, "node depth")
		object.__setattr__(self, "role", requireToken(self.role, "role"))
		if self.hasName and not self.name:
			raise ValueError("a named node must carry its display name")
		if not self.hasName and self.name:
			raise ValueError("an unnamed node cannot carry a display name")


@dataclass(frozen=True, slots=True)
class HierarchyNode:
	"""A facet plus its live child-enumeration state, as the workspace tree shows it."""

	facet: NodeFacet
	childState: ChildState = ChildState.UNKNOWN
	childIds: tuple[str, ...] = ()
	exceptionalSuffix: str | None = None

	def __post_init__(self) -> None:
		if self.childIds and self.childState not in _CHILD_BEARING_STATE:
			raise ValueError("a node without proven or partial children cannot enumerate them")
		if self.exceptionalSuffix is not None:
			object.__setattr__(
				self,
				"exceptionalSuffix",
				requireToken(self.exceptionalSuffix, "exceptional suffix"),
			)

	@property
	def nodeId(self) -> str:
		return self.facet.nodeId

	@property
	def hasExpander(self) -> bool:
		"""``childCount`` may suggest an expander but children are only proven once loaded."""

		return self.childState in (ChildState.HINT, ChildState.LOADING) or bool(self.childIds)


# ---------------------------------------------------------------------------
# Property rows, structured values, and the one-level All Properties expansion.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PropertyRow:
	"""One flat property row; ``value`` is a complete privacy-safe rendering or ``None``."""

	fieldKey: str
	name: str
	status: PropertyStatus
	value: str | None = None
	source: str = "keystone"
	confidence: Confidence = Confidence.INDETERMINATE
	diagnosticRef: str | None = None

	def __post_init__(self) -> None:
		object.__setattr__(self, "fieldKey", requireToken(self.fieldKey, "field key"))
		object.__setattr__(self, "name", requireToken(self.name, "property name"))
		object.__setattr__(self, "source", requireToken(self.source, "property source"))
		if self.status in _VALUE_BEARING_STATUS:
			if self.value is None:
				raise ValueError("value and truncated rows require a value")
		elif self.value is not None:
			raise ValueError(f"{self.status} rows cannot carry a value")
		if self.diagnosticRef is not None:
			object.__setattr__(self, "diagnosticRef", requireToken(self.diagnosticRef, "diagnostic ref"))

	@property
	def retryable(self) -> bool:
		return self.status in _RETRYABLE_STATUS


@dataclass(frozen=True, slots=True)
class StructuredPropertyNode:
	"""A node in the All Properties tree-list: either a scalar value or a container of children."""

	key: str
	label: str
	status: PropertyStatus
	value: str | None = None
	children: tuple[StructuredPropertyNode, ...] = ()
	expanded: bool = False

	def __post_init__(self) -> None:
		object.__setattr__(self, "key", requireToken(self.key, "structured key"))
		object.__setattr__(self, "label", requireToken(self.label, "structured label"))
		if self.children and self.value is not None:
			raise ValueError("a structured node is either a scalar value or a container of children")
		if self.expanded and not self.children:
			raise ValueError("only a container node can be expanded")
		if not self.children:
			if self.status in _VALUE_BEARING_STATUS and self.value is None:
				raise ValueError("a scalar value node requires its value")
			if self.status not in _VALUE_BEARING_STATUS and self.value is not None:
				raise ValueError(f"{self.status} nodes cannot carry a value")

	@property
	def isStructured(self) -> bool:
		return bool(self.children)


def _forceCollapsed(node: StructuredPropertyNode) -> StructuredPropertyNode:
	return replace(
		node,
		expanded=False,
		children=tuple(_forceCollapsed(child) for child in node.children),
	)


def expandAllPropertiesOneLevel(
	nodes: tuple[StructuredPropertyNode, ...],
) -> tuple[StructuredPropertyNode, ...]:
	"""Mark every immediate structured node expanded exactly once; keep all deeper nodes collapsed.

	This is the All Properties auto-expansion applied on each fresh selection. Immediate structured
	children are revealed one level; every grandchild and deeper node stays collapsed until the user
	expands it natively.
	"""

	return tuple(
		replace(
			node,
			expanded=node.isStructured,
			children=tuple(_forceCollapsed(child) for child in node.children),
		)
		for node in nodes
	)


# ---------------------------------------------------------------------------
# Per-tab cursor state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PaneCursor:
	"""One property tab's independently retained selection and scroll position."""

	selectedFieldKey: str | None = None
	topIndex: int = 0
	horizontalOffset: int = 0

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.topIndex, "top index")
		_ = requireNonnegativeInteger(self.horizontalOffset, "horizontal offset")
		if self.selectedFieldKey is not None:
			object.__setattr__(
				self,
				"selectedFieldKey",
				requireToken(self.selectedFieldKey, "selected field key"),
			)


# ---------------------------------------------------------------------------
# Quick-property layout-tolerant digits and repeat cycles.
# ---------------------------------------------------------------------------

_GESTURE_PREFIX = re.compile(r"^kb(?:\([^)]*\))?:")
_NUMPAD_DIGIT = re.compile(r"^numpad([0-9])$")
_ASCII_DIGITS = frozenset("0123456789")


def normalizeQuickPropertyDigit(gestureIdentifier: object) -> int | None:
	"""Return the 0..9 digit a normalized NVDA gesture identifier selects, else ``None``.

	Layout tolerance comes from ignoring the optional ``kb(layout):`` prefix, so the desktop,
	laptop, and any localized layout of the same digit are equivalent. Both the main number row and
	the numeric keypad map to the same digit; every non-digit key is rejected.
	"""

	if not isinstance(gestureIdentifier, str):
		return None
	text = _GESTURE_PREFIX.sub("", gestureIdentifier.strip().lower(), count=1)
	if not text:
		return None
	key = text.rsplit("+", 1)[-1]
	if len(key) == 1 and key in _ASCII_DIGITS:
		return int(key)
	numpad = _NUMPAD_DIGIT.fullmatch(key)
	if numpad is not None:
		return int(numpad.group(1))
	return None


def _propertyIntervalSpec() -> tuple[int, int, int]:
	for definition in SETTING_DEFINITIONS:
		if definition.settingId is SettingId.PROPERTY_INTERVAL_MILLISECONDS:
			default = definition.default
			if (
				definition.minimum is None
				or definition.maximum is None
				or not isinstance(default, int)
				or isinstance(default, bool)
			):
				break
			return definition.minimum, definition.maximum, default
	raise ValueError("the property interval setting must define integer bounds and a default")


MINIMUM_PROPERTY_INTERVAL_MS, MAXIMUM_PROPERTY_INTERVAL_MS, DEFAULT_PROPERTY_INTERVAL_MS = (
	_propertyIntervalSpec()
)


class QuickPropertyAction(StrEnum):
	ANNOUNCE = "announce"
	BROWSE = "browse"
	COPY = "copy"
	RESET = "reset"


@dataclass(frozen=True, slots=True)
class QuickPropertyDecision:
	digit: int
	action: QuickPropertyAction
	deadlineMilliseconds: int


@dataclass(slots=True)
class _DigitCycle:
	pressCount: int = 0
	deadlineMilliseconds: int = -1


class QuickPropertyRepeatState:
	"""One deterministic per-digit press cycle bounded by the validated property interval.

	The state is fed only the shared, already-validated ``PROPERTY_INTERVAL_MILLISECONDS`` value. A
	first press announces the property, a second and third perform the two configured browse/copy
	actions (swappable), and a fourth resets the cycle. Each digit 0..9 keeps an independent cycle,
	and every selection, source, retarget, or lifecycle change cancels the pending timers.
	"""

	__slots__ = ("_cycles", "_interval", "_swap")

	def __init__(self, *, intervalMilliseconds: int, swapActions: bool = False) -> None:
		super().__init__()
		interval = requireNonnegativeInteger(intervalMilliseconds, "quick property interval")
		if not MINIMUM_PROPERTY_INTERVAL_MS <= interval <= MAXIMUM_PROPERTY_INTERVAL_MS:
			raise ValueError("quick property interval must stay within the validated bounds")
		self._interval = interval
		self._swap = swapActions
		self._cycles: dict[int, _DigitCycle] = {digit: _DigitCycle() for digit in range(10)}

	@property
	def intervalMilliseconds(self) -> int:
		return self._interval

	@property
	def swapActions(self) -> bool:
		return self._swap

	def _doubleAction(self) -> QuickPropertyAction:
		return QuickPropertyAction.COPY if self._swap else QuickPropertyAction.BROWSE

	def _tripleAction(self) -> QuickPropertyAction:
		return QuickPropertyAction.BROWSE if self._swap else QuickPropertyAction.COPY

	def press(self, digit: int, *, nowMilliseconds: int) -> QuickPropertyDecision:
		_ = requireNonnegativeInteger(nowMilliseconds, "quick property clock")
		cycle = self._cycles.get(digit)
		if cycle is None:
			raise ValueError("quick property digit must be 0..9")
		if nowMilliseconds > cycle.deadlineMilliseconds:
			cycle.pressCount = 1
			cycle.deadlineMilliseconds = nowMilliseconds + self._interval
			return QuickPropertyDecision(digit, QuickPropertyAction.ANNOUNCE, cycle.deadlineMilliseconds)
		cycle.pressCount += 1
		if cycle.pressCount == 2:
			action = self._doubleAction()
			cycle.deadlineMilliseconds = nowMilliseconds + self._interval
		elif cycle.pressCount == 3:
			action = self._tripleAction()
			cycle.deadlineMilliseconds = nowMilliseconds + self._interval
		else:
			action = QuickPropertyAction.RESET
			cycle.pressCount = 0
			cycle.deadlineMilliseconds = -1
		return QuickPropertyDecision(digit, action, cycle.deadlineMilliseconds)

	def cancel(self) -> None:
		"""Cancel every pending repeat timer; the next press of any digit is a fresh cycle."""

		for cycle in self._cycles.values():
			cycle.pressCount = 0
			cycle.deadlineMilliseconds = -1


# ---------------------------------------------------------------------------
# Retarget and Follow Focus identity ladder under fixed budgets.
# ---------------------------------------------------------------------------


class FocusMatchDecision(StrEnum):
	MATCHED = "matched"
	UNAVAILABLE = "unavailable"
	AMBIGUOUS = "ambiguous"
	REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class FocusMatchEvidence:
	"""Layered identity evidence for one focus-match candidate; geometry never matches alone."""

	pythonIdentity: bool = False
	nvdaEquality: bool | None = None
	providerNative: Literal["same", "different", "conflict"] | None = None
	stableIdEqual: bool | None = None
	roleAgrees: bool | None = None
	geometryCandidate: bool = False


@dataclass(frozen=True, slots=True)
class FocusMatchCandidate:
	candidateId: str
	depth: int
	evidence: FocusMatchEvidence

	def __post_init__(self) -> None:
		object.__setattr__(self, "candidateId", requireToken(self.candidateId, "candidate id"))
		_ = requireNonnegativeInteger(self.depth, "candidate depth")


@dataclass(frozen=True, slots=True)
class FocusMatchLimits:
	maximumNodes: int
	maximumDepth: int

	def __post_init__(self) -> None:
		if requireNonnegativeInteger(self.maximumNodes, "maximum focus-match nodes") == 0:
			raise ValueError("focus matching must allow at least one candidate")
		_ = requireNonnegativeInteger(self.maximumDepth, "maximum focus-match depth")


def focusMatchLimits() -> FocusMatchLimits:
	"""The fixed 150-node and depth-40 focus-match budgets from the capture limit registry."""

	fixed = dict(SettingsSnapshot.fixedCaptureLimits())
	return FocusMatchLimits(fixed["focusMatchNodes"], fixed["focusMatchDepth"])


@dataclass(frozen=True, slots=True)
class FocusMatchResult:
	decision: FocusMatchDecision
	candidateId: str | None
	reasonCode: str
	visitedNodes: int

	def __post_init__(self) -> None:
		object.__setattr__(self, "reasonCode", requireToken(self.reasonCode, "focus reason code"))
		_ = requireNonnegativeInteger(self.visitedNodes, "visited nodes")
		if (self.decision is FocusMatchDecision.MATCHED) != (self.candidateId is not None):
			raise ValueError("only a matched focus result names a candidate")


def _focusMatchMethod(evidence: FocusMatchEvidence) -> tuple[bool, str]:
	"""Apply the closed identity ladder in order; geometry hints can only reject."""

	if evidence.pythonIdentity:
		return True, "KS.INSPECTOR.FOCUS.PYTHON_IDENTITY"
	if evidence.nvdaEquality is True:
		return True, "KS.INSPECTOR.FOCUS.NVDA_EQUALITY"
	if evidence.providerNative == "same":
		return True, "KS.INSPECTOR.FOCUS.PROVIDER_NATIVE"
	if evidence.providerNative in ("different", "conflict"):
		return False, "KS.INSPECTOR.FOCUS.PROVIDER_CONFLICT"
	if evidence.stableIdEqual is True:
		if evidence.roleAgrees is True:
			return True, "KS.INSPECTOR.FOCUS.STABLE_ID"
		return False, "KS.INSPECTOR.FOCUS.ROLE_MISMATCH"
	if evidence.geometryCandidate:
		return False, "KS.INSPECTOR.FOCUS.GEOMETRY_ONLY"
	return False, "KS.INSPECTOR.FOCUS.IDENTITY_UNPROVEN"


def matchInspectorTarget(
	candidates: tuple[FocusMatchCandidate, ...],
	*,
	limits: FocusMatchLimits,
) -> FocusMatchResult:
	"""Resolve one retarget/Follow Focus target through the identity ladder under fixed budgets.

	Geometry may bound the candidate neighbourhood but never returns a match on its own; every
	geometry candidate still has to pass one positive identity layer. Conflicting or role-mismatched
	stable-ID evidence rejects, two or more positive matches are ambiguous, and exceeding the
	150-node or depth-40 budget is reported as unavailable rather than guessed.
	"""

	visited = 0
	accepted: list[str] = []
	firstRejection = "KS.INSPECTOR.FOCUS.NO_CANDIDATE"
	for candidate in candidates:
		if candidate.depth > limits.maximumDepth:
			return FocusMatchResult(
				FocusMatchDecision.UNAVAILABLE,
				None,
				"KS.INSPECTOR.FOCUS.DEPTH_BUDGET",
				visited,
			)
		if visited >= limits.maximumNodes:
			return FocusMatchResult(
				FocusMatchDecision.UNAVAILABLE,
				None,
				"KS.INSPECTOR.FOCUS.NODE_BUDGET",
				visited,
			)
		visited += 1
		matched, reason = _focusMatchMethod(candidate.evidence)
		if matched:
			accepted.append(candidate.candidateId)
		else:
			firstRejection = reason
	if len(accepted) == 1:
		return FocusMatchResult(
			FocusMatchDecision.MATCHED,
			accepted[0],
			"KS.INSPECTOR.FOCUS.MATCHED",
			visited,
		)
	if len(accepted) > 1:
		return FocusMatchResult(
			FocusMatchDecision.AMBIGUOUS,
			None,
			"KS.INSPECTOR.FOCUS.AMBIGUOUS",
			visited,
		)
	return FocusMatchResult(FocusMatchDecision.REJECTED, None, firstRejection, visited)


# ---------------------------------------------------------------------------
# Loaded-only hierarchy search.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SearchableNode:
	"""One already-loaded node's privacy-safe searchable text; no source read is implied."""

	nodeId: str
	name: str
	role: str
	loadedText: tuple[str, ...] = ()

	def __post_init__(self) -> None:
		object.__setattr__(self, "nodeId", requireToken(self.nodeId, "node id"))
		object.__setattr__(self, "role", requireToken(self.role, "role"))


@dataclass(frozen=True, slots=True)
class SearchOutcome:
	decision: Literal["match", "noMatch", "empty"]
	nodeId: str | None
	wrapped: Literal["none", "start", "end"]
	query: str


def _matchesNeedle(node: SearchableNode, needle: str) -> bool:
	if needle in node.name.casefold() or needle in node.role.casefold():
		return True
	return any(needle in text.casefold() for text in node.loadedText)


def searchLoadedNodes(
	nodes: tuple[SearchableNode, ...],
	query: str,
	*,
	currentNodeId: str | None = None,
	forward: bool = True,
) -> SearchOutcome:
	"""Find the next/previous already-loaded node matching ``query``, wrapping in both directions.

	The search only ever inspects the supplied loaded nodes' privacy-safe name, role, and loaded
	property text. It never expands a branch or triggers hidden traversal, so an unexpanded subtree
	is reported as unsearched rather than silently opened.
	"""

	normalized = query.strip()
	if not normalized:
		return SearchOutcome("empty", None, "none", query)
	count = len(nodes)
	if count == 0:
		return SearchOutcome("noMatch", None, "none", normalized)
	needle = normalized.casefold()
	start = 0
	if currentNodeId is not None:
		for index, node in enumerate(nodes):
			if node.nodeId == currentNodeId:
				start = index
				break
	step = 1 if forward else -1
	for offset in range(1, count + 1):
		raw = start + step * offset
		node = nodes[raw % count]
		if _matchesNeedle(node, needle):
			wrapped: Literal["none", "start", "end"] = "none"
			if forward and raw >= count:
				wrapped = "start"
			elif not forward and raw < 0:
				wrapped = "end"
			return SearchOutcome("match", node.nodeId, wrapped, normalized)
	return SearchOutcome("noMatch", None, "none", normalized)
