"""Deterministic representative accessibility capture for bundle-economics tests.

This module builds a fixed, sanitized 413-node capture that stands in for the large
real-world capture used to compare snapshot serialization formats. It exists so every
bundle-economics test has one tracked, reproducible input and never depends on a private,
machine-specific measurement.

The generator is pure. It takes no arguments, reads no files, consults no clock, locale, or
environment, and enumerates no directories. It returns identical evidence on every call, so
two independent generations serialize to byte-identical topic files. All text is fixed product
language, and at least one protected input is transformed through the privacy policy before it
can reach the generated evidence, so no protected content is ever serialized.

The capture partitions deep information into the useful topic families: normalized core nodes,
supported patterns, UIA, IA2/MSAA, Java Access Bridge, overlay, raw UIA, custom UIA, semantics,
diagnostics, one once-per-capture configuration record, and one screenshot record. Node presence
in each topic follows fixed divisibility rules over the traversal-order node index, which produce
the exact closed inventory published in ``EXPECTED_RECORD_COUNTS``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Final

from addon.globalPlugins.keystone.domain.document_records import (
	JsonArray,
	JsonObject,
	JsonValue,
	evidenceObject,
)
from addon.globalPlugins.keystone.domain.evidence import (
	ErrorReference,
	EvidenceEnvelope,
	PrivacyClassification,
	PrivacyReference,
	Projection,
	Source,
	Truncation,
)
from addon.globalPlugins.keystone.domain.privacy import (
	UNREDACTED_SCREENSHOT_WARNING,
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	transformValue,
)
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState


NODE_COUNT: Final = 413

CORE: Final = "nodes"
PATTERNS: Final = "patterns"
UIA: Final = "uia"
IA2_MSAA: Final = "ia2Msaa"
JAB: Final = "jab"
OVERLAY: Final = "overlay"
RAW_UIA: Final = "rawUia"
CUSTOM_UIA: Final = "customUia"
SEMANTICS: Final = "semantics"
DIAGNOSTICS: Final = "diagnostics"
CAPTURE_CONFIGURATION: Final = "captureConfiguration"
SCREENSHOT: Final = "screenshot"

TOPIC_ORDER: Final[tuple[str, ...]] = (
	CORE,
	PATTERNS,
	UIA,
	IA2_MSAA,
	JAB,
	OVERLAY,
	RAW_UIA,
	CUSTOM_UIA,
	SEMANTICS,
	DIAGNOSTICS,
	CAPTURE_CONFIGURATION,
	SCREENSHOT,
)

# The closed useful-evidence inventory. Every count is derived from a fixed divisibility rule over
# the traversal-order node index, so a fresh clone reproduces exactly these numbers.
EXPECTED_RECORD_COUNTS: Final[dict[str, int]] = {
	CORE: 413,
	PATTERNS: 207,
	UIA: 413,
	IA2_MSAA: 138,
	JAB: 83,
	OVERLAY: 104,
	RAW_UIA: 59,
	CUSTOM_UIA: 46,
	SEMANTICS: 413,
	DIAGNOSTICS: 38,
	CAPTURE_CONFIGURATION: 1,
	SCREENSHOT: 1,
}

# A sanitized placeholder that models protected source content (for example a password field
# value). It is transformed to a redacted record before generation and must never appear in any
# serialized topic bytes.
PROTECTED_SAMPLE_SECRET: Final = "sample-protected-value-that-must-never-serialize"

_BRANCHING: Final = 8
_PROTECTED_INDEX: Final = 13
_PROTECTED_POLICY: Final = PrivacyPolicy(1, 1, True)

_ROLES: Final[tuple[str, ...]] = (
	"pane",
	"group",
	"list",
	"listItem",
	"button",
	"staticText",
	"checkBox",
	"link",
)
_IA2_ROLES: Final[tuple[str, ...]] = ("section", "paragraph", "list", "listItem", "pushButton")
_JAB_ROLES: Final[tuple[str, ...]] = ("panel", "label", "list", "pushButton")
_OVERLAY_CLASSES: Final[tuple[str, ...]] = ("EditableText", "List", "Button", "Document")
_CUSTOM_DEFINITIONS: Final[tuple[str, ...]] = ("gridCell", "richText", "annotation")
_PATTERN_CATALOG: Final[tuple[str, ...]] = (
	"invoke",
	"value",
	"selection",
	"expandCollapse",
	"scroll",
	"toggle",
	"grid",
	"table",
	"text",
)
_LANDMARKS: Final[tuple[str | None, ...]] = ("main", "navigation", None, "complementary", None)
_DIAGNOSTIC_CATEGORIES: Final[tuple[str, ...]] = (
	"providerTiming",
	"fallbackApplied",
	"cacheReuse",
)

_CLASSIFICATION_TOKENS: Final[dict[PrivacyClass, PrivacyClassification]] = {
	PrivacyClass.PUBLIC: "public",
	PrivacyClass.UNKNOWN: "unknown",
	PrivacyClass.SENSITIVE: "sensitive",
	PrivacyClass.PROTECTED: "protected",
}


def _computeChildCounts() -> tuple[int, ...]:
	counts = [0] * NODE_COUNT
	for index in range(1, NODE_COUNT):
		counts[(index - 1) // _BRANCHING] += 1
	return tuple(counts)


def _computeDepths() -> tuple[int, ...]:
	depths = [0] * NODE_COUNT
	for index in range(1, NODE_COUNT):
		depths[index] = depths[(index - 1) // _BRANCHING] + 1
	return tuple(depths)


_CHILD_COUNTS: Final[tuple[int, ...]] = _computeChildCounts()
_DEPTHS: Final[tuple[int, ...]] = _computeDepths()

_PUBLIC_PRIVACY: Final = PrivacyReference("node", "public", "retain", 1)
_NORMAL_PROJECTION: Final = Projection("normalNvda")


@dataclass(frozen=True, slots=True)
class CaptureTopic:
	"""One topic family and its ordered records."""

	name: str
	records: tuple[JsonObject, ...]


@dataclass(frozen=True, slots=True)
class RepresentativeCapture:
	"""The complete deterministic capture as ordered topic families."""

	topics: tuple[CaptureTopic, ...]

	def topic(self, name: str) -> CaptureTopic:
		for candidate in self.topics:
			if candidate.name == name:
				return candidate
		raise KeyError(name)

	@property
	def recordCounts(self) -> dict[str, int]:
		return {topic.name: len(topic.records) for topic in self.topics}

	@property
	def nodeCount(self) -> int:
		return len(self.topic(CORE).records)


def fieldValue(record: JsonObject, key: str) -> JsonValue:
	for name, value in record.items:
		if name == key:
			return value
	raise KeyError(f"missing field {key!r}")


def _nodeName(index: int, role: str) -> str:
	if index == 0:
		return "Keystone accessible sample document"
	return f"Sample {role} {index}"


def _coreRecord(index: int) -> JsonObject:
	role = _ROLES[index % len(_ROLES)]
	if index == 0:
		parent: JsonValue = None
		indexInParent = 0
	else:
		parent = f"n{(index - 1) // _BRANCHING}"
		indexInParent = (index - 1) % _BRANCHING
	return JsonObject(
		(
			("id", f"n{index}"),
			("parent", parent),
			("depth", _DEPTHS[index]),
			("indexInParent", indexInParent),
			("childCount", _CHILD_COUNTS[index]),
			("role", role),
			("name", _nodeName(index, role)),
			("focused", index == 0),
		),
	)


def _uiaEnvelope(index: int) -> EvidenceEnvelope:
	name = _nodeName(index, _ROLES[index % len(_ROLES)])
	if index == 0:
		return EvidenceEnvelope(
			status=EvidenceState.VALUE,
			source=Source("uia", "namePattern", "CurrentName"),
			projection=_NORMAL_PROJECTION,
			confidence=Confidence.DIRECT,
			privacy=_PUBLIC_PRIVACY,
			value=name,
		)
	if index == _PROTECTED_INDEX:
		observed = ObservedValue(
			fieldGroup=FieldGroup.NODE,
			value=PROTECTED_SAMPLE_SECRET,
			privacyClass=PrivacyClass.SENSITIVE,
			protection=ProtectionEvidence(True),
			sourceId="uiaValuePattern",
		)
		transformed = transformValue(observed, SinkId.NODE, _PROTECTED_POLICY)
		if transformed.action is not TransformAction.REDACT or transformed.value is not None:
			raise AssertionError("protected sample value must be redacted before serialization")
		return EvidenceEnvelope(
			status=EvidenceState.REDACTED,
			source=Source("uia", "valuePattern", "CurrentValue"),
			projection=_NORMAL_PROJECTION,
			confidence=Confidence.INDETERMINATE,
			privacy=PrivacyReference(
				"node",
				_CLASSIFICATION_TOKENS[transformed.effectiveClass],
				transformed.action.value,
				1,
			),
		)
	if index % 19 == 0:
		return EvidenceEnvelope(
			status=EvidenceState.TRUNCATED,
			source=Source("uia", "selectionPattern", "GetSelection"),
			projection=_NORMAL_PROJECTION,
			confidence=Confidence.DIRECT,
			privacy=_PUBLIC_PRIVACY,
			value=("first selected item", "second selected item"),
			truncation=Truncation("collectionItems", 2, 5, 3, "collectionItemLimit", True),
		)
	if index % 17 == 0:
		return EvidenceEnvelope(
			status=EvidenceState.STALE,
			source=Source("uia", "valuePattern", "CurrentValue"),
			projection=_NORMAL_PROJECTION,
			confidence=Confidence.INDETERMINATE,
			privacy=_PUBLIC_PRIVACY,
			errorRef=ErrorReference("staleElement", "diagnostic-stale-element"),
		)
	if index % 23 == 0:
		return EvidenceEnvelope(
			status=EvidenceState.VALUE,
			source=Source("uia", "wrapperBridge", "FlattenedName", "ancestorChainCollapsed"),
			projection=Projection("normalNvda", "wrapperFallback", True, "wrapperFlattened"),
			confidence=Confidence.FLATTENED_BY_WRAPPER,
			privacy=_PUBLIC_PRIVACY,
			value=f"Flattened representation for {name}",
		)
	if index % 13 == 0:
		return EvidenceEnvelope(
			status=EvidenceState.EMPTY,
			source=Source("uia", "valuePattern", "CurrentValue"),
			projection=_NORMAL_PROJECTION,
			confidence=Confidence.DIRECT,
			privacy=_PUBLIC_PRIVACY,
		)
	return EvidenceEnvelope(
		status=EvidenceState.VALUE,
		source=Source("uia", "namePattern", "CurrentName"),
		projection=_NORMAL_PROJECTION,
		confidence=Confidence.DIRECT,
		privacy=_PUBLIC_PRIVACY,
		value=name,
	)


def _uiaRecord(index: int) -> JsonObject:
	return JsonObject((("id", f"n{index}"), ("evidence", evidenceObject(_uiaEnvelope(index)))))


def _patternsRecord(index: int) -> JsonObject:
	start = (index // 2) % len(_PATTERN_CATALOG)
	chosen: tuple[JsonValue, ...] = _PATTERN_CATALOG[start : start + 2]
	return JsonObject((("id", f"n{index}"), ("patterns", JsonArray(chosen))))


def _ia2Record(index: int) -> JsonObject:
	states: tuple[JsonValue, ...] = ("focusable", "visible")
	return JsonObject(
		(
			("id", f"n{index}"),
			("role", _IA2_ROLES[index % len(_IA2_ROLES)]),
			("states", JsonArray(states)),
		),
	)


def _jabRecord(index: int) -> JsonObject:
	return JsonObject(
		(
			("id", f"n{index}"),
			("role", _JAB_ROLES[index % len(_JAB_ROLES)]),
			("name", f"Java component {index}"),
		),
	)


def _overlayRecord(index: int) -> JsonObject:
	return JsonObject(
		(
			("id", f"n{index}"),
			("overlayClass", _OVERLAY_CLASSES[index % len(_OVERLAY_CLASSES)]),
			("announced", index % 8 == 0),
		),
	)


def _rawUiaRecord(index: int) -> JsonObject:
	return JsonObject(
		(
			("id", f"n{index}"),
			("propertyId", 30005 + (index % 7)),
			("cached", False),
		),
	)


def _customUiaRecord(index: int) -> JsonObject:
	return JsonObject(
		(
			("id", f"n{index}"),
			("definition", _CUSTOM_DEFINITIONS[index % len(_CUSTOM_DEFINITIONS)]),
			("propertyGuid", "{d0f6a3b1-0000-4000-8000-000000000001}"),
		),
	)


def _semanticsRecord(index: int) -> JsonObject:
	landmark: JsonValue = _LANDMARKS[index % len(_LANDMARKS)]
	annotations: tuple[JsonValue, ...] = ("comment",) if index % 3 == 0 else ()
	return JsonObject(
		(
			("id", f"n{index}"),
			("landmark", landmark),
			("liveRegion", False),
			("annotations", JsonArray(annotations)),
		),
	)


def _diagnosticsRecord(index: int) -> JsonObject:
	sequence = index // 11
	return JsonObject(
		(
			("id", f"n{index}"),
			("category", _DIAGNOSTIC_CATEGORIES[sequence % len(_DIAGNOSTIC_CATEGORIES)]),
			("durationMicroseconds", sequence * 25),
			("detail", "Provider read completed within the cooperative slice budget."),
		),
	)


def _captureConfigurationRecord() -> JsonObject:
	scanPlan = JsonObject(
		(
			("uiaPropertyCount", 42),
			("cacheRequest", "reuseCurrent"),
			("note", "Recorded once per capture instead of on every node."),
		),
	)
	return JsonObject(
		(
			("formatMajor", 2),
			("formatMinor", 0),
			("snapshotKind", "snapshot"),
			("nodeCount", NODE_COUNT),
			("rootIds", JsonArray(("n0",))),
			("redactionEnabled", True),
			("policyRevision", 1),
			("settingsRevision", 1),
			("installedScanPlan", scanPlan),
		),
	)


def _screenshotRecord() -> JsonObject:
	geometry: tuple[JsonValue, ...] = (0, 0, 1280, 720)
	return JsonObject(
		(
			("status", "value"),
			("format", "png"),
			("geometry", JsonArray(geometry)),
			("byteLength", 48211),
			("warning", UNREDACTED_SCREENSHOT_WARNING),
		),
	)


def representativeCapture() -> RepresentativeCapture:
	"""Build the complete deterministic representative capture."""

	topics = (
		CaptureTopic(CORE, tuple(_coreRecord(index) for index in range(NODE_COUNT))),
		CaptureTopic(
			PATTERNS,
			tuple(_patternsRecord(index) for index in range(NODE_COUNT) if index % 2 == 0),
		),
		CaptureTopic(UIA, tuple(_uiaRecord(index) for index in range(NODE_COUNT))),
		CaptureTopic(IA2_MSAA, tuple(_ia2Record(index) for index in range(NODE_COUNT) if index % 3 == 0)),
		CaptureTopic(JAB, tuple(_jabRecord(index) for index in range(NODE_COUNT) if index % 5 == 0)),
		CaptureTopic(OVERLAY, tuple(_overlayRecord(index) for index in range(NODE_COUNT) if index % 4 == 0)),
		CaptureTopic(RAW_UIA, tuple(_rawUiaRecord(index) for index in range(NODE_COUNT) if index % 7 == 0)),
		CaptureTopic(
			CUSTOM_UIA,
			tuple(_customUiaRecord(index) for index in range(NODE_COUNT) if index % 9 == 0),
		),
		CaptureTopic(SEMANTICS, tuple(_semanticsRecord(index) for index in range(NODE_COUNT))),
		CaptureTopic(
			DIAGNOSTICS,
			tuple(_diagnosticsRecord(index) for index in range(NODE_COUNT) if index % 11 == 0),
		),
		CaptureTopic(CAPTURE_CONFIGURATION, (_captureConfigurationRecord(),)),
		CaptureTopic(SCREENSHOT, (_screenshotRecord(),)),
	)
	return RepresentativeCapture(topics)


def _plain(value: JsonValue) -> object:
	if isinstance(value, JsonObject):
		return {key: _plain(item) for key, item in value.items}
	if isinstance(value, JsonArray):
		return [_plain(item) for item in value.items]
	return value


def _encodeRecord(record: JsonObject) -> str:
	return json.dumps(_plain(record), ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def topicBytes(topic: CaptureTopic) -> bytes:
	"""Serialize one topic to deterministic uncompressed JSON Lines bytes."""

	return "".join(f"{_encodeRecord(record)}\n" for record in topic.records).encode("utf-8")


def estimatedTokens(byteLength: int) -> int:
	"""Return the documented token estimate ``ceil(byteLength / 4)`` for a byte length."""

	if byteLength < 0:
		raise ValueError("byte length must be nonnegative")
	return -(-byteLength // 4)
