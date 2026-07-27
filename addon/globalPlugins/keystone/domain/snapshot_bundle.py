"""Partitioned capture bundle: encoding, admission, offsets, projection, and economics.

A capture bundle stores one accessibility capture as a small standalone ``index.json``
plus one line-delimited JSON file per useful topic family. The index is the default
handoff: it names the format, the redaction posture, the application, the traversal roots,
a concise structural outline, and a closed catalog with the record count, byte length, and
SHA-256 of every present topic file. Consumers open the index first, then join selected lines
by recorded byte offsets. Each lazily accessed topic is revalidated against its admitted file
identity and catalog before its verified bytes are cached for later joins.

The module is pure. Encoding is deterministic: records serialise to one compact object per
line in ascending local-identifier order, so two independent generations of the same capture
produce byte-identical files. Admission opens a committed directory without following reparse
points, reads the index under a hard byte ceiling, validates the closed catalog, then streams
every cataloged file once under one shared structural budget while recording byte offsets. No
protected content can appear here that was not already present in the privacy-transformed
input, because projection only re-reads bytes that were serialised upstream.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field as dataclassField, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Final, Protocol, cast

from .document_records import (
	COMMON_NODE_FIELDS,
	PROVIDER_SECTIONS,
	JsonArray,
	JsonObject,
	JsonValue,
	NodeStructure,
	ProviderSectionRecord,
	ProviderSections,
	evidenceObject,
	parseEvidenceEnvelope,
)
from .documents import NavigatorSnapshot, Snapshot
from .evidence import ErrorReference, EvidenceEnvelope, PrivacyReference, Projection, Source
from .inspector import (
	AnnotationRecord,
	AnnotationStatus,
	annotationConversionFailure,
	annotationRecordsFromPlain,
	validateAnnotationKeys,
)
from .status import Confidence, EvidenceState

BUNDLE_FORMAT_MAJOR: Final = 1
BUNDLE_FORMAT_MINOR: Final = 1

INDEX_FILENAME: Final = "index.json"
SCREENSHOT_IMAGE_FILENAME: Final = "screenshot.png"
# The atomic publisher always writes this receipt next to the artifacts it commits. It is an
# operational sidecar, never part of the model-facing bundle, so admission tolerates it when present
# and excludes it from every economics total.
PUBLICATION_RECEIPT_FILENAME: Final = "publication-metadata.json"

SNAPSHOT_KINDS: Final[tuple[str, ...]] = ("snapshot", "navigatorSnapshot")

NODE_TOPICS: Final[tuple[str, ...]] = (
	"nodes",
	"patterns",
	"uia",
	"ia2Msaa",
	"jab",
	"overlay",
	"rawUia",
	"customUia",
	"semantics",
	"diagnostics",
)
DOCUMENT_TOPICS: Final[tuple[str, ...]] = ("captureConfiguration", "screenshot")
BUNDLE_TOPIC_ORDER: Final[tuple[str, ...]] = NODE_TOPICS + DOCUMENT_TOPICS

TOPIC_FILENAMES: Final[dict[str, str]] = {
	"nodes": "nodes.jsonl",
	"patterns": "patterns.jsonl",
	"uia": "uia.jsonl",
	"ia2Msaa": "ia2.jsonl",
	"jab": "jab.jsonl",
	"overlay": "overlay.jsonl",
	"rawUia": "raw-uia.jsonl",
	"customUia": "custom-uia.jsonl",
	"semantics": "semantics.jsonl",
	"diagnostics": "diagnostics.jsonl",
	"captureConfiguration": "capture-config.jsonl",
	"screenshot": "screenshot.jsonl",
}
_FILENAME_TOPICS: Final[dict[str, str]] = {filename: topic for topic, filename in TOPIC_FILENAMES.items()}

OUTLINE_LIMIT: Final = 64

COMPLETE_HARD_BYTES: Final = 2_621_440
COMPLETE_HARD_TOKENS: Final = 655_360
COMPLETE_TARGET_BYTES: Final = 2_359_296

# Format-1 stores validated capture-wide tables in the index. Its parsing budget must therefore
# accommodate the ordinary decoded-content budget while the total admission budget remains bounded.
INDEX_HARD_BYTES: Final = COMPLETE_HARD_BYTES
INDEX_HARD_TOKENS: Final = COMPLETE_HARD_TOKENS
INDEX_TARGET_BYTES: Final = 96 * 1024
INDEX_TARGET_TOKENS: Final = 24_576
INDEX_NODES_HARD_BYTES: Final = 512 * 1024
INDEX_NODES_HARD_TOKENS: Final = 131_072

_REPARSE_POINT_ATTRIBUTE: Final = 0x400
_NODE_ID_PATTERN: Final = re.compile(r"n(0|[1-9][0-9]*)")
_HEX_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_PATTERN: Final = re.compile(
	r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z",
)


def estimateTokenCount(byteLength: int) -> int:
	"""Return the documented token estimate ``ceil(byteLength / 4)``."""

	if byteLength < 0:
		raise ValueError("byte length must be nonnegative")
	return -(-byteLength // 4)


def _plain(value: JsonValue) -> object:
	if isinstance(value, JsonObject):
		return {key: _plain(item) for key, item in value.items}
	if isinstance(value, JsonArray):
		return [_plain(item) for item in value.items]
	return value


def _encodeLine(record: JsonObject) -> str:
	return json.dumps(_plain(record), ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _encodeCompact(value: object) -> bytes:
	return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode(
		"utf-8",
	)


def _objectField(record: JsonObject, key: str) -> JsonValue | None:
	for name, value in record.items:
		if name == key:
			return value
	return None


def _requireStringField(record: JsonObject, key: str) -> str:
	value = _objectField(record, key)
	if not isinstance(value, str):
		raise ValueError(f"record field {key!r} must be a string")
	return value


def _localIdOrder(nodeId: str) -> int:
	if _NODE_ID_PATTERN.fullmatch(nodeId) is None:
		raise ValueError("node local identifier must match n<digits>")
	return int(nodeId[1:])


def _customUiaDefinitionPair(value: object) -> list[object] | None:
	if not isinstance(value, list):
		return None
	items = cast("list[object]", value)
	if len(items) != 2 or not all(isinstance(item, str) and item for item in items):
		return None
	return items


@dataclass(frozen=True, slots=True)
class BundleCatalogEntry:
	"""One present topic file described by count, byte length, and content hash."""

	topic: str
	filename: str
	recordCount: int
	byteLength: int
	sha256: str

	def __post_init__(self) -> None:
		if self.topic not in BUNDLE_TOPIC_ORDER:
			raise ValueError("catalog topic is not a known topic family")
		if TOPIC_FILENAMES[self.topic] != self.filename:
			raise ValueError("catalog filename does not match its topic")
		if Path(self.filename).name != self.filename or self.filename in {".", ".."}:
			raise ValueError("catalog filename must be a single safe component")
		if self.recordCount < 0 or self.byteLength < 0:
			raise ValueError("catalog counts must be nonnegative")
		if _HEX_DIGEST_PATTERN.fullmatch(self.sha256) is None:
			raise ValueError("catalog hash must be lowercase 64-character hexadecimal")

	@property
	def nodeKeyed(self) -> bool:
		return self.topic in NODE_TOPICS


@dataclass(frozen=True, slots=True)
class BundleNode:
	"""A concise outline entry drawn from the normalized core node record."""

	id: str
	parent: str | None
	depth: int
	childCount: int
	role: str
	name: str


@dataclass(frozen=True, slots=True)
class CompactSharedTables:
	"""Capture-wide values that compact records may reference by zero-based index.

	The tables are deliberately closed.  They keep identity and provenance that commonly recur
	across a capture out of individual node records without giving the reader an open-ended,
	unvalidated side channel.
	"""

	processIds: tuple[int, ...] = ()
	windowHandles: tuple[int, ...] = ()
	classHierarchies: tuple[tuple[str, ...], ...] = ()
	customUiaDefinitions: tuple[object, ...] = ()
	providerDefaults: tuple[object, ...] = ()
	sources: tuple[object, ...] = ()
	projections: tuple[object, ...] = ()
	privacy: tuple[object, ...] = ()
	provenance: tuple[object, ...] = ()

	def __post_init__(self) -> None:
		if any(type(value) is not int or value < 0 for value in self.processIds):
			raise ValueError("shared process identifiers must be nonnegative integers")
		if any(type(value) is not int or value < 0 for value in self.windowHandles):
			raise ValueError("shared window handles must be nonnegative integers")
		if any(not hierarchy or any(not item for item in hierarchy) for hierarchy in self.classHierarchies):
			raise ValueError("shared class hierarchies must contain nonempty text")
		for definition in self.customUiaDefinitions:
			if _customUiaDefinitionPair(definition) is None:
				raise ValueError("shared Custom UIA definitions must be stable-key and GUID pairs")
		for table in (
			self.processIds,
			self.windowHandles,
			self.classHierarchies,
			self.customUiaDefinitions,
			self.providerDefaults,
			self.sources,
			self.projections,
			self.privacy,
			self.provenance,
		):
			if len(set(_encodeCompact(item) for item in table)) != len(table):
				raise ValueError("shared compact tables must not contain duplicate values")

	def asPlain(self) -> dict[str, object]:
		return {
			"processIds": list(self.processIds),
			"windowHandles": list(self.windowHandles),
			"classHierarchies": [list(hierarchy) for hierarchy in self.classHierarchies],
			"customUiaDefinitions": list(self.customUiaDefinitions),
			"providerDefaults": list(self.providerDefaults),
			"sources": list(self.sources),
			"projections": list(self.projections),
			"privacy": list(self.privacy),
			"provenance": list(self.provenance),
		}


@dataclass(frozen=True, slots=True)
class CompactUiaSchema:
	"""Ordered standard-UIA columns shared by compact ``uia`` records."""

	columns: tuple[str, ...] = ()

	def __post_init__(self) -> None:
		if len(set(self.columns)) != len(self.columns):
			raise ValueError("compact UIA schema columns must be unique")
		if any(not column for column in self.columns):
			raise ValueError("compact UIA schema columns must be nonempty text")

	def asPlain(self) -> list[str]:
		return list(self.columns)


@dataclass(frozen=True, slots=True)
class CompactDefaultsSchema:
	"""One closed default-and-exception schema for a compact topic section."""

	topic: str
	columns: tuple[str, ...]
	defaults: tuple[object, ...]

	def __post_init__(self) -> None:
		if self.topic not in ("nodes", "ia2Msaa", "overlay"):
			raise ValueError("compact default schema topic is not supported")
		if not self.columns or len(set(self.columns)) != len(self.columns):
			raise ValueError("compact default schema columns must be nonempty and unique")
		if any(not column for column in self.columns):
			raise ValueError("compact default schema columns must be nonempty text")
		if len(self.defaults) != len(self.columns):
			raise ValueError("compact default schema defaults must align with the columns")

	def asPlain(self) -> dict[str, object]:
		return {
			"topic": self.topic,
			"columns": list(self.columns),
			"defaults": list(self.defaults),
		}


def _outlineNodePlain(node: BundleNode) -> dict[str, object]:
	return {
		"id": node.id,
		"parent": node.parent,
		"depth": node.depth,
		"childCount": node.childCount,
		"role": node.role,
		"name": node.name,
	}


@dataclass(frozen=True, slots=True)
class BundleIndex:
	"""The closed, privacy-safe index that opens a bundle standalone."""

	formatMajor: int
	formatMinor: int
	snapshotKind: str
	generatedAt: str
	redactionEnabled: bool
	policyRevision: int
	settingsRevision: int
	executable: str
	processId: int
	rootIds: tuple[str, ...]
	nodeCount: int
	outline: tuple[BundleNode, ...]
	outlineTruncated: bool
	catalog: tuple[BundleCatalogEntry, ...]
	sharedTables: CompactSharedTables = CompactSharedTables()
	uiaSchema: CompactUiaSchema = CompactUiaSchema()
	uiaDefaults: tuple[object, ...] = ()
	compactDefaults: tuple[CompactDefaultsSchema, ...] = ()

	def __post_init__(self) -> None:
		if self.formatMajor != BUNDLE_FORMAT_MAJOR:
			raise ValueError("bundle format major version is not supported")
		if self.formatMinor not in (0, BUNDLE_FORMAT_MINOR):
			raise ValueError("bundle format minor version is not supported")
		if self.snapshotKind not in SNAPSHOT_KINDS:
			raise ValueError("bundle snapshot kind is not supported")
		if _TIMESTAMP_PATTERN.fullmatch(self.generatedAt) is None:
			raise ValueError("bundle generated timestamp must be RFC 3339 UTC")
		if self.policyRevision < 0 or self.settingsRevision < 0:
			raise ValueError("bundle revisions must be nonnegative")
		if not self.executable:
			raise ValueError("bundle executable must be present")
		if type(self.processId) is not int or self.processId < 0 or self.processId > 0xFFFFFFFF:
			raise ValueError("bundle process identifier must be a nonnegative 32-bit integer")
		if not self.rootIds:
			raise ValueError("bundle must declare at least one root")
		if len(set(self.rootIds)) != len(self.rootIds):
			raise ValueError("bundle roots must be unique")
		for rootId in self.rootIds:
			_ = _localIdOrder(rootId)
		if self.nodeCount < 0:
			raise ValueError("bundle node count must be nonnegative")
		topics = tuple(entry.topic for entry in self.catalog)
		if len(set(topics)) != len(topics):
			raise ValueError("catalog topics must be unique")
		filenames = tuple(entry.filename.lower() for entry in self.catalog)
		if len(set(filenames)) != len(filenames):
			raise ValueError("catalog filenames must not collide under case folding")
		if len(self.uiaDefaults) != len(self.uiaSchema.columns):
			raise ValueError("compact UIA defaults must align with the schema")
		if self.formatMinor == 0 and self.compactDefaults:
			raise ValueError("format 1.0 cannot carry compact default schemas")
		if len({schema.topic for schema in self.compactDefaults}) != len(self.compactDefaults):
			raise ValueError("compact default schema topics must be unique")

	def entry(self, topic: str) -> BundleCatalogEntry | None:
		for candidate in self.catalog:
			if candidate.topic == topic:
				return candidate
		return None

	def orderedFilenames(self) -> tuple[str, ...]:
		byTopic = {entry.topic: entry.filename for entry in self.catalog}
		return tuple(byTopic[topic] for topic in BUNDLE_TOPIC_ORDER if topic in byTopic)

	def _asPlain(self) -> dict[str, object]:
		result: dict[str, object] = {
			"formatMajor": self.formatMajor,
			"formatMinor": self.formatMinor,
			"snapshotKind": self.snapshotKind,
			"generatedAt": self.generatedAt,
			"redactionEnabled": self.redactionEnabled,
			"policyRevision": self.policyRevision,
			"settingsRevision": self.settingsRevision,
			"executable": self.executable,
			"processId": self.processId,
			"rootIds": list(self.rootIds),
			"nodeCount": self.nodeCount,
			"outline": [_outlineNodePlain(node) for node in self.outline],
			"outlineTruncated": self.outlineTruncated,
			"catalog": [
				{
					"topic": entry.topic,
					"filename": entry.filename,
					"recordCount": entry.recordCount,
					"byteLength": entry.byteLength,
					"sha256": entry.sha256,
				}
				for entry in self.catalog
			],
			"sharedTables": self.sharedTables.asPlain(),
			"uiaSchema": self.uiaSchema.asPlain(),
			"uiaDefaults": list(self.uiaDefaults),
		}
		if self.formatMinor == BUNDLE_FORMAT_MINOR:
			result["compactDefaults"] = [schema.asPlain() for schema in self.compactDefaults]
		return result

	def encode(self) -> bytes:
		return _encodeCompact(self._asPlain())


@dataclass(frozen=True, slots=True)
class BundleTopicRecords:
	"""One topic family and its ordered records prepared for serialisation."""

	topic: str
	records: tuple[JsonObject, ...]

	def __post_init__(self) -> None:
		if self.topic not in BUNDLE_TOPIC_ORDER:
			raise ValueError("topic is not a known topic family")


def _annotationObject(
	record: AnnotationRecord,
	privacyTransform: Callable[[str], str],
) -> JsonObject:
	def transformed(value: str) -> str:
		return privacyTransform(value)

	items: list[tuple[str, JsonValue]] = [
		("key", record.key),
		("status", record.status.value),
		("typeName", transformed(record.typeName)),
		("source", transformed(record.source)),
	]
	if record.errorRef is not None:
		items.append(
			(
				"errorRef",
				JsonObject(
					(
						("code", record.errorRef.code),
						("diagnosticId", record.errorRef.diagnosticId),
					),
				),
			),
		)
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
		value = getattr(record, name)
		if value is not None:
			items.append((name, transformed(value)))
	if record.targetIdentityProven:
		items.append(("targetIdentityProven", True))
	if record.related:
		items.append(
			(
				"related",
				JsonArray(
					tuple(
						_annotationObject(related, privacyTransform)
						for related in sorted(record.related, key=lambda item: item.key)
					),
				),
			),
		)
	return JsonObject(tuple(items))


def annotationTopicRecords(
	recordsByNode: Mapping[str, tuple[AnnotationRecord, ...]],
	*,
	privacyTransform: Callable[[str], str],
) -> BundleTopicRecords:
	"""Build the node-keyed semantics topic after applying privacy to every captured text value."""

	records: list[JsonObject] = []
	for nodeId in sorted(recordsByNode, key=_localIdOrder):
		annotations = recordsByNode[nodeId]
		validateAnnotationKeys(annotations)
		if not annotations:
			continue
		records.append(
			JsonObject(
				(
					("id", nodeId),
					(
						"annotations",
						JsonArray(
							tuple(
								_annotationObject(record, privacyTransform)
								for record in sorted(annotations, key=lambda item: item.key)
							),
						),
					),
				),
			),
		)
	return BundleTopicRecords("semantics", tuple(records))


@dataclass(frozen=True, slots=True)
class BundleSource:
	"""The privacy-transformed capture prepared as ordered topic families."""

	snapshotKind: str
	generatedAt: str
	redactionEnabled: bool
	policyRevision: int
	settingsRevision: int
	executable: str
	processId: int
	rootIds: tuple[str, ...]
	topics: tuple[BundleTopicRecords, ...]
	screenshotImage: bytes | None = None


_STANDARD_UIA_FIELDS: Final[tuple[str, ...]] = ("status", "identity", "properties")
_COMPACT_UIA_KEYS: Final[tuple[str, ...]] = ("id", "exceptions")
_DEFAULT_CORE_FLAGS: Final[dict[str, bool]] = {
	"cycleDetected": False,
	"truncated": False,
	"childFetchFailed": False,
}


def _plainObject(record: JsonObject) -> dict[str, object]:
	return cast("dict[str, object]", _plain(record))


def _canonicalCompactValue(value: object) -> bytes:
	return _encodeCompact(value)


def _compactValueKind(value: object) -> str:
	if value is None:
		return "null"
	if type(value) is bool:
		return "bool"
	if type(value) is int:
		return "int"
	if isinstance(value, float):
		return "float"
	if isinstance(value, str):
		return "str"
	if isinstance(value, list):
		return "list"
	if isinstance(value, dict):
		return "object"
	raise ValueError("compact bundle value is not JSON-compatible")


def _compactStandardUia(
	topics: tuple[BundleTopicRecords, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], CompactUiaSchema, tuple[object, ...]]:
	"""Replace complete standard-UIA sections with defaults plus ordered exceptions."""

	uia = next((topic for topic in topics if topic.topic == "uia"), None)
	if uia is None or not uia.records:
		return topics, CompactUiaSchema(), ()
	plainRecords = tuple(_plainObject(record) for record in uia.records)
	if not all(tuple(record) == ("id", *_STANDARD_UIA_FIELDS) for record in plainRecords):
		return topics, CompactUiaSchema(), ()
	if any(not isinstance(record["id"], str) for record in plainRecords):
		raise ValueError("standard UIA record identifier must be text")

	defaults: list[object] = []
	for field in _STANDARD_UIA_FIELDS:
		counts: dict[bytes, tuple[int, object]] = {}
		for record in plainRecords:
			value = record[field]
			encoded = _canonicalCompactValue(value)
			count, _first = counts.get(encoded, (0, value))
			counts[encoded] = (count + 1, value)
			if cooperate is not None:
				cooperate()
		defaults.append(max(counts.values(), key=lambda item: item[0])[1])

	compactRecords: list[JsonObject] = []
	for record in plainRecords:
		exceptions: list[JsonArray] = []
		for column, field in enumerate(_STANDARD_UIA_FIELDS):
			value = record[field]
			if _canonicalCompactValue(value) != _canonicalCompactValue(defaults[column]):
				exceptions.append(JsonArray((column, _fromPlain(value))))
		compactRecords.append(
			JsonObject(
				(
					("id", cast(str, record["id"])),
					("exceptions", JsonArray(tuple(exceptions))),
				),
			),
		)
		if cooperate is not None:
			cooperate()
	compactTopic = BundleTopicRecords("uia", tuple(compactRecords))
	return (
		tuple(compactTopic if topic.topic == "uia" else topic for topic in topics),
		CompactUiaSchema(_STANDARD_UIA_FIELDS),
		tuple(defaults),
	)


def _uniqueCompactValues(values: list[object]) -> tuple[object, ...]:
	unique: dict[bytes, object] = {}
	for value in values:
		encoded = _canonicalCompactValue(value)
		if encoded not in unique:
			unique[encoded] = value
	return tuple(unique.values())


def _sharedTableValues(
	topics: tuple[BundleTopicRecords, ...],
	*,
	extraValues: tuple[object, ...] = (),
	cooperate: Callable[[], None] | None = None,
) -> CompactSharedTables:
	processIds: list[int] = []
	windowHandles: list[int] = []
	classHierarchies: list[tuple[str, ...]] = []
	sources: list[object] = []
	projections: list[object] = []
	privacy: list[object] = []
	provenance: list[object] = []

	def visit(value: object, key: str | None = None) -> None:
		if isinstance(value, dict):
			mapping = cast("dict[str, object]", value)
			if key == "source":
				sources.append(mapping)
			elif key == "projection":
				projections.append(mapping)
			elif key == "privacy":
				privacy.append(mapping)
			elif key in ("provenance", "errorRef"):
				provenance.append(mapping)
			for childKey, child in mapping.items():
				visit(child, childKey)
			return
		if key in ("process", "processId") and type(value) is int and value >= 0:
			processIds.append(value)
		elif key == "windowHandle" and type(value) is int and value >= 0:
			windowHandles.append(value)
		elif key == "windowClass" and isinstance(value, str) and value:
			classHierarchies.append((value,))
		elif isinstance(value, list):
			for child in cast("list[object]", value):
				visit(child)

	for topic in topics:
		for record in topic.records:
			visit(_plainObject(record))
			if cooperate is not None:
				cooperate()
	for value in extraValues:
		visit(value)
		if cooperate is not None:
			cooperate()
	return CompactSharedTables(
		processIds=tuple(dict.fromkeys(processIds)),
		windowHandles=tuple(dict.fromkeys(windowHandles)),
		classHierarchies=tuple(dict.fromkeys(classHierarchies)),
		sources=_uniqueCompactValues(sources),
		projections=_uniqueCompactValues(projections),
		privacy=_uniqueCompactValues(privacy),
		provenance=_uniqueCompactValues(provenance),
	)


def _compactGenericDefaults(
	topics: tuple[BundleTopicRecords, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], tuple[object, ...]]:
	"""Move complete generic sections into an index table and retain only references in core nodes."""

	nodes = next((topic for topic in topics if topic.topic == "nodes"), None)
	if nodes is None:
		return topics, ()
	plainRecords = tuple(_plainObject(record) for record in nodes.records)
	generics: list[object] = []
	for record in plainRecords:
		candidate = record.get("generic")
		if isinstance(candidate, dict):
			section = cast("dict[str, object]", candidate)
			if tuple(section) == _STANDARD_UIA_FIELDS:
				generics.append(section)
		if cooperate is not None:
			cooperate()
	providerDefaults = _uniqueCompactValues(generics)
	references = {_canonicalCompactValue(value): index for index, value in enumerate(providerDefaults)}
	compactRecords: list[JsonObject] = []
	for original, plain in zip(nodes.records, plainRecords, strict=True):
		generic = plain.get("generic")
		if not isinstance(generic, dict):
			compactRecords.append(original)
			continue
		section = cast("dict[str, object]", generic)
		if tuple(section) != _STANDARD_UIA_FIELDS:
			compactRecords.append(original)
			continue
		items = [(key, value) for key, value in original.items if key != "generic"]
		items.append(("genericRef", references[_canonicalCompactValue(section)]))
		compactRecords.append(JsonObject(tuple(items)))
		if cooperate is not None:
			cooperate()
	compactTopics = tuple(
		BundleTopicRecords("nodes", tuple(compactRecords)) if topic.topic == "nodes" else topic
		for topic in topics
	)
	return compactTopics, providerDefaults


def _compactCoreFlags(
	topics: tuple[BundleTopicRecords, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[BundleTopicRecords, ...]:
	"""Omit the common all-clear traversal flags, which reconstruct to their canonical values."""

	nodes = next((topic for topic in topics if topic.topic == "nodes"), None)
	if nodes is None:
		return topics
	compactRecords: list[JsonObject] = []
	for record in nodes.records:
		plain = _plainObject(record)
		if plain.get("flags") != _DEFAULT_CORE_FLAGS:
			compactRecords.append(record)
			continue
		compactRecords.append(
			JsonObject(tuple((name, value) for name, value in record.items if name != "flags")),
		)
		if cooperate is not None:
			cooperate()
	return tuple(
		BundleTopicRecords("nodes", tuple(compactRecords)) if topic.topic == "nodes" else topic
		for topic in topics
	)


_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
	(
		"status",
		"source",
		"projection",
		"confidence",
		"privacy",
		"value",
		"truncation",
		"errorRef",
		"observedAt",
		"scope",
	),
)
_COMPACT_EVIDENCE_REQUIRED: Final[frozenset[str]] = frozenset(("s", "o", "j", "c", "p"))
_COMPACT_EVIDENCE_KEYS: Final[frozenset[str]] = _COMPACT_EVIDENCE_REQUIRED | frozenset(
	("v", "t", "e", "a", "q"),
)


def _isEvidencePlain(value: object) -> bool:
	if not isinstance(value, dict):
		return False
	record = cast("dict[str, object]", value)
	return (
		{"status", "source", "projection", "confidence", "privacy"}.issubset(record)
		and set(record).issubset(_EVIDENCE_KEYS)
		and isinstance(record["status"], str)
		and isinstance(record["confidence"], str)
		and isinstance(record["source"], dict)
		and isinstance(record["projection"], dict)
		and isinstance(record["privacy"], dict)
	)


def _compactEvidenceValues(
	topics: tuple[BundleTopicRecords, ...],
	providerDefaults: tuple[object, ...],
	uiaDefaults: tuple[object, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], CompactSharedTables, tuple[object, ...]]:
	"""Replace repeated evidence provenance with closed, capture-wide table references."""

	tables = _sharedTableValues(
		topics,
		extraValues=(*providerDefaults, *uiaDefaults),
		cooperate=cooperate,
	)

	def lookup(values: tuple[object, ...], value: object, label: str) -> int:
		references = {_canonicalCompactValue(item): index for index, item in enumerate(values)}
		try:
			return references[_canonicalCompactValue(value)]
		except KeyError as error:
			raise ValueError(f"compact {label} value is missing from its shared table") from error

	def compact(value: object) -> object:
		if _isEvidencePlain(value):
			record = cast("dict[str, object]", value)
			encoded: dict[str, object] = {
				"s": record["status"],
				"o": lookup(tables.sources, record["source"], "source"),
				"j": lookup(tables.projections, record["projection"], "projection"),
				"c": record["confidence"],
				"p": lookup(tables.privacy, record["privacy"], "privacy"),
			}
			if "value" in record:
				encoded["v"] = compact(record["value"])
			if "truncation" in record:
				encoded["t"] = compact(record["truncation"])
			if "errorRef" in record:
				encoded["e"] = lookup(tables.provenance, record["errorRef"], "provenance")
			if "observedAt" in record:
				encoded["a"] = record["observedAt"]
			if "scope" in record:
				encoded["q"] = compact(record["scope"])
			return encoded
		if isinstance(value, dict):
			return {key: compact(item) for key, item in cast("dict[str, object]", value).items()}
		if isinstance(value, list):
			return [compact(item) for item in cast("list[object]", value)]
		return value

	def compactRecord(record: JsonObject) -> JsonObject:
		return _fromPlainObject(cast("dict[str, object]", compact(_plainObject(record))))

	compactTopics: list[BundleTopicRecords] = []
	for topic in topics:
		records: list[JsonObject] = []
		for record in topic.records:
			records.append(compactRecord(record))
			if cooperate is not None:
				cooperate()
		compactTopics.append(BundleTopicRecords(topic.topic, tuple(records)))
	compactDefaults: list[object] = []
	for value in providerDefaults:
		compactDefaults.append(compact(value))
		if cooperate is not None:
			cooperate()
	compactUiaDefaults: list[object] = []
	for value in uiaDefaults:
		compactUiaDefaults.append(compact(value))
		if cooperate is not None:
			cooperate()
	return (
		tuple(compactTopics),
		replace(tables, providerDefaults=tuple(compactDefaults)),
		tuple(compactUiaDefaults),
	)


_COMPACT_CORE_FIELDS: Final[tuple[str, ...]] = tuple(
	name
	for name in COMMON_NODE_FIELDS
	if name not in ("annotations", "children", "developerInformation", "apiDetails", "diagnostics")
)
_COMPACT_ABSENT: Final[dict[str, bool]] = {"absent": True}


def _isCompactAbsent(value: object) -> bool:
	return isinstance(value, dict) and cast("dict[str, object]", value) == _COMPACT_ABSENT


def _sharedDefaults(
	records: tuple[dict[str, object], ...],
	columns: tuple[str, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[object, ...]:
	defaults: list[object] = []
	for column in columns:
		counts: dict[bytes, tuple[int, object]] = {}
		for record in records:
			value = record.get(column, _COMPACT_ABSENT)
			encoded = _canonicalCompactValue(value)
			count, _first = counts.get(encoded, (0, value))
			counts[encoded] = (count + 1, value)
			if cooperate is not None:
				cooperate()
		defaults.append(max(counts.values(), key=lambda item: item[0])[1])
	return tuple(defaults)


def _compactDefaultExceptions(
	records: tuple[dict[str, object], ...],
	columns: tuple[str, ...],
	defaults: tuple[object, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> list[JsonObject]:
	compacted: list[JsonObject] = []
	for record in records:
		exceptions: list[JsonArray] = []
		for column, default in enumerate(defaults):
			value = record.get(columns[column], _COMPACT_ABSENT)
			if _canonicalCompactValue(value) != _canonicalCompactValue(default):
				exceptions.append(JsonArray((column, _fromPlain(value))))
		compacted.append(
			JsonObject(
				(
					("id", _expectString(record["id"], "compact record identifier")),
					("exceptions", JsonArray(tuple(exceptions))),
				),
			),
		)
		if cooperate is not None:
			cooperate()
	return compacted


def _compactCoreFields(
	topics: tuple[BundleTopicRecords, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], CompactDefaultsSchema | None]:
	"""Replace repeated core envelopes with per-field defaults and explicit absent exceptions."""

	nodes = next((topic for topic in topics if topic.topic == "nodes"), None)
	if nodes is None or not nodes.records:
		return topics, None
	plainRecords = tuple(_plainObject(record) for record in nodes.records)
	fieldRecords: list[dict[str, object]] = []
	for record in plainRecords:
		if not isinstance(record.get("id"), str) or not isinstance(record.get("fields"), dict):
			return topics, None
		fields = cast("dict[str, object]", record["fields"])
		if not set(fields).issubset(_COMPACT_CORE_FIELDS):
			return topics, None
		fieldRecords.append(fields)
		if cooperate is not None:
			cooperate()
	defaults = _sharedDefaults(tuple(fieldRecords), _COMPACT_CORE_FIELDS, cooperate=cooperate)
	exceptions = _compactDefaultExceptions(
		tuple(
			dict(fields, id=cast(str, record["id"]))
			for record, fields in zip(plainRecords, fieldRecords, strict=True)
		),
		_COMPACT_CORE_FIELDS,
		defaults,
		cooperate=cooperate,
	)
	compactRecords: list[JsonObject] = []
	for record, compactFields in zip(plainRecords, exceptions, strict=True):
		record["fields"] = {
			name: value for name, value in _plainObject(compactFields).items() if name != "id"
		}
		compactRecords.append(_fromPlainObject(record))
		if cooperate is not None:
			cooperate()
	compactTopics = tuple(
		BundleTopicRecords("nodes", tuple(compactRecords)) if topic.topic == "nodes" else topic
		for topic in topics
	)
	return compactTopics, CompactDefaultsSchema("nodes", _COMPACT_CORE_FIELDS, defaults)


def _compactProviderDefaults(
	topics: tuple[BundleTopicRecords, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], tuple[CompactDefaultsSchema, ...]]:
	"""Compact repeated IA2/MSAA and overlay provider envelopes with ordered exceptions."""

	schemas: list[CompactDefaultsSchema] = []
	replacements: dict[str, tuple[JsonObject, ...]] = {}
	for topicName in ("ia2Msaa", "overlay"):
		topic = next((candidate for candidate in topics if candidate.topic == topicName), None)
		if topic is None or not topic.records:
			continue
		records = tuple(_plainObject(record) for record in topic.records)
		if not all(tuple(record) == ("id", *_STANDARD_UIA_FIELDS) for record in records):
			continue
		if any(not isinstance(record["id"], str) for record in records):
			raise ValueError(f"{topicName} record identifier must be text")
		defaults = _sharedDefaults(records, _STANDARD_UIA_FIELDS, cooperate=cooperate)
		replacements[topicName] = tuple(
			_compactDefaultExceptions(
				records,
				_STANDARD_UIA_FIELDS,
				defaults,
				cooperate=cooperate,
			),
		)
		schemas.append(CompactDefaultsSchema(topicName, _STANDARD_UIA_FIELDS, defaults))
	return (
		tuple(
			BundleTopicRecords(topic.topic, replacements[topic.topic])
			if topic.topic in replacements
			else topic
			for topic in topics
		),
		tuple(schemas),
	)


def _compactCustomUiaDefinitions(
	topics: tuple[BundleTopicRecords, ...],
	tables: CompactSharedTables,
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleTopicRecords, ...], CompactSharedTables]:
	"""Move configured Custom UIA definition pairs to one closed capture-wide table."""

	definitions: list[object] = []
	positions: dict[bytes, int] = {}

	def definitionReference(value: object) -> int | None:
		pair = _customUiaDefinitionPair(value)
		if pair is None:
			return None
		key = _canonicalCompactValue(pair)
		if key not in positions:
			positions[key] = len(definitions)
			definitions.append(pair)
		return positions[key]

	def compactRecord(record: JsonObject) -> JsonObject:
		plain = _plainObject(record)
		identity = plain.get("identity")
		if not isinstance(identity, dict):
			return record
		identityObject = cast("dict[str, object]", identity)
		values = identityObject.get("v")
		if not isinstance(values, list):
			return record
		datums = cast("list[object]", values)
		replaced = False
		compacted: list[object] = []
		for rawValue in datums:
			if not isinstance(rawValue, list):
				compacted.append(rawValue)
				continue
			rawDatum = cast("list[object]", rawValue)
			if not rawDatum or not isinstance(rawDatum[0], str):
				compacted.append(rawDatum)
				continue
			fieldId = rawDatum[0]
			if not fieldId.endswith(".definition"):
				compacted.append(rawDatum)
				continue
			if len(rawDatum) == 2 and isinstance(rawDatum[1], dict):
				envelope = cast("dict[str, object]", rawDatum[1])
				reference = definitionReference(envelope.get("v"))
				if reference is not None:
					replacedEnvelope = dict(envelope)
					replacedEnvelope["v"] = {"definitionRef": reference}
					compacted.append([fieldId, replacedEnvelope])
					replaced = True
					continue
			if len(rawDatum) == 5 and isinstance(rawDatum[2], list):
				valueMarker = cast("list[object]", rawDatum[2])
				if len(valueMarker) != 2 or valueMarker[0] != "value":
					compacted.append(rawDatum)
					continue
				reference = definitionReference(valueMarker[1])
				if reference is not None:
					replacedDatum = list(rawDatum)
					replacedDatum[2] = ["value", {"definitionRef": reference}]
					compacted.append(replacedDatum)
					replaced = True
					continue
			compacted.append(rawDatum)
		if not replaced:
			return record
		replacedIdentity = dict(identityObject)
		replacedIdentity["v"] = compacted
		replacedRecord = dict(plain)
		replacedRecord["identity"] = replacedIdentity
		return _fromPlainObject(replacedRecord)

	compactTopics: list[BundleTopicRecords] = []
	for topic in topics:
		if topic.topic != "customUia":
			compactTopics.append(topic)
			continue
		records: list[JsonObject] = []
		for record in topic.records:
			records.append(compactRecord(record))
			if cooperate is not None:
				cooperate()
		compactTopics.append(BundleTopicRecords(topic.topic, tuple(records)))
	return tuple(compactTopics), replace(tables, customUiaDefinitions=tuple(definitions))


@dataclass(frozen=True, slots=True)
class BundlePackage:
	"""A prepared bundle: the index bytes, ordered topic files, and optional image."""

	index: BundleIndex
	indexBytes: bytes
	topicFiles: tuple[tuple[str, str, bytes], ...]
	screenshotImage: bytes | None

	def artifacts(self) -> tuple[tuple[str, bytes], ...]:
		items: list[tuple[str, bytes]] = [(INDEX_FILENAME, self.indexBytes)]
		for _topic, filename, payload in self.topicFiles:
			items.append((filename, payload))
		if self.screenshotImage is not None:
			items.append((SCREENSHOT_IMAGE_FILENAME, self.screenshotImage))
		return tuple(items)

	@property
	def indexByteLength(self) -> int:
		return len(self.indexBytes)

	@property
	def nodesByteLength(self) -> int:
		for topic, _filename, payload in self.topicFiles:
			if topic == "nodes":
				return len(payload)
		return 0

	@property
	def nonImageByteLength(self) -> int:
		return len(self.indexBytes) + sum(len(payload) for _topic, _filename, payload in self.topicFiles)


@dataclass(frozen=True, slots=True)
class BundleAdmissionLimits:
	"""Hard structural ceilings enforced while admitting an untrusted bundle.

	``maximumNodes`` counts distinct core-node records, not their repeated records in
	other node-keyed topic files.
	"""

	indexMaximumBytes: int = INDEX_HARD_BYTES
	maximumBytes: int = COMPLETE_HARD_BYTES
	maximumDepth: int = 64
	maximumNodes: int = 500_000
	maximumStringScalars: int = 1_000_000
	maximumCollectionItems: int = 500_000


DEFAULT_BUNDLE_LIMITS: Final = BundleAdmissionLimits()
LOCAL_SELECTED_BUNDLE_LIMITS: Final = replace(
	DEFAULT_BUNDLE_LIMITS,
	maximumBytes=64 * 1024 * 1024,
	# The confirmed 64 MiB retry must also admit the nested JSON and text carried by a
	# bundle of that size. The normal limits stay unchanged for every other open.
	maximumStringScalars=4_000_000,
	maximumCollectionItems=4_000_000,
)


class BundleAdmissionLimitExceeded(ValueError):
	"""A bundle exceeded the selected decoded-byte admission ceiling."""

	def __init__(self, *, maximumBytes: int) -> None:
		super().__init__("bundle exceeds the permitted total byte length")
		self.maximumBytes = maximumBytes


@dataclass(frozen=True, slots=True)
class _FilesystemIdentity:
	device: int
	inode: int


def _emptyArtifactIdentities() -> dict[str, _FilesystemIdentity]:
	return {}


def _emptyArtifactContents() -> dict[str, bytes]:
	return {}


def _emptyCoreChildren() -> dict[str, tuple[str, ...]]:
	return {}


@dataclass(frozen=True, slots=True)
class BundleAdmission:
	"""The result of admitting a committed bundle directory."""

	index: BundleIndex
	sourceGeneration: int
	offsets: Mapping[str, Mapping[str, tuple[int, int]]]
	totalByteLength: int
	directoryIdentity: _FilesystemIdentity | None = None
	artifactIdentities: Mapping[str, _FilesystemIdentity] = dataclassField(
		default_factory=_emptyArtifactIdentities,
		repr=False,
	)
	artifactContents: dict[str, bytes] = dataclassField(default_factory=_emptyArtifactContents, repr=False)
	coreChildren: Mapping[str, tuple[str, ...]] = dataclassField(
		default_factory=_emptyCoreChildren,
		repr=False,
	)

	def nodeIds(self) -> tuple[str, ...]:
		seen: dict[str, None] = {}
		for topic in NODE_TOPICS:
			for nodeId in self.offsets.get(topic, {}):
				seen[nodeId] = None
		return tuple(sorted(seen, key=_localIdOrder))

	def topicsForNode(self, nodeId: str) -> tuple[str, ...]:
		return tuple(topic for topic in NODE_TOPICS if nodeId in self.offsets.get(topic, {}))


@dataclass(frozen=True, slots=True)
class SelectedNodeProjection:
	"""One node joined across topic files by seeking recorded offsets."""

	nodeId: str
	sourceGeneration: int
	records: tuple[tuple[str, Mapping[str, object]], ...]

	def toJsonBytes(self) -> bytes:
		topics = {topic: dict(record) for topic, record in self.records}
		return _encodeCompact({"id": self.nodeId, "topics": topics})

	def toText(self) -> str:
		lines = [f"Node {self.nodeId}"]
		for topic, record in self.records:
			lines.append(f"Topic {topic}")
			for key, value in record.items():
				lines.append(f"  {key}: {_scalarText(value)}")
		return "\n".join(lines) + "\n"

	def toMarkdown(self) -> str:
		lines = [f"# Node {self.nodeId}"]
		for topic, record in self.records:
			lines.append(f"## {topic}")
			for key, value in record.items():
				lines.append(f"- {key}: {_scalarText(value)}")
		return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class SelectedSubtreeProjection:
	"""A portable, privacy-safe bundle containing one selected node and its descendants."""

	nodeId: str
	sourceGeneration: int
	package: BundlePackage

	def toJsonBytes(self) -> bytes:
		"""Return the complete portable bundle as one JSON clipboard document."""

		topics: dict[str, list[object]] = {}
		for topic, _filename, payload in self.package.topicFiles:
			topics[topic] = [
				_loadStrictJson(line, f"{topic} topic line") for line in payload.splitlines() if line
			]
		return _encodeCompact(
			{
				"format": "keystone-inspector-subtree-v1",
				"index": _loadStrictJson(self.package.indexBytes, "bundle index"),
				"topics": topics,
			},
		)


def _scalarText(value: object) -> str:
	if isinstance(value, str):
		return value
	return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _coreOutline(
	records: tuple[JsonObject, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[tuple[BundleNode, ...], bool]:
	ordered = sorted(records, key=lambda record: _localIdOrder(_requireStringField(record, "id")))
	outline: list[BundleNode] = []
	for record in ordered[:OUTLINE_LIMIT]:
		parent = _objectField(record, "parent")
		if parent is not None and not isinstance(parent, str):
			raise ValueError("core node parent must be a local identifier or null")
		depth = _objectField(record, "depth")
		childCount = _objectField(record, "childCount")
		role = _objectField(record, "role")
		name = _objectField(record, "name")
		outline.append(
			BundleNode(
				id=_requireStringField(record, "id"),
				parent=parent,
				depth=depth if isinstance(depth, int) else 0,
				childCount=childCount if isinstance(childCount, int) else 0,
				role=role if isinstance(role, str) else "",
				name=name if isinstance(name, str) else "",
			),
		)
		if cooperate is not None:
			cooperate()
	return tuple(outline), len(ordered) > OUTLINE_LIMIT


def _serializeNodeTopic(
	records: tuple[JsonObject, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[bytes, int]:
	ordered = sorted(records, key=lambda record: _localIdOrder(_requireStringField(record, "id")))
	seen: set[str] = set()
	lines: list[str] = []
	for record in ordered:
		nodeId = _requireStringField(record, "id")
		if nodeId in seen:
			raise ValueError("node topic contains a duplicate local identifier")
		seen.add(nodeId)
		lines.append(_encodeLine(record))
		if cooperate is not None:
			cooperate()
	return ("\n".join(lines) + "\n").encode("utf-8"), len(ordered)


def _serializeDocumentTopic(
	records: tuple[JsonObject, ...],
	*,
	cooperate: Callable[[], None] | None = None,
) -> tuple[bytes, int]:
	lines: list[str] = []
	for record in records:
		lines.append(_encodeLine(record))
		if cooperate is not None:
			cooperate()
	return ("\n".join(lines) + "\n").encode("utf-8"), len(records)


def prepareBundle(
	source: BundleSource,
	*,
	cooperate: Callable[[], None] | None = None,
) -> BundlePackage:
	"""Serialise a privacy-transformed capture into a deterministic bundle."""

	if source.snapshotKind not in SNAPSHOT_KINDS:
		raise ValueError("bundle snapshot kind is not supported")
	topics = _compactCoreFlags(source.topics, cooperate=cooperate)
	topics, providerDefaults = _compactGenericDefaults(topics, cooperate=cooperate)
	topics, uiaSchema, uiaDefaults = _compactStandardUia(topics, cooperate=cooperate)
	topics, sharedTables, uiaDefaults = _compactEvidenceValues(
		topics,
		providerDefaults,
		uiaDefaults,
		cooperate=cooperate,
	)
	topics, coreDefaults = _compactCoreFields(topics, cooperate=cooperate)
	topics, providerDefaultSchemas = _compactProviderDefaults(topics, cooperate=cooperate)
	topics, sharedTables = _compactCustomUiaDefinitions(topics, sharedTables, cooperate=cooperate)
	present = {records.topic: records.records for records in topics}
	if len(present) != len(topics):
		raise ValueError("bundle source declares a topic more than once")
	coreRecords = present.get("nodes", ())
	nodeCount = len(coreRecords)
	outline, outlineTruncated = _coreOutline(coreRecords, cooperate=cooperate)

	topicFiles: list[tuple[str, str, bytes]] = []
	catalog: list[BundleCatalogEntry] = []
	for topic in BUNDLE_TOPIC_ORDER:
		records = present.get(topic)
		if not records:
			continue
		if topic in NODE_TOPICS:
			payload, count = _serializeNodeTopic(records, cooperate=cooperate)
		else:
			payload, count = _serializeDocumentTopic(records, cooperate=cooperate)
		filename = TOPIC_FILENAMES[topic]
		topicFiles.append((topic, filename, payload))
		catalog.append(
			BundleCatalogEntry(
				topic=topic,
				filename=filename,
				recordCount=count,
				byteLength=len(payload),
				sha256=hashlib.sha256(payload).hexdigest(),
			),
		)

	index = BundleIndex(
		formatMajor=BUNDLE_FORMAT_MAJOR,
		formatMinor=BUNDLE_FORMAT_MINOR,
		snapshotKind=source.snapshotKind,
		generatedAt=source.generatedAt,
		redactionEnabled=source.redactionEnabled,
		policyRevision=source.policyRevision,
		settingsRevision=source.settingsRevision,
		executable=source.executable,
		processId=source.processId,
		rootIds=source.rootIds,
		nodeCount=nodeCount,
		outline=outline,
		outlineTruncated=outlineTruncated,
		catalog=tuple(catalog),
		sharedTables=sharedTables,
		uiaSchema=uiaSchema,
		uiaDefaults=uiaDefaults,
		compactDefaults=tuple(
			schema for schema in (coreDefaults, *providerDefaultSchemas) if schema is not None
		),
	)
	return BundlePackage(
		index=index,
		indexBytes=index.encode(),
		topicFiles=tuple(topicFiles),
		screenshotImage=source.screenshotImage,
	)


def _rejectDuplicateKeys(pairs: list[tuple[str, object]]) -> dict[str, object]:
	result: dict[str, object] = {}
	for key, value in pairs:
		if key in result:
			raise ValueError("duplicate object key is not permitted")
		result[key] = value
	return result


def _rejectNonFiniteConstant(_token: str) -> object:
	raise ValueError("non-finite numbers are not permitted")


def _checkFiniteFloat(token: str) -> float:
	number = float(token)
	if not math.isfinite(number):
		raise ValueError("non-finite numbers are not permitted")
	return number


def _checkJsonNesting(data: bytes, what: str, maximumDepth: int) -> None:
	"""Bound JSON nesting before handing untrusted bytes to Python's recursive decoder."""

	depth = 0
	inString = False
	escaped = False
	for byte in data:
		if inString:
			if escaped:
				escaped = False
			elif byte == ord("\\"):
				escaped = True
			elif byte == ord('"'):
				inString = False
			continue
		if byte == ord('"'):
			inString = True
		elif byte in (ord("{"), ord("[")):
			depth += 1
			if depth > maximumDepth:
				raise ValueError(f"{what} exceeds the permitted structural depth")
		elif byte in (ord("}"), ord("]")):
			depth -= 1


def _loadStrictJson(
	data: bytes,
	what: str,
	*,
	maximumDepth: int = DEFAULT_BUNDLE_LIMITS.maximumDepth,
) -> object:
	if data.startswith(b"\xef\xbb\xbf"):
		raise ValueError(f"{what} must not begin with a byte-order mark")
	_checkJsonNesting(data, what, maximumDepth)
	try:
		text = data.decode("utf-8")
	except UnicodeDecodeError as error:
		raise ValueError(f"{what} must be strict UTF-8") from error
	try:
		return json.loads(
			text,
			object_pairs_hook=_rejectDuplicateKeys,
			parse_constant=_rejectNonFiniteConstant,
			parse_float=_checkFiniteFloat,
		)
	except (json.JSONDecodeError, RecursionError) as error:
		raise ValueError(f"{what} is not well-formed JSON") from error


def _requireObject(value: object, what: str) -> dict[str, object]:
	if not isinstance(value, dict):
		raise ValueError(f"{what} must be a JSON object")
	return cast("dict[str, object]", value)


def _closedObject(value: object, what: str, keys: tuple[str, ...]) -> dict[str, object]:
	obj = _requireObject(value, what)
	if tuple(obj) != keys:
		raise ValueError(f"{what} fields are not the exact expected closed set in order")
	return obj


def _expectInt(value: object, what: str) -> int:
	if type(value) is not int:
		raise ValueError(f"{what} must be an integer")
	return value


def _expectString(value: object, what: str) -> str:
	if not isinstance(value, str):
		raise ValueError(f"{what} must be a string")
	return value


def _expectBool(value: object, what: str) -> bool:
	if type(value) is not bool:
		raise ValueError(f"{what} must be a boolean")
	return value


_INDEX_KEYS_1_0: Final[tuple[str, ...]] = (
	"formatMajor",
	"formatMinor",
	"snapshotKind",
	"generatedAt",
	"redactionEnabled",
	"policyRevision",
	"settingsRevision",
	"executable",
	"processId",
	"rootIds",
	"nodeCount",
	"outline",
	"outlineTruncated",
	"catalog",
	"sharedTables",
	"uiaSchema",
	"uiaDefaults",
)
_INDEX_KEYS_1_1: Final[tuple[str, ...]] = (*_INDEX_KEYS_1_0, "compactDefaults")
_OUTLINE_KEYS: Final[tuple[str, ...]] = ("id", "parent", "depth", "childCount", "role", "name")
_CATALOG_KEYS: Final[tuple[str, ...]] = ("topic", "filename", "recordCount", "byteLength", "sha256")
_COMPACT_DEFAULT_SCHEMA_KEYS: Final[tuple[str, ...]] = ("topic", "columns", "defaults")
_SHARED_TABLE_KEYS: Final[tuple[str, ...]] = (
	"processIds",
	"windowHandles",
	"classHierarchies",
	"customUiaDefinitions",
	"providerDefaults",
	"sources",
	"projections",
	"privacy",
	"provenance",
)


def _parseOutlineNode(value: object) -> BundleNode:
	obj = _closedObject(value, "outline node", _OUTLINE_KEYS)
	parent = obj["parent"]
	if parent is not None and not isinstance(parent, str):
		raise ValueError("outline node parent must be a local identifier or null")
	return BundleNode(
		id=_expectString(obj["id"], "outline node id"),
		parent=parent,
		depth=_expectInt(obj["depth"], "outline node depth"),
		childCount=_expectInt(obj["childCount"], "outline node child count"),
		role=_expectString(obj["role"], "outline node role"),
		name=_expectString(obj["name"], "outline node name"),
	)


def _parseCatalogEntry(value: object) -> BundleCatalogEntry:
	obj = _closedObject(value, "catalog entry", _CATALOG_KEYS)
	return BundleCatalogEntry(
		topic=_expectString(obj["topic"], "catalog topic"),
		filename=_expectString(obj["filename"], "catalog filename"),
		recordCount=_expectInt(obj["recordCount"], "catalog record count"),
		byteLength=_expectInt(obj["byteLength"], "catalog byte length"),
		sha256=_expectString(obj["sha256"], "catalog hash"),
	)


def _parseSharedTables(value: object) -> CompactSharedTables:
	obj = _closedObject(value, "compact shared tables", _SHARED_TABLE_KEYS)

	def items(name: str) -> list[object]:
		raw = obj[name]
		if not isinstance(raw, list):
			raise ValueError(f"compact shared table {name!r} must be an array")
		return cast("list[object]", raw)

	classHierarchies: list[tuple[str, ...]] = []
	for rawHierarchy in items("classHierarchies"):
		if not isinstance(rawHierarchy, list):
			raise ValueError("compact class hierarchy must be an array")
		hierarchy = cast("list[object]", rawHierarchy)
		classHierarchies.append(
			tuple(_expectString(item, "compact class hierarchy item") for item in hierarchy),
		)
	return CompactSharedTables(
		processIds=tuple(_expectInt(item, "compact process identifier") for item in items("processIds")),
		windowHandles=tuple(_expectInt(item, "compact window handle") for item in items("windowHandles")),
		classHierarchies=tuple(classHierarchies),
		customUiaDefinitions=tuple(items("customUiaDefinitions")),
		providerDefaults=tuple(items("providerDefaults")),
		sources=tuple(items("sources")),
		projections=tuple(items("projections")),
		privacy=tuple(items("privacy")),
		provenance=tuple(items("provenance")),
	)


def _parseUiaSchema(value: object) -> CompactUiaSchema:
	if not isinstance(value, list):
		raise ValueError("compact UIA schema must be an array")
	return CompactUiaSchema(
		tuple(_expectString(item, "compact UIA schema column") for item in cast("list[object]", value)),
	)


def _parseCompactDefaults(value: object) -> tuple[CompactDefaultsSchema, ...]:
	if not isinstance(value, list):
		raise ValueError("compact default schemas must be an array")
	schemas: list[CompactDefaultsSchema] = []
	for rawSchema in cast("list[object]", value):
		obj = _closedObject(rawSchema, "compact default schema", _COMPACT_DEFAULT_SCHEMA_KEYS)
		columnsRaw = obj["columns"]
		defaultsRaw = obj["defaults"]
		if not isinstance(columnsRaw, list) or not isinstance(defaultsRaw, list):
			raise ValueError("compact default schema columns and defaults must be arrays")
		schema = CompactDefaultsSchema(
			_expectString(obj["topic"], "compact default schema topic"),
			tuple(
				_expectString(item, "compact default schema column")
				for item in cast("list[object]", columnsRaw)
			),
			tuple(cast("list[object]", defaultsRaw)),
		)
		expected = _COMPACT_CORE_FIELDS if schema.topic == "nodes" else _STANDARD_UIA_FIELDS
		if schema.columns != expected:
			raise ValueError("compact default schema columns do not match the closed topic schema")
		schemas.append(schema)
	return tuple(schemas)


def parseIndex(
	data: bytes,
	*,
	limits: BundleAdmissionLimits = DEFAULT_BUNDLE_LIMITS,
	state: _BudgetState | None = None,
) -> BundleIndex:
	"""Parse and validate the closed ``index.json`` payload."""

	raw = _requireObject(
		_loadStrictJson(data, "bundle index", maximumDepth=limits.maximumDepth),
		"bundle index",
	)
	_accountValue(raw, 1, limits, _BudgetState() if state is None else state)
	formatMajor = _expectInt(raw.get("formatMajor"), "format major")
	formatMinor = _expectInt(raw.get("formatMinor"), "format minor")
	if formatMajor != BUNDLE_FORMAT_MAJOR or formatMinor not in (0, BUNDLE_FORMAT_MINOR):
		raise ValueError("bundle format version is not supported")
	indexKeys = _INDEX_KEYS_1_0 if formatMinor == 0 else _INDEX_KEYS_1_1
	obj = _closedObject(raw, "bundle index", indexKeys)
	rootIdsValue = obj["rootIds"]
	if not isinstance(rootIdsValue, list):
		raise ValueError("bundle root identifiers must be a list")
	rootIds = tuple(_expectString(item, "root identifier") for item in cast("list[object]", rootIdsValue))
	outlineValue = obj["outline"]
	if not isinstance(outlineValue, list):
		raise ValueError("bundle outline must be a list")
	outline = tuple(_parseOutlineNode(item) for item in cast("list[object]", outlineValue))
	catalogValue = obj["catalog"]
	if not isinstance(catalogValue, list):
		raise ValueError("bundle catalog must be a list")
	catalog = tuple(_parseCatalogEntry(item) for item in cast("list[object]", catalogValue))
	uiaDefaultsValue = obj["uiaDefaults"]
	if not isinstance(uiaDefaultsValue, list):
		raise ValueError("compact UIA defaults must be an array")
	compactDefaults = () if formatMinor == 0 else _parseCompactDefaults(obj["compactDefaults"])
	index = BundleIndex(
		formatMajor=formatMajor,
		formatMinor=formatMinor,
		snapshotKind=_expectString(obj["snapshotKind"], "snapshot kind"),
		generatedAt=_expectString(obj["generatedAt"], "generated timestamp"),
		redactionEnabled=_expectBool(obj["redactionEnabled"], "redaction flag"),
		policyRevision=_expectInt(obj["policyRevision"], "policy revision"),
		settingsRevision=_expectInt(obj["settingsRevision"], "settings revision"),
		executable=_expectString(obj["executable"], "executable"),
		processId=_expectInt(obj["processId"], "process identifier"),
		rootIds=rootIds,
		nodeCount=_expectInt(obj["nodeCount"], "node count"),
		outline=outline,
		outlineTruncated=_expectBool(obj["outlineTruncated"], "outline truncated flag"),
		catalog=catalog,
		sharedTables=_parseSharedTables(obj["sharedTables"]),
		uiaSchema=_parseUiaSchema(obj["uiaSchema"]),
		uiaDefaults=tuple(cast("list[object]", uiaDefaultsValue)),
		compactDefaults=compactDefaults,
	)
	_validateCompactDefaults(index)
	return index


def _validateCompactUiaRecord(record: Mapping[str, object], index: BundleIndex) -> None:
	"""Reject malformed compact UIA references before any offline source is installed."""

	obj = _closedObject(record, "compact UIA record", _COMPACT_UIA_KEYS)
	_ = _expectString(obj["id"], "compact UIA record identifier")
	exceptions = obj["exceptions"]
	if not isinstance(exceptions, list):
		raise ValueError("compact UIA exceptions must be an array")
	lastColumn = -1
	for rawException in cast("list[object]", exceptions):
		if not isinstance(rawException, list):
			raise ValueError("compact UIA exception must be a [column, value] pair")
		exception = cast("list[object]", rawException)
		if len(exception) != 2:
			raise ValueError("compact UIA exception must be a [column, value] pair")
		column = _expectInt(exception[0], "compact UIA exception column")
		if column <= lastColumn:
			raise ValueError("compact UIA exception columns must be unique and ascending")
		if column < 0 or column >= len(index.uiaSchema.columns):
			raise ValueError("compact UIA exception column is outside the schema")
		if _compactValueKind(exception[1]) != _compactValueKind(index.uiaDefaults[column]):
			raise ValueError("compact UIA exception type is incompatible with its default")
		lastColumn = column


def _compactDefaultsForTopic(
	index: BundleIndex,
	topic: str,
) -> CompactDefaultsSchema | None:
	return next((schema for schema in index.compactDefaults if schema.topic == topic), None)


def _validateCompactDefaultValue(
	value: object,
	schema: CompactDefaultsSchema,
	index: BundleIndex,
) -> None:
	if _isCompactAbsent(value):
		if schema.topic != "nodes":
			raise ValueError("only compact core fields may use an absent marker")
		return
	if not isinstance(value, dict):
		raise ValueError("compact default value must be an evidence envelope or absent marker")
	record = cast("dict[str, object]", value)
	if "s" not in record:
		raise ValueError("compact default value must be an evidence envelope or absent marker")
	_validateCompactEvidenceReferences(record, index)


def _validateCompactDefaults(index: BundleIndex) -> None:
	"""Validate each schema default once while parsing the index."""

	for schema in index.compactDefaults:
		for value in schema.defaults:
			_validateCompactDefaultValue(value, schema, index)


def _validateCompactDefaultExceptions(
	record: Mapping[str, object],
	schema: CompactDefaultsSchema,
	index: BundleIndex,
	*,
	label: str,
) -> tuple[object, ...]:
	obj = _closedObject(record, f"compact {label} record", _COMPACT_UIA_KEYS)
	_ = _expectString(obj["id"], f"compact {label} record identifier")
	exceptions = obj["exceptions"]
	if not isinstance(exceptions, list):
		raise ValueError(f"compact {label} exceptions must be an array")
	values = list(schema.defaults)
	lastColumn = -1
	for rawException in cast("list[object]", exceptions):
		if not isinstance(rawException, list):
			raise ValueError(f"compact {label} exception must be a [column, value] pair")
		exception = cast("list[object]", rawException)
		if len(exception) != 2:
			raise ValueError(f"compact {label} exception must be a [column, value] pair")
		column = _expectInt(exception[0], f"compact {label} exception column")
		if column <= lastColumn or column < 0 or column >= len(schema.columns):
			raise ValueError(f"compact {label} exception columns must be unique and ascending")
		_validateCompactDefaultValue(exception[1], schema, index)
		values[column] = exception[1]
		lastColumn = column
	return tuple(values)


def _validateCompactCoreRecord(record: Mapping[str, object], index: BundleIndex) -> None:
	schema = _compactDefaultsForTopic(index, "nodes")
	if schema is None:
		return
	fields = _closedObject(_require(record, "fields"), "compact core fields", ("exceptions",))
	_ = _validateCompactDefaultExceptions(
		{"id": _require(record, "id"), "exceptions": fields["exceptions"]},
		schema,
		index,
		label="core fields",
	)


def _expandCompactDefaultRecord(
	record: Mapping[str, object],
	index: BundleIndex,
	topic: str,
) -> dict[str, object]:
	schema = _compactDefaultsForTopic(index, topic)
	if schema is None:
		return dict(record)
	values = _validateCompactDefaultExceptions(record, schema, index, label=topic)
	expanded: dict[str, object] = {
		"id": _expectString(record["id"], f"compact {topic} record identifier"),
	}
	for column, value in zip(schema.columns, values, strict=True):
		if not _isCompactAbsent(value):
			expanded[column] = value
	return expanded


def _expandCompactCoreRecord(record: Mapping[str, object], index: BundleIndex) -> dict[str, object]:
	schema = _compactDefaultsForTopic(index, "nodes")
	if schema is None:
		return dict(record)
	_validateCompactCoreRecord(record, index)
	fields = _closedObject(_require(record, "fields"), "compact core fields", ("exceptions",))
	expandedFields = _expandCompactDefaultRecord(
		{"id": _require(record, "id"), "exceptions": fields["exceptions"]},
		index,
		"nodes",
	)
	expanded = dict(record)
	expanded["fields"] = {name: value for name, value in expandedFields.items() if name != "id"}
	return expanded


def _compactGenericDefault(record: Mapping[str, object], index: BundleIndex) -> object | None:
	if "genericRef" not in record:
		return None
	if "generic" in record:
		raise ValueError("core node cannot carry both a generic section and a generic reference")
	reference = _expectInt(record["genericRef"], "generic provider reference")
	if reference < 0 or reference >= len(index.sharedTables.providerDefaults):
		raise ValueError("generic provider reference is outside the shared table")
	value = index.sharedTables.providerDefaults[reference]
	if not isinstance(value, dict):
		raise ValueError("generic provider reference does not resolve to a provider section")
	section = cast("dict[str, object]", value)
	if tuple(section) != _STANDARD_UIA_FIELDS:
		raise ValueError("generic provider reference does not resolve to a provider section")
	return section


def _compactTableReference(
	values: tuple[object, ...],
	reference: object,
	label: str,
) -> object:
	position = _expectInt(reference, f"compact {label} reference")
	if position < 0 or position >= len(values):
		raise ValueError(f"compact {label} reference is outside the shared table")
	value = values[position]
	if not isinstance(value, dict):
		raise ValueError(f"compact {label} reference does not resolve to an object")
	return cast("dict[str, object]", value)


def _validateCompactEvidenceReferences(value: object, index: BundleIndex) -> None:
	"""Validate every compact evidence reference before offline data reaches a reader."""

	pending = [value]
	while pending:
		current = pending.pop()
		if isinstance(current, dict):
			record = cast("dict[str, object]", current)
			if "s" in record:
				if not _COMPACT_EVIDENCE_REQUIRED.issubset(record) or not set(record).issubset(
					_COMPACT_EVIDENCE_KEYS,
				):
					raise ValueError("compact evidence record has an invalid field set")
				_ = _expectString(record["s"], "compact evidence status")
				_ = _expectString(record["c"], "compact evidence confidence")
				_ = _compactTableReference(index.sharedTables.sources, record["o"], "source")
				_ = _compactTableReference(index.sharedTables.projections, record["j"], "projection")
				_ = _compactTableReference(index.sharedTables.privacy, record["p"], "privacy")
				if "e" in record:
					_ = _compactTableReference(index.sharedTables.provenance, record["e"], "provenance")
				pending.extend(record[field] for field in ("v", "t", "q") if field in record)
				continue
			pending.extend(record.values())
		elif isinstance(current, list):
			pending.extend(cast("list[object]", current))


def _expandCompactEvidence(value: object, index: BundleIndex) -> object:
	"""Restore compact evidence envelopes to the typed document-record wire shape."""

	if isinstance(value, dict):
		record = cast("dict[str, object]", value)
		if "s" in record:
			_validateCompactEvidenceReferences(record, index)
			expanded: dict[str, object] = {
				"status": record["s"],
				"source": _compactTableReference(index.sharedTables.sources, record["o"], "source"),
				"projection": _compactTableReference(
					index.sharedTables.projections,
					record["j"],
					"projection",
				),
				"confidence": record["c"],
				"privacy": _compactTableReference(index.sharedTables.privacy, record["p"], "privacy"),
			}
			if "v" in record:
				expanded["value"] = _expandCompactEvidence(record["v"], index)
			if "t" in record:
				expanded["truncation"] = _expandCompactEvidence(record["t"], index)
			if "e" in record:
				expanded["errorRef"] = _compactTableReference(
					index.sharedTables.provenance,
					record["e"],
					"provenance",
				)
			if "a" in record:
				expanded["observedAt"] = record["a"]
			if "q" in record:
				expanded["scope"] = _expandCompactEvidence(record["q"], index)
			return expanded
		return {key: _expandCompactEvidence(item, index) for key, item in record.items()}
	if isinstance(value, list):
		return [_expandCompactEvidence(item, index) for item in cast("list[object]", value)]
	return value


def _expandCustomUiaDefinitionReferences(value: object, index: BundleIndex) -> object:
	"""Restore tabled definition pairs before typed provider reconstruction or selected export."""
	if isinstance(value, dict):
		record = cast("dict[str, object]", value)
		if set(record) == {"definitionRef"}:
			reference = _expectInt(record["definitionRef"], "Custom UIA definition reference")
			if reference < 0 or reference >= len(index.sharedTables.customUiaDefinitions):
				raise ValueError("Custom UIA definition reference is outside the shared table")
			definition = index.sharedTables.customUiaDefinitions[reference]
			pair = _customUiaDefinitionPair(definition)
			if pair is None:
				raise ValueError("Custom UIA definition reference does not resolve to a definition pair")
			return list(pair)
		return {key: _expandCustomUiaDefinitionReferences(item, index) for key, item in record.items()}
	if isinstance(value, list):
		return [_expandCustomUiaDefinitionReferences(item, index) for item in cast("list[object]", value)]
	return value


def _expandCompactUiaRecord(record: Mapping[str, object], index: BundleIndex) -> dict[str, object]:
	_validateCompactUiaRecord(record, index)
	expanded: dict[str, object] = {
		"id": _expectString(record["id"], "compact UIA record identifier"),
	}
	for column, default in zip(index.uiaSchema.columns, index.uiaDefaults, strict=True):
		expanded[column] = default
	for rawException in cast("list[object]", record["exceptions"]):
		exception = cast("list[object]", rawException)
		expanded[index.uiaSchema.columns[cast(int, exception[0])]] = exception[1]
	return expanded


def _validateBundleRecord(
	record: Mapping[str, object],
	entry: BundleCatalogEntry,
	index: BundleIndex,
) -> None:
	if entry.topic == "nodes":
		_ = _compactGenericDefault(record, index)
		_validateCompactCoreRecord(record, index)
	elif entry.topic == "uia" and index.uiaSchema.columns:
		_validateCompactUiaRecord(record, index)
	elif entry.topic == "uia" and "exceptions" in record:
		raise ValueError("compact UIA records require a compact UIA schema")
	elif _compactDefaultsForTopic(index, entry.topic) is not None:
		_ = _validateCompactDefaultExceptions(
			record,
			cast(CompactDefaultsSchema, _compactDefaultsForTopic(index, entry.topic)),
			index,
			label=entry.topic,
		)
	_validateCompactEvidenceReferences(record, index)
	if entry.topic == "customUia":
		_validateCustomUiaDefinitionReferences(record, index)


def _validateCustomUiaDefinitionReferences(record: Mapping[str, object], index: BundleIndex) -> None:
	"""Reject every untrusted Custom UIA definition reference during admission."""

	pending: list[object] = [record]
	while pending:
		value = pending.pop()
		if isinstance(value, dict):
			obj = cast("dict[str, object]", value)
			if set(obj) == {"definitionRef"}:
				reference = _expectInt(obj["definitionRef"], "Custom UIA definition reference")
				if reference < 0 or reference >= len(index.sharedTables.customUiaDefinitions):
					raise ValueError("Custom UIA definition reference is outside the shared table")
				continue
			pending.extend(obj.values())
		elif isinstance(value, list):
			pending.extend(cast("list[object]", value))


@dataclass
class _BudgetState:
	byteTotal: int = 0
	nodeTotal: int = 0
	stringTotal: int = 0
	collectionTotal: int = 0


@dataclass(frozen=True, slots=True)
class _CoreNodeStructure:
	parent: str | None
	depth: int
	children: tuple[str, ...] | None
	childCount: int
	indexInParent: int | None


def _coreNodeStructure(record: Mapping[str, object], index: BundleIndex) -> _CoreNodeStructure:
	"""Extract the core-tree facts that must agree across admitted topic records."""

	expanded = _expandCompactCoreRecord(record, index)
	parentValue = _require(expanded, "parent")
	if parentValue is not None and not isinstance(parentValue, str):
		raise ValueError("core node parent must be a local identifier or null")
	parent = parentValue
	if parent is not None:
		_ = _localIdOrder(parent)
	depth = _expectInt(_require(expanded, "depth"), "core node depth")
	if depth < 0:
		raise ValueError("core node depth must be nonnegative")
	childCount = _expectInt(_require(expanded, "childCount"), "core node child count")
	if childCount < 0:
		raise ValueError("core node child count must be nonnegative")
	children: tuple[str, ...] | None = None
	if "children" in expanded:
		childrenValue = expanded["children"]
		if not isinstance(childrenValue, list):
			raise ValueError("core node children must be an array")
		children = tuple(
			_expectString(child, "core node child identifier")
			for child in cast("list[object]", childrenValue)
		)
		for child in children:
			_ = _localIdOrder(child)
		if len(set(children)) != len(children):
			raise ValueError("core node children must be unique")
		if childCount != len(children):
			raise ValueError("core node child count must match its children")
	indexInParent: int | None = None
	if "indexInParent" in expanded:
		indexInParent = _expectInt(expanded["indexInParent"], "core node index in parent")
		if indexInParent < 0:
			raise ValueError("core node index in parent must be nonnegative")
	return _CoreNodeStructure(parent, depth, children, childCount, indexInParent)


def _validateBundleStructure(
	index: BundleIndex,
	coreNodes: Mapping[str, _CoreNodeStructure],
	offsets: Mapping[str, Mapping[str, tuple[int, int]]],
) -> dict[str, tuple[str, ...]]:
	"""Require the admitted node topics to describe one internally consistent forest."""

	if len(coreNodes) != index.nodeCount:
		raise ValueError("bundle node count does not match the core node topic")
	coreIds = set(coreNodes)
	rootIds = set(index.rootIds)
	if not rootIds <= coreIds:
		raise ValueError("bundle roots must resolve to core node records")
	parentClaims: dict[str, str] = {}
	childrenClaimedByParent: dict[str, list[str]] = {nodeId: [] for nodeId in coreNodes}
	for nodeId, node in coreNodes.items():
		if node.parent is not None:
			if node.parent not in coreIds:
				raise ValueError("core node parent does not resolve to a core node record")
			childrenClaimedByParent[node.parent].append(nodeId)
	for parentId, node in coreNodes.items():
		for position, childId in enumerate(node.children or ()):
			if childId not in coreIds:
				raise ValueError("core node child does not resolve to a core node record")
			if childId in parentClaims:
				raise ValueError("core node child has multiple structural parents")
			parentClaims[childId] = parentId
			child = coreNodes[childId]
			if child.indexInParent is not None and child.indexInParent != position:
				raise ValueError("core node index in parent does not match child order")
	for nodeId, node in coreNodes.items():
		claimedParent = parentClaims.get(nodeId)
		if claimedParent is not None and node.parent != claimedParent:
			raise ValueError("core node parent and children do not agree")
		if node.parent is not None:
			parentChildren = coreNodes[node.parent].children
			if parentChildren is not None and nodeId not in parentChildren:
				raise ValueError("core node parent and children do not agree")
	for nodeId, node in coreNodes.items():
		if node.children is None and node.childCount != len(childrenClaimedByParent[nodeId]):
			raise ValueError("core node child count does not match parent claims")
	unvisited = set(coreNodes)
	while unvisited:
		currentId = next(iter(unvisited))
		path: set[str] = set()
		while currentId in unvisited:
			if currentId in path:
				raise ValueError("core node structure contains a cycle")
			path.add(currentId)
			parent = coreNodes[currentId].parent
			if parent is None:
				break
			currentId = parent
		unvisited.difference_update(path)
	if rootIds != {nodeId for nodeId, node in coreNodes.items() if node.parent is None}:
		raise ValueError("bundle roots must exactly identify parentless core nodes")
	for topic, topicOffsets in offsets.items():
		if topic != "nodes" and not set(topicOffsets) <= coreIds:
			raise ValueError("node topic identifier does not resolve to a core node record")
	childrenByNode: dict[str, tuple[str, ...]] = {}
	for nodeId, node in coreNodes.items():
		if node.children is not None:
			childrenByNode[nodeId] = node.children
			continue
		children = tuple(
			sorted(
				childrenClaimedByParent[nodeId],
				key=lambda childId: (
					coreNodes[childId].indexInParent is None,
					coreNodes[childId].indexInParent,
					_localIdOrder(childId),
				),
			),
		)
		for position, childId in enumerate(children):
			childIndex = coreNodes[childId].indexInParent
			if childIndex is not None and childIndex != position:
				raise ValueError("core node index in parent does not match child order")
		childrenByNode[nodeId] = children
	return childrenByNode


def _accountValue(value: object, depth: int, limits: BundleAdmissionLimits, state: _BudgetState) -> None:
	pending = [(value, depth)]
	while pending:
		current, currentDepth = pending.pop()
		if currentDepth > limits.maximumDepth:
			raise ValueError("bundle record exceeds the permitted structural depth")
		if isinstance(current, str):
			state.stringTotal += 1
			if state.stringTotal > limits.maximumStringScalars:
				raise ValueError("bundle exceeds the permitted number of string scalars")
		elif isinstance(current, dict):
			entries = cast("dict[str, object]", current)
			state.collectionTotal += len(entries)
			if state.collectionTotal > limits.maximumCollectionItems:
				raise ValueError("bundle exceeds the permitted number of collection items")
			pending.extend((item, currentDepth + 1) for item in entries.values())
		elif isinstance(current, list):
			items = cast("list[object]", current)
			state.collectionTotal += len(items)
			if state.collectionTotal > limits.maximumCollectionItems:
				raise ValueError("bundle exceeds the permitted number of collection items")
			pending.extend((item, currentDepth + 1) for item in items)


def _ordinaryDirectoryInfo(info: os.stat_result) -> bool:
	return stat.S_ISDIR(info.st_mode) and not bool(
		getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE,
	)


def _ordinaryDirectory(path: Path) -> bool:
	try:
		info = path.lstat()
	except OSError:
		return False
	return _ordinaryDirectoryInfo(info)


def _ordinaryFileInfo(info: os.stat_result) -> bool:
	return stat.S_ISREG(info.st_mode) and not bool(
		getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE,
	)


def _ordinaryFile(path: Path) -> bool:
	try:
		info = path.lstat()
	except OSError:
		return False
	return _ordinaryFileInfo(info)


def _filesystemIdentity(info: os.stat_result) -> _FilesystemIdentity:
	return _FilesystemIdentity(info.st_dev, info.st_ino)


def _pathIdentity(path: Path, *, directory: bool) -> _FilesystemIdentity:
	try:
		info = path.lstat()
	except OSError as error:
		raise ValueError("bundle path is missing or inaccessible") from error
	ordinary = _ordinaryDirectoryInfo(info) if directory else _ordinaryFileInfo(info)
	if not ordinary:
		kind = "directory" if directory else "artifact"
		raise ValueError(f"bundle {kind} is not an ordinary file system entry")
	return _filesystemIdentity(info)


def _streamTopicFile(
	path: Path,
	entry: BundleCatalogEntry,
	index: BundleIndex,
	limits: BundleAdmissionLimits,
	state: _BudgetState,
) -> tuple[dict[str, tuple[int, int]], _FilesystemIdentity, dict[str, _CoreNodeStructure]]:
	digest = hashlib.sha256()
	offsets: dict[str, tuple[int, int]] = {}
	coreNodes: dict[str, _CoreNodeStructure] = {}
	offset = 0
	lineCount = 0
	lastOrder = -1
	try:
		with path.open("rb") as stream:
			info = os.fstat(stream.fileno())
			if not _ordinaryFileInfo(info):
				raise ValueError("bundle topic is not an ordinary file")
			identity = _filesystemIdentity(info)
			if state.byteTotal + info.st_size > limits.maximumBytes:
				raise BundleAdmissionLimitExceeded(maximumBytes=limits.maximumBytes)
			if info.st_size != entry.byteLength:
				raise ValueError("cataloged byte length does not match the topic file")
			while offset < entry.byteLength:
				remaining = entry.byteLength - offset
				rawLine = stream.readline(remaining)
				if not rawLine:
					break
				digest.update(rawLine)
				length = len(rawLine)
				state.byteTotal += length
				if state.byteTotal > limits.maximumBytes:
					raise BundleAdmissionLimitExceeded(maximumBytes=limits.maximumBytes)
				if not rawLine.endswith(b"\n"):
					raise ValueError("bundle topic line is not newline terminated")
				payload = _loadStrictJson(
					rawLine[:-1],
					"bundle topic line",
					maximumDepth=limits.maximumDepth,
				)
				record = _requireObject(payload, "bundle topic record")
				_accountValue(record, 1, limits, state)
				if entry.nodeKeyed:
					nodeId = record.get("id")
					if not isinstance(nodeId, str):
						raise ValueError("node topic line is missing a string local identifier")
					order = _localIdOrder(nodeId)
					if order <= lastOrder:
						raise ValueError("node topic lines are not in ascending local-identifier order")
					lastOrder = order
					if nodeId in offsets:
						raise ValueError("node topic line repeats a local identifier")
					offsets[nodeId] = (offset, length)
					if entry.topic == "nodes":
						state.nodeTotal += 1
						if state.nodeTotal > limits.maximumNodes:
							raise ValueError("bundle exceeds the permitted number of nodes")
						coreNodes[nodeId] = _coreNodeStructure(record, index)
				_validateBundleRecord(record, entry, index)
				offset += length
				lineCount += 1
			finalInfo = os.fstat(stream.fileno())
			if _filesystemIdentity(finalInfo) != identity:
				raise ValueError("bundle topic identity changed while it was admitted")
			if finalInfo.st_size != entry.byteLength:
				raise ValueError("cataloged byte length does not match the topic file")
	except OSError as error:
		raise ValueError("bundle topic is missing or inaccessible") from error
	if _pathIdentity(path, directory=False) != identity:
		raise ValueError("bundle topic path changed while it was admitted")
	if lineCount != entry.recordCount:
		raise ValueError("cataloged record count does not match the topic file")
	if offset != entry.byteLength:
		raise ValueError("cataloged byte length does not match the topic file")
	if digest.hexdigest() != entry.sha256:
		raise ValueError("cataloged content hash does not match the topic file")
	if not entry.nodeKeyed and lineCount != 1:
		raise ValueError("document topic file must contain exactly one record")
	return offsets, identity, coreNodes


def _readAdmittedArtifact(
	admission: BundleAdmission,
	directory: Path,
	entry: BundleCatalogEntry,
) -> bytes:
	"""Read one cataloged artifact from its admitted file identity before exposing its bytes."""

	cached = admission.artifactContents.get(entry.filename)
	if cached is not None:
		return cached
	directory = Path(directory)
	directoryIdentity = admission.directoryIdentity
	if directoryIdentity is None:
		raise ValueError("admission has no directory identity")
	if _pathIdentity(directory, directory=True) != directoryIdentity:
		raise ValueError("bundle directory identity changed after admission")
	expected = admission.artifactIdentities.get(entry.filename)
	if expected is None:
		raise ValueError("admitted catalog entry has no file identity")
	path = directory / entry.filename
	try:
		with path.open("rb") as stream:
			info = os.fstat(stream.fileno())
			if not _ordinaryFileInfo(info) or _filesystemIdentity(info) != expected:
				raise ValueError("bundle artifact identity changed after admission")
			if info.st_size != entry.byteLength:
				raise ValueError("cataloged byte length does not match the admitted artifact")
			if _pathIdentity(path, directory=False) != expected:
				raise ValueError("bundle artifact path changed after admission")
			payload = stream.read(entry.byteLength)
			finalInfo = os.fstat(stream.fileno())
			if not _ordinaryFileInfo(finalInfo) or _filesystemIdentity(finalInfo) != expected:
				raise ValueError("bundle artifact identity changed while it was read")
			if finalInfo.st_size != entry.byteLength:
				raise ValueError("cataloged byte length does not match the admitted artifact")
	except OSError as error:
		raise ValueError("bundle artifact is missing or inaccessible") from error
	if _pathIdentity(directory, directory=True) != directoryIdentity:
		raise ValueError("bundle directory identity changed while an artifact was read")
	if _pathIdentity(path, directory=False) != expected:
		raise ValueError("bundle artifact path changed while it was read")
	if len(payload) != entry.byteLength:
		raise ValueError("cataloged byte length does not match the admitted artifact")
	if hashlib.sha256(payload).hexdigest() != entry.sha256:
		raise ValueError("cataloged content hash does not match the admitted artifact")
	admission.artifactContents[entry.filename] = payload
	return payload


def admitBundle(
	directory: Path,
	*,
	sourceGeneration: int,
	limits: BundleAdmissionLimits = DEFAULT_BUNDLE_LIMITS,
) -> BundleAdmission:
	"""Admit a committed bundle directory, streaming topics under one shared budget."""

	if sourceGeneration < 0:
		raise ValueError("source generation must be nonnegative")
	if not _ordinaryDirectory(directory):
		raise ValueError("bundle directory is not an ordinary directory")
	directoryIdentity = _pathIdentity(directory, directory=True)
	indexPath = directory / INDEX_FILENAME
	if not _ordinaryFile(indexPath):
		raise ValueError("bundle index is missing or is not an ordinary file")
	try:
		with indexPath.open("rb") as stream:
			indexInfo = os.fstat(stream.fileno())
			if not _ordinaryFileInfo(indexInfo):
				raise ValueError("bundle index is missing or is not an ordinary file")
			if indexInfo.st_size > limits.indexMaximumBytes:
				raise ValueError("bundle index exceeds the permitted byte ceiling")
			indexBytes = stream.read(indexInfo.st_size)
			if len(indexBytes) != indexInfo.st_size:
				raise ValueError("bundle index changed while it was read")
	except OSError as error:
		raise ValueError("bundle index is missing or inaccessible") from error
	if _pathIdentity(indexPath, directory=False) != _filesystemIdentity(indexInfo):
		raise ValueError("bundle index path changed while it was admitted")
	state = _BudgetState(byteTotal=indexInfo.st_size)
	index = parseIndex(indexBytes, limits=limits, state=state)
	_validateCompactEvidenceReferences(index.sharedTables.providerDefaults, index)
	_validateCompactEvidenceReferences(index.uiaDefaults, index)

	declared = {entry.filename for entry in index.catalog}
	declared.add(INDEX_FILENAME)
	present: set[str] = set()
	for child in directory.iterdir():
		if not _ordinaryFile(child):
			raise ValueError("bundle directory contains a non-ordinary entry")
		present.add(child.name)
	if SCREENSHOT_IMAGE_FILENAME in present:
		declared.add(SCREENSHOT_IMAGE_FILENAME)
	if PUBLICATION_RECEIPT_FILENAME in present:
		declared.add(PUBLICATION_RECEIPT_FILENAME)
	if present != declared:
		raise ValueError("bundle directory files do not match the declared closed set")

	offsets: dict[str, dict[str, tuple[int, int]]] = {}
	artifactIdentities: dict[str, _FilesystemIdentity] = {}
	coreNodes: dict[str, _CoreNodeStructure] = {}
	for topic in BUNDLE_TOPIC_ORDER:
		entry = index.entry(topic)
		if entry is None:
			continue
		fileOffsets, artifactIdentity, topicCoreNodes = _streamTopicFile(
			directory / entry.filename,
			entry,
			index,
			limits,
			state,
		)
		artifactIdentities[entry.filename] = artifactIdentity
		if entry.nodeKeyed:
			offsets[topic] = fileOffsets
		if topic == "nodes":
			coreNodes = topicCoreNodes
	coreChildren = _validateBundleStructure(index, coreNodes, offsets)
	if _pathIdentity(directory, directory=True) != directoryIdentity:
		raise ValueError("bundle directory identity changed while it was admitted")
	return BundleAdmission(
		index=index,
		sourceGeneration=sourceGeneration,
		offsets=offsets,
		totalByteLength=state.byteTotal,
		directoryIdentity=directoryIdentity,
		artifactIdentities=artifactIdentities,
		coreChildren=coreChildren,
	)


def projectSelectedNode(
	admission: BundleAdmission,
	directory: Path,
	nodeId: str,
) -> SelectedNodeProjection:
	"""Join one node across topic files from verified, lazily cached artifact bytes."""

	_ = _localIdOrder(nodeId)
	records: list[tuple[str, Mapping[str, object]]] = []
	for topic in NODE_TOPICS:
		topicOffsets = admission.offsets.get(topic)
		if topicOffsets is None:
			continue
		location = topicOffsets.get(nodeId)
		if location is None:
			continue
		entry = admission.index.entry(topic)
		if entry is None:
			raise ValueError("admitted offsets reference an uncataloged topic")
		offset, length = location
		payload = _readAdmittedArtifact(admission, directory, entry)
		rawLine = payload[offset : offset + length]
		if len(rawLine) != length:
			raise ValueError("admitted topic offset is outside its artifact")
		record = _requireObject(_loadStrictJson(rawLine[:-1], "bundle topic line"), "bundle topic record")
		if record.get("id") != nodeId:
			raise ValueError("seeked topic line does not match the requested node")
		if topic == "nodes":
			record = _expandCompactCoreRecord(record, admission.index)
		elif topic == "uia" and admission.index.uiaSchema.columns:
			record = _expandCompactUiaRecord(record, admission.index)
		elif _compactDefaultsForTopic(admission.index, topic) is not None:
			record = _expandCompactDefaultRecord(record, admission.index, topic)
		record = _requireObject(
			_expandCompactEvidence(record, admission.index),
			"expanded bundle topic record",
		)
		if topic == "customUia":
			record = _requireObject(
				_expandCustomUiaDefinitionReferences(record, admission.index),
				"expanded Custom UIA definition record",
			)
		records.append((topic, record))
	if not records:
		raise ValueError("requested node is not present in any node topic")
	return SelectedNodeProjection(
		nodeId=nodeId,
		sourceGeneration=admission.sourceGeneration,
		records=tuple(records),
	)


def projectSelectedSubtree(
	admission: BundleAdmission,
	directory: Path,
	nodeId: str,
) -> SelectedSubtreeProjection:
	"""Repackage one recorded subtree without reading any live provider.

	The selected record becomes the sole root.  Every node-keyed topic is restricted to the same
	descendant set; capture-wide metadata is retained so the result reopens through normal bundle
	admission.
	"""

	selected: dict[str, tuple[tuple[str, Mapping[str, object]], ...]] = {}
	childPositions: dict[str, int] = {}
	pending = [nodeId]
	while pending:
		currentId = pending.pop()
		if currentId in selected:
			continue
		projection = projectSelectedNode(admission, directory, currentId)
		selected[currentId] = projection.records
		coreRecord = next((record for topic, record in projection.records if topic == "nodes"), None)
		if coreRecord is None:
			raise ValueError("selected node has no core node record")
		childIds = admission.coreChildren.get(currentId)
		if childIds is None:
			raise ValueError("admission has no validated children for the selected node")
		childPositions.update({childId: position for position, childId in enumerate(childIds)})
		pending.extend(reversed(childIds))

	orderedIds = tuple(sorted(selected, key=_localIdOrder))
	rootRecord = next((record for topic, record in selected[nodeId] if topic == "nodes"), None)
	if rootRecord is None:
		raise ValueError("selected root has no core node record")
	rootDepthValue = dict(rootRecord).get("depth")
	if type(rootDepthValue) is not int:
		raise ValueError("selected node has an invalid depth record")
	rootDepth = rootDepthValue
	topics: dict[str, list[JsonObject]] = {topic: [] for topic in NODE_TOPICS}
	selectedIds = set(selected)
	for currentId in orderedIds:
		for topic, sourceRecord in selected[currentId]:
			record = dict(sourceRecord)
			if topic == "nodes":
				generic = _compactGenericDefault(record, admission.index)
				if generic is not None:
					_ = record.pop("genericRef", None)
					record["generic"] = _expandCompactEvidence(generic, admission.index)
				childIds = admission.coreChildren.get(currentId)
				if childIds is None:
					raise ValueError("admission has no validated children for the selected node")
				children = [child for child in childIds if child in selectedIds]
				record["children"] = children
				record["childCount"] = len(children)
				record["parent"] = None if currentId == nodeId else record.get("parent")
				if currentId != nodeId:
					record["indexInParent"] = childPositions[currentId]
				depth = record.get("depth")
				if type(depth) is not int:
					raise ValueError("selected node has an invalid depth record")
				record["depth"] = depth - rootDepth
			topics[topic].append(_fromPlainObject(record))

	for topic in DOCUMENT_TOPICS:
		entry = admission.index.entry(topic)
		if entry is None:
			continue
		payload = _readAdmittedArtifact(admission, directory, entry)
		records = [
			_fromPlainObject(
				_requireObject(_loadStrictJson(line, f"{topic} topic line"), f"{topic} topic record"),
			)
			for line in payload.splitlines()
			if line
		]
		topics[topic] = records
	source = BundleSource(
		snapshotKind=admission.index.snapshotKind,
		generatedAt=admission.index.generatedAt,
		redactionEnabled=admission.index.redactionEnabled,
		policyRevision=admission.index.policyRevision,
		settingsRevision=admission.index.settingsRevision,
		executable=admission.index.executable,
		processId=admission.index.processId,
		rootIds=(nodeId,),
		topics=tuple(
			BundleTopicRecords(topic, tuple(records)) for topic, records in topics.items() if records
		),
	)
	return SelectedSubtreeProjection(
		nodeId=nodeId,
		sourceGeneration=admission.sourceGeneration,
		package=prepareBundle(source),
	)


def validateBundleArtifacts(artifactMap: Mapping[str, bytes]) -> tuple[str, ...]:
	"""Validate an in-memory bundle artifact set for publication and return ordered names."""

	if INDEX_FILENAME not in artifactMap:
		raise ValueError("bundle publication is missing its index")
	index = parseIndex(artifactMap[INDEX_FILENAME])
	declared = {entry.filename for entry in index.catalog}
	declared.add(INDEX_FILENAME)
	names = set(artifactMap)
	hasImage = SCREENSHOT_IMAGE_FILENAME in names
	if hasImage:
		declared.add(SCREENSHOT_IMAGE_FILENAME)
	if names != declared:
		raise ValueError("bundle publication files do not match the declared closed set")
	for entry in index.catalog:
		payload = artifactMap[entry.filename]
		if len(payload) != entry.byteLength:
			raise ValueError("bundle publication byte length does not match the catalog")
		if hashlib.sha256(payload).hexdigest() != entry.sha256:
			raise ValueError("bundle publication content hash does not match the catalog")
		lineCount = payload.count(b"\n")
		if payload and not payload.endswith(b"\n"):
			lineCount += 1
		if lineCount != entry.recordCount:
			raise ValueError("bundle publication record count does not match the catalog")
	ordered = [INDEX_FILENAME, *index.orderedFilenames()]
	if hasImage:
		ordered.append(SCREENSHOT_IMAGE_FILENAME)
	return tuple(ordered)


# ---------------------------------------------------------------------------
# Typed capture projection and reconstruction.
#
# The partitioned bundle is the single production capture output. ``projectSnapshotTopics``
# turns an already privacy-transformed in-memory capture into the ordered topic families that
# ``prepareBundle`` serialises; ``BundleSnapshotView`` reads a committed bundle back through the
# same typed getters diffing consumes, opening the deep provider topics only when a caller
# actually reaches for them. ``InMemorySnapshotView`` presents a live capture through the
# identical protocol, so an in-memory diff and a reconstructed diff share one comparison path.
# ---------------------------------------------------------------------------

# The scan plan and equivalent technical defaults are recorded once in the capture-configuration
# document topic, never appended to a per-node provider record. The name is defined here so both
# the projector and its tests can assert the field never leaks into a node topic line.
INSTALLED_SCAN_PLAN_FIELD: Final = "installedScanPlan"

_DEEP_PROVIDER_TOPICS: Final[tuple[str, ...]] = PROVIDER_SECTIONS[1:]
_ABSENT_STATES: Final = frozenset((EvidenceState.NOT_APPLICABLE, EvidenceState.UNSUPPORTED))


class SnapshotNodeView(Protocol):
	"""The typed getters diffing reads from one node, satisfied by records and bundles alike."""

	@property
	def key(self) -> str: ...

	@property
	def structure(self) -> NodeStructure: ...

	@property
	def fields(self) -> tuple[tuple[str, EvidenceEnvelope], ...]: ...

	def field(self, name: str) -> EvidenceEnvelope: ...

	@property
	def providers(self) -> ProviderSections: ...


class SnapshotView(Protocol):
	"""A capture presented as traversal roots and nodes, whatever the backing store."""

	@property
	def captureRoots(self) -> tuple[str, ...]: ...

	@property
	def captureNodes(self) -> tuple[SnapshotNodeView, ...]: ...


@dataclass(frozen=True, slots=True)
class InMemorySnapshotView:
	"""Present an in-memory capture through the shared view protocol without copying it."""

	snapshot: Snapshot | NavigatorSnapshot

	@property
	def captureRoots(self) -> tuple[str, ...]:
		return self.snapshot.captureRoots

	@property
	def captureNodes(self) -> tuple[SnapshotNodeView, ...]:
		return self.snapshot.captureNodes

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		node = next((candidate for candidate in self.snapshot.captureNodes if candidate.key == nodeId), None)
		if node is None:
			return ()
		envelope = node.field("annotations")
		if envelope.status is not EvidenceState.VALUE:
			return ()
		try:
			return annotationRecordsFromPlain(envelope.value)
		except (TypeError, ValueError):
			return (annotationConversionFailure(node.key, source="capture"),)


@dataclass(frozen=True, slots=True)
class TopicProjection:
	"""One topic family and its projected records, ready to hand to ``prepareBundle``."""

	topic: str
	records: tuple[JsonObject, ...]

	def asTopicRecords(self) -> BundleTopicRecords:
		return BundleTopicRecords(self.topic, self.records)


def _absentEnvelope(policyRevision: int) -> EvidenceEnvelope:
	"""Return the canonical envelope that stands in for a field or section omitted for economy."""

	return EvidenceEnvelope(
		EvidenceState.NOT_APPLICABLE,
		Source("nvdaSelected", "CaptureService", "absent"),
		Projection("normalNvda"),
		Confidence.INDETERMINATE,
		PrivacyReference("node", "unknown", "retain", max(policyRevision, 1)),
	)


def _absentSection(policyRevision: int) -> ProviderSectionRecord:
	envelope = _absentEnvelope(policyRevision)
	return ProviderSectionRecord(envelope, envelope, envelope)


def _fromPlain(value: object) -> JsonValue:
	if isinstance(value, (JsonObject, JsonArray)):
		return value
	if isinstance(value, Mapping):
		mapping = cast("Mapping[object, object]", value)
		return JsonObject(tuple((str(key), _fromPlain(item)) for key, item in mapping.items()))
	if isinstance(value, (list, tuple)):
		sequence = cast("list[object] | tuple[object, ...]", value)
		return JsonArray(tuple(_fromPlain(item) for item in sequence))
	if value is None or isinstance(value, (bool, int, float, str)):
		return value
	raise ValueError("unsupported plain value for bundle conversion")


def _fromPlainObject(mapping: Mapping[str, object]) -> JsonObject:
	converted = _fromPlain(mapping)
	if not isinstance(converted, JsonObject):
		raise ValueError("document topic record must be an object")
	return converted


def _require(mapping: Mapping[str, object], key: str) -> object:
	if key not in mapping:
		raise ValueError(f"bundle record is missing required field {key!r}")
	return mapping[key]


def _valueString(envelope: EvidenceEnvelope) -> str:
	if envelope.status is EvidenceState.VALUE and isinstance(envelope.value, str):
		return envelope.value
	return ""


def _sectionByName(providers: ProviderSections, name: str) -> ProviderSectionRecord:
	for candidate, section in providers.items:
		if candidate == name:
			return section
	raise ValueError(f"provider sections are missing the {name!r} family")


def _sectionAllAbsent(section: ProviderSectionRecord) -> bool:
	return all(
		envelope.status in _ABSENT_STATES
		for envelope in (section.status, section.identity, section.properties)
	)


def _sectionObject(section: ProviderSectionRecord) -> JsonObject:
	return JsonObject(
		(
			("status", evidenceObject(section.status)),
			("identity", evidenceObject(section.identity)),
			("properties", evidenceObject(section.properties)),
		),
	)


def _normalProviderDatums(values: list[object], discardedFields: frozenset[str]) -> list[object]:
	"""Discard normal-mode discovery fields and canonical unsupported datum results."""

	filtered: list[object] = []
	for rawDatum in values:
		if not isinstance(rawDatum, list):
			filtered.append(rawDatum)
			continue
		datum = cast("list[object]", rawDatum)
		if not datum or not isinstance(datum[0], str):
			filtered.append(datum)
			continue
		if datum[0] in discardedFields:
			continue
		if len(datum) == 5 and datum[1] == EvidenceState.UNSUPPORTED.value:
			continue
		if len(datum) == 2 and isinstance(datum[1], list):
			result = cast("list[object]", datum[1])
			if result and result[0] == EvidenceState.UNSUPPORTED.value:
				continue
		if len(datum) not in (2, 5):
			filtered.append(datum)
			continue
		filtered.append(datum)
	return filtered


def _normalGenericSection(section: ProviderSectionRecord) -> JsonObject:
	"""Remove developer-only and canonical-absence generic metadata from normal bundles."""

	plain = _plainObject(_sectionObject(section))
	properties = _requireObject(plain["properties"], "generic provider properties")
	if properties.get("status") != EvidenceState.VALUE.value:
		return _fromPlainObject(plain)
	values = properties.get("value")
	if not isinstance(values, list):
		return _fromPlainObject(plain)
	properties["value"] = _normalProviderDatums(
		cast("list[object]", values),
		frozenset(("developerInformation",)),
	)
	plain["properties"] = properties
	return _fromPlainObject(plain)


def _requireLocalId(localById: Mapping[str, str], key: str) -> str:
	try:
		return localById[key]
	except KeyError as error:
		raise ValueError("capture node references a key that is not present in the capture") from error


def _coreRecord(
	localId: str,
	parentLocalId: str | None,
	node: SnapshotNodeView,
	childLocalIds: tuple[str, ...],
) -> JsonObject:
	storedFields = tuple(
		(name, evidenceObject(envelope))
		for name, envelope in node.fields
		if name not in ("annotations", "children", "developerInformation", "apiDetails", "diagnostics")
	)
	items: list[tuple[str, JsonValue]] = [
		("id", localId),
		("parent", parentLocalId),
		("depth", node.structure.depth),
		("childCount", len(childLocalIds)),
		("role", _valueString(node.field("role"))),
		("name", _valueString(node.field("name"))),
		("children", JsonArray(childLocalIds)),
		(
			"flags",
			JsonObject(
				(
					("cycleDetected", node.structure.cycleDetected),
					("truncated", node.structure.truncated),
					("childFetchFailed", node.structure.childFetchFailed),
				),
			),
		),
		("fields", JsonObject(storedFields)),
	]
	generic = _sectionByName(node.providers, "generic")
	if not _sectionAllAbsent(generic):
		items.append(("generic", _normalGenericSection(generic)))
	return JsonObject(tuple(items))


def _normalUiaSection(section: ProviderSectionRecord) -> JsonObject:
	"""Drop discovery bookkeeping and canonical unsupported UIA datums from normal bundles."""

	plain = _plainObject(_sectionObject(section))
	properties = _requireObject(plain["properties"], "standard UIA properties")
	if properties.get("status") != EvidenceState.VALUE.value:
		return _fromPlainObject(plain)
	values = properties.get("value")
	if not isinstance(values, list):
		return _fromPlainObject(plain)
	properties["value"] = _normalProviderDatums(
		cast("list[object]", values),
		frozenset(("propertyInventory", "patternInventory")),
	)
	plain["properties"] = properties
	return _fromPlainObject(plain)


def _normalCustomUiaSection(section: ProviderSectionRecord) -> JsonObject | None:
	"""Keep configured custom-definition evidence while discarding old discovery collections."""

	plain = _plainObject(_sectionObject(section))

	def retain(value: object, suffix: str) -> list[object]:
		envelope = _requireObject(value, "custom UIA collection")
		if envelope.get("status") != EvidenceState.VALUE.value:
			return []
		items = envelope.get("value")
		if not isinstance(items, list):
			return []
		retained: list[object] = []
		for rawItem in cast("list[object]", items):
			if not isinstance(rawItem, list):
				continue
			item = cast("list[object]", rawItem)
			if len(item) not in (2, 5) or not isinstance(item[0], str):
				continue
			field = item[0]
			if field.startswith("known.") and field.endswith(suffix):
				retained.append(item)
		return retained

	identity = _requireObject(plain["identity"], "custom UIA identity")
	properties = _requireObject(plain["properties"], "custom UIA properties")
	if not isinstance(identity.get("value"), list) and not isinstance(properties.get("value"), list):
		# A foreign or synthetic provider section has no datum collection to classify. Preserve it
		# rather than assuming it is the discovery-heavy native Custom UIA wire shape.
		return _fromPlainObject(plain)
	retainedIdentity = retain(identity, ".identity") + retain(identity, ".definition")
	retainedProperties = retain(properties, ".current")
	if not retainedIdentity and not retainedProperties:
		status = _requireObject(plain["status"], "custom UIA status")
		if status.get("status") in (EvidenceState.VALUE.value, EvidenceState.EMPTY.value):
			return None
	if identity.get("status") == EvidenceState.VALUE.value:
		identity["value"] = retainedIdentity
	if properties.get("status") == EvidenceState.VALUE.value:
		properties["value"] = retainedProperties
	plain["identity"] = identity
	plain["properties"] = properties
	return _fromPlainObject(plain)


def _deepRecord(
	localId: str,
	topic: str,
	section: ProviderSectionRecord,
	*,
	customUiaDiagnosticExport: bool,
) -> JsonObject | None:
	if topic == "uia":
		serialized = _normalUiaSection(section)
	elif topic == "customUia":
		serialized = (
			_sectionObject(section) if customUiaDiagnosticExport else _normalCustomUiaSection(section)
		)
		if serialized is None:
			return None
	else:
		serialized = _sectionObject(section)
	return JsonObject((("id", localId), *serialized.items))


def projectSnapshotTopics(
	snapshot: Snapshot | NavigatorSnapshot,
	*,
	generatedAt: str,
	executable: str,
	processId: int,
	redactionEnabled: bool,
	policyRevision: int,
	settingsRevision: int,
	snapshotKind: str,
	captureConfiguration: Mapping[str, object] | None = None,
	screenshot: Mapping[str, object] | None = None,
	screenshotImage: bytes | None = None,
	annotations: Mapping[str, tuple[AnnotationRecord, ...]] | None = None,
	annotationPrivacyTransform: Callable[[str], str] | None = None,
	customUiaDiagnosticExport: bool = False,
	cooperate: Callable[[], None] | None = None,
) -> BundleSource:
	"""Project one privacy-transformed capture into the ordered bundle topic families.

	Core identity, structure, and the folded generic section are written to the ``nodes`` topic.
	Each deep provider family becomes its own node-keyed topic, emitted only for the nodes whose
	section carries something beyond ``notApplicable``/``unsupported``. Fields that are absent for
	economy are dropped here and rebuilt as the canonical absent envelope on read, so a field that
	both captures omit contributes no spurious difference.
	"""

	if snapshotKind not in SNAPSHOT_KINDS:
		raise ValueError("bundle snapshot kind is not supported")
	captureNodes = snapshot.captureNodes
	localById: dict[str, str] = {node.key: f"n{index}" for index, node in enumerate(captureNodes)}
	if len(localById) != len(captureNodes):
		raise ValueError("capture node keys must be unique")
	coreRecords: list[JsonObject] = []
	deepRecords: dict[str, list[JsonObject]] = {topic: [] for topic in _DEEP_PROVIDER_TOPICS}
	projectedAnnotations: dict[str, tuple[AnnotationRecord, ...]] = {}
	rootIds: list[str] = []
	for index, node in enumerate(captureNodes):
		localId = f"n{index}"
		parentKey = node.structure.parentKey
		parentLocalId = _requireLocalId(localById, parentKey) if parentKey is not None else None
		if parentLocalId is None:
			rootIds.append(localId)
		childLocalIds = tuple(_requireLocalId(localById, key) for key in node.structure.childKeys)
		coreRecords.append(_coreRecord(localId, parentLocalId, node, childLocalIds))
		annotationEnvelope = node.field("annotations")
		if annotationEnvelope.status is EvidenceState.VALUE:
			try:
				records = annotationRecordsFromPlain(annotationEnvelope.value)
			except (TypeError, ValueError):
				records = (annotationConversionFailure(node.key, source="capture"),)
			if records:
				projectedAnnotations[node.key] = records
		elif annotationEnvelope.status is EvidenceState.REDACTED:
			projectedAnnotations[node.key] = (
				AnnotationRecord(
					key="annotations-redacted",
					status=AnnotationStatus.UNAVAILABLE,
					typeName="Annotations",
					source="privacy policy",
				),
			)
		for topic in _DEEP_PROVIDER_TOPICS:
			section = _sectionByName(node.providers, topic)
			if not _sectionAllAbsent(section):
				record = _deepRecord(
					localId,
					topic,
					section,
					customUiaDiagnosticExport=customUiaDiagnosticExport,
				)
				if record is not None:
					deepRecords[topic].append(record)
		if cooperate is not None:
			cooperate()
	if not rootIds:
		raise ValueError("capture must declare at least one root")
	projections: list[TopicProjection] = [TopicProjection("nodes", tuple(coreRecords))]
	for topic in _DEEP_PROVIDER_TOPICS:
		records = deepRecords[topic]
		if records:
			projections.append(TopicProjection(topic, tuple(records)))
	if annotations is not None:
		if annotationPrivacyTransform is None:
			raise ValueError("annotation projection requires a privacy transformation")
		unknownNodes = set(annotations) - set(localById)
		if unknownNodes:
			raise ValueError("annotation projection references an unknown capture node")
		duplicateNodes = set(projectedAnnotations).intersection(annotations)
		if duplicateNodes:
			raise ValueError("annotation projection duplicates captured annotation nodes")
		projectedAnnotations.update(annotations)
	if projectedAnnotations:

		def localize(record: AnnotationRecord) -> AnnotationRecord:
			targetNodeId = record.targetNodeId
			if targetNodeId is not None:
				targetNodeId = _requireLocalId(localById, targetNodeId)
			return replace(
				record,
				targetNodeId=targetNodeId,
				related=tuple(localize(related) for related in record.related),
			)

		annotationTopic = annotationTopicRecords(
			{
				localById[nodeId]: tuple(localize(record) for record in records)
				for nodeId, records in projectedAnnotations.items()
			},
			privacyTransform=annotationPrivacyTransform or (lambda value: value),
		)
		if annotationTopic.records:
			projections.append(TopicProjection(annotationTopic.topic, annotationTopic.records))
	if captureConfiguration is not None:
		projections.append(
			TopicProjection("captureConfiguration", (_fromPlainObject(captureConfiguration),)),
		)
	if screenshot is not None:
		projections.append(TopicProjection("screenshot", (_fromPlainObject(screenshot),)))
	return BundleSource(
		snapshotKind=snapshotKind,
		generatedAt=generatedAt,
		redactionEnabled=redactionEnabled,
		policyRevision=policyRevision,
		settingsRevision=settingsRevision,
		executable=executable,
		processId=processId,
		rootIds=tuple(rootIds),
		topics=tuple(projection.asTopicRecords() for projection in projections),
		screenshotImage=screenshotImage,
	)


class _BundleNode:
	"""One reconstructed node whose deep provider sections open lazily on first access."""

	def __init__(
		self,
		localId: str,
		structure: NodeStructure,
		fields: tuple[tuple[str, EvidenceEnvelope], ...],
		generic: ProviderSectionRecord,
		deepReader: Callable[[str, str], ProviderSectionRecord],
	) -> None:
		super().__init__()
		self._localId = localId
		self._structure = structure
		self._fields = fields
		self._fieldMap = dict(fields)
		self._generic = generic
		self._deepReader = deepReader
		self._providers: ProviderSections | None = None

	@property
	def key(self) -> str:
		return self._localId

	@property
	def structure(self) -> NodeStructure:
		return self._structure

	@property
	def fields(self) -> tuple[tuple[str, EvidenceEnvelope], ...]:
		return self._fields

	def field(self, name: str) -> EvidenceEnvelope:
		try:
			return self._fieldMap[name]
		except KeyError as error:
			raise KeyError(f"unknown common node field: {name}") from error

	@property
	def providers(self) -> ProviderSections:
		cached = self._providers
		if cached is not None:
			return cached
		sections: list[tuple[str, ProviderSectionRecord]] = [("generic", self._generic)]
		for topic in _DEEP_PROVIDER_TOPICS:
			sections.append((topic, self._deepReader(topic, self._localId)))
		built = ProviderSections(tuple(sections))
		self._providers = built
		return built


_ANNOTATION_BUNDLE_FIELDS: Final = frozenset(
	(
		"key",
		"status",
		"typeName",
		"source",
		"typeId",
		"summary",
		"author",
		"dateTime",
		"targetName",
		"targetRole",
		"targetIdentity",
		"targetNodeId",
		"targetIdentityProven",
		"relationship",
		"errorRef",
		"related",
	),
)


def _annotationFromBundle(value: object) -> AnnotationRecord:
	record = _requireObject(value, "annotation record")
	if not {"key", "status", "typeName", "source"}.issubset(record):
		raise ValueError("annotation record is missing required fields")
	if not set(record).issubset(_ANNOTATION_BUNDLE_FIELDS):
		raise ValueError("annotation record contains an unknown field")

	def text(name: str, *, required: bool = False) -> str | None:
		item = record.get(name)
		if item is None and not required:
			return None
		if not isinstance(item, str):
			raise ValueError(f"annotation field {name!r} must be text")
		return item

	proven = record.get("targetIdentityProven", False)
	if not isinstance(proven, bool):
		raise ValueError("annotation target proof must be boolean")
	relatedValue = record.get("related", [])
	if not isinstance(relatedValue, list):
		raise ValueError("related annotations must be an array")
	errorValue = record.get("errorRef")
	errorRef: ErrorReference | None
	if errorValue is None:
		errorRef = None
	else:
		error = _requireObject(errorValue, "annotation error reference")
		if set(error) != {"code", "diagnosticId"}:
			raise ValueError("annotation error reference has an invalid shape")
		code = error.get("code")
		diagnosticId = error.get("diagnosticId")
		if not isinstance(code, str) or not isinstance(diagnosticId, str):
			raise ValueError("annotation error reference fields must be text")
		errorRef = ErrorReference(code, diagnosticId)
	return AnnotationRecord(
		key=cast(str, text("key", required=True)),
		status=AnnotationStatus(cast(str, text("status", required=True))),
		typeName=cast(str, text("typeName", required=True)),
		source=cast(str, text("source", required=True)),
		typeId=text("typeId"),
		summary=text("summary"),
		author=text("author"),
		dateTime=text("dateTime"),
		targetName=text("targetName"),
		targetRole=text("targetRole"),
		targetIdentity=text("targetIdentity"),
		targetNodeId=text("targetNodeId"),
		targetIdentityProven=proven,
		relationship=text("relationship"),
		errorRef=errorRef,
		related=tuple(_annotationFromBundle(item) for item in cast(list[object], relatedValue)),
	)


class BundleSnapshotView:
	"""Reconstruct a committed bundle directory as typed, lazily deepened snapshot getters.

	Construction admits the directory and reads the core ``nodes`` topic once so structure and
	identity are available for every node. The deep provider families stay on disk until a caller
	touches a node's :pyattr:`providers`; the first access to a topic validates and caches its
	admitted artifact before selecting that node's line. A comparison that never leaves the core
	therefore opens no deep topic files at all.
	"""

	def __init__(
		self,
		directory: Path,
		*,
		sourceGeneration: int = 0,
		limits: BundleAdmissionLimits = DEFAULT_BUNDLE_LIMITS,
	) -> None:
		super().__init__()
		self._directory = Path(directory)
		self._admission = admitBundle(self._directory, sourceGeneration=sourceGeneration, limits=limits)
		policyRevision = self._admission.index.policyRevision
		self._absent = _absentEnvelope(policyRevision)
		self._absentProviderSection = _absentSection(policyRevision)
		self._deepOpens = 0
		self._openHandles = 0
		self._nodes = self._buildCoreNodes()

	@property
	def deepOpens(self) -> int:
		return self._deepOpens

	@property
	def index(self) -> BundleIndex:
		"""The admitted index describing this offline snapshot."""

		return self._admission.index

	@property
	def openHandles(self) -> int:
		return self._openHandles

	@property
	def captureRoots(self) -> tuple[str, ...]:
		return self._admission.index.rootIds

	@property
	def captureNodes(self) -> tuple[SnapshotNodeView, ...]:
		return self._nodes

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		topicOffsets = self._admission.offsets.get("semantics")
		location = topicOffsets.get(nodeId) if topicOffsets is not None else None
		if location is None:
			return ()
		offset, length = location
		entry = self._admission.index.entry("semantics")
		if entry is None:
			raise ValueError("admitted offsets reference an uncataloged topic")
		payload = _readAdmittedArtifact(self._admission, self._directory, entry)
		rawLine = payload[offset : offset + length]
		if len(rawLine) != length:
			raise ValueError("admitted annotation offset is outside its artifact")
		record = _requireObject(
			_loadStrictJson(rawLine[:-1], "bundle annotation line"),
			"bundle annotation record",
		)
		if record.get("id") != nodeId:
			raise ValueError("annotation topic line does not match the requested node")
		annotations = record.get("annotations")
		if not isinstance(annotations, list):
			raise ValueError("annotation topic record must contain an annotations array")
		records = tuple(_annotationFromBundle(item) for item in cast(list[object], annotations))
		validateAnnotationKeys(records)
		return records

	def _buildCoreNodes(self) -> tuple[SnapshotNodeView, ...]:
		entry = self._admission.index.entry("nodes")
		if entry is None:
			return ()
		payload = _readAdmittedArtifact(self._admission, self._directory, entry)
		nodes: list[_BundleNode] = []
		for line in payload.split(b"\n"):
			if not line:
				continue
			plain = _requireObject(_loadStrictJson(line, "bundle node line"), "bundle node record")
			nodes.append(self._coreNode(plain))
		nodes.sort(key=lambda node: _localIdOrder(node.key))
		return tuple(nodes)

	def _coreNode(self, plain: Mapping[str, object]) -> _BundleNode:
		plain = _expandCompactCoreRecord(plain, self._admission.index)
		plain = _requireObject(
			_expandCompactEvidence(plain, self._admission.index),
			"expanded core node record",
		)
		localId = _expectString(_require(plain, "id"), "core node identifier")
		parentRaw = plain.get("parent")
		parent = None if parentRaw is None else _expectString(parentRaw, "core node parent")
		depth = _expectInt(_require(plain, "depth"), "core node depth")
		childrenRaw = _require(plain, "children")
		if not isinstance(childrenRaw, list):
			raise ValueError("core node children must be an array")
		childKeys = tuple(
			_expectString(item, "core node child identifier") for item in cast("list[object]", childrenRaw)
		)
		flags = _requireObject(plain.get("flags", _DEFAULT_CORE_FLAGS), "core node flags")
		structure = NodeStructure(
			parent,
			depth,
			childKeys,
			_expectBool(_require(flags, "cycleDetected"), "cycleDetected flag"),
			_expectBool(_require(flags, "truncated"), "truncated flag"),
			_expectBool(_require(flags, "childFetchFailed"), "childFetchFailed flag"),
		)
		storedRaw = plain.get("fields")
		stored = _requireObject(storedRaw, "core node fields") if storedRaw is not None else {}
		fields = tuple((name, self._reconstructField(name, stored)) for name in COMMON_NODE_FIELDS)
		genericValue = plain.get("generic", _compactGenericDefault(plain, self._admission.index))
		generic = self._reconstructSection(
			_expandCompactEvidence(genericValue, self._admission.index),
		)
		return _BundleNode(localId, structure, fields, generic, self._readDeepSection)

	def _reconstructField(self, name: str, stored: Mapping[str, object]) -> EvidenceEnvelope:
		if name == "children":
			return self._absent
		if name in stored:
			return parseEvidenceEnvelope(_fromPlain(stored[name]))
		return self._absent

	def _reconstructSection(self, value: object) -> ProviderSectionRecord:
		if value is None:
			return self._absentProviderSection
		obj = _requireObject(value, "provider section record")
		return ProviderSectionRecord(
			parseEvidenceEnvelope(_fromPlain(_require(obj, "status"))),
			parseEvidenceEnvelope(_fromPlain(_require(obj, "identity"))),
			parseEvidenceEnvelope(_fromPlain(_require(obj, "properties"))),
		)

	def _readDeepSection(self, topic: str, localId: str) -> ProviderSectionRecord:
		topicOffsets = self._admission.offsets.get(topic)
		location = topicOffsets.get(localId) if topicOffsets is not None else None
		if location is None:
			return self._absentProviderSection
		offset, length = location
		self._openHandles += 1
		try:
			entry = self._admission.index.entry(topic)
			if entry is None:
				raise ValueError("admitted offsets reference an uncataloged topic")
			payload = _readAdmittedArtifact(self._admission, self._directory, entry)
			raw = payload[offset : offset + length]
			if len(raw) != length:
				raise ValueError("admitted topic offset is outside its artifact")
		finally:
			self._openHandles -= 1
		self._deepOpens += 1
		plain = _requireObject(_loadStrictJson(raw[:-1], "bundle topic line"), "bundle topic record")
		if topic == "uia" and self._admission.index.uiaSchema.columns:
			plain = _expandCompactUiaRecord(plain, self._admission.index)
		elif _compactDefaultsForTopic(self._admission.index, topic) is not None:
			plain = _expandCompactDefaultRecord(plain, self._admission.index, topic)
		plain = _requireObject(
			_expandCompactEvidence(plain, self._admission.index),
			"expanded bundle topic record",
		)
		if topic == "customUia":
			plain = _requireObject(
				_expandCustomUiaDefinitionReferences(plain, self._admission.index),
				"expanded Custom UIA definition record",
			)
		return self._reconstructSection(plain)
