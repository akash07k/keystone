from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import cast
import unicodedata

from ..domain.documents import (
	DOCUMENT_FIELDS,
	METADATA_FIELDS,
	Document,
	DocumentKind,
	JsonArray,
	JsonObject,
	JsonValue,
	buildDocument,
)


class _Pairs(list[tuple[str, object]]):
	pass


@dataclass(frozen=True, slots=True)
class AdmissionLimits:
	maximumBytes: int = 8 * 1024 * 1024
	maximumDepth: int = 64
	maximumNodes: int = 500_000
	maximumStringScalars: int = 1_000_000
	maximumCollectionItems: int = 500_000

	def __post_init__(self) -> None:
		for value in cast(
			tuple[object, ...],
			(
				self.maximumBytes,
				self.maximumDepth,
				self.maximumNodes,
				self.maximumStringScalars,
				self.maximumCollectionItems,
			),
		):
			if not isinstance(value, int) or isinstance(value, bool) or value < 0:
				raise ValueError("admission limits must be nonnegative integers")


@dataclass(slots=True)
class _Budget:
	limits: AdmissionLimits
	nodes: int = 0
	stringScalars: int = 0
	collectionItems: int = 0


def _normalizeString(value: str, budget: _Budget) -> str:
	budget.stringScalars += len(value)
	if budget.stringScalars > budget.limits.maximumStringScalars:
		raise ValueError("document exceeds the string-scalar limit")
	return unicodedata.normalize("NFC", value)


def _normalize(value: object, budget: _Budget, depth: int = 0) -> JsonValue:
	if depth > budget.limits.maximumDepth:
		raise ValueError("document exceeds the depth limit")
	budget.nodes += 1
	if budget.nodes > budget.limits.maximumNodes:
		raise ValueError("document exceeds the node limit")
	if value is None or isinstance(value, bool) or isinstance(value, int):
		return value
	if isinstance(value, float):
		if not math.isfinite(value):
			raise ValueError("JSON numbers must be finite")
		return value
	if isinstance(value, str):
		return _normalizeString(value, budget)
	if isinstance(value, _Pairs):
		budget.collectionItems += len(value)
		if budget.collectionItems > budget.limits.maximumCollectionItems:
			raise ValueError("document exceeds the collection-item limit")
		normalized: list[tuple[str, JsonValue]] = []
		seen: set[str] = set()
		for key, item in value:
			normalizedKey = _normalizeString(key, budget)
			if normalizedKey in seen:
				raise ValueError("duplicate JSON key")
			seen.add(normalizedKey)
			normalized.append((normalizedKey, _normalize(item, budget, depth + 1)))
		return JsonObject(tuple(normalized))
	if isinstance(value, list):
		items = cast(list[object], value)
		budget.collectionItems += len(items)
		if budget.collectionItems > budget.limits.maximumCollectionItems:
			raise ValueError("document exceeds the collection-item limit")
		return JsonArray(tuple(_normalize(item, budget, depth + 1) for item in items))
	raise TypeError("unsupported JSON value")


def _object(value: JsonValue, label: str) -> JsonObject:
	if not isinstance(value, JsonObject):
		raise ValueError(f"{label} must be an object")
	return value


def admitDocument(data: bytes, limits: AdmissionLimits | None = None) -> Document:
	limits = limits or AdmissionLimits()
	if len(data) > limits.maximumBytes:
		raise ValueError("document exceeds the byte limit")
	if data.startswith(b"\xef\xbb\xbf"):
		raise ValueError("UTF-8 BOM is forbidden")
	try:
		text = data.decode("utf-8", errors="strict")
		raw = json.loads(
			text,
			object_pairs_hook=_Pairs,
			parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"invalid number: {token}")),
		)
	except (UnicodeDecodeError, json.JSONDecodeError) as error:
		raise ValueError("document is not strict UTF-8 JSON") from error
	value = _normalize(raw, _Budget(limits))
	top = _object(value, "document")
	fields = dict(top.items)
	version = dict(_object(fields.get("schemaVersion"), "schema version").items)
	if set(version) != {"major", "minor"} or version["major"] != 2 or version["minor"] != 0:
		raise ValueError("unsupported schema version")
	kind = fields.get("documentKind")
	if not isinstance(kind, str) or kind not in DOCUMENT_FIELDS:
		raise ValueError("unsupported document kind")
	documentKind: DocumentKind = kind
	expected = {"schemaVersion", "documentKind", "documentId", "metadata", *DOCUMENT_FIELDS[documentKind]}
	if set(fields) != expected or len(top.items) != len(expected):
		raise ValueError("document fields do not match the closed kind schema")
	documentId = fields["documentId"]
	if not isinstance(documentId, str):
		raise ValueError("document ID must be a string")
	metadata = _object(fields["metadata"], "metadata")
	if set(name for name, _item in metadata.items) != set(METADATA_FIELDS):
		raise ValueError("metadata fields do not match the closed schema")
	return buildDocument(documentKind, documentId, metadata, fields)


def _sortKey(key: str) -> bytes:
	return key.encode("utf-16-be", errors="strict")


def _plain(value: JsonValue) -> object:
	if isinstance(value, JsonObject):
		return {key: _plain(item) for key, item in sorted(value.items, key=lambda pair: _sortKey(pair[0]))}
	if isinstance(value, JsonArray):
		return [_plain(item) for item in value.items]
	return value


def encodeCanonical(document: Document) -> bytes:
	return (
		json.dumps(
			_plain(document.asObject()),
			allow_nan=False,
			ensure_ascii=False,
			separators=(",", ":"),
		)
		+ "\n"
	).encode("utf-8", errors="strict")
