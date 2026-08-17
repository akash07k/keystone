from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError
import json
import unittest

from addon.globalPlugins.keystone.domain.document_records import CaptureMetadata
from addon.globalPlugins.keystone.domain.documents import (
	NavigatorSnapshot,
	NavigatorSummary,
	Snapshot,
	SnapshotSummary,
)
from addon.globalPlugins.keystone.encoding.canonical_json import admitDocument, encodeCanonical


COMMON_NODE_FIELDS = (
	"name",
	"role",
	"roleText",
	"states",
	"description",
	"value",
	"geometry",
	"windowHandle",
	"windowClass",
	"windowControlId",
	"childCount",
	"indexInParent",
	"keyboardShortcut",
	"position",
	"table",
	"pythonClass",
	"classHierarchy",
	"backend",
	"process",
	"focusable",
	"focused",
	"stableIds",
	"privacy",
	"validation",
	"placeholder",
	"landmark",
	"currentState",
	"descriptionSource",
	"liveRegion",
	"math",
	"annotations",
	"developerInformation",
	"apiDetails",
	"diagnostics",
	"children",
)
type FixtureValue = None | bool | int | float | str | FixtureArray | FixtureObject
type FixtureArray = list[FixtureValue]
type FixtureObject = dict[str, FixtureValue]
type FixtureMutation = Callable[[FixtureObject], object]


def objectValue(container: FixtureObject, key: str) -> FixtureObject:
	value = container[key]
	if not isinstance(value, dict):
		raise AssertionError(f"{key} is not an object fixture")
	return value


def arrayValue(container: FixtureObject, key: str) -> FixtureArray:
	value = container[key]
	if not isinstance(value, list):
		raise AssertionError(f"{key} is not an array fixture")
	return value


def envelope(value: FixtureValue, symbol: str = "field") -> FixtureObject:
	return {
		"status": "value",
		"value": value,
		"source": {"backend": "generic", "component": "CaptureAdapter", "symbol": symbol},
		"projection": {"mode": "normalNvda", "fallbackApplied": False},
		"confidence": "direct",
		"privacy": {
			"fieldGroup": "node",
			"classification": "public",
			"effectiveTransform": "retain",
			"policyRevision": 1,
		},
	}


def nonvalue(status: str = "notApplicable", symbol: str = "field") -> FixtureObject:
	return {
		"status": status,
		"source": {"backend": "generic", "component": "CaptureAdapter", "symbol": symbol},
		"projection": {"mode": "normalNvda", "fallbackApplied": False},
		"confidence": "indeterminate",
		"privacy": {
			"fieldGroup": "node",
			"classification": "unknown",
			"effectiveTransform": "retain",
			"policyRevision": 1,
		},
	}


def conventions() -> FixtureObject:
	return {
		"schemaName": "keystone.capture",
		"schemaVersion": "2.0",
		"requiredFieldPolicy": "required fields are never omitted",
		"nonValuePolicy": "status is independent from value",
		"geometryPolicy": "signed half-open virtual-screen pixels",
		"nodeOrdering": "capture traversal order",
		"childOrdering": "provider child order",
	}


def metadata(
	kind: str,
	*,
	node_count: int,
	containing_foreground: FixtureObject | None = None,
) -> FixtureObject:
	return {
		"capture": {
			"generatedAt": "2026-07-25T10:30:00+00:00",
			"sourcePath": envelope("", "sourcePath"),
			"outputPath": envelope("snapshot.json", "outputPath"),
			"captureKind": kind,
			"rawUiaEnabled": False,
			"containingForeground": containing_foreground or nonvalue(),
			"screenshot": {
				"attempted": False,
				"result": nonvalue(),
				"warning": "Screenshots are unredacted visual evidence.",
			},
			"diagnostics": {"retained": 0, "total": 0, "truncated": False},
			"conventions": conventions(),
		},
		"environment": {
			"keystoneVersion": envelope("0.0.0", "keystoneVersion"),
			"nvdaVersion": envelope("2026.1", "nvdaVersion"),
			"windowsVersion": envelope("11", "windowsVersion"),
			"architecture": envelope("x86_64", "architecture"),
			"dpi": envelope(96, "dpi"),
			"monitors": envelope([], "monitors"),
			"backends": envelope(["generic"], "backends"),
		},
		"limits": {
			"maximumDepth": 64,
			"maximumNodes": 1000,
			"maximumStringScalars": 100000,
			"maximumCollectionItems": 100000,
		},
		"counts": {"visited": node_count, "emitted": node_count, "failed": 0, "truncated": 0},
		"duration": {"elapsedMilliseconds": 0},
		"projection": {"name": "normalNvda", "revision": 1},
		"redaction": {"enabled": False, "policy": "default", "revision": 1},
	}


def provider_section(applicable: bool) -> FixtureObject:
	return {
		"status": envelope("available") if applicable else nonvalue(),
		"identity": envelope("generic") if applicable else nonvalue(),
		"properties": envelope([]) if applicable else nonvalue(),
	}


def node(key: str = "n1", *, parent: str | None = None, children: list[str] | None = None) -> FixtureObject:
	child_keys: FixtureArray = [item for item in (() if children is None else children)]
	values: FixtureObject = {
		field: envelope([], field)
		if field in {"states", "annotations", "diagnostics"}
		else envelope("", field)
		for field in COMMON_NODE_FIELDS
	}
	details: FixtureObject = {
		"key": key,
		"structure": {
			"parentKey": parent,
			"depth": 0 if parent is None else 1,
			"childKeys": child_keys,
			"cycleDetected": False,
			"truncated": False,
			"childFetchFailed": False,
		},
		"geometry": envelope([-10, 0, 0, 0, -10, 0], "geometry"),
		"windowHandle": envelope(0, "windowHandle"),
		"windowControlId": envelope(0, "windowControlId"),
		"childCount": envelope(len(child_keys), "childCount"),
		"indexInParent": envelope(0, "indexInParent"),
		"focusable": envelope(False, "focusable"),
		"focused": envelope(False, "focused"),
		"children": envelope(child_keys, "children"),
		"providers": {
			"generic": provider_section(True),
			"uia": provider_section(False),
			"ia2Msaa": provider_section(False),
			"jab": provider_section(False),
			"overlay": provider_section(False),
			"rawUia": provider_section(False),
			"customUia": provider_section(False),
		},
	}
	values.update(details)
	return values


def summary_node(key: str = "n1", children: list[str] | None = None) -> FixtureObject:
	child_keys: FixtureArray = [item for item in (() if children is None else children)]
	return {
		"key": key,
		"name": envelope("", "name"),
		"role": envelope("document", "role"),
		"states": envelope([], "states"),
		"protection": envelope(False, "protection"),
		"children": envelope(child_keys, "children"),
		"cycleDetected": False,
		"truncated": False,
		"childFetchFailed": False,
	}


def document(kind: str, document_id: int = 1) -> FixtureObject:
	document_id_text = f"00000000-0000-0000-0000-{document_id:012d}"
	base: FixtureObject = {
		"schemaVersion": {"major": 2, "minor": 0},
		"documentKind": kind,
		"documentId": document_id_text,
	}
	if kind == "snapshot":
		base["metadata"] = metadata(kind, node_count=1)
		base["roots"] = ["n1"]
		base["nodes"] = [node()]
	elif kind == "navigatorSnapshot":
		base["metadata"] = metadata(
			kind,
			node_count=1,
			containing_foreground=envelope("foreground-1", "containingForeground"),
		)
		base["root"] = "n1"
		base["nodes"] = [node()]
	elif kind in {"snapshotSummary", "navigatorSummary"}:
		source_kind = "snapshot" if kind == "snapshotSummary" else "navigatorSnapshot"
		base["metadata"] = metadata(kind, node_count=1)
		base["summary"] = {
			"sourceDocumentId": "00000000-0000-0000-0000-000000000099",
			"sourceKind": source_kind,
			"rootKeys": ["n1"],
			"nodes": [summary_node()],
			"counts": {
				"roots": 1,
				"nodes": 1,
				"cycles": 0,
				"truncated": 0,
				"childFetchFailures": 0,
			},
		}
	else:
		raise ValueError(f"unsupported capture document kind: {kind}")
	return base


def encoded_document(kind: str, document_id: int = 1) -> bytes:
	return json.dumps(document(kind, document_id), ensure_ascii=False, separators=(",", ":")).encode()


class SnapshotTracerTests(unittest.TestCase):
	def test_complete_snapshot_round_trips_byte_identically_and_is_immutable(self) -> None:
		admitted = admitDocument(encoded_document("snapshot"))
		self.assertIsInstance(admitted, Snapshot)
		metadata = admitted.metadata
		self.assertIsInstance(metadata, CaptureMetadata)
		assert isinstance(metadata, CaptureMetadata)
		self.assertEqual(
			("", False, 0, ()),
			(
				metadata.capture.sourcePath.value,
				metadata.redaction.enabled,
				metadata.duration.elapsedMilliseconds,
				admitted.nodes[0].structure.childKeys,
			),
		)
		canonical = encodeCanonical(admitted)
		self.assertEqual(canonical, encodeCanonical(admitDocument(canonical)))
		with self.assertRaises(FrozenInstanceError):
			admitted.nodes[0].key = "changed"  # type: ignore[misc]

	def test_hollow_snapshot_layers_and_stale_screenshot_values_are_rejected(self) -> None:
		mutations: tuple[tuple[str, FixtureMutation], ...] = (
			("node", lambda value: arrayValue(value, "nodes").__setitem__(0, {"key": "n1"})),
			("capture", lambda value: objectValue(value, "metadata").__setitem__("capture", {})),
			("environment", lambda value: objectValue(value, "metadata").__setitem__("environment", {})),
			(
				"conventions",
				lambda value: objectValue(objectValue(value, "metadata"), "capture").__setitem__(
					"conventions",
					{},
				),
			),
			(
				"failed screenshot retaining a path",
				lambda value: objectValue(
					objectValue(objectValue(value, "metadata"), "capture"),
					"screenshot",
				).__setitem__(
					"result",
					{
						**envelope("old.png"),
						"status": "failed",
						"errorRef": {"code": "capture.failed", "diagnosticId": "diag-1"},
					},
				),
			),
		)
		for label, mutate in mutations:
			candidate = document("snapshot")
			_ = mutate(candidate)
			with self.subTest(label=label), self.assertRaisesRegex(ValueError, "closed|requires|forbids"):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())


class CaptureFamilyClosureTests(unittest.TestCase):
	def test_navigator_and_summary_families_have_concrete_records(self) -> None:
		cases = (
			("navigatorSnapshot", NavigatorSnapshot),
			("snapshotSummary", SnapshotSummary),
			("navigatorSummary", NavigatorSummary),
		)
		for kind, expected_type in cases:
			with self.subTest(kind=kind):
				admitted = admitDocument(encoded_document(kind))
				self.assertIsInstance(admitted, expected_type)
				self.assertEqual(
					encodeCanonical(admitted),
					encodeCanonical(admitDocument(encodeCanonical(admitted))),
				)

	def test_navigator_root_is_exact_and_carries_foreground_evidence(self) -> None:
		admitted = admitDocument(encoded_document("navigatorSnapshot"))
		self.assertEqual("n1", admitted.root)
		self.assertEqual(1, len(admitted.nodes))
		metadata = admitted.metadata
		assert isinstance(metadata, CaptureMetadata)
		self.assertEqual("foreground-1", metadata.capture.containingForeground.value)
		mutations: tuple[FixtureMutation, ...] = (
			lambda value: value.__setitem__("root", "missing"),
			lambda value: arrayValue(value, "nodes").append(node("n2")),
			lambda value: objectValue(objectValue(value, "metadata"), "capture").__setitem__(
				"containingForeground",
				nonvalue(),
			),
		)
		for mutation in mutations:
			candidate = document("navigatorSnapshot")
			_ = mutation(candidate)
			with self.assertRaises(ValueError):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())

	def test_summary_shape_flags_references_and_counts_are_closed(self) -> None:
		def summaryNode(value: FixtureObject) -> FixtureObject:
			item = arrayValue(objectValue(value, "summary"), "nodes")[0]
			if not isinstance(item, dict):
				raise AssertionError("summary node fixture is not an object")
			return item

		mutations: tuple[FixtureMutation, ...] = (
			lambda value: value.__setitem__("summary", {}),
			lambda value: summaryNode(value).pop("protection"),
			lambda value: summaryNode(value).__setitem__("extra", True),
			lambda value: arrayValue(objectValue(value, "summary"), "rootKeys").__setitem__(0, "missing"),
			lambda value: objectValue(objectValue(value, "summary"), "counts").__setitem__("nodes", 2),
			lambda value: summaryNode(value).__setitem__("cycleDetected", True),
			lambda value: objectValue(value, "summary").__setitem__("sourceKind", "navigatorSnapshot"),
		)
		for mutation in mutations:
			candidate = document("snapshotSummary")
			_ = mutation(candidate)
			with self.assertRaises(ValueError):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())

	def test_every_required_nested_field_and_unknown_field_are_rejected(self) -> None:
		def firstNode(value: FixtureObject) -> FixtureObject:
			item = arrayValue(value, "nodes")[0]
			if not isinstance(item, dict):
				raise AssertionError("node fixture is not an object")
			return item

		mutations: tuple[tuple[str, FixtureMutation], ...] = (
			(
				"capture.generatedAt",
				lambda value: objectValue(objectValue(value, "metadata"), "capture").pop("generatedAt"),
			),
			(
				"environment.dpi",
				lambda value: objectValue(objectValue(value, "metadata"), "environment").pop("dpi"),
			),
			(
				"limits.maximumDepth",
				lambda value: objectValue(objectValue(value, "metadata"), "limits").pop("maximumDepth"),
			),
			(
				"counts.visited",
				lambda value: objectValue(objectValue(value, "metadata"), "counts").pop("visited"),
			),
			(
				"duration.elapsedMilliseconds",
				lambda value: objectValue(objectValue(value, "metadata"), "duration").pop(
					"elapsedMilliseconds",
				),
			),
			(
				"projection.name",
				lambda value: objectValue(objectValue(value, "metadata"), "projection").pop("name"),
			),
			(
				"redaction.enabled",
				lambda value: objectValue(objectValue(value, "metadata"), "redaction").pop("enabled"),
			),
			("node.role", lambda value: firstNode(value).pop("role")),
			(
				"structure.childKeys",
				lambda value: objectValue(firstNode(value), "structure").pop("childKeys"),
			),
			("providers.generic", lambda value: objectValue(firstNode(value), "providers").pop("generic")),
		)
		for label, mutate in mutations:
			candidate = document("snapshot")
			_ = mutate(candidate)
			with self.subTest(field=label), self.assertRaises(ValueError):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())
		for field in COMMON_NODE_FIELDS:
			candidate = document("snapshot")
			_ = firstNode(candidate).pop(field)
			with self.subTest(commonNodeField=field), self.assertRaises(ValueError):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())
		metadataFields = {
			"capture": (
				"generatedAt",
				"sourcePath",
				"outputPath",
				"captureKind",
				"rawUiaEnabled",
				"containingForeground",
				"screenshot",
				"diagnostics",
				"conventions",
			),
			"environment": (
				"keystoneVersion",
				"nvdaVersion",
				"windowsVersion",
				"architecture",
				"dpi",
				"monitors",
				"backends",
			),
			"limits": (
				"maximumDepth",
				"maximumNodes",
				"maximumStringScalars",
				"maximumCollectionItems",
			),
			"counts": ("visited", "emitted", "failed", "truncated"),
			"duration": ("elapsedMilliseconds",),
			"projection": ("name", "revision"),
			"redaction": ("enabled", "policy", "revision"),
		}
		for category, fields in metadataFields.items():
			for field in fields:
				candidate = document("snapshot")
				metadataFixture = objectValue(candidate, "metadata")
				_ = objectValue(metadataFixture, category).pop(field)
				with (
					self.subTest(metadataCategory=category, metadataField=field),
					self.assertRaises(ValueError),
				):
					_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())
		for section in ("generic", "uia", "ia2Msaa", "jab", "overlay", "rawUia", "customUia"):
			for field in ("status", "identity", "properties"):
				candidate = document("snapshot")
				providers = objectValue(firstNode(candidate), "providers")
				_ = objectValue(providers, section).pop(field)
				with (
					self.subTest(providerSection=section, providerField=field),
					self.assertRaises(ValueError),
				):
					_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())
		for field in (
			"schemaName",
			"schemaVersion",
			"requiredFieldPolicy",
			"nonValuePolicy",
			"geometryPolicy",
			"nodeOrdering",
			"childOrdering",
		):
			candidate = document("snapshot")
			capture = objectValue(objectValue(candidate, "metadata"), "capture")
			_ = objectValue(capture, "conventions").pop(field)
			with self.subTest(conventionField=field), self.assertRaises(ValueError):
				_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())
		candidate = document("snapshot")
		objectValue(objectValue(candidate, "metadata"), "capture")["unknown"] = True
		with self.assertRaises(ValueError):
			_ = admitDocument(json.dumps(candidate, separators=(",", ":")).encode())


if __name__ == "__main__":
	_ = unittest.main()
