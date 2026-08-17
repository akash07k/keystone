from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from addon.globalPlugins.keystone.domain.document_records import (
	CustomUiaConfigurationRecord,
	DiagnosticRecord,
	DiffChange,
	EventDrops,
	EventRecord,
	PublicationRecord,
	ScreenshotDocumentResult,
	SettingsSnapshotRecord,
)
from addon.globalPlugins.keystone.domain.documents import (
	CustomUiaConfiguration,
	DiagnosticBundleDocument,
	Diff,
	EventExport,
	PublicationReceipt,
	ScreenshotResult,
	SettingsSnapshot,
)
from addon.globalPlugins.keystone.domain.settings import SETTING_DEFINITIONS
from addon.globalPlugins.keystone.encoding.canonical_json import admitDocument, encodeCanonical
from tests.unit.test_document_capture_families import document as capture_document


type FixtureValue = None | bool | int | float | str | FixtureArray | FixtureObject
type FixtureArray = list[FixtureValue]
type FixtureObject = dict[str, FixtureValue]


def envelope(value: FixtureValue, symbol: str = "field") -> FixtureObject:
	return {
		"status": "value",
		"value": value,
		"source": {"backend": "generic", "component": "DocumentWriter", "symbol": symbol},
		"projection": {"mode": "derived", "fallbackApplied": False},
		"confidence": "direct",
		"privacy": {
			"fieldGroup": "document",
			"classification": "public",
			"effectiveTransform": "retain",
			"policyRevision": 3,
		},
	}


def nonvalue(status: str = "notApplicable", symbol: str = "field") -> FixtureObject:
	result: FixtureObject = {
		"status": status,
		"source": {"backend": "generic", "component": "DocumentWriter", "symbol": symbol},
		"projection": {"mode": "derived", "fallbackApplied": False},
		"confidence": "indeterminate",
		"privacy": {
			"fieldGroup": "document",
			"classification": "unknown",
			"effectiveTransform": "retain",
			"policyRevision": 3,
		},
	}
	if status in {"failed", "rejected"}:
		result["errorRef"] = {"code": "document.failed", "diagnosticId": "diag-error"}
	return result


def metadata() -> FixtureObject:
	return {
		"capture": {
			"generatedAt": "2026-07-25T10:30:00+00:00",
			"operationId": "operation-1",
			"sourceDocumentIds": ["00000000-0000-0000-0000-000000000001"],
			"conventions": {
				"schemaName": "keystone.document",
				"schemaVersion": "2.0",
				"requiredFieldPolicy": "required fields are never omitted",
				"nonValuePolicy": "status is independent from value",
				"orderingPolicy": "document semantic order",
			},
		},
		"environment": {
			"keystoneVersion": "0.0.0",
			"nvdaVersion": "2026.1",
			"windowsVersion": "11",
		},
		"limits": {"maximumItems": 1000},
		"counts": {"emitted": 1},
		"duration": {"elapsedMilliseconds": 3},
		"projection": {"name": "derived", "revision": 1},
		"redaction": {"enabled": True, "policy": "default", "revision": 3},
	}


def identity(document_id: int) -> FixtureObject:
	return {
		"documentId": f"00000000-0000-0000-0000-{document_id:012d}",
		"documentKind": "snapshot",
		"schema": {"major": 2, "minor": 0},
		"projection": "normalNvda",
		"privacyRevision": 3,
		"admission": {"admitted": True, "code": None},
	}


def diff_change(kind: str = "modified") -> FixtureObject:
	before: FixtureValue = envelope("old", "before")
	after: FixtureValue = envelope("new", "after")
	children: FixtureArray = []
	if kind == "added":
		before = None
	elif kind == "removed":
		after = None
	elif kind == "nested":
		before = after = None
		children = [diff_change()]
	return {
		"changeKind": kind,
		"ancestorPath": ["root", "name"],
		"before": before,
		"after": after,
		"changes": children,
	}


def event_record() -> FixtureObject:
	return {
		"eventId": "event-1",
		"eventName": "nameChange",
		"receivedAt": "2026-07-25T10:30:00+00:00",
		"processedAt": "2026-07-25T10:30:00.010000+00:00",
		"propertyReadAt": "2026-07-25T10:30:00.005000+00:00",
		"source": envelope("uia", "eventSource"),
		"settings": {
			"revision": 4,
			"redactionEnabled": True,
			"eventDetailCharacters": 100,
		},
		"target": {"scopeKind": "operation", "scopeId": "operation-1", "providerProcessId": 42},
		"sanitizedDetail": envelope("Name changed", "eventDetail"),
	}


def drop_counter(count: int = 0) -> FixtureObject:
	return {"count": count, "reasonCode": None if count == 0 else "queue.full"}


def event_drops() -> FixtureObject:
	return {
		"receipt": drop_counter(),
		"pendingQueue": drop_counter(2),
		"processing": drop_counter(),
		"propertyRead": drop_counter(),
		"retainedRows": drop_counter(1),
		"export": drop_counter(),
	}


def diagnostic(index: int = 0) -> FixtureObject:
	start = index * 10
	return {
		"diagnosticId": f"diag-{index}",
		"code": "document.read.failed",
		"fieldPath": "/nodes/0/name",
		"safeBreadcrumb": ["document", "node-0"],
		"component": "DocumentWriter",
		"provider": envelope("uia", "provider"),
		"severity": "warning",
		"sanitizedDetail": "A bounded safe detail.",
		"timing": {
			"startMilliseconds": start,
			"endMilliseconds": start + 3,
			"elapsedMilliseconds": 3,
		},
		"budget": envelope(100, "budget"),
		"fallback": envelope(True, "fallback"),
		"correlation": {
			"sessionCorrelationId": "session-1",
			"operationCorrelationId": "operation-1",
			"documentCorrelationId": "document-1",
		},
	}


def document(kind: str, content: FixtureObject, document_id: int) -> FixtureObject:
	return {
		"schemaVersion": {"major": 2, "minor": 0},
		"documentKind": kind,
		"documentId": f"00000000-0000-0000-0000-{document_id:012d}",
		"metadata": metadata(),
		**content,
	}


def settings_record() -> FixtureObject:
	values: FixtureArray = []
	for definition in SETTING_DEFINITIONS:
		value = definition.default
		if not isinstance(value, (bool, int, float, str)):
			raise AssertionError("setting fixture default is not JSON-compatible")
		entry: FixtureObject = {
			"settingId": definition.settingId.value,
			"kind": definition.kind.value,
			"value": value,
		}
		values.append(entry)
	return {
		"scope": "global",
		"revision": 4,
		"values": values,
		"validation": {
			"status": "validated",
			"validator": "settingsRegistry",
			"validatedAt": "2026-07-25T10:30:00+00:00",
		},
		"correlationId": "settings-1",
	}


def custom_configuration() -> FixtureObject:
	return {
		"configurationId": "custom-uia-1",
		"definitions": [
			{
				"definitionId": "definition-1",
				"guid": "00000000-0000-0000-0000-000000000001",
				"name": "ExampleProperty",
				"valueType": "string",
				"privacyClassification": "sensitive",
				"targets": ["application"],
			},
		],
		"allowedTargets": ["application", "window"],
		"allowedValueTypes": ["string", "integer", "boolean"],
		"allowedPrivacyClassifications": ["public", "unknown", "sensitive", "protected"],
		"validation": {
			"status": "validated",
			"code": None,
			"validatedAt": "2026-07-25T10:30:00+00:00",
		},
		"restartRequired": True,
	}


def screenshot_result(*, status: str = "value") -> FixtureObject:
	image: FixtureValue = {
		"storage": "path",
		"mediaType": "image/png",
		"value": envelope("screenshot-current.png", "screenshotPath"),
		"sha256": "a" * 64,
		"byteLength": 1024,
		"width": 800,
		"height": 600,
		"capturedAt": "2026-07-25T10:30:00.020000+00:00",
	}
	error: FixtureValue = None
	if status != "value":
		image = None
		error = {"code": "screenshot.failed", "diagnosticId": "diag-screenshot"}
	return {
		"attempt": {
			"requestId": "screenshot-1",
			"generation": 2,
			"target": {"scopeKind": "operation", "scopeId": "operation-1"},
			"requestedAt": "2026-07-25T10:30:00+00:00",
		},
		"status": status,
		"image": image,
		"error": error,
		"warning": (
			"Screenshot pixels are unredacted visual evidence and may contain sensitive visible content."
		),
	}


def publication_record() -> FixtureObject:
	return {
		"publicationId": "publication-1",
		"captureKind": "snapshot",
		"committedFiles": [
			{"name": "snapshot.json", "sha256": "b" * 64, "byteLength": 2048},
			{"name": "publication-metadata.json", "sha256": "c" * 64, "byteLength": 512},
		],
		"metadataHash": "d" * 64,
		"committedAt": "2026-07-25T10:30:00.030000+00:00",
		"targetIdentity": {"applicationName": "example-42", "folderName": "capture-1"},
		"commitReceipt": "receipt-1",
	}


def family_document(kind: str, document_id: int | None = None) -> FixtureObject:
	identifiers = {
		"diff": 5,
		"eventExport": 6,
		"diagnosticBundle": 7,
		"settingsSnapshot": 8,
		"customUiaConfiguration": 9,
		"screenshotResult": 10,
		"publicationReceipt": 11,
	}
	identifier = identifiers[kind] if document_id is None else document_id
	content: FixtureObject
	if kind == "diff":
		content = {
			"baseline": identity(1),
			"current": identity(2),
			"changes": [diff_change()],
			"noChange": False,
		}
	elif kind == "eventExport":
		content = {"events": [event_record()], "drops": event_drops()}
	elif kind == "diagnosticBundle":
		content = {
			"diagnostics": [diagnostic()],
			"diagnosticsTotal": 1,
			"diagnosticsTruncated": False,
		}
	elif kind == "settingsSnapshot":
		content = {"settings": settings_record()}
	elif kind == "customUiaConfiguration":
		content = {"configuration": custom_configuration()}
	elif kind == "screenshotResult":
		content = {"result": screenshot_result(), "correlationId": "operation-1"}
	elif kind == "publicationReceipt":
		content = {"publication": publication_record(), "correlationId": "job-1"}
	else:
		raise ValueError(f"unsupported document family: {kind}")
	return document(kind, content, identifier)


def encoded(value: FixtureObject) -> bytes:
	return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class ActivityDocumentTests(unittest.TestCase):
	def test_diff_event_and_diagnostic_documents_round_trip_as_immutable_records(self) -> None:
		fixtures = (
			(
				document(
					"diff",
					{
						"baseline": identity(1),
						"current": identity(2),
						"changes": [diff_change(kind) for kind in ("added", "removed", "modified", "nested")],
						"noChange": False,
					},
					5,
				),
				Diff,
				DiffChange,
			),
			(
				document("eventExport", {"events": [event_record()], "drops": event_drops()}, 6),
				EventExport,
				EventRecord,
			),
			(
				document(
					"diagnosticBundle",
					{
						"diagnostics": [diagnostic()],
						"diagnosticsTotal": 1,
						"diagnosticsTruncated": False,
					},
					7,
				),
				DiagnosticBundleDocument,
				DiagnosticRecord,
			),
		)
		for fixture, document_type, record_type in fixtures:
			with self.subTest(kind=fixture["documentKind"]):
				admitted = admitDocument(encoded(fixture))
				self.assertIsInstance(admitted, document_type)
				self.assertIs(type(admitted.records[0]), record_type)
				canonical = encodeCanonical(admitted)
				self.assertEqual(canonical, encodeCanonical(admitDocument(canonical)))
				with self.assertRaises(FrozenInstanceError):
					admitted.records[0].__setattr__("invalid", True)

	def test_explicit_no_change_uses_null_and_no_records(self) -> None:
		fixture = document(
			"diff",
			{"baseline": identity(1), "current": identity(1), "changes": None, "noChange": True},
			5,
		)
		admitted = admitDocument(encoded(fixture))
		self.assertIsInstance(admitted, Diff)
		self.assertEqual((), admitted.records)

	def test_contradictory_activity_evidence_is_rejected(self) -> None:
		cases: list[tuple[str, FixtureObject]] = []
		bad_diff = document(
			"diff",
			{"baseline": identity(1), "current": identity(2), "changes": None, "noChange": False},
			5,
		)
		cases.append(("no-change", bad_diff))
		bad_change = document(
			"diff",
			{
				"baseline": identity(1),
				"current": identity(2),
				"changes": [diff_change("added")],
				"noChange": False,
			},
			5,
		)
		change = bad_change["changes"]
		assert isinstance(change, list)
		assert isinstance(change[0], dict)
		change[0]["before"] = envelope("stale")
		cases.append(("change discriminator", bad_change))
		bad_event = document("eventExport", {"events": [event_record()], "drops": event_drops()}, 6)
		events = bad_event["events"]
		assert isinstance(events, list)
		assert isinstance(events[0], dict)
		events[0]["processedAt"] = "2026-07-25T10:29:59+00:00"
		cases.append(("event timing", bad_event))
		bad_event_timestamp = document("eventExport", {"events": [event_record()], "drops": event_drops()}, 6)
		events = bad_event_timestamp["events"]
		assert isinstance(events, list)
		assert isinstance(events[0], dict)
		events[0]["receivedAt"] = "2026-07-25 10:30:00+00:00"
		cases.append(("event timestamp grammar", bad_event_timestamp))
		bad_drops = document("eventExport", {"events": [event_record()], "drops": event_drops()}, 6)
		drops = bad_drops["drops"]
		assert isinstance(drops, dict)
		pending = drops["pendingQueue"]
		assert isinstance(pending, dict)
		pending["reasonCode"] = None
		cases.append(("drop count", bad_drops))
		bad_diagnostics = document(
			"diagnosticBundle",
			{
				"diagnostics": [diagnostic()],
				"diagnosticsTotal": 2,
				"diagnosticsTruncated": False,
			},
			7,
		)
		cases.append(("diagnostic retention", bad_diagnostics))
		for label, fixture in cases:
			with self.subTest(label=label), self.assertRaises(ValueError):
				_ = admitDocument(encoded(fixture))

	def test_event_drop_categories_remain_distinct(self) -> None:
		admitted = admitDocument(
			encoded(document("eventExport", {"events": [event_record()], "drops": event_drops()}, 6)),
		)
		self.assertIsInstance(admitted, EventExport)
		drops = admitted.drops
		assert isinstance(drops, EventDrops)
		self.assertEqual((2, 1), (drops.pendingQueue.count, drops.retainedRows.count))


class RemainingDocumentFamilyTests(unittest.TestCase):
	def test_settings_custom_screenshot_and_publication_are_substantive_immutable_records(self) -> None:
		cases = (
			("settingsSnapshot", SettingsSnapshot, SettingsSnapshotRecord),
			("customUiaConfiguration", CustomUiaConfiguration, CustomUiaConfigurationRecord),
			("screenshotResult", ScreenshotResult, ScreenshotDocumentResult),
			("publicationReceipt", PublicationReceipt, PublicationRecord),
		)
		for kind, document_type, record_type in cases:
			with self.subTest(kind=kind):
				admitted = admitDocument(encoded(family_document(kind)))
				self.assertIsInstance(admitted, document_type)
				self.assertIsInstance(admitted.record, record_type)
				canonical = encodeCanonical(admitted)
				self.assertEqual(canonical, encodeCanonical(admitDocument(canonical)))
				with self.assertRaises(FrozenInstanceError):
					admitted.record.__setattr__("invalid", True)

	def test_settings_include_the_exact_registry_and_global_validation_provenance(self) -> None:
		admitted = admitDocument(encoded(family_document("settingsSnapshot")))
		self.assertIsInstance(admitted, SettingsSnapshot)
		record = admitted.record
		assert isinstance(record, SettingsSnapshotRecord)
		self.assertEqual(
			tuple(definition.settingId.value for definition in SETTING_DEFINITIONS),
			tuple(value.settingId for value in record.values),
		)
		self.assertEqual(
			("global", 4, "validated"),
			(record.scope, record.revision, record.validation.status),
		)

	def test_capability_boolean_records_the_user_choice_without_review_state(self) -> None:
		fixture = family_document("settingsSnapshot")
		settings = fixture["settings"]
		assert isinstance(settings, dict)
		values = settings["values"]
		assert isinstance(values, list)
		for value in values:
			assert isinstance(value, dict)
			if value["settingId"] == "forceRawUia":
				value["value"] = True
				break

		admitted = admitDocument(encoded(fixture))

		self.assertIsInstance(admitted, SettingsSnapshot)
		record = admitted.record
		assert isinstance(record, SettingsSnapshotRecord)
		for value in record.values:
			if value.settingId == "forceRawUia":
				self.assertTrue(value.value)
				break
		else:
			self.fail("forceRawUia setting was not retained")

	def test_screenshot_nonvalue_cannot_retain_current_image_metadata(self) -> None:
		fixture = family_document("screenshotResult")
		fixture["result"] = screenshot_result(status="failed")
		admitted = admitDocument(encoded(fixture))
		self.assertIsInstance(admitted, ScreenshotResult)
		record = admitted.record
		assert isinstance(record, ScreenshotDocumentResult)
		self.assertIsNone(record.image)
		result = fixture["result"]
		assert isinstance(result, dict)
		result["image"] = screenshot_result()["image"]
		with self.assertRaises(ValueError):
			_ = admitDocument(encoded(fixture))

	def test_publication_receipt_binds_identity_files_hash_and_correlation(self) -> None:
		admitted = admitDocument(encoded(family_document("publicationReceipt")))
		self.assertIsInstance(admitted, PublicationReceipt)
		record = admitted.record
		assert isinstance(record, PublicationRecord)
		self.assertEqual("publication-1", record.publicationId)
		self.assertEqual("job-1", admitted.correlationId)
		self.assertEqual(2, len(record.committedFiles))
		self.assertEqual("d" * 64, record.metadataHash)


def _all_documents() -> tuple[FixtureObject, ...]:
	captures = tuple(
		capture_document(kind, index)
		for index, kind in enumerate(
			("snapshot", "navigatorSnapshot", "snapshotSummary", "navigatorSummary"),
			start=1,
		)
	)
	remaining = tuple(
		family_document(kind)
		for kind in (
			"diff",
			"eventExport",
			"diagnosticBundle",
			"settingsSnapshot",
			"customUiaConfiguration",
			"screenshotResult",
			"publicationReceipt",
		)
	)
	return (*captures, *remaining)


def _object_paths(value: FixtureValue, path: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
	paths: list[tuple[str | int, ...]] = []
	if isinstance(value, dict):
		paths.append(path)
		for key, child in value.items():
			paths.extend(_object_paths(child, (*path, key)))
	elif isinstance(value, list):
		for index, child in enumerate(value):
			paths.extend(_object_paths(child, (*path, index)))
	return paths


def _at_path(value: FixtureObject, path: tuple[str | int, ...]) -> FixtureObject:
	current: object = value
	for part in path:
		if isinstance(part, int):
			assert isinstance(current, list)
			current = list(current)[part]
		else:
			assert isinstance(current, dict)
			current = dict(current)[part]
	if not isinstance(current, dict):
		raise AssertionError("fixture path does not resolve to an object")
	return current


class ExhaustiveDocumentShapeTests(unittest.TestCase):
	def test_exactly_eleven_closed_document_kinds_round_trip(self) -> None:
		documents = _all_documents()
		self.assertEqual(11, len(documents))
		kinds: set[str] = set()
		for fixture in documents:
			kind = fixture["documentKind"]
			assert isinstance(kind, str)
			kinds.add(kind)
		self.assertEqual(11, len(kinds))
		for fixture in documents:
			with self.subTest(kind=fixture["documentKind"]):
				admitted = admitDocument(encoded(fixture))
				self.assertEqual(
					encodeCanonical(admitted),
					encodeCanonical(admitDocument(encodeCanonical(admitted))),
				)

	def test_every_nested_object_rejects_missing_unknown_empty_and_duplicate_keys(self) -> None:
		for fixture in _all_documents():
			kind = fixture["documentKind"]
			for path in _object_paths(fixture):
				target = _at_path(fixture, path)
				if not target:
					continue
				for required_field in target:
					candidate = json.loads(json.dumps(fixture))
					candidate_target = _at_path(candidate, path)
					del candidate_target[required_field]
					with (
						self.subTest(
							kind=kind,
							path=path,
							mutation="missing",
							field=required_field,
						),
						self.assertRaises(ValueError),
					):
						_ = admitDocument(encoded(candidate))
				for mutation in ("unknown", "empty", "normalizedDuplicate"):
					candidate = json.loads(json.dumps(fixture))
					candidate_target = _at_path(candidate, path)
					if mutation == "unknown":
						candidate_target["unknownField"] = True
					elif mutation == "empty":
						candidate_target.clear()
					else:
						candidate_target["é"] = 1
						candidate_target["é"] = 2
					with (
						self.subTest(kind=kind, path=path, mutation=mutation),
						self.assertRaises(ValueError),
					):
						_ = admitDocument(encoded(candidate))


if __name__ == "__main__":
	_ = unittest.main()
