from __future__ import annotations

import json
from pathlib import Path
from typing import cast
import unittest

from addon.globalPlugins.keystone.domain.documents import DOCUMENT_TYPES, DocumentKind
from addon.globalPlugins.keystone.encoding.canonical_json import (
	AdmissionLimits,
	admitDocument,
	encodeCanonical,
)
from tests.unit.test_document_capture_families import document, encoded_document, objectValue
from tests.unit.test_document_families import family_document


ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "encoding" / "canonical_document.json"
type JsonFixture = None | bool | int | float | str | list[JsonFixture] | dict[str, JsonFixture]


class DocumentAdmissionTests(unittest.TestCase):
	def test_all_closed_document_families_admit(self) -> None:
		cases: dict[DocumentKind, bytes] = {
			"snapshot": encoded_document("snapshot", 1),
			"navigatorSnapshot": encoded_document("navigatorSnapshot", 2),
			"snapshotSummary": encoded_document("snapshotSummary", 3),
			"navigatorSummary": encoded_document("navigatorSummary", 4),
			"diff": json.dumps(family_document("diff"), separators=(",", ":")).encode(),
			"eventExport": json.dumps(family_document("eventExport"), separators=(",", ":")).encode(),
			"diagnosticBundle": json.dumps(
				family_document("diagnosticBundle"),
				separators=(",", ":"),
			).encode(),
			"settingsSnapshot": json.dumps(
				family_document("settingsSnapshot"),
				separators=(",", ":"),
			).encode(),
			"customUiaConfiguration": json.dumps(
				family_document("customUiaConfiguration"),
				separators=(",", ":"),
			).encode(),
			"screenshotResult": json.dumps(
				family_document("screenshotResult"),
				separators=(",", ":"),
			).encode(),
			"publicationReceipt": json.dumps(
				family_document("publicationReceipt"),
				separators=(",", ":"),
			).encode(),
		}
		for kind, source in cases.items():
			with self.subTest(kind=kind):
				self.assertIsInstance(admitDocument(source), DOCUMENT_TYPES[kind])

	def test_unknown_missing_duplicate_and_unsupported_inputs_are_rejected(self) -> None:
		valid = encoded_document("snapshot")
		for invalid in (
			valid[:-1] + b',"secret":"x"}',
			valid.replace(b',"nodes":[', b',"missingNodes":['),
			valid.replace(b'"roots":["n1"]', b'"roots":["n1"],"roots":["n1"]'),
			valid.replace(b'"major":2', b'"major":1'),
			valid.replace(b'"snapshot"', b'"unknown"', 1),
		):
			with self.subTest(invalid=invalid), self.assertRaises(ValueError):
				_ = admitDocument(invalid)

	def test_kind_invariants_reject_contradictory_or_stale_evidence(self) -> None:
		diff = family_document("diff")
		diff["changes"] = None
		diff["noChange"] = False
		with self.assertRaises(ValueError):
			_ = admitDocument(json.dumps(diff, separators=(",", ":")).encode())
		screenshot = family_document("screenshotResult")
		result = screenshot["result"]
		assert isinstance(result, dict)
		result["status"] = "failed"
		result["error"] = {"code": "x", "diagnosticId": "d"}
		with self.assertRaises(ValueError):
			_ = admitDocument(json.dumps(screenshot, separators=(",", ":")).encode())

	def test_rejection_never_modifies_source_bytes(self) -> None:
		candidate = document("snapshot")
		del candidate["nodes"]
		source = bytearray(json.dumps(candidate, separators=(",", ":")).encode())
		before = bytes(source)
		with self.assertRaises(ValueError):
			_ = admitDocument(bytes(source))
		self.assertEqual(before, source)

	def test_each_admission_budget_has_an_exact_boundary(self) -> None:
		valid = encoded_document("snapshotSummary")
		self.assertIsNotNone(admitDocument(valid, AdmissionLimits(maximumBytes=len(valid))))
		with self.assertRaises(ValueError):
			_ = admitDocument(valid, AdmissionLimits(maximumBytes=len(valid) - 1))
		with self.assertRaises(ValueError):
			_ = admitDocument(valid, AdmissionLimits(maximumDepth=1))
		with self.assertRaises(ValueError):
			_ = admitDocument(valid, AdmissionLimits(maximumNodes=1))
		with self.assertRaises(ValueError):
			_ = admitDocument(valid, AdmissionLimits(maximumStringScalars=1))
		with self.assertRaises(ValueError):
			_ = admitDocument(valid, AdmissionLimits(maximumCollectionItems=1))

	def test_string_scalar_budget_counts_object_keys_and_values(self) -> None:
		valid = encoded_document("snapshotSummary")

		def scalarCount(value: JsonFixture) -> int:
			if isinstance(value, str):
				return len(value)
			if isinstance(value, list):
				return sum(scalarCount(item) for item in cast(list[JsonFixture], value))
			if isinstance(value, dict):
				items = cast(dict[str, JsonFixture], value)
				return sum(len(key) + scalarCount(item) for key, item in items.items())
			return 0

		total = scalarCount(cast(JsonFixture, json.loads(valid)))
		self.assertIsNotNone(admitDocument(valid, AdmissionLimits(maximumStringScalars=total)))
		with self.assertRaisesRegex(ValueError, "string-scalar limit"):
			_ = admitDocument(valid, AdmissionLimits(maximumStringScalars=total - 1))
		with self.assertRaisesRegex(ValueError, "string-scalar limit"):
			_ = admitDocument(b'{"oversizedKey":0}', AdmissionLimits(maximumStringScalars=11))

	def test_strict_utf8_bom_nonfinite_and_normalized_duplicate_keys_are_rejected(self) -> None:
		valid = encoded_document("snapshotSummary")
		for invalid in (
			b"\xef\xbb\xbf" + valid,
			valid[:-1] + b',"x":NaN}',
			valid.replace(
				b'"summary":{',
				'"summary":{"é":1,"é":2,'.encode(),
				1,
			),
			valid + b"\xff",
		):
			with self.assertRaises(ValueError):
				_ = admitDocument(invalid)
		with self.assertRaisesRegex(ValueError, "RFC 3339"):
			_ = admitDocument(valid.replace(b"2026-07-25T10:30:00+00:00", b"2026-07-25 10:30:00+00:00", 1))


class CanonicalEncodingTests(unittest.TestCase):
	def test_golden_bytes_are_a_complete_standalone_capture(self) -> None:
		encoded = encodeCanonical(admitDocument(encoded_document("snapshotSummary")))
		self.assertEqual(GOLDEN.read_bytes(), encoded)
		self.assertTrue(encoded.endswith(b"\n"))
		self.assertFalse(encoded.startswith(b"\xef\xbb\xbf"))
		self.assertIn(b'"requiredFieldPolicy":"required fields are never omitted"', encoded)

	def test_equivalent_ordering_and_normalization_produce_identical_bytes(self) -> None:
		first = document("snapshotSummary")
		second = document("snapshotSummary")
		objectValue(objectValue(objectValue(first, "metadata"), "capture"), "outputPath")["value"] = "é"
		objectValue(objectValue(objectValue(second, "metadata"), "capture"), "outputPath")["value"] = "é"
		second = dict(reversed(tuple(second.items())))
		self.assertEqual(
			encodeCanonical(admitDocument(json.dumps(first, ensure_ascii=False).encode())),
			encodeCanonical(admitDocument(json.dumps(second, ensure_ascii=False).encode())),
		)

	def test_concurrent_encoding_has_no_shared_mutable_state(self) -> None:
		from concurrent.futures import ThreadPoolExecutor

		admitted = admitDocument(encoded_document("snapshot"))
		with ThreadPoolExecutor(max_workers=8) as executor:

			def encode(_index: int) -> bytes:
				return encodeCanonical(admitted)

			results = tuple(executor.map(encode, range(100)))
		self.assertEqual(1, len(set(results)))


if __name__ == "__main__":
	_ = unittest.main()
