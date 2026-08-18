from __future__ import annotations

import unittest

from addon.globalPlugins.keystone.domain.document_records import (
	JsonArray,
	JsonObject,
	JsonValue,
	parseEvidenceEnvelope,
)
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState
from tests.fixtures.representative_capture import (
	CAPTURE_CONFIGURATION,
	CORE,
	EXPECTED_RECORD_COUNTS,
	NODE_COUNT,
	PROTECTED_SAMPLE_SECRET,
	SCREENSHOT,
	TOPIC_ORDER,
	UIA,
	estimatedTokens,
	fieldValue,
	representativeCapture,
	topicBytes,
)

# The monolithic snapshot format previously serialized this same 413-node capture to 12,687,027
# uncompressed bytes (roughly 3.17 million estimated tokens); a hand-reduced high-signal proof of the
# same capture measured 71,697 bytes (roughly 18,000 estimated tokens). Those figures are recorded here
# only as narrative context for why a lean, partitioned benchmark exists. They are never written to a
# file and never used as a pass or fail threshold.


def _stringValue(record: JsonObject, key: str) -> str:
	value = fieldValue(record, key)
	if not isinstance(value, str):
		raise AssertionError(f"field {key!r} is not a string")
	return value


class RepresentativeInventoryTests(unittest.TestCase):
	def test_closed_inventory_matches_the_published_counts(self) -> None:
		capture = representativeCapture()
		self.assertEqual(EXPECTED_RECORD_COUNTS, capture.recordCounts)
		self.assertEqual(413, NODE_COUNT)
		self.assertEqual(413, capture.nodeCount)
		self.assertEqual(413, len(capture.topic(CORE).records))
		self.assertEqual(413, len(capture.topic(UIA).records))
		self.assertEqual(1, len(capture.topic(CAPTURE_CONFIGURATION).records))
		self.assertEqual(1, len(capture.topic(SCREENSHOT).records))

	def test_every_expected_topic_family_is_present_exactly_once(self) -> None:
		capture = representativeCapture()
		names = tuple(topic.name for topic in capture.topics)
		self.assertEqual(TOPIC_ORDER, names)
		self.assertEqual(len(set(names)), len(names))
		self.assertEqual(set(EXPECTED_RECORD_COUNTS), set(names))


class RepresentativeDeterminismTests(unittest.TestCase):
	def test_two_generations_are_equal_category_for_category(self) -> None:
		first = representativeCapture()
		second = representativeCapture()
		self.assertEqual(first, second)
		self.assertEqual(first.topics, second.topics)

	def test_two_generations_serialize_byte_for_byte(self) -> None:
		first = representativeCapture()
		second = representativeCapture()
		for left, right in zip(first.topics, second.topics, strict=True):
			self.assertEqual(left.name, right.name)
			self.assertEqual(topicBytes(left), topicBytes(right))

	def test_bundle_serializes_to_measurable_bytes_and_token_estimate(self) -> None:
		capture = representativeCapture()
		totalBytes = sum(len(topicBytes(topic)) for topic in capture.topics)
		self.assertGreater(totalBytes, 0)
		self.assertEqual(-(-totalBytes // 4), estimatedTokens(totalBytes))


class RepresentativeTopologyTests(unittest.TestCase):
	def test_single_root_bounded_depth_and_stable_sibling_order(self) -> None:
		capture = representativeCapture()
		coreRecords = capture.topic(CORE).records
		ids = tuple(_stringValue(record, "id") for record in coreRecords)
		self.assertEqual(tuple(f"n{index}" for index in range(NODE_COUNT)), ids)

		roots = tuple(record for record in coreRecords if fieldValue(record, "parent") is None)
		self.assertEqual(1, len(roots))
		self.assertEqual("n0", _stringValue(roots[0], "id"))

		depths = tuple(fieldValue(record, "depth") for record in coreRecords)
		self.assertEqual(0, depths[0])
		self.assertTrue(all(isinstance(depth, int) for depth in depths))
		self.assertLessEqual(max(depth for depth in depths if isinstance(depth, int)), 8)

		for index, record in enumerate(coreRecords):
			parent = fieldValue(record, "parent")
			if parent is None:
				continue
			self.assertIsInstance(parent, str)
			assert isinstance(parent, str)
			parentIndex = int(parent[1:])
			self.assertLess(parentIndex, index)


class RepresentativeEvidenceVarietyTests(unittest.TestCase):
	def test_normal_false_and_zero_observations_are_present(self) -> None:
		capture = representativeCapture()
		coreRecords = capture.topic(CORE).records
		focused = {fieldValue(record, "focused") for record in coreRecords}
		childCounts = {fieldValue(record, "childCount") for record in coreRecords}
		self.assertIn(True, focused)
		self.assertIn(False, focused)
		self.assertIn(0, childCounts)
		self.assertTrue(any(isinstance(count, int) and count > 0 for count in childCounts))

	def test_empty_observations_are_present_in_semantics(self) -> None:
		capture = representativeCapture()
		semantics = capture.topic("semantics").records
		emptyAnnotations = 0
		nullLandmarks = 0
		for record in semantics:
			annotations = fieldValue(record, "annotations")
			if isinstance(annotations, JsonArray) and not annotations.items:
				emptyAnnotations += 1
			if fieldValue(record, "landmark") is None:
				nullLandmarks += 1
		self.assertGreater(emptyAnnotations, 0)
		self.assertGreater(nullLandmarks, 0)

	def test_exceptional_evidence_records_round_trip_through_the_domain_parser(self) -> None:
		capture = representativeCapture()
		envelopes = tuple(
			parseEvidenceEnvelope(fieldValue(record, "evidence")) for record in capture.topic(UIA).records
		)
		statuses = {envelope.status for envelope in envelopes}
		self.assertIn(EvidenceState.VALUE, statuses)
		self.assertIn(EvidenceState.EMPTY, statuses)
		self.assertIn(EvidenceState.STALE, statuses)
		self.assertIn(EvidenceState.TRUNCATED, statuses)
		self.assertIn(EvidenceState.REDACTED, statuses)

		confidences = {envelope.confidence for envelope in envelopes}
		self.assertIn(Confidence.DIRECT, confidences)
		self.assertIn(Confidence.FLATTENED_BY_WRAPPER, confidences)

		self.assertTrue(any(envelope.source.wrapperLoss is not None for envelope in envelopes))
		self.assertTrue(any(envelope.truncation is not None for envelope in envelopes))
		self.assertTrue(any(envelope.projection.fallbackApplied for envelope in envelopes))

	def test_capture_wide_configuration_record_is_recorded_once(self) -> None:
		capture = representativeCapture()
		configuration = capture.topic(CAPTURE_CONFIGURATION).records
		self.assertEqual(1, len(configuration))
		record = configuration[0]
		self.assertEqual(413, fieldValue(record, "nodeCount"))
		rootIds = fieldValue(record, "rootIds")
		self.assertIsInstance(rootIds, JsonArray)
		assert isinstance(rootIds, JsonArray)
		self.assertEqual(("n0",), rootIds.items)


class RepresentativePrivacyTests(unittest.TestCase):
	def test_protected_sample_value_never_reaches_serialized_evidence(self) -> None:
		capture = representativeCapture()
		secret = PROTECTED_SAMPLE_SECRET.encode("utf-8")
		for topic in capture.topics:
			self.assertNotIn(secret, topicBytes(topic))

	def test_a_protected_value_is_transformed_to_a_redacted_record(self) -> None:
		capture = representativeCapture()
		redacted = tuple(
			parseEvidenceEnvelope(fieldValue(record, "evidence"))
			for record in capture.topic(UIA).records
			if _isRedacted(fieldValue(record, "evidence"))
		)
		self.assertTrue(redacted)
		for envelope in redacted:
			self.assertEqual(EvidenceState.REDACTED, envelope.status)
			self.assertIsNone(envelope.value)
			self.assertEqual("protected", envelope.privacy.classification)


def _isRedacted(evidence: JsonValue) -> bool:
	if not isinstance(evidence, JsonObject):
		return False
	for name, value in evidence.items:
		if name == "status":
			return value == EvidenceState.REDACTED.value
	return False


if __name__ == "__main__":
	_ = unittest.main()
