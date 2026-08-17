from __future__ import annotations

import json
from pathlib import Path
import unittest

from addon.globalPlugins.keystone.domain.provider_measurement import (
	BACKEND_IDS,
	CONTRACT_DIGEST,
	MEASUREMENT_OUTCOMES,
	MeasurementObservation,
	MeasurementProvenance,
	MeasurementRecorder,
	aggregateMeasurements,
	candidateArtifact,
	distribution,
	proposeThreshold,
	sourceDigest,
	validateCandidateArtifact,
)
from tests.contract.fakes import ExpectedCall, StrictCallFake


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "provider" / "measurement_cases.json"
DIGEST = "1" * 64
PROVENANCE = MeasurementProvenance(DIGEST, CONTRACT_DIGEST)


def observations() -> tuple[MeasurementObservation, ...]:
	rows = json.loads(FIXTURE_PATH.read_bytes())
	return tuple(
		MeasurementObservation(
			row["backend"],
			row["operation"],
			row["outcome"],
			row["durationMicroseconds"],
			row["itemCount"],
			row["budget"],
			PROVENANCE,
		)
		for row in rows
	)


class _FakeClock:
	def __init__(self, values: tuple[int, ...]) -> None:
		super().__init__()
		self._fake = StrictCallFake(
			"clock",
			tuple(ExpectedCall("nowMicroseconds", (), value) for value in values),
		)

	def nowMicroseconds(self) -> int:
		value = self._fake.member("nowMicroseconds")()
		if not isinstance(value, int):
			raise AssertionError("clock fake returned a non-integer")
		return value


class MeasurementRecorderTests(unittest.TestCase):
	def test_recorder_uses_only_monotonic_integer_duration(self) -> None:
		recorder = MeasurementRecorder(_FakeClock((100, 175)))
		result = recorder.observe("uia", "fieldRead", "success", PROVENANCE, lambda: None)
		self.assertEqual(75, result.durationMicroseconds)

	def test_recorder_rejects_backwards_clock_and_unsafe_shapes(self) -> None:
		with self.assertRaises(ValueError):
			_ = MeasurementRecorder(_FakeClock((5, 4))).observe(
				"uia",
				"fieldRead",
				"success",
				PROVENANCE,
				lambda: None,
			)
		with self.assertRaises((TypeError, ValueError)):
			_ = MeasurementObservation(
				"uia",
				"fieldRead",
				"success",
				1,
				0,
				0,
				PROVENANCE,
				(("budget", "C:\\Users\\name\\secret"),),  # pyright: ignore[reportArgumentType]
			)

	def test_closed_registries_reject_unknown_values(self) -> None:
		with self.assertRaises(ValueError):
			_ = MeasurementObservation(
				"unknown",  # pyright: ignore[reportArgumentType]
				"fieldRead",
				"success",
				1,
				0,
				0,
				PROVENANCE,
			)
		self.assertEqual(5, len(BACKEND_IDS))
		self.assertEqual(11, len(MEASUREMENT_OUTCOMES))


class DistributionTests(unittest.TestCase):
	def test_nearest_rank_and_histogram_boundaries_are_exact(self) -> None:
		result = distribution((100_001, 1, 1_000, 10_000, 100_000, 1_000_001))
		self.assertEqual(
			(6, 1, 1_000_001, 10_000, 1_000_001),
			(
				result.count,
				result.minimum,
				result.maximum,
				result.median,
				result.p95,
			),
		)
		self.assertEqual((2, 1, 1, 1, 1), tuple(count for _limit, count in result.histogram))

	def test_empty_singleton_equal_and_reordered_inputs_are_deterministic(self) -> None:
		self.assertEqual(0, distribution(()).count)
		self.assertEqual(7, distribution((7,)).median)
		self.assertEqual(distribution((1, 2, 3, 4)), distribution((4, 2, 1, 3)))
		self.assertEqual(4, distribution((4, 4, 4)).p99)

	def test_aggregation_keeps_every_fault_outcome_separate(self) -> None:
		aggregates = aggregateMeasurements(observations())
		uia = next(item for item in aggregates if item.backend == "uia")
		counts = dict(uia.faults.counts)
		self.assertEqual(1, counts["slow"])
		self.assertEqual(1, counts["blocked"])
		self.assertEqual(1, counts["success"])
		self.assertEqual(
			tuple(sorted(aggregates, key=lambda item: (item.backend, item.operation))),
			aggregates,
		)


class CandidateArtifactTests(unittest.TestCase):
	def test_candidate_and_no_candidate_reasons_are_typed(self) -> None:
		aggregates = aggregateMeasurements(observations())
		ia2 = next(item for item in aggregates if item.backend == "ia2Msaa")
		self.assertEqual("candidate", proposeThreshold(ia2).status)
		singleton = aggregateMeasurements((observations()[0],))[0]
		self.assertEqual("insufficientSamples", proposeThreshold(singleton).reasonCode)

	def test_artifact_is_byte_stable_candidate_only_and_validates(self) -> None:
		rows = observations()
		data = candidateArtifact(aggregateMeasurements(rows), sourceDigest(rows), CONTRACT_DIGEST)
		self.assertEqual(
			data,
			candidateArtifact(
				aggregateMeasurements(tuple(reversed(rows))),
				sourceDigest(rows),
				CONTRACT_DIGEST,
			),
		)
		validateCandidateArtifact(data)
		self.assertIn(b'"status":"candidateOnly"', data)

	def test_artifact_rejects_noncanonical_or_authoritative_claims(self) -> None:
		rows = observations()
		data = candidateArtifact(aggregateMeasurements(rows), sourceDigest(rows), CONTRACT_DIGEST)
		with self.assertRaises(ValueError):
			validateCandidateArtifact(data.rstrip())
		with self.assertRaises(ValueError):
			validateCandidateArtifact(data.replace(b"candidateOnly", b"approved     "))
		for data in (b"[]\n", b'"value"\n'):
			with self.subTest(data=data), self.assertRaisesRegex(ValueError, "root must be an object"):
				validateCandidateArtifact(data)

	def test_artifact_rejects_nonstring_digests_as_validation_errors(self) -> None:
		rows = observations()
		data = candidateArtifact(aggregateMeasurements(rows), sourceDigest(rows), CONTRACT_DIGEST)
		for digest in (sourceDigest(rows), CONTRACT_DIGEST):
			invalid = data.replace(f'"{digest}"'.encode(), b"7")
			self.assertNotEqual(data, invalid)
			with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "digest"):
				validateCandidateArtifact(invalid)


if __name__ == "__main__":
	_ = unittest.main()
