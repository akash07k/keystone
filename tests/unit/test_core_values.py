from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from addon.globalPlugins.keystone.domain.correlation import CorrelationContext, CorrelationId
from addon.globalPlugins.keystone.domain.diagnostics import (
	Diagnostic,
	DiagnosticSnapshot,
	Severity,
	Timing,
	retainDiagnostics,
)
from addon.globalPlugins.keystone.domain.evidence import (
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Scope,
	Source,
)
from addon.globalPlugins.keystone.domain.geometry import (
	GeometryState,
	Point,
	Rectangle,
	Size,
	checkedRectangle,
	clipRectangle,
)
from addon.globalPlugins.keystone.domain.identity import (
	IdentityCandidate,
	IdentityConflict,
	IdentityDecision,
	IdentityRecord,
	resolveIndexInParent,
)
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState


SOURCE = Source("generic", "provider", "field")
PROJECTION = Projection("normalNvda")
PRIVACY = PrivacyReference("node", "public", "retain", 1)
SESSION = CorrelationId("00000000-0000-4000-8000-000000000001")


def evidence(state: EvidenceState, value: object = None) -> EvidenceEnvelope:
	return EvidenceEnvelope(
		status=state,
		value=value,  # pyright: ignore[reportArgumentType]
		source=SOURCE,
		projection=PROJECTION,
		confidence=Confidence.DIRECT,
		privacy=PRIVACY,
	)


def diagnostic(index: int, *, code: str = "fieldUnavailable", path: str | None = None) -> Diagnostic:
	return Diagnostic(
		diagnosticId=f"diagnostic-{index}",
		code=code,
		fieldPath=path or f"/nodes/{index}/name",
		safeBreadcrumb=("window[0]", f"button[{index}]"),
		component="provider",
		provider=evidence(EvidenceState.VALUE, "uia"),
		severity=Severity.WARNING,
		sanitizedDetail="A bounded safe explanation.",
		timing=Timing(1.0, 2.5, 1.5),
		budget=evidence(EvidenceState.VALUE, (("limit", 50), ("consumed", 10))),
		fallback=evidence(EvidenceState.NOT_APPLICABLE),
		correlation=CorrelationContext(SESSION, generation=3),
	)


class EvidenceTests(unittest.TestCase):
	def test_privacy_reference_requires_positive_policy_revision(self) -> None:
		for revision in (0, True):
			with self.subTest(revision=revision), self.assertRaises(ValueError):
				_ = PrivacyReference("node", "public", "retain", revision)


class GeometryTests(unittest.TestCase):
	def test_rectangle_uses_checked_half_open_coordinates(self) -> None:
		rectangle = Rectangle(-100, -50, 30, 20)
		self.assertEqual(
			(-100, -50, -70, -30),
			(
				rectangle.left,
				rectangle.top,
				rectangle.right,
				rectangle.bottom,
			),
		)
		self.assertTrue(rectangle.contains(Point(-100, -50)))
		self.assertFalse(rectangle.contains(Point(-70, -30)))

	def test_empty_invalid_and_off_desktop_are_distinct(self) -> None:
		self.assertEqual(GeometryState.EMPTY, checkedRectangle(0, 0, 0, 10).state)
		self.assertEqual(GeometryState.INVALID, checkedRectangle(0, 0, -1, 10).state)
		desktop = Rectangle(0, 0, 1920, 1080)
		offDesktop = clipRectangle(Rectangle(-200, -100, 10, 10), desktop)
		self.assertEqual(GeometryState.OFF_DESKTOP, offDesktop.state)

	def test_clipping_keeps_requested_and_captured_rectangles_separate(self) -> None:
		requested = Rectangle(-10, -10, 30, 30)
		result = clipRectangle(requested, Rectangle(0, 0, 100, 100))
		self.assertEqual(GeometryState.VALID, result.state)
		self.assertEqual(requested, result.requested)
		self.assertEqual(Rectangle(0, 0, 20, 20), result.captured)

	def test_touching_edges_do_not_overlap(self) -> None:
		result = clipRectangle(Rectangle(100, 20, 10, 10), Rectangle(0, 0, 100, 100))
		self.assertEqual(GeometryState.OFF_DESKTOP, result.state)

	def test_checked_arithmetic_rejects_signed_overflow(self) -> None:
		maximum = (1 << 63) - 1
		self.assertEqual(GeometryState.INVALID, checkedRectangle(maximum, 0, 1, 1).state)
		with self.assertRaises(ValueError):
			_ = Point(maximum + 1, 0)
		with self.assertRaises(ValueError):
			_ = Size(-1, 1)


class IdentityTests(unittest.TestCase):
	def test_record_retains_ordered_candidates_conflicts_and_ambiguity(self) -> None:
		scope = Scope("process", "process-7", providerProcessId=7)
		first = IdentityCandidate(
			"candidate-a",
			"uiaAutomationId",
			evidence(EvidenceState.VALUE, "save"),
			scope,
			Confidence.DIRECT,
		)
		second = IdentityCandidate(
			"candidate-b",
			"uiaRuntimeId",
			evidence(EvidenceState.VALUE, (1, 2)),
			scope,
			Confidence.DIRECT,
		)
		conflict = IdentityConflict("candidate-a", "candidate-b", "differentProviderIdentity")
		record = IdentityRecord(
			identityRecordVersion=1,
			providerProcessId=evidence(EvidenceState.VALUE, 7),
			logicalApplication=evidence(EvidenceState.VALUE, (("module", "notepad"),)),
			windowHandle=evidence(EvidenceState.VALUE, 42),
			backend=evidence(EvidenceState.VALUE, "uia"),
			overlayClasses=evidence(EvidenceState.VALUE, ("Button",)),
			candidates=(first, second),
			conflicts=(conflict,),
			ambiguous=True,
			decision=IdentityDecision.AMBIGUOUS,
		)
		self.assertEqual((first, second), record.candidates)
		self.assertTrue(record.ambiguous)

	def test_candidates_must_be_unique_ordered_and_conflicts_must_resolve(self) -> None:
		scope = Scope("process", "process-7")
		first = IdentityCandidate(
			"candidate-b",
			"uiaRuntimeId",
			evidence(EvidenceState.VALUE, (1,)),
			scope,
			Confidence.DIRECT,
		)
		second = IdentityCandidate(
			"candidate-a",
			"uiaAutomationId",
			evidence(EvidenceState.VALUE, "save"),
			scope,
			Confidence.DIRECT,
		)
		with self.assertRaises(ValueError):
			_ = IdentityRecord(
				1,
				evidence(EvidenceState.VALUE, 7),
				evidence(EvidenceState.VALUE, (("module", "notepad"),)),
				evidence(EvidenceState.EMPTY),
				evidence(EvidenceState.VALUE, "uia"),
				evidence(EvidenceState.VALUE, ()),
				(first, second),
				(),
				False,
				IdentityDecision.CONSISTENT,
			)
		with self.assertRaises(ValueError):
			_ = IdentityConflict("missing", "candidate-a", "conflict").validateAgainst(
				frozenset(("candidate-a",)),
			)

	def test_identity_scalar_envelopes_reject_wrong_or_negative_values(self) -> None:
		with self.assertRaises(ValueError):
			_ = IdentityRecord(
				1,
				evidence(EvidenceState.VALUE, -1),
				evidence(EvidenceState.VALUE, (("module", "notepad"),)),
				evidence(EvidenceState.EMPTY),
				evidence(EvidenceState.VALUE, "uia"),
				evidence(EvidenceState.VALUE, ()),
				(),
				(),
				False,
				IdentityDecision.CANDIDATE_ONLY,
			)

	def test_index_in_parent_uses_only_provider_or_successful_ordinal(self) -> None:
		provider = resolveIndexInParent(evidence(EvidenceState.VALUE, 4), successfulChildOrdinal=2)
		self.assertEqual(("provider", 4), (provider.source, provider.value))
		ordinal = resolveIndexInParent(evidence(EvidenceState.UNAVAILABLE), successfulChildOrdinal=2)
		self.assertEqual(("ordinal", 2), (ordinal.source, ordinal.value))
		unavailable = resolveIndexInParent(evidence(EvidenceState.UNAVAILABLE), successfulChildOrdinal=None)
		self.assertEqual("unavailable", unavailable.source)
		with self.assertRaises(ValueError):
			_ = resolveIndexInParent(evidence(EvidenceState.VALUE, -1), successfulChildOrdinal=None)


class DiagnosticTests(unittest.TestCase):
	def test_retention_boundaries_preserve_exact_totals_and_order(self) -> None:
		for total in (0, 1, 249, 250, 251, 299, 300, 301, 350, 1000):
			with self.subTest(total=total):
				bundle = retainDiagnostics(tuple(diagnostic(index) for index in range(total)))
				expectedCount = total if total <= 300 else 300
				self.assertEqual(total, bundle.diagnosticsTotal)
				self.assertEqual(expectedCount, len(bundle.diagnostics))
				self.assertEqual(total > 300, bundle.diagnosticsTruncated)
				if total > 300:
					expectedIds = tuple(
						[f"diagnostic-{index}" for index in range(250)]
						+ [f"diagnostic-{index}" for index in range(total - 50, total)],
					)
					self.assertEqual(expectedIds, tuple(item.diagnosticId for item in bundle.diagnostics))

	def test_repeated_codes_at_different_locations_remain_distinct(self) -> None:
		bundle = retainDiagnostics(
			(
				diagnostic(1, code="sameCode", path="/nodes/1/name"),
				diagnostic(2, code="sameCode", path="/nodes/2/name"),
			),
		)
		self.assertEqual(2, len(bundle.diagnostics))
		self.assertNotEqual(bundle.diagnostics[0].fieldPath, bundle.diagnostics[1].fieldPath)

	def test_diagnostic_detail_is_bounded_and_records_are_frozen(self) -> None:
		item = diagnostic(1)
		with self.assertRaises(FrozenInstanceError):
			item.code = "changed"  # type: ignore[misc]
		with self.assertRaises(ValueError):
			_ = Diagnostic(
				diagnosticId="too-long",
				code="detailTooLong",
				fieldPath="/nodes/1",
				safeBreadcrumb=("window[0]",),
				component="provider",
				provider=evidence(EvidenceState.NOT_APPLICABLE),
				severity=Severity.ERROR,
				sanitizedDetail="x" * 1025,
				timing=Timing(0, 0, 0),
				budget=evidence(EvidenceState.NOT_APPLICABLE),
				fallback=evidence(EvidenceState.NOT_APPLICABLE),
				correlation=CorrelationContext(SESSION),
			)

	def test_empty_bundle_is_exact_and_stale_snapshot_access_is_rejected(self) -> None:
		bundle = retainDiagnostics(())
		self.assertEqual(
			((), 0, False),
			(
				bundle.diagnostics,
				bundle.diagnosticsTotal,
				bundle.diagnosticsTruncated,
			),
		)
		snapshot = DiagnosticSnapshot(4, retainDiagnostics((diagnostic(1),)))
		self.assertEqual("diagnostic-1", snapshot.get(4, 0).diagnosticId)
		with self.assertRaises(ValueError):
			_ = snapshot.get(3, 0)

	def test_timing_and_structural_fields_reject_malformed_values(self) -> None:
		with self.assertRaises(ValueError):
			_ = Timing(3, 2, 1)
		with self.assertRaises(ValueError):
			_ = diagnostic(1, path="not-a-json-pointer")
		with self.assertRaises(ValueError):
			_ = retainDiagnostics((diagnostic(1), diagnostic(1)))


if __name__ == "__main__":
	_ = unittest.main()
