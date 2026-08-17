from __future__ import annotations

import ctypes
from dataclasses import FrozenInstanceError
import sys
import unittest

from addon.globalPlugins.keystone.domain.correlation import CorrelationContext, CorrelationId
from addon.globalPlugins.keystone.domain.evidence import (
	ErrorReference,
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Scope,
	Source,
	Truncation,
)
from addon.globalPlugins.keystone.domain.state import (
	CaptureLifecycle,
	CaptureState,
	PublicationLifecycle,
	PublicationState,
)
from addon.globalPlugins.keystone.domain.status import (
	Confidence,
	EvidenceState,
	EvidenceStateCounts,
	EvidenceValue,
	OutcomeSummary,
	normalizeEvidenceValue,
)


SOURCE = Source("uia", "provider", "name")
PROJECTION = Projection("normalNvda")
PRIVACY = PrivacyReference("node", "public", "retain", 1)
ERROR = ErrorReference("readFailed", "diagnostic-1")
TRUNCATION = Truncation("elements", 2, 5, 3, "elementLimit", False)


def envelope(
	state: EvidenceState,
	*,
	value: EvidenceValue | None = None,
	error: ErrorReference | None = None,
	truncation: Truncation | None = None,
) -> EvidenceEnvelope:
	return EvidenceEnvelope(
		status=state,
		value=value,
		source=SOURCE,
		projection=PROJECTION,
		confidence=Confidence.DIRECT,
		privacy=PRIVACY,
		truncation=truncation,
		errorRef=error,
		observedAt=None,
		scope=None,
	)


class EvidenceEnvelopeTests(unittest.TestCase):
	def test_projection_and_privacy_registries_are_closed_at_runtime(self) -> None:
		with self.assertRaisesRegex(ValueError, "projection mode"):
			_ = Projection("invalid")  # pyright: ignore[reportArgumentType]
		with self.assertRaisesRegex(ValueError, "privacy classification"):
			_ = PrivacyReference(
				"node",
				"invalid",  # pyright: ignore[reportArgumentType]
				"retain",
				1,
			)

	def test_all_closed_states_accept_their_minimal_valid_shape(self) -> None:
		valid = {
			EvidenceState.VALUE: envelope(EvidenceState.VALUE, value="name"),
			EvidenceState.EMPTY: envelope(EvidenceState.EMPTY),
			EvidenceState.UNSUPPORTED: envelope(EvidenceState.UNSUPPORTED),
			EvidenceState.NOT_APPLICABLE: envelope(EvidenceState.NOT_APPLICABLE),
			EvidenceState.UNAVAILABLE: envelope(EvidenceState.UNAVAILABLE),
			EvidenceState.STALE: envelope(EvidenceState.STALE),
			EvidenceState.REJECTED: envelope(EvidenceState.REJECTED, error=ERROR),
			EvidenceState.REDACTED: envelope(EvidenceState.REDACTED),
			EvidenceState.TRUNCATED: envelope(
				EvidenceState.TRUNCATED,
				value=("first", "second"),
				truncation=TRUNCATION,
			),
			EvidenceState.CANCELLED: envelope(EvidenceState.CANCELLED),
			EvidenceState.FAILED: envelope(EvidenceState.FAILED, error=ERROR),
			EvidenceState.MIXED: envelope(EvidenceState.MIXED, value=(("marker", "providerMixed"),)),
		}
		self.assertEqual(tuple(EvidenceState), tuple(valid))

	def test_false_zero_empty_string_and_empty_tuple_remain_values(self) -> None:
		for value in (False, 0, "", ()):
			with self.subTest(value=value):
				self.assertEqual(value, envelope(EvidenceState.VALUE, value=value).value)

	def test_nonvalue_states_reject_success_shaped_values(self) -> None:
		for state in EvidenceState:
			if state in {EvidenceState.VALUE, EvidenceState.TRUNCATED, EvidenceState.MIXED}:
				continue
			with self.subTest(state=state), self.assertRaises(ValueError):
				_ = envelope(
					state,
					value="optimistic",
					error=ERROR
					if state
					in {
						EvidenceState.REJECTED,
						EvidenceState.FAILED,
					}
					else None,
				)

	def test_value_error_and_truncation_compatibility_is_exact(self) -> None:
		with self.assertRaises(ValueError):
			_ = envelope(EvidenceState.VALUE)
		with self.assertRaises(ValueError):
			_ = envelope(EvidenceState.VALUE, value="name", error=ERROR)
		with self.assertRaises(ValueError):
			_ = envelope(EvidenceState.TRUNCATED, value=("one",))
		with self.assertRaises(ValueError):
			_ = envelope(EvidenceState.FAILED)
		with self.assertRaises(ValueError):
			_ = envelope(EvidenceState.EMPTY, error=ERROR)

	def test_values_are_normalized_and_mutable_values_are_rejected(self) -> None:
		result = envelope(EvidenceState.VALUE, value=("e\u0301", (("enabled", True),)))
		self.assertEqual(("é", (("enabled", True),)), result.value)
		with self.assertRaises(TypeError):
			_ = envelope(EvidenceState.VALUE, value=["mutable"])  # pyright: ignore[reportArgumentType]
		with self.assertRaises(TypeError):
			_ = envelope(EvidenceState.VALUE, value=lambda: None)  # pyright: ignore[reportArgumentType]

	def test_deep_values_are_rejected_before_python_recursion_is_exhausted(self) -> None:
		value: object = None
		for _ in range(65):
			value = (value,)

		with self.assertRaisesRegex(ValueError, "depth limit"):
			_ = normalizeEvidenceValue(value)

	def test_provider_compatible_value_depth_is_normalized(self) -> None:
		value: object = "e\u0301"
		for _ in range(64):
			value = (value,)

		normalized: EvidenceValue = normalizeEvidenceValue(value)
		for _ in range(64):
			self.assertIsInstance(normalized, tuple)
			if not isinstance(normalized, tuple):
				self.fail("nested evidence value must remain a tuple")
			normalized = normalized[0]
		self.assertEqual("é", normalized)

	@unittest.skipUnless(sys.implementation.name == "cpython", "requires CPython tuple internals")
	def test_cyclic_tuple_value_is_rejected_without_recursion(self) -> None:
		value: tuple[object, ...] = (None,)
		items = (ctypes.py_object * len(value)).from_address(id(value) + tuple.__basicsize__)
		items[0] = value
		try:
			with self.assertRaisesRegex(ValueError, "cyclic tuple"):
				_ = normalizeEvidenceValue(value)
		finally:
			items[0] = None

	def test_scoped_observation_requires_valid_timestamp_and_scope(self) -> None:
		scope = Scope("capture", "capture-1", providerProcessId=4)
		result = EvidenceEnvelope(
			status=EvidenceState.VALUE,
			value="name",
			source=SOURCE,
			projection=PROJECTION,
			confidence=Confidence.DIRECT,
			privacy=PRIVACY,
			observedAt="2026-07-23T19:00:00+00:00",
			scope=scope,
		)
		self.assertEqual(scope, result.scope)
		for invalid in (
			"2026-07-23T19:00:00",
			"2026-07-23 19:00:00+00:00",
			"2026-07-23T19:00:00+0000",
			"2026-07-23T19:00:00+00:00:30",
		):
			with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "RFC 3339"):
				_ = EvidenceEnvelope(
					status=EvidenceState.VALUE,
					value="name",
					source=SOURCE,
					projection=PROJECTION,
					confidence=Confidence.DIRECT,
					privacy=PRIVACY,
					observedAt=invalid,
					scope=scope,
				)
		self.assertEqual(
			"2026-07-23T19:00:00Z",
			EvidenceEnvelope(
				status=EvidenceState.VALUE,
				value="name",
				source=SOURCE,
				projection=PROJECTION,
				confidence=Confidence.DIRECT,
				privacy=PRIVACY,
				observedAt="2026-07-23T19:00:00Z",
				scope=scope,
			).observedAt,
		)
		for observedAt, candidateScope in (
			("2026-07-23T19:00:00+00:00", None),
			(None, scope),
		):
			with self.subTest(observedAt=observedAt, scope=candidateScope), self.assertRaises(ValueError):
				_ = EvidenceEnvelope(
					status=EvidenceState.VALUE,
					value="name",
					source=SOURCE,
					projection=PROJECTION,
					confidence=Confidence.DIRECT,
					privacy=PRIVACY,
					observedAt=observedAt,
					scope=candidateScope,
				)

	def test_envelopes_are_frozen(self) -> None:
		result = envelope(EvidenceState.VALUE, value="name")
		with self.assertRaises(FrozenInstanceError):
			result.value = "changed"  # type: ignore[misc]


class StatusTests(unittest.TestCase):
	def test_state_tokens_parse_encode_and_expose_stable_label_keys(self) -> None:
		for state in EvidenceState:
			with self.subTest(state=state):
				self.assertIs(state, EvidenceState.parse(state.value))
				self.assertEqual(f"evidenceState.{state.value}", state.labelKey)
		with self.assertRaises(ValueError):
			_ = EvidenceState.parse("unknown")

	def test_counts_follow_registry_order_and_keep_zeroes(self) -> None:
		counts = EvidenceStateCounts.fromEnvelopes(
			(
				envelope(EvidenceState.VALUE, value=False),
				envelope(EvidenceState.EMPTY),
				envelope(EvidenceState.VALUE, value=0),
			),
		)
		self.assertEqual(2, counts.count(EvidenceState.VALUE))
		self.assertEqual(1, counts.count(EvidenceState.EMPTY))
		self.assertEqual(0, counts.count(EvidenceState.FAILED))
		self.assertEqual(tuple(EvidenceState), tuple(state for state, _count in counts.items))

	def test_partial_and_failure_summaries_are_explicit(self) -> None:
		counts = EvidenceStateCounts.fromEnvelopes((envelope(EvidenceState.VALUE, value="name"),))
		partial = OutcomeSummary(
			"completedPartial",
			counts,
			successfulAreas=("accessibility",),
			failedAreas=("screenshot",),
		)
		self.assertTrue(partial.isPartial)
		failed = OutcomeSummary(
			"failed",
			counts,
			failedAreas=("provider",),
			errorCode="providerReadFailed",
			diagnosticId="diagnostic-2",
		)
		self.assertEqual("providerReadFailed", failed.errorCode)
		with self.assertRaises(ValueError):
			_ = OutcomeSummary("failed", counts, failedAreas=("provider",))


class CorrelationTests(unittest.TestCase):
	def test_ids_are_canonical_and_shortened_only_for_status(self) -> None:
		identifier = CorrelationId("12345678-1234-5678-9abc-def012345678")
		self.assertEqual("12345678-1234-5678-9abc-def012345678", identifier.value)
		self.assertEqual("12345678", identifier.statusSuffix)
		with self.assertRaises(ValueError):
			_ = CorrelationId("12345678-1234-5678-9ABC-DEF012345678")

	def test_context_retains_full_applicable_ids(self) -> None:
		session = CorrelationId("00000000-0000-4000-8000-000000000001")
		operation = CorrelationId("00000000-0000-4000-8000-000000000002")
		context = CorrelationContext(session, operationId=operation, generation=7)
		self.assertEqual(operation, context.operationId)
		self.assertEqual(7, context.generation)


class LifecycleTests(unittest.TestCase):
	def test_capture_cancellation_is_active_and_commit_success_wins(self) -> None:
		capture = CaptureLifecycle.start(4)
		cancelled = capture.requestCancellation().finishCancellation()
		self.assertEqual(CaptureState.CANCELLED, cancelled.state)
		self.assertTrue(cancelled.isTerminal)

		ready = (
			CaptureLifecycle.start(5)
			.advance(CaptureState.COLLECTING)
			.advance(CaptureState.YIELDED)
			.advance(CaptureState.COLLECTING)
			.advance(CaptureState.TRANSFORMING)
			.advance(CaptureState.SCREENSHOT)
			.advance(CaptureState.SERIALIZING)
			.advance(CaptureState.STAGING)
			.advance(CaptureState.VALIDATING)
			.advance(CaptureState.READY_TO_COMMIT)
		)
		committing = ready.beginCommit()
		with self.assertRaises(ValueError):
			_ = committing.requestCancellation()
		committed = committing.finishCommit(CaptureState.COMPLETED)
		self.assertTrue(committed.publicationCommitted)
		with self.assertRaises(ValueError):
			_ = committed.fail()

	def test_capture_pipeline_rejects_skipped_and_reverse_transitions(self) -> None:
		capture = CaptureLifecycle.start(1)
		with self.assertRaises(ValueError):
			_ = capture.advance(CaptureState.READY_TO_COMMIT)
		collecting = capture.advance(CaptureState.BASELINE_CAPTURE).advance(CaptureState.COLLECTING)
		with self.assertRaises(ValueError):
			_ = collecting.advance(CaptureState.ACQUIRING_TARGET)

	def test_publication_rename_is_the_only_commit_point(self) -> None:
		publication = PublicationLifecycle(PublicationState.STAGING, 2)
		ready = publication.markReady()
		committing = ready.beginRename()
		with self.assertRaises(ValueError):
			_ = committing.cancel()
		committed = committing.renameSucceeded()
		self.assertEqual(PublicationState.COMMITTED, committed.state)
		self.assertTrue(committed.committed)


if __name__ == "__main__":
	_ = unittest.main()
