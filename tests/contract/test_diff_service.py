from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import unittest

from addon.globalPlugins.keystone.adapters.windows.publication import PublicationPackage, PublicationPolicy
from addon.globalPlugins.keystone.application.capture_service import CaptureRequest, CaptureResult
from addon.globalPlugins.keystone.application.diff_service import DiffService
from addon.globalPlugins.keystone.domain.correlation import CorrelationContext, CorrelationFactory
from addon.globalPlugins.keystone.domain.document_records import RedactionMetadata
from addon.globalPlugins.keystone.domain.documents import Snapshot
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy
from addon.globalPlugins.keystone.ports.effects import ScreenshotTarget
from addon.globalPlugins.keystone.presentation.status_presenter import (
	OutputCompletionOutcome,
	OutputCompletionPresentation,
	presentOutputCompletion,
)
from tests.unit.test_diffing import makeNode, makeSnapshot


@dataclass
class _Capture:
	fullCaptureBaseline: Snapshot | None
	fullCaptureBaselineRequest: CaptureRequest | None
	bootstrap: CaptureResult
	current: CaptureResult
	captureCalls: int = field(default=0, init=False)
	currentCalls: int = field(default=0, init=False)

	def __post_init__(self) -> None:
		self.captureCalls = 0
		self.currentCalls = 0

	def capture(self, request: CaptureRequest) -> CaptureResult:
		self.captureCalls += 1
		snapshot = self.bootstrap.snapshot
		if not isinstance(snapshot, Snapshot):
			raise AssertionError("bootstrap fake requires a full snapshot")
		self.fullCaptureBaseline = snapshot
		self.fullCaptureBaselineRequest = request
		return self.bootstrap

	def captureForDiff(self, request: CaptureRequest) -> CaptureResult:
		self.currentCalls += 1
		return self.current


class _Output:
	def __init__(self, outcome: OutputCompletionOutcome = OutputCompletionOutcome.COMMITTED) -> None:
		super().__init__()
		self.outcome = outcome
		self.calls: list[tuple[PublicationPackage, ScreenshotTarget, int, object]] = []

	def publishDiff(
		self,
		package: PublicationPackage,
		target: ScreenshotTarget,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation:
		self.calls.append((package, target, lifecycleGeneration, context))
		if self.outcome is OutputCompletionOutcome.COMMITTED_WITH_WARNING:
			return presentOutputCompletion(
				self.outcome,
				"20260726-120000.000-diff",
				"diff-action",
				"KS.OUTPUT.SIDECAR_WARNING",
			)
		return presentOutputCompletion(
			self.outcome,
			"20260726-120000.000-diff",
			"diff-action",
		)


def _captureResult(snapshot: Snapshot, *, generation: int = 1) -> CaptureResult:
	from addon.globalPlugins.keystone.domain.state import CaptureLifecycle, CaptureState
	from addon.globalPlugins.keystone.domain.traversal import ProviderDegradation, TraversalResult

	context = CorrelationFactory().admit(generation=generation)
	return CaptureResult(
		CaptureLifecycle.start(generation)
		.advance(CaptureState.COLLECTING)
		.advance(CaptureState.TRANSFORMING)
		.advance(CaptureState.SCREENSHOT)
		.advance(CaptureState.SERIALIZING)
		.advance(CaptureState.STAGING)
		.advance(CaptureState.VALIDATING)
		.advance(CaptureState.READY_TO_COMMIT)
		.beginCommit()
		.finishCommit(CaptureState.COMPLETED),
		context,
		TraversalResult((), (), (), (), (), ProviderDegradation("closed", 0, 0, 3), False, False),
		snapshot,
		None,
		None,
		None,
		True,
	)


class DiffServiceTracerTests(unittest.TestCase):
	def _request(
		self,
		*,
		processId: int = 42,
		scopeId: str = "window-42",
	) -> CaptureRequest:
		return CaptureRequest(
			"foreground",
			"root-ref",
			ScreenshotTarget("containingForeground", scopeId, (0, 0, 40, 30)),
			"reader.exe",
			processId,
		)

	def _service(
		self,
		baseline: Snapshot | None,
		current: Snapshot,
		*,
		baselineRequest: CaptureRequest | None = None,
	) -> tuple[DiffService, _Capture, _Output]:
		bootstrap = _captureResult(current)
		capture = _Capture(baseline, baselineRequest, bootstrap, _captureResult(current))
		output = _Output()
		service = DiffService(
			capture,
			output,
			privacyPolicy=PrivacyPolicy(2, 2, True),
			documentIdFactory=lambda: "00000000-0000-4000-8000-000000000099",
			publicationIdFactory=lambda: "publication-diff",
			now=lambda: datetime(2026, 7, 26, 6, 30, tzinfo=timezone.utc),
			environment=("0.0.0", "2026.1", "Windows 11"),
		)
		return service, capture, output

	def test_same_target_change_publishes_privacy_safe_old_and_new(self) -> None:
		request = self._request()
		baseline = makeSnapshot((makeNode("old", name="Before", automationId="root"),))
		current = makeSnapshot((makeNode("new", name="After", automationId="root"),), identifier=2)
		service, capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("changed", result.outcome)
		self.assertEqual(1, capture.currentCalls)
		self.assertIs(baseline, capture.fullCaptureBaseline)
		self.assertEqual(1, len(output.calls))
		document = json.loads(output.calls[0][0].artifacts[0][1])
		self.assertEqual("modified", document["changes"][0]["changeKind"])
		self.assertEqual(["root", "name"], document["changes"][0]["ancestorPath"])
		self.assertEqual("Before", document["changes"][0]["before"]["value"])
		self.assertEqual("After", document["changes"][0]["after"]["value"])
		self.assertNotIn("screenshot", document)
		self.assertTrue(document["diffMetadata"]["admission"]["admitted"])

	def test_a_baseline_redacted_under_another_rule_is_refused_not_relabelled(self) -> None:
		request = self._request()
		baseline = makeSnapshot(
			(makeNode("old", name="Before", automationId="root"),),
			redaction=RedactionMetadata(True, "default", 2),
		)
		current = makeSnapshot(
			(makeNode("new", name="After", automationId="root"),),
			identifier=2,
			redaction=RedactionMetadata(False, "default", 7),
		)
		service, capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("rejected", result.outcome)
		self.assertEqual("KS.DIFF.BASELINE_POLICY_MISMATCH", result.errorCode)
		self.assertEqual([], output.calls)
		# The baseline is left exactly as captured, so the user can re-baseline deliberately.
		self.assertIs(baseline, capture.fullCaptureBaseline)

	def test_each_reference_reports_the_revision_its_own_capture_recorded(self) -> None:
		request = self._request()
		baseline = makeSnapshot(
			(makeNode("old", name="Before", automationId="root"),),
			redaction=RedactionMetadata(False, "default", 3),
		)
		current = makeSnapshot(
			(makeNode("new", name="After", automationId="root"),),
			identifier=2,
			redaction=RedactionMetadata(False, "default", 9),
		)
		service, _capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("changed", result.outcome)
		document = json.loads(output.calls[0][0].artifacts[0][1])
		self.assertEqual(3, document["baseline"]["privacyRevision"])
		self.assertEqual(9, document["current"]["privacyRevision"])

	def test_a_staged_policy_reaches_the_next_diff_and_leaves_the_published_one_alone(self) -> None:
		request = self._request()
		baseline = makeSnapshot((makeNode("old", name="Before", automationId="root"),))
		current = makeSnapshot((makeNode("new", name="After", automationId="root"),), identifier=2)
		service, capture, output = self._service(baseline, current, baselineRequest=request)
		staged: list[int] = []
		takeCurrent = capture.captureForDiff

		def stageWhileDiffing(request: CaptureRequest) -> CaptureResult:
			# A settings dialog is applied while this diff is already comparing.
			if not staged:
				staged.append(1)
				service.stageConfiguration(PrivacyPolicy(7, 7, False))
			return takeCurrent(request)

		capture.captureForDiff = stageWhileDiffing

		firstResult = service.diff(request)
		secondResult = service.diff(request)

		self.assertEqual([1], staged)
		self.assertEqual("changed", firstResult.outcome)
		self.assertEqual("changed", secondResult.outcome)
		published = json.loads(output.calls[0][0].artifacts[0][1])
		following = json.loads(output.calls[1][0].artifacts[0][1])
		# The diff that was already comparing keeps the policy it started under.
		self.assertEqual(2, published["diffMetadata"]["privacy"]["policyRevision"])
		self.assertTrue(published["diffMetadata"]["privacy"]["redactionEnabled"])
		self.assertEqual(7, following["diffMetadata"]["privacy"]["policyRevision"])
		self.assertFalse(following["diffMetadata"]["privacy"]["redactionEnabled"])

	def test_target_mismatch_rejects_before_diff_publication(self) -> None:
		baselineRequest = self._request()
		request = self._request(processId=43)
		baseline = makeSnapshot((makeNode("old", automationId="root"),))
		current = makeSnapshot((makeNode("new", automationId="root"),), identifier=2)
		service, _capture, output = self._service(baseline, current, baselineRequest=baselineRequest)

		result = service.diff(request)

		self.assertEqual("rejected", result.outcome)
		self.assertEqual("KS.DIFF.TARGET_PROCESS_MISMATCH", result.errorCode)
		self.assertEqual([], output.calls)


class DiffServiceOutcomeTests(DiffServiceTracerTests):
	def test_missing_baseline_commits_full_capture_and_requires_second_invocation(self) -> None:
		request = self._request()
		current = makeSnapshot((makeNode("root", automationId="root"),))
		service, capture, output = self._service(None, current)

		result = service.diff(request)

		self.assertEqual("baselineCreated", result.outcome)
		self.assertEqual(1, capture.captureCalls)
		self.assertEqual(0, capture.currentCalls)
		self.assertEqual([], output.calls)

	def test_no_change_publishes_explicit_null_content_and_keeps_baseline(self) -> None:
		request = self._request()
		baseline = makeSnapshot((makeNode("old", automationId="root"),))
		current = makeSnapshot((makeNode("new", automationId="root"),), identifier=2)
		service, capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("noChange", result.outcome)
		self.assertIs(baseline, capture.fullCaptureBaseline)
		document = json.loads(output.calls[0][0].artifacts[0][1])
		self.assertTrue(document["noChange"])
		self.assertIsNone(document["changes"])
		self.assertEqual("normalNvda", document["diffMetadata"]["baseline"]["projection"])
		self.assertFalse(document["diffMetadata"]["baseline"]["rawUiaEnabled"])
		self.assertEqual("reader.exe", document["diffMetadata"]["baseline"]["application"])

	def test_warned_publication_returns_a_successful_diff_and_preserves_feedback(self) -> None:
		request = self._request()
		baseline = makeSnapshot((makeNode("old", name="Before", automationId="root"),))
		current = makeSnapshot((makeNode("new", name="After", automationId="root"),), identifier=2)
		service, _capture, output = self._service(baseline, current, baselineRequest=request)
		output.outcome = OutputCompletionOutcome.COMMITTED_WITH_WARNING

		result = service.diff(request)

		self.assertEqual("changed", result.outcome)
		self.assertIsNone(result.errorCode)
		assert result.document is not None
		assert result.publication is not None
		self.assertEqual(OutputCompletionOutcome.COMMITTED_WITH_WARNING, result.publication.outcome)
		self.assertEqual(3, len(result.publication.actions))

	def test_current_privacy_policy_blocks_old_and_new_protected_text(self) -> None:
		request = self._request()
		baseline = makeSnapshot(
			(makeNode("old", name="old secret", automationId="root", protectedName=True),),
		)
		current = makeSnapshot(
			(makeNode("new", name="new secret", automationId="root", protectedName=True),),
			identifier=2,
		)
		service, _capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("noChange", result.outcome)
		payload = output.calls[0][0].artifacts[0][1]
		self.assertNotIn(b"old secret", payload)
		self.assertNotIn(b"new secret", payload)

	def test_ambiguous_duplicate_group_rejects_without_artifact(self) -> None:
		request = self._request()
		baseline = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), automationId="root"),
				makeNode("a", parent="root"),
				makeNode("b", parent="root"),
			),
		)
		current = makeSnapshot(
			(
				makeNode("root2", children=("c", "d"), automationId="root"),
				makeNode("c", parent="root2"),
				makeNode("d", parent="root2"),
			),
			identifier=2,
		)
		service, _capture, output = self._service(baseline, current, baselineRequest=request)

		result = service.diff(request)

		self.assertEqual("rejected", result.outcome)
		self.assertEqual("KS.DIFF.AMBIGUOUS_MATCH", result.errorCode)
		self.assertEqual([], output.calls)


if __name__ == "__main__":
	_ = unittest.main()
