from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import threading
from typing import cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.windows.publication import PublicationPackage, PublicationPolicy
from addon.globalPlugins.keystone.application.capture_service import (
	CaptureResult,
	CaptureRequest,
	CaptureService,
	CaptureTargetKind,
	CustomUiaCaptureOptions,
)
from addon.globalPlugins.keystone.adapters.providers.common import ProviderDatum, ProviderSectionData
from addon.globalPlugins.keystone.adapters.providers.custom_uia import (
	CustomUiaBudget,
	CustomUiaCaptureMode,
)
from addon.globalPlugins.keystone.application.lifecycle import LifecycleAdmission, LifecycleService
from addon.globalPlugins.keystone.capability import PlainValue
from addon.globalPlugins.keystone.domain.correlation import CorrelationContext
from addon.globalPlugins.keystone.domain import snapshot_bundle as sb
from addon.globalPlugins.keystone.domain.document_records import CaptureMetadata
from addon.globalPlugins.keystone.domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	annotationRecordsPlain,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy, ProtectionEvidence
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.domain.state import CaptureState
from addon.globalPlugins.keystone.domain.traversal import TraversalProgress
from addon.globalPlugins.keystone.ports.effects import ScreenshotAttempt, ScreenshotResult, ScreenshotTarget
from addon.globalPlugins.keystone.ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ProviderRelationRequest,
	ProviderTextRequest,
)
from addon.globalPlugins.keystone.presentation.status_presenter import (
	OutputCompletionOutcome,
	OutputCompletionPresentation,
	presentOutputCompletion,
)


class _Provider:
	def __init__(
		self,
		*,
		failedField: str | None = None,
		protected: bool = False,
		children: tuple[str, ...] = (),
		focusedByRef: dict[str, bool] | None = None,
		blockEntered: threading.Event | None = None,
		blockRelease: threading.Event | None = None,
		annotations: PlainValue | None = None,
	) -> None:
		super().__init__()
		self.failedField = failedField
		self.protected = protected
		self.children = children
		self.focusedByRef = focusedByRef or {}
		self.blockEntered = blockEntered
		self.blockRelease = blockRelease
		self.annotations = annotations
		self.contexts: list[object] = []
		self.metadataReads = 0

	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult:
		self.contexts.append(request.context)
		if self.blockEntered is not None and not self.blockEntered.is_set():
			self.blockEntered.set()
			assert self.blockRelease is not None
			if not self.blockRelease.wait(5):
				raise AssertionError("capture test did not release blocked provider")
		if request.fieldId == self.failedField:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.FIELD_FAILED")
		if request.fieldId == "annotations":
			return (
				ProviderReadResult("value", self.annotations)
				if self.annotations is not None
				else ProviderReadResult("unsupported")
			)
		values: dict[str, PlainValue] = {
			"name": "Selected root",
			"role": "document",
			"states": ("focusable",),
			"protection": self.protected,
			"windowHandle": 42,
			"windowControlId": 0,
			"childCount": 0,
			"indexInParent": 0,
			"focusable": True,
			"focused": self.focusedByRef.get(request.nodeRef, True),
			"geometry": (0, 0, 40, 30),
		}
		return ProviderReadResult("value", values.get(request.fieldId, ""))

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult:
		return ProviderReadResult("unsupported")

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult:
		return ProviderReadResult("unsupported")

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		self.metadataReads += 1
		return ProviderReadResult("unsupported")

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		self.contexts.append(request.context)
		items = self.children if request.nodeRef == "root-ref" else ()
		return ProviderChildBatch("value" if items else "empty", items, len(items), False)

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		self.contexts.append(request.context)
		return ProviderChildBatch("empty", (), 0, False)


class _Identity:
	def __init__(self, matches: tuple[tuple[str, str], ...] = ()) -> None:
		super().__init__()
		self.matches = frozenset(matches)
		self.requests: list[IdentityComparisonRequest] = []

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		self.requests.append(request)
		return IdentityComparisonResult(
			"value",
			"same"
			if (
				request.firstNodeRef == request.secondNodeRef
				or (request.firstNodeRef, request.secondNodeRef) in self.matches
			)
			else "different",
			(),
		)


class _Screenshot:
	def __init__(self, *, fail: bool = False, mismatchedAttempt: bool = False) -> None:
		super().__init__()
		self.fail = fail
		self.mismatchedAttempt = mismatchedAttempt
		self.attempts: list[ScreenshotAttempt] = []

	def captureScreenshot(self, attempt: ScreenshotAttempt) -> ScreenshotResult:
		self.attempts.append(attempt)
		resultAttempt = (
			ScreenshotAttempt(
				attempt.attemptId,
				attempt.generation,
				attempt.target,
				attempt.context,
			)
			if self.mismatchedAttempt
			else attempt
		)
		if self.fail:
			return ScreenshotResult(
				resultAttempt,
				"failed",
				None,
				None,
				None,
				"KS.SCREENSHOT.CAPTURE_FAILED",
				"screenshot-current",
			)
		return ScreenshotResult(
			resultAttempt,
			"value",
			b"\x89PNG\r\n\x1a\ncurrent",
			attempt.target.geometry,
			"2026-07-26T05:45:00+00:00",
			None,
			None,
		)


class _Output:
	def __init__(
		self,
		outcome: OutputCompletionOutcome = OutputCompletionOutcome.COMMITTED,
		onPublish: object | None = None,
	) -> None:
		super().__init__()
		self.outcome = outcome
		self.onPublish = onPublish
		self.packages: list[PublicationPackage] = []

	def publish(
		self,
		package: PublicationPackage,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation:
		self.packages.append(package)
		if callable(self.onPublish):
			_ = self.onPublish()
		if self.outcome is OutputCompletionOutcome.COMMITTED_WITH_WARNING:
			return presentOutputCompletion(
				self.outcome,
				"20260726-054500.000-snapshot",
				"capture-action",
				"KS.OUTPUT.SIDECAR_WARNING",
			)
		if self.outcome is not OutputCompletionOutcome.COMMITTED:
			return presentOutputCompletion(self.outcome)
		return presentOutputCompletion(
			OutputCompletionOutcome.COMMITTED,
			"20260726-054500.000-snapshot",
			"capture-action",
		)


class _CustomUiaCapture:
	def __init__(self) -> None:
		super().__init__()
		self.modes: list[CustomUiaCaptureMode] = []

	def collectCustomUia(
		self,
		nodeRef: object,
		*,
		mode: CustomUiaCaptureMode,
		captureSessionId: str,
		providerProcessId: int,
		budget: CustomUiaBudget,
		privacyPolicy: PrivacyPolicy,
		protection: ProtectionEvidence,
	) -> ProviderSectionData:
		_ = (
			nodeRef,
			captureSessionId,
			providerProcessId,
			budget,
			privacyPolicy,
			protection,
		)
		self.modes.append(mode)
		identity = (
			ProviderDatum(
				"known.sample.reading-mode.definition",
				ProviderReadResult(
					"value",
					("sample.reading-mode", "{12345678-1234-4ABC-8DEF-1234567890AB}"),
				),
			),
		)
		properties = (
			ProviderDatum("known.sample.reading-mode.current", ProviderReadResult("value", "current")),
		)
		if mode is CustomUiaCaptureMode.DIAGNOSTIC_EXPORT:
			properties += (
				ProviderDatum(
					"potentialProperties",
					ProviderReadResult("value", ("developer-only-inventory",)),
				),
				ProviderDatum(
					"collectionBudget",
					ProviderReadResult("value", (("calls", 3),)),
				),
			)
		return ProviderSectionData(
			"customUia",
			ProviderReadResult("value", "configured"),
			identity,
			properties,
		)


class _Ids:
	def __init__(self) -> None:
		super().__init__()
		self.value = 0

	def __call__(self) -> str:
		self.value += 1
		return f"00000000-0000-4000-8000-{self.value:012d}"


class _StepClock:
	def __init__(self, stepMilliseconds: int) -> None:
		super().__init__()
		self._stepMilliseconds = stepMilliseconds
		self._value = 0

	def __call__(self) -> int:
		self._value += self._stepMilliseconds
		return self._value


class _StalePrecommitLifecycle(LifecycleService):
	def __init__(self, staleCheck: int) -> None:
		super().__init__()
		self._staleCheck = staleCheck
		self._precommitChecks = 0

	@override
	def precommit(self, admission: LifecycleAdmission) -> bool:
		self._precommitChecks += 1
		if self._precommitChecks == self._staleCheck:
			self.transition("secure")
		return super().precommit(admission)


class CaptureTracerTests(unittest.TestCase):
	def _service(
		self,
		provider: _Provider | None = None,
		*,
		output: _Output | None = None,
		screenshotFail: bool = False,
		screenshotAttemptMismatch: bool = False,
		identity: _Identity | None = None,
		clockMilliseconds: Callable[[], int] | None = None,
		yieldControl: Callable[[int], None] | None = None,
		customUia: _CustomUiaCapture | None = None,
		lifecycle: LifecycleService | None = None,
	) -> tuple[CaptureService, _Provider, _Screenshot, _Output]:
		actualProvider = provider or _Provider()
		screenshot = _Screenshot(
			fail=screenshotFail,
			mismatchedAttempt=screenshotAttemptMismatch,
		)
		actualOutput = output or _Output()
		service = CaptureService(
			lifecycle or LifecycleService(),
			actualProvider,
			identity or _Identity(),
			actualOutput,
			screenshot,
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			privacyPolicy=PrivacyPolicy(1, 1, True),
			documentIdFactory=_Ids(),
			publicationIdFactory=lambda: "publication-current",
			screenshotAttemptIdFactory=lambda: "screenshot-current",
			now=lambda: datetime(2026, 7, 26, 5, 45, tzinfo=timezone.utc),
			clockMilliseconds=clockMilliseconds or (lambda: 0),
			yieldControl=yieldControl,
			customUia=customUia,
			customUiaOptions=CustomUiaCaptureOptions.defaults(),
		)
		return service, actualProvider, screenshot, actualOutput

	def test_document_transform_services_cancellation_on_a_work_slice(self) -> None:
		provider = _Provider(children=("child-one", "child-two"))
		clock = _StepClock(100)
		pulses: list[tuple[int, int]] = []
		service: CaptureService

		def cooperate(milliseconds: int) -> None:
			pulses.append((milliseconds, provider.metadataReads))
			if provider.metadataReads:
				service.requestCancellation()

		service, _provider, _screenshot, output = self._service(
			provider,
			clockMilliseconds=clock,
			yieldControl=cooperate,
		)

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
		)

		self.assertTrue(
			any(0 < metadataReads < len(provider.children) + 1 for _milliseconds, metadataReads in pulses),
		)
		self.assertEqual(CaptureState.CANCELLED, result.lifecycle.state)
		self.assertFalse(result.committed)
		self.assertEqual([], output.packages)

	def test_selected_foreground_root_reaches_current_screenshot_and_publication(self) -> None:
		service, provider, screenshot, output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				target,
				"reader.exe",
				42,
			),
		)

		self.assertEqual(CaptureState.COMPLETED, result.lifecycle.state)
		self.assertTrue(result.committed)
		assert result.snapshot is not None
		assert result.summary is not None
		self.assertEqual(("n1",), result.snapshot.captureRoots)
		self.assertEqual("Selected root", result.snapshot.captureNodes[0].field("name").value)
		self.assertEqual(1, result.summary.summary.counts.nodes)
		self.assertEqual(1, len(screenshot.attempts))
		self.assertEqual(result.context, screenshot.attempts[0].context)
		self.assertTrue(provider.contexts)
		self.assertTrue(all(context is result.context for context in provider.contexts))
		self.assertEqual(1, len(output.packages))
		package = output.packages[0]
		self.assertEqual(
			("index.json", "nodes.jsonl", "capture-config.jsonl", "screenshot.jsonl", "screenshot.png"),
			tuple(name for name, _ in package.artifacts),
		)
		artifacts = dict(package.artifacts)
		record = json.loads(artifacts["screenshot.jsonl"].decode("utf-8").splitlines()[0])
		self.assertEqual("value", record["screenshot"]["status"])
		self.assertEqual("window-42", record["containingForeground"]["scopeId"])
		self.assertIs(result.snapshot, service.fullCaptureBaseline)

	def test_capture_reports_progress_without_exposing_provider_values(self) -> None:
		service, _provider, _screenshot, _output = self._service()
		progress: list[TraversalProgress] = []

		_ = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
			progress=progress.append,
		)

		self.assertTrue(progress)
		first = progress[0]
		self.assertEqual(0, first.processedNodes)
		self.assertGreater(first.pendingWorkCount, 0)
		self.assertGreaterEqual(first.elapsedMilliseconds, 0)
		self.assertIn("preparing", {item.phase for item in progress})

	def test_inspection_target_reference_never_enters_snapshot_or_bundle_output(self) -> None:
		service, _provider, _screenshot, output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				target,
				"reader.exe",
				42,
				inspectionTargetRef="focus-object-ref",
			),
		)

		assert result.snapshot is not None
		self.assertNotIn("focus-object-ref", repr(result.snapshot.asObject()))
		for _name, payload in output.packages[0].artifacts:
			self.assertNotIn(b"focus-object-ref", payload)

	def test_cycle_reference_nodes_complete_without_protection_metadata(self) -> None:
		service, _provider, _screenshot, _output = self._service(_Provider(children=("root-ref",)))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
		)

		self.assertEqual(CaptureState.COMPLETED, result.lifecycle.state)
		assert result.snapshot is not None
		assert result.summary is not None
		self.assertEqual(2, len(result.snapshot.captureNodes))
		self.assertTrue(result.snapshot.captureNodes[1].structure.cycleDetected)
		self.assertEqual("notApplicable", result.summary.summary.nodes[1].protection.status.value)

	def test_field_failure_remains_explicit_without_erasing_safe_fields(self) -> None:
		service, _provider, _screenshot, _output = self._service(_Provider(failedField="role"))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
		)

		assert result.snapshot is not None
		node = result.snapshot.captureNodes[0]
		self.assertEqual("failed", node.field("role").status.value)
		error = node.field("role").errorRef
		assert error is not None
		self.assertEqual("KS.PROVIDER.FIELD_FAILED", error.code)
		self.assertEqual("Selected root", node.field("name").value)
		self.assertTrue(result.committed)

	def test_a_staged_settings_change_reaches_the_next_capture_only(self) -> None:
		service, _provider, _screenshot, output = self._service(_Provider(protected=True))
		request = CaptureRequest(
			CaptureTargetKind.FOREGROUND,
			"root-ref",
			ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
			"reader.exe",
			42,
		)

		redactedResult = service.capture(request)
		service.stageConfiguration(
			replace(SettingsSnapshot.defaults(settingsRevision=2), redactProtectedText=False),
			PrivacyPolicy(2, 2, False),
		)
		# Nothing has started since the change, so the artifact already stored is untouched.
		assert redactedResult.snapshot is not None
		self.assertEqual("redacted", redactedResult.snapshot.captureNodes[0].field("name").status.value)

		visibleResult = service.capture(request)

		assert visibleResult.snapshot is not None
		name = visibleResult.snapshot.captureNodes[0].field("name")
		self.assertEqual("Selected root", name.value)
		self.assertEqual("protected", name.privacy.classification)
		# The first bundle still carries the redaction that actually produced it.
		for artifactName, payload in output.packages[0].artifacts:
			self.assertNotIn(b"Selected root", payload, artifactName)
		self.assertTrue(
			any(b"Selected root" in payload for _name, payload in output.packages[1].artifacts),
		)

	def test_a_change_applied_mid_capture_waits_for_the_next_capture(self) -> None:
		service: CaptureService
		staged: list[int] = []

		def applyDuringWalk(_milliseconds: int) -> None:
			if staged:
				return
			staged.append(1)
			service.stageConfiguration(
				replace(SettingsSnapshot.defaults(settingsRevision=2), redactProtectedText=False),
				PrivacyPolicy(2, 2, False),
			)

		service, _provider, _screenshot, _output = self._service(
			_Provider(protected=True, children=("child-one",)),
			yieldControl=applyDuringWalk,
		)
		request = CaptureRequest(
			CaptureTargetKind.FOREGROUND,
			"root-ref",
			ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
			"reader.exe",
			42,
		)

		running = service.capture(request)
		following = service.capture(request)

		self.assertEqual([1], staged)
		assert running.snapshot is not None
		assert following.snapshot is not None
		# The capture that was already walking keeps the policy it started with.
		self.assertEqual("redacted", running.snapshot.captureNodes[0].field("name").status.value)
		self.assertEqual("Selected root", following.snapshot.captureNodes[0].field("name").value)

	def test_protected_text_is_transformed_before_documents_or_publication(self) -> None:
		service, _provider, _screenshot, output = self._service(_Provider(protected=True))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
		)

		assert result.snapshot is not None
		name = result.snapshot.captureNodes[0].field("name")
		self.assertEqual("redacted", name.status.value)
		self.assertIsNone(name.value)
		self.assertEqual("protected", name.privacy.classification)
		for name, payload in output.packages[0].artifacts:
			self.assertNotIn(b"Selected root", payload, name)

	def test_annotations_flow_through_capture_bundle_and_protected_content_is_redacted(self) -> None:
		records = annotationRecordsPlain(
			(
				AnnotationRecord(
					key="comment",
					status=AnnotationStatus.VALUE,
					typeName="Comment",
					source="NVDA annotations",
					summary="private review note",
				),
			),
		)
		for protected in (False, True):
			with self.subTest(protected=protected):
				service, _provider, _screenshot, output = self._service(
					_Provider(
						protected=protected,
						annotations=cast(PlainValue, records),
					),
				)
				result = service.capture(
					CaptureRequest(
						CaptureTargetKind.FOREGROUND,
						"root-ref",
						ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
						"reader.exe",
						42,
					),
				)

				self.assertTrue(result.committed)
				artifacts = dict(output.packages[0].artifacts)
				self.assertIn("semantics.jsonl", artifacts)
				self.assertNotIn(b'"annotations"', artifacts["nodes.jsonl"])
				if protected:
					self.assertNotIn(b"private review note", artifacts["semantics.jsonl"])
				else:
					self.assertIn(b"private review note", artifacts["semantics.jsonl"])

	def test_normal_capture_and_explicit_diagnostic_export_use_separate_custom_uia_modes(self) -> None:
		customUia = _CustomUiaCapture()
		service, _provider, _screenshot, output = self._service(customUia=customUia)
		request = CaptureRequest(
			CaptureTargetKind.FOREGROUND,
			"root-ref",
			ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
			"reader.exe",
			42,
			detailCollection=True,
		)

		normal = service.capture(request)
		diagnostic = service.exportCustomUiaDiagnostics(request)

		self.assertTrue(normal.committed)
		self.assertTrue(diagnostic.committed)
		self.assertEqual(
			[CustomUiaCaptureMode.NORMAL, CustomUiaCaptureMode.DIAGNOSTIC_EXPORT],
			customUia.modes,
		)
		self.assertEqual(2, len(output.packages))
		self.assertIsNot(output.packages[0], output.packages[1])
		normalArtifacts = dict(output.packages[0].artifacts)
		diagnosticArtifacts = dict(output.packages[1].artifacts)
		self.assertIn(b'"customUiaDefinitions"', normalArtifacts["index.json"])
		self.assertNotIn(b"developer-only-inventory", normalArtifacts["custom-uia.jsonl"])
		self.assertNotIn(b"collectionBudget", normalArtifacts["custom-uia.jsonl"])
		self.assertNotIn(b"{12345678-1234-4ABC-8DEF-1234567890AB}", normalArtifacts["custom-uia.jsonl"])
		self.assertIn(b"developer-only-inventory", diagnosticArtifacts["custom-uia.jsonl"])
		self.assertIn(b"collectionBudget", diagnosticArtifacts["custom-uia.jsonl"])
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in normalArtifacts.items():
				_ = (directory / name).write_bytes(payload)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			selected = sb.projectSelectedNode(admission, directory, "n0").toJsonBytes()
			restored = sb.BundleSnapshotView(directory).captureNodes[0].providers

		self.assertIn(b"{12345678-1234-4ABC-8DEF-1234567890AB}", selected)
		self.assertEqual("configured", dict(restored.items)["customUia"].status.value)


class CaptureOutcomeTests(CaptureTracerTests):
	def test_unlimited_uses_process_ceiling_and_navigator_preserves_full_baseline(self) -> None:
		service, _provider, _screenshot, _output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))
		foreground = service.capture(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
		)
		baseline = service.fullCaptureBaseline

		navigator = service.capture(
			CaptureRequest(
				CaptureTargetKind.NAVIGATOR,
				"navigator-ref",
				target,
				"reader.exe",
				42,
				mode="unlimited",
			),
		)

		self.assertTrue(foreground.committed)
		self.assertTrue(navigator.committed)
		self.assertIs(baseline, service.fullCaptureBaseline)
		assert navigator.snapshot is not None
		self.assertEqual("navigatorSnapshot", navigator.snapshot.documentKind)
		nodeLimit = next(item for item in navigator.traversal.limits if item.limitType == "nodes")
		self.assertEqual(1_000_000, nodeLimit.configuredLimit)
		self.assertTrue(nodeLimit.processSafetyCeiling)
		metadata = navigator.snapshot.metadata
		assert isinstance(metadata, CaptureMetadata)
		self.assertEqual("window-42", metadata.capture.containingForeground.value)

	def test_navigator_captures_selected_subtree_when_the_provider_reports_descendants(self) -> None:
		service, _provider, _screenshot, _output = self._service(_Provider(children=("child-ref",)))

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.NAVIGATOR,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
				includeRootNameInOutput=True,
			),
		)

		assert result.snapshot is not None
		self.assertEqual(2, len(result.snapshot.captureNodes))
		self.assertEqual(("n2",), result.snapshot.captureNodes[0].structure.childKeys)
		self.assertEqual("n1", result.snapshot.captureNodes[1].structure.parentKey)
		self.assertTrue(result.committed)
		self.assertEqual("Selected root", _output.packages[-1].subject)

	def test_focus_subtree_capture_publishes_a_normal_snapshot_without_replacing_the_baseline(self) -> None:
		service, _provider, _screenshot, output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))
		baseline = service.capture(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "foreground-root", target, "reader.exe", 42),
		).snapshot

		result = service.captureSubtree(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"focus-root",
				target,
				"reader.exe",
				42,
				mode="unlimited",
				includeRootNameInOutput=True,
			),
		)

		self.assertTrue(result.committed)
		self.assertEqual("focus-root", result.traversal.nodes[0].nodeRef)
		assert result.snapshot is not None
		self.assertEqual("snapshot", result.snapshot.documentKind)
		self.assertIs(baseline, service.fullCaptureBaseline)
		self.assertEqual("snapshot", output.packages[-1].captureKind)
		self.assertEqual("Selected root", output.packages[-1].subject)

	def test_fresh_screenshot_failure_commits_typed_partial_without_stale_png(self) -> None:
		service, _provider, screenshot, output = self._service(screenshotFail=True)

		result = service.capture(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
			),
		)

		self.assertEqual(CaptureState.COMPLETED_PARTIAL_SCREENSHOT, result.lifecycle.state)
		self.assertEqual(1, len(screenshot.attempts))
		self.assertEqual(
			("index.json", "nodes.jsonl", "capture-config.jsonl", "screenshot.jsonl"),
			tuple(name for name, _ in output.packages[0].artifacts),
		)
		artifacts = dict(output.packages[0].artifacts)
		record = json.loads(artifacts["screenshot.jsonl"].decode("utf-8").splitlines()[0])
		self.assertEqual("failed", record["screenshot"]["status"])
		self.assertIsNone(record["screenshot"]["image"])
		self.assertIs(result.snapshot, service.fullCaptureBaseline)

	def test_mismatched_screenshot_attempt_fails_terminally(self) -> None:
		service, _provider, screenshot, output = self._service(screenshotAttemptMismatch=True)

		with self.assertRaisesRegex(RuntimeError, "^KS.CAPTURE.SCREENSHOT_ATTEMPT_MISMATCH$"):
			_ = service.capture(
				CaptureRequest(
					CaptureTargetKind.FOREGROUND,
					"root-ref",
					ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
					"reader.exe",
					42,
				),
			)

		active = service.activeLifecycle
		assert active is not None
		self.assertEqual(CaptureState.FAILED, active.state)
		self.assertTrue(active.isTerminal)
		self.assertEqual(1, len(screenshot.attempts))
		self.assertEqual([], output.packages)

	def test_stale_generation_failures_leave_the_active_lifecycle_terminal(self) -> None:
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		for staleCheck in range(1, 4):
			with self.subTest(staleCheck=staleCheck):
				service, _provider, _screenshot, output = self._service(
					lifecycle=_StalePrecommitLifecycle(staleCheck),
				)

				with (
					patch.object(service, "_documents", return_value=(object(), object())),
					patch.object(service, "_bundle", return_value=object()),
					self.assertRaisesRegex(RuntimeError, "KS.CAPTURE.STALE_GENERATION"),
				):
					_ = service.capture(
						CaptureRequest(
							CaptureTargetKind.FOREGROUND,
							"root-ref",
							target,
							"reader.exe",
							42,
						),
					)

				active = service.activeLifecycle
				assert active is not None
				self.assertEqual(CaptureState.FAILED, active.state)
				self.assertTrue(active.isTerminal)
				self.assertEqual([], output.packages)

	def test_cancellation_remains_requested_while_provider_is_blocked_then_finishes_without_publication(
		self,
	) -> None:
		entered = threading.Event()
		release = threading.Event()
		service, _provider, _screenshot, output = self._service(
			_Provider(blockEntered=entered, blockRelease=release),
		)
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))
		results: list[CaptureResult] = []

		thread = threading.Thread(
			target=lambda: results.append(
				service.capture(
					CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
				),
			),
		)
		thread.start()
		self.assertTrue(entered.wait(2))
		service.requestCancellation()
		active = service.activeLifecycle
		assert active is not None
		self.assertEqual(CaptureState.CANCELLATION_REQUESTED, active.state)
		self.assertTrue(thread.is_alive())
		release.set()
		thread.join(5)

		self.assertFalse(thread.is_alive())
		self.assertEqual(1, len(results))
		result = results[0]
		self.assertEqual(CaptureState.CANCELLED, result.lifecycle.state)
		self.assertFalse(result.committed)
		self.assertIsNone(service.fullCaptureBaseline)
		self.assertEqual([], output.packages)

	def test_failed_publication_never_updates_baseline_and_successful_rename_wins_late_cancel(self) -> None:
		failedOutput = _Output(OutputCompletionOutcome.PARTIAL_WITHOUT_PUBLICATION)
		failedService, _provider, _screenshot, _output = self._service(output=failedOutput)
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		failed = failedService.capture(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
		)
		self.assertEqual(CaptureState.FAILED, failed.lifecycle.state)
		self.assertFalse(failed.committed)
		self.assertIsNone(failedService.fullCaptureBaseline)

		output = _Output()
		service, _provider, _screenshot, output = self._service(output=output)
		output.onPublish = service.requestCancellation
		committed = service.capture(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
		)
		self.assertEqual(CaptureState.COMPLETED, committed.lifecycle.state)
		self.assertTrue(committed.committed)
		self.assertIs(committed.snapshot, service.fullCaptureBaseline)

	def test_warned_publication_commits_and_updates_the_full_capture_baseline(self) -> None:
		output = _Output(OutputCompletionOutcome.COMMITTED_WITH_WARNING)
		service, _provider, _screenshot, _output = self._service(output=output)
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.capture(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
		)

		self.assertEqual(CaptureState.COMPLETED, result.lifecycle.state)
		self.assertTrue(result.committed)
		self.assertIsNone(result.errorCode)
		self.assertIs(result.snapshot, service.fullCaptureBaseline)
		assert result.publication is not None
		self.assertEqual(OutputCompletionOutcome.COMMITTED_WITH_WARNING, result.publication.outcome)
		self.assertEqual(3, len(result.publication.actions))


class CaptureForInspectionTests(CaptureTracerTests):
	def test_inspection_capture_materialises_evidence_without_publishing_or_baselining(self) -> None:
		service, provider, _screenshot, output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.captureForInspection(
			CaptureRequest(CaptureTargetKind.FOREGROUND, "root-ref", target, "reader.exe", 42),
		)

		self.assertEqual(CaptureState.COMPLETED, result.lifecycle.state)
		self.assertTrue(result.committed)
		assert result.snapshot is not None
		self.assertEqual(("n1",), result.snapshot.captureRoots)
		self.assertEqual("Selected root", result.snapshot.captureNodes[0].field("name").value)
		self.assertIsNotNone(result.bundle)
		assert result.bundle is not None
		self.assertIn("index.json", dict(result.bundle.artifacts()))
		self.assertTrue(provider.contexts)
		self.assertEqual([], output.packages)
		self.assertIsNone(service.fullCaptureBaseline)

	def test_inspection_target_identity_selects_unfocused_matching_traversal_node(self) -> None:
		identity = _Identity((("focus-object-ref", "focus-traversed-ref"),))
		provider = _Provider(
			children=("focused-true-ref", "focus-traversed-ref"),
			focusedByRef={
				"root-ref": False,
				"focused-true-ref": True,
				"focus-traversed-ref": False,
			},
		)
		service, _provider, _screenshot, output = self._service(provider, identity=identity)
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.captureForInspection(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				target,
				"reader.exe",
				42,
				inspectionTargetRef="focus-object-ref",
			),
		)

		self.assertTrue(result.committed)
		self.assertEqual("n3", result.inspectionTargetKey)
		self.assertIn(
			("focus-object-ref", "focus-traversed-ref"),
			tuple((request.firstNodeRef, request.secondNodeRef) for request in identity.requests),
		)
		assert result.snapshot is not None
		self.assertNotIn("focus-object-ref", repr(result.snapshot.asObject()))
		self.assertEqual([], output.packages)

	def test_inspection_target_identity_lookup_yields_and_cancels(self) -> None:
		identity = _Identity()
		provider = _Provider(children=("child-one", "child-two"))
		clock = _StepClock(100)
		pulses: list[int] = []
		service: CaptureService

		def cooperate(milliseconds: int) -> None:
			pulses.append(len(identity.requests))
			if identity.requests:
				service.requestCancellation()

		service, _provider, screenshot, output = self._service(
			provider,
			identity=identity,
			clockMilliseconds=clock,
			yieldControl=cooperate,
		)

		result = service.captureForInspection(
			CaptureRequest(
				CaptureTargetKind.FOREGROUND,
				"root-ref",
				ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30)),
				"reader.exe",
				42,
				inspectionTargetRef="inspection-target",
			),
		)

		self.assertEqual(CaptureState.CANCELLED, result.lifecycle.state)
		self.assertEqual("KS.CAPTURE.CANCELLED", result.errorCode)
		self.assertTrue(any(requests for requests in pulses))
		self.assertEqual(1, len(identity.requests))
		self.assertEqual([], screenshot.attempts)
		self.assertEqual([], output.packages)

	def test_inspection_capture_accepts_the_navigator_target(self) -> None:
		service, _provider, _screenshot, output = self._service()
		target = ScreenshotTarget("containingForeground", "window-42", (0, 0, 40, 30))

		result = service.captureForInspection(
			CaptureRequest(CaptureTargetKind.NAVIGATOR, "navigator-ref", target, "reader.exe", 42),
		)

		self.assertTrue(result.committed)
		assert result.snapshot is not None
		self.assertEqual("navigatorSnapshot", result.snapshot.documentKind)
		self.assertEqual([], output.packages)
		self.assertIsNone(service.fullCaptureBaseline)


if __name__ == "__main__":
	_ = unittest.main()
