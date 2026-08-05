from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Literal, Protocol, cast

from ..adapters.windows.publication import PublicationPackage, PublicationPolicy
from ..domain.correlation import CorrelationContext
from ..domain.diffing import AmbiguousMatchError, diffSnapshotViews
from ..domain.document_records import (
	AdmissionRecord,
	CaptureMetadata,
	CaptureDuration,
	DiffChange,
	DocumentConventions,
	DocumentCounts,
	DocumentEnvironment,
	DocumentGeneration,
	DocumentLimits,
	DocumentReference,
	JsonArray,
	JsonObject,
	NodeRecord,
	PersistedDocumentMetadata,
	ProjectionMetadata,
	RedactionMetadata,
)
from ..domain.documents import Diff, Snapshot
from ..domain.privacy import PrivacyPolicy, UNREDACTED_SCREENSHOT_WARNING
from ..domain.snapshot_bundle import InMemorySnapshotView
from ..domain.status import EvidenceState
from ..encoding.canonical_json import encodeCanonical
from ..ports.effects import ScreenshotTarget
from ..presentation.status_presenter import OutputCompletionOutcome, OutputCompletionPresentation
from .capture_service import CaptureRequest, CaptureResult, CaptureTargetKind


type DiffOutcome = Literal["baselineCreated", "changed", "noChange", "rejected", "failed"]


class DiffCapturePort(Protocol):
	@property
	def fullCaptureBaseline(self) -> Snapshot | None: ...

	@property
	def fullCaptureBaselineRequest(self) -> CaptureRequest | None: ...

	def capture(self, request: CaptureRequest) -> CaptureResult: ...

	def captureForDiff(self, request: CaptureRequest) -> CaptureResult: ...


class DiffOutputPort(Protocol):
	def publishDiff(
		self,
		package: PublicationPackage,
		target: ScreenshotTarget,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation: ...


@dataclass(frozen=True, slots=True)
class TargetAdmission:
	admitted: bool
	code: str | None

	def __post_init__(self) -> None:
		if self.admitted != (self.code is None):
			raise ValueError("target admission code must exist exactly when rejected")


@dataclass(frozen=True, slots=True)
class DiffResult:
	outcome: DiffOutcome
	baseline: Snapshot | None
	current: Snapshot | None
	document: Diff | None
	publication: OutputCompletionPresentation | None
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.outcome in {"rejected", "failed"}:
			if self.errorCode is None or self.document is not None or self.publication is not None:
				raise ValueError("failed diff outcomes require only a stable error code")
		elif self.errorCode is not None:
			raise ValueError("successful diff outcomes cannot carry an error code")
		if self.outcome == "baselineCreated" and (self.baseline is None or self.current is not None):
			raise ValueError("baseline-created outcome must carry only the committed baseline")
		if self.outcome in {"changed", "noChange"} and (
			self.baseline is None or self.current is None or self.document is None
		):
			raise ValueError("published diff outcomes require both snapshots and a document")


def _captureMetadata(snapshot: Snapshot) -> CaptureMetadata:
	if not isinstance(snapshot.metadata, CaptureMetadata):
		raise TypeError("snapshot requires capture metadata")
	return snapshot.metadata


def _root(snapshot: Snapshot) -> NodeRecord | None:
	if len(snapshot.captureRoots) != 1:
		return None
	rootKey = snapshot.captureRoots[0]
	return next((node for node in snapshot.captureNodes if node.key == rootKey), None)


def _rootValue(snapshot: Snapshot, field: str) -> object:
	root = _root(snapshot)
	if root is None:
		return None
	envelope = root.field(field)
	return envelope.value if envelope.status is EvidenceState.VALUE else None


def _automationIds(snapshot: Snapshot) -> frozenset[tuple[str, str]]:
	value = _rootValue(snapshot, "stableIds")
	if not isinstance(value, tuple):
		return frozenset()
	result: set[tuple[str, str]] = set()
	for candidate in cast(tuple[object, ...], value):
		if isinstance(candidate, tuple):
			parts = cast(tuple[object, ...], candidate)
		else:
			continue
		if (
			len(parts) == 3
			and parts[0] == "uiaAutomationId"
			and isinstance(parts[1], str)
			and isinstance(parts[2], str)
			and parts[1]
			and parts[2]
		):
			result.add((parts[1], parts[2]))
	return frozenset(result)


def _admitTarget(
	baseline: Snapshot,
	baselineRequest: CaptureRequest | None,
	current: Snapshot,
	currentRequest: CaptureRequest,
) -> TargetAdmission:
	if baselineRequest is None:
		return TargetAdmission(False, "KS.DIFF.BASELINE_IDENTITY_UNAVAILABLE")
	baselineMetadata = _captureMetadata(baseline)
	currentMetadata = _captureMetadata(current)
	for differs, code in (
		(baselineRequest.processId != currentRequest.processId, "KS.DIFF.TARGET_PROCESS_MISMATCH"),
		(
			baselineRequest.executable.casefold() != currentRequest.executable.casefold(),
			"KS.DIFF.TARGET_APPLICATION_MISMATCH",
		),
		(
			baselineRequest.containingForeground.scopeId != currentRequest.containingForeground.scopeId,
			"KS.DIFF.TARGET_WINDOW_MISMATCH",
		),
		(baselineRequest.providerScope != currentRequest.providerScope, "KS.DIFF.TARGET_PROVIDER_MISMATCH"),
		(baselineRequest.processScope != currentRequest.processScope, "KS.DIFF.TARGET_SCOPE_MISMATCH"),
		(baselineRequest.backend != currentRequest.backend, "KS.DIFF.TARGET_BACKEND_MISMATCH"),
		(
			baselineMetadata.projection != currentMetadata.projection
			or baselineMetadata.capture.rawUiaEnabled != currentMetadata.capture.rawUiaEnabled,
			"KS.DIFF.TARGET_PROJECTION_MISMATCH",
		),
		(
			# A baseline redacted under one rule and a current capture read under another cannot be
			# compared: a value withheld on one side and shown on the other would be reported as a
			# change that never happened, and stamping either reference with the other's policy
			# would label stored evidence with a rule that never applied to it.
			baselineMetadata.redaction.enabled != currentMetadata.redaction.enabled,
			"KS.DIFF.BASELINE_POLICY_MISMATCH",
		),
	):
		if differs:
			return TargetAdmission(False, code)
	for field, code in (
		("windowHandle", "KS.DIFF.TARGET_WINDOW_EVIDENCE_MISMATCH"),
		("process", "KS.DIFF.TARGET_PROCESS_EVIDENCE_MISMATCH"),
		("backend", "KS.DIFF.TARGET_BACKEND_EVIDENCE_MISMATCH"),
	):
		left = _rootValue(baseline, field)
		right = _rootValue(current, field)
		if left is not None and right is not None and left != right:
			return TargetAdmission(False, code)
	leftAutomationIds = _automationIds(baseline)
	rightAutomationIds = _automationIds(current)
	if len(leftAutomationIds) > 1 or len(rightAutomationIds) > 1:
		return TargetAdmission(False, "KS.DIFF.TARGET_IDENTITY_AMBIGUOUS")
	if leftAutomationIds and rightAutomationIds and leftAutomationIds != rightAutomationIds:
		return TargetAdmission(False, "KS.DIFF.TARGET_STABLE_ID_MISMATCH")
	return TargetAdmission(True, None)


class DiffService:
	def __init__(
		self,
		capture: DiffCapturePort,
		output: DiffOutputPort,
		*,
		privacyPolicy: PrivacyPolicy,
		documentIdFactory: Callable[[], str],
		publicationIdFactory: Callable[[], str],
		now: Callable[[], datetime] | None = None,
		environment: tuple[str, str, str] = ("unknown", "unknown", "unknown"),
	) -> None:
		super().__init__()
		if len(environment) != 3 or any(not item for item in environment):
			raise ValueError("diff environment must contain three nonempty version strings")
		self._capture = capture
		self._output = output
		self._privacyPolicy = privacyPolicy
		self._documentIdFactory = documentIdFactory
		self._publicationIdFactory = publicationIdFactory
		self._now = now or (lambda: datetime.now(timezone.utc))
		self._environment = environment
		self._stagedPolicy: PrivacyPolicy | None = None

	def stageConfiguration(self, privacyPolicy: PrivacyPolicy) -> None:
		"""Hold a committed policy change until the next diff starts.

		A diff reads a baseline and a fresh capture and compares them under one policy. Changing that
		policy mid-comparison would leave the published diff describing a rule that applied to only
		half of it.
		"""

		self._stagedPolicy = privacyPolicy

	def adoptStagedConfiguration(self) -> None:
		"""Adopt a staged policy; a no-op when nothing is staged."""

		staged = self._stagedPolicy
		if staged is None:
			return
		self._stagedPolicy = None
		self._privacyPolicy = staged

	def _document(
		self,
		baseline: Snapshot,
		current: Snapshot,
		changes: tuple[DiffChange, ...],
		context: CorrelationContext,
	) -> Diff:
		if context.operationId is None:
			raise ValueError("diff document requires an admitted operation")
		metadata = PersistedDocumentMetadata(
			DocumentGeneration(
				self._now().isoformat(),
				context.operationId.value,
				(baseline.documentId, current.documentId),
				DocumentConventions(
					"keystone.document",
					"2.0",
					"required fields are never omitted",
					"status is independent from value",
					"document semantic order",
				),
			),
			DocumentEnvironment(*self._environment),
			DocumentLimits(max(1, len(changes))),
			DocumentCounts(len(changes)),
			CaptureDuration(0),
			ProjectionMetadata("derived", 1),
			RedactionMetadata(
				self._privacyPolicy.redactProtectedText,
				"default",
				self._privacyPolicy.policyRevision,
			),
		)
		baselineReference = DocumentReference(
			baseline.documentId,
			baseline.documentKind,
			2,
			0,
			_captureMetadata(baseline).projection.name,
			# The baseline carries the revision recorded when it was captured, never the revision
			# governing this comparison.
			_captureMetadata(baseline).redaction.revision,
			AdmissionRecord(True, None),
		)
		currentReference = DocumentReference(
			current.documentId,
			current.documentKind,
			2,
			0,
			_captureMetadata(current).projection.name,
			_captureMetadata(current).redaction.revision,
			AdmissionRecord(True, None),
		)
		noChange = not changes
		return Diff(
			"diff",
			self._documentIdFactory(),
			metadata,
			JsonObject(
				(
					("baseline", baselineReference.asObject()),
					("current", currentReference.asObject()),
					(
						"changes",
						None if noChange else JsonArray(tuple(change.asObject() for change in changes)),
					),
					("noChange", noChange),
				),
			),
			records=changes,
		)

	def _package(
		self,
		document: Diff,
		baseline: Snapshot,
		baselineRequest: CaptureRequest,
		current: Snapshot,
		currentRequest: CaptureRequest,
		admission: TargetAdmission,
	) -> PublicationPackage:
		payload = cast(dict[str, object], json.loads(encodeCanonical(document)))
		target = currentRequest.containingForeground
		baselineMetadata = _captureMetadata(baseline)
		currentMetadata = _captureMetadata(current)
		payload["containingForeground"] = {
			"scopeId": target.scopeId,
			"geometry": list(target.geometry),
		}
		payload["diffMetadata"] = {
			"baseline": {
				"generatedAt": baselineMetadata.capture.generatedAt,
				"sourceDocumentId": baseline.documentId,
				"sourcePathEvidence": {
					"status": baselineMetadata.capture.outputPath.status.value,
					"value": baselineMetadata.capture.outputPath.value,
				},
				"application": baselineRequest.executable,
				"processId": baselineRequest.processId,
				"projection": baselineMetadata.projection.name,
				"rawUiaEnabled": baselineMetadata.capture.rawUiaEnabled,
			},
			"current": {
				"generatedAt": currentMetadata.capture.generatedAt,
				"application": currentRequest.executable,
				"processId": currentRequest.processId,
				"projection": currentMetadata.projection.name,
				"rawUiaEnabled": currentMetadata.capture.rawUiaEnabled,
				"environment": {
					"keystoneVersion": self._environment[0],
					"nvdaVersion": self._environment[1],
					"windowsVersion": self._environment[2],
				},
			},
			"admission": {"admitted": admission.admitted, "code": admission.code},
			"privacy": {
				"policyRevision": self._privacyPolicy.policyRevision,
				"settingsRevision": self._privacyPolicy.settingsRevision,
				"redactionEnabled": self._privacyPolicy.redactProtectedText,
			},
		}
		completedAt = self._now()
		if completedAt.tzinfo is not None:
			completedAt = completedAt.astimezone().replace(tzinfo=None)
		return PublicationPackage(
			self._publicationIdFactory(),
			currentRequest.executable,
			currentRequest.processId,
			"diff",
			completedAt,
			(
				(
					"diff.json",
					(
						json.dumps(payload, allow_nan=False, ensure_ascii=False, separators=(",", ":")) + "\n"
					).encode(
						"utf-8",
					),
				),
			),
			UNREDACTED_SCREENSHOT_WARNING,
		)

	def diff(self, request: CaptureRequest) -> DiffResult:
		self.adoptStagedConfiguration()
		if request.targetKind != CaptureTargetKind.FOREGROUND:
			return DiffResult(
				"rejected",
				self._capture.fullCaptureBaseline,
				None,
				None,
				None,
				"KS.DIFF.FULL_ONLY",
			)
		baseline = self._capture.fullCaptureBaseline
		if baseline is None:
			bootstrap = self._capture.capture(request)
			if not bootstrap.committed or not isinstance(bootstrap.snapshot, Snapshot):
				return DiffResult(
					"failed",
					None,
					None,
					None,
					None,
					bootstrap.errorCode or "KS.DIFF.BASELINE_CREATION_FAILED",
				)
			return DiffResult("baselineCreated", bootstrap.snapshot, None, None, None)
		baselineRequest = self._capture.fullCaptureBaselineRequest
		currentResult = self._capture.captureForDiff(request)
		if not currentResult.committed or not isinstance(currentResult.snapshot, Snapshot):
			return DiffResult(
				"failed",
				baseline,
				None,
				None,
				None,
				currentResult.errorCode or "KS.DIFF.CURRENT_CAPTURE_FAILED",
			)
		current = currentResult.snapshot
		admission = _admitTarget(baseline, baselineRequest, current, request)
		if not admission.admitted:
			return DiffResult("rejected", baseline, current, None, None, admission.code)
		try:
			changes = diffSnapshotViews(
				InMemorySnapshotView(baseline),
				InMemorySnapshotView(current),
				self._privacyPolicy,
			)
		except AmbiguousMatchError:
			return DiffResult("rejected", baseline, current, None, None, "KS.DIFF.AMBIGUOUS_MATCH")
		document = self._document(baseline, current, changes, currentResult.context)
		assert baselineRequest is not None
		package = self._package(document, baseline, baselineRequest, current, request, admission)
		publication = self._output.publishDiff(
			package,
			request.containingForeground,
			lifecycleGeneration=currentResult.context.generation or 0,
			context=currentResult.context,
			policy=PublicationPolicy(
				cancelled=False,
				secure=False,
				schemaValidated=True,
				privacyValidated=True,
				generationCurrent=True,
			),
		)
		if publication.outcome not in (
			OutputCompletionOutcome.COMMITTED,
			OutputCompletionOutcome.COMMITTED_WITH_WARNING,
		):
			return DiffResult("failed", baseline, current, None, None, "KS.DIFF.PUBLICATION_FAILED")
		return DiffResult("noChange" if not changes else "changed", baseline, current, document, publication)
