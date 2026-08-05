from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
from typing import Literal, Protocol, cast

from ..adapters.windows.publication import (
	CaptureKind,
	CleanupOutcome,
	DiscoverySnapshot,
	PublicationPackage,
	PublicationPolicy,
	PublicationReceipt,
	PublicationResult,
)
from ..domain.correlation import CorrelationContext, requireCompleteCorrelation
from ..domain.snapshot_bundle import BundlePackage
from ..ports.effects import (
	CaptureManagementRequest,
	CaptureManagementResult,
	ClipboardPort,
	ClipboardRequest,
	FeedbackPort,
	FeedbackRequest,
	PortError,
	PortOutcome,
	PortStatus,
	ScreenshotAttempt,
	ScreenshotPort,
	ScreenshotResult,
	ScreenshotTarget,
	ShellPort,
	ShellRequest,
)
from ..domain.privacy import UNREDACTED_SCREENSHOT_WARNING
from ..presentation.status_presenter import (
	OutputCompletionOutcome,
	OutputCompletionPresentation,
	presentOutputCompletion,
)
from .bundle_service import toPublicationPackage


class OutputRepository(Protocol):
	def publish(
		self,
		package: PublicationPackage,
		policyProvider: Callable[[], PublicationPolicy],
		context: CorrelationContext,
	) -> PublicationResult: ...

	def discover(self, context: CorrelationContext) -> DiscoverySnapshot: ...

	def clearAll(self, discoveryRevision: int, context: CorrelationContext) -> CleanupOutcome: ...

	def revalidate(self, receipt: PublicationReceipt, context: CorrelationContext) -> bool: ...

	def newest(self, captureKind: CaptureKind, context: CorrelationContext) -> PublicationReceipt | None: ...


def _requireScreenshotResult(value: object) -> ScreenshotResult:
	if not isinstance(value, ScreenshotResult):
		raise ValueError("screenshot boundary returned no current attempt result")
	return value


@dataclass(frozen=True, slots=True)
class _ActionBinding:
	actionId: str
	lifecycleGeneration: int
	receipt: PublicationReceipt
	context: CorrelationContext


class OutputService:
	def __init__(
		self,
		repository: OutputRepository,
		feedback: FeedbackPort,
		clipboard: ClipboardPort,
		shell: ShellPort,
		*,
		actionIdFactory: Callable[[], str],
		screenshot: ScreenshotPort | None = None,
		screenshotAttemptIdFactory: Callable[[], str] | None = None,
		lifecycleGeneration: int = 0,
	) -> None:
		super().__init__()
		if (screenshot is None) != (screenshotAttemptIdFactory is None):
			raise ValueError("screenshot output support requires a port and attempt ID factory together")
		if lifecycleGeneration < 0:
			raise ValueError("output lifecycle generation must be nonnegative")
		self._repository = repository
		self._feedback = feedback
		self._clipboard = clipboard
		self._shell = shell
		self._actionIdFactory = actionIdFactory
		self._screenshot = screenshot
		self._screenshotAttemptIdFactory = screenshotAttemptIdFactory
		self._lifecycleGeneration = lifecycleGeneration
		self._confirmationRevision = 0
		self._binding: _ActionBinding | None = None

	@property
	def screenshotPort(self) -> ScreenshotPort | None:
		return self._screenshot

	@staticmethod
	def _correlation(context: CorrelationContext) -> dict[str, object]:
		complete = requireCompleteCorrelation(context)
		assert complete.operationId is not None
		assert complete.jobId is not None
		return {
			"sessionId": complete.sessionId.value,
			"operationId": complete.operationId.value,
			"jobId": complete.jobId.value,
			"generation": complete.generation,
		}

	@classmethod
	def _screenshotDocumentResult(cls, result: ScreenshotResult) -> dict[str, object]:
		attempt = result.attempt
		target = attempt.target
		image: dict[str, object] | None = None
		if result.status == "value":
			assert result.image is not None
			assert result.capturedGeometry is not None
			assert result.succeededAt is not None
			image = {
				"sha256": hashlib.sha256(result.image).hexdigest(),
				"byteLength": len(result.image),
				"width": result.capturedGeometry[2],
				"height": result.capturedGeometry[3],
				"capturedAt": result.succeededAt,
			}
		return {
			"attempt": {
				"attemptId": attempt.attemptId,
				"generation": attempt.generation,
				"target": {
					"scopeKind": target.scopeKind,
					"scopeId": target.scopeId,
					"geometry": list(target.geometry),
				},
				"correlation": cls._correlation(attempt.context),
			},
			"status": result.status,
			"image": image,
			"error": (
				None
				if result.status == "value"
				else {"code": result.errorCode, "diagnosticId": result.diagnosticId}
			),
			"warning": result.warning,
		}

	def publishDiff(
		self,
		package: PublicationPackage,
		target: ScreenshotTarget,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation:
		context = requireCompleteCorrelation(context)
		if context.generation != lifecycleGeneration:
			raise ValueError("output lifecycle generation must match admitted correlation")
		if target.scopeKind != "containingForeground":
			raise ValueError("diff screenshot target must be the containing foreground")
		if package.captureKind != "diff" or tuple(name for name, _payload in package.artifacts) != (
			"diff.json",
		):
			raise ValueError("diff publication accepts exactly one prepared diff document")
		try:
			loaded: object = json.loads(package.artifacts[0][1].decode("utf-8", errors="strict"))
		except (UnicodeDecodeError, json.JSONDecodeError) as error:
			raise ValueError("prepared diff document is not strict UTF-8 JSON") from error
		if not isinstance(loaded, dict):
			raise ValueError("prepared diff document has the wrong kind")
		document = cast(dict[str, object], loaded)
		if document.get("documentKind") != "diff":
			raise ValueError("prepared diff document has the wrong kind")
		containingForeground = document.get("containingForeground")
		if not isinstance(containingForeground, dict):
			raise ValueError("prepared diff document lacks a containing foreground target")
		foreground = cast(dict[str, object], containingForeground)
		if foreground != {"scopeId": target.scopeId, "geometry": list(target.geometry)}:
			raise ValueError("diff target does not match the containing foreground")
		if "screenshot" in document:
			raise ValueError("caller-supplied prior screenshot result is forbidden")
		screenshot = self._screenshot
		attemptIdFactory = self._screenshotAttemptIdFactory
		if screenshot is None or attemptIdFactory is None:
			raise ValueError("diff publication requires a screenshot boundary")

		attempt = ScreenshotAttempt(
			attemptIdFactory(),
			lifecycleGeneration,
			target,
			context,
		)
		result = _requireScreenshotResult(screenshot.captureScreenshot(attempt))
		if (
			result.attempt is not attempt
			or result.attempt.target is not target
			or result.attempt.context is not context
			or result.attempt.generation != lifecycleGeneration
		):
			raise ValueError("screenshot result does not match the fresh attempt")
		document["screenshot"] = self._screenshotDocumentResult(result)
		diffPayload = (
			json.dumps(document, allow_nan=False, ensure_ascii=False, separators=(",", ":")) + "\n"
		).encode("utf-8")
		artifacts: tuple[tuple[str, bytes], ...] = (("diff.json", diffPayload),)
		if result.status == "value":
			assert result.image is not None
			artifacts = (*artifacts, ("screenshot.png", result.image))
		current = replace(package, artifacts=artifacts, screenshotWarning=UNREDACTED_SCREENSHOT_WARNING)
		return self.publish(
			current,
			lifecycleGeneration=lifecycleGeneration,
			context=context,
			policy=policy,
		)

	def _announce(
		self,
		presentation: OutputCompletionPresentation,
		context: CorrelationContext,
	) -> None:
		message = presentation.automaticSpeech
		_ = self._feedback.announce(FeedbackRequest(message.messageId, message.arguments, context))

	def publish(
		self,
		package: PublicationPackage,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation:
		context = requireCompleteCorrelation(context)
		if context.generation != lifecycleGeneration:
			raise ValueError("output lifecycle generation must match admitted correlation")
		if lifecycleGeneration > self._lifecycleGeneration:
			self._confirmationRevision = 0
		self._lifecycleGeneration = lifecycleGeneration
		self._binding = None
		currentPolicy = policy if policy is not None else PublicationPolicy()
		result = self._repository.publish(package, lambda: currentPolicy, context)
		if not result.committed:
			assert result.errorCode is not None
			presentation = presentOutputCompletion(
				OutputCompletionOutcome.FAILED,
				completionCode=result.errorCode,
			)
			self._announce(presentation, context)
			return presentation
		if result.warningCode is not None:
			outcome = OutputCompletionOutcome.COMMITTED_WITH_WARNING
		else:
			outcome = OutputCompletionOutcome.COMMITTED
		if result.receipt is None:
			presentation = presentOutputCompletion(outcome, completionCode=result.warningCode)
			self._announce(presentation, context)
			return presentation
		actionId = self._actionIdFactory()
		self._binding = _ActionBinding(actionId, lifecycleGeneration, result.receipt, context)
		presentation = presentOutputCompletion(
			outcome,
			result.receipt.folderName,
			actionId,
			result.warningCode,
		)
		self._announce(presentation, context)
		return presentation

	def publishBundle(
		self,
		package: BundlePackage,
		*,
		publicationId: str,
		completedAt: datetime,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation:
		"""Publish a partitioned capture bundle through the strict publication path."""
		publication = toPublicationPackage(package, publicationId=publicationId, completedAt=completedAt)
		return self.publish(
			publication,
			lifecycleGeneration=lifecycleGeneration,
			context=context,
			policy=policy,
		)

	def _result(
		self,
		request: CaptureManagementRequest,
		status: PortStatus,
		*,
		outcome: PortOutcome | None = None,
		error: PortError | None = None,
		recognized: int = 0,
		suspicious: int = 0,
		deleted: int = 0,
		skipped: int = 0,
		failed: int = 0,
	) -> CaptureManagementResult:
		binding = self._binding
		actionId = None if binding is None else binding.actionId
		return CaptureManagementResult(
			request.operation,
			request.lifecycleGeneration,
			status,
			outcome,
			error,
			recognized,
			suspicious,
			deleted,
			skipped,
			failed,
			self._confirmationRevision,
			actionId,
			actionId,
			actionId,
		)

	def _revalidateBinding(self) -> None:
		binding = self._binding
		if binding is not None and not self._repository.revalidate(binding.receipt, binding.context):
			self._binding = None

	def _bindingFor(self, request: CaptureManagementRequest) -> _ActionBinding | None:
		binding = self._binding
		if (
			binding is None
			or request.actionId != binding.actionId
			or request.lifecycleGeneration != binding.lifecycleGeneration
			or request.context is not binding.context
			or not self._repository.revalidate(binding.receipt, request.context)
		):
			self._binding = None
			return None
		return binding

	def _actOnPath(self, request: CaptureManagementRequest) -> CaptureManagementResult:
		binding = self._bindingFor(request)
		if binding is None:
			return self._result(request, PortStatus("stale", self._confirmationRevision))
		path = str(binding.receipt.path)
		if request.operation == "copyCommittedPath":
			effect = self._clipboard.copyText(ClipboardRequest(path, binding.actionId, request.context))
		elif request.operation == "openCommittedFolder":
			effect = self._shell.openFolder(
				ShellRequest(path, self._confirmationRevision, request.context),
			)
		else:
			effect = self._shell.revealFile(
				ShellRequest(path, self._confirmationRevision, request.context),
			)
		return self._result(
			request,
			effect.status,
			outcome=effect.outcome,
			error=effect.error,
		)

	def manageCaptures(self, request: CaptureManagementRequest) -> CaptureManagementResult:
		if request.lifecycleGeneration != self._lifecycleGeneration:
			return self._result(request, PortStatus("stale", self._confirmationRevision))
		if request.operation in (
			"copyCommittedPath",
			"openCommittedFolder",
			"revealCommittedFolder",
		):
			return self._actOnPath(request)
		if request.operation == "refresh":
			discovery = self._repository.discover(request.context)
			self._confirmationRevision = discovery.revision
			self._revalidateBinding()
			token = "empty" if discovery.recognizedCount == 0 else "ready"
			return self._result(
				request,
				PortStatus(token, discovery.revision),
				outcome=PortOutcome(
					"captureSummary",
					(discovery.recognizedCount, discovery.suspiciousCount),
				),
				recognized=discovery.recognizedCount,
				suspicious=discovery.suspiciousCount,
			)
		self._revalidateBinding()
		if self._confirmationRevision == 0 or request.confirmationRevision != self._confirmationRevision:
			return self._result(request, PortStatus("stale", self._confirmationRevision))
		cleanup = self._repository.clearAll(self._confirmationRevision, request.context)
		self._revalidateBinding()
		failed = cleanup.failedCount
		status = (
			PortStatus("failed", self._confirmationRevision)
			if failed
			else PortStatus("ready", self._confirmationRevision)
		)
		error = PortError("KS.OUTPUT.CLEANUP_FAILED") if failed else None
		return self._result(
			request,
			status,
			outcome=PortOutcome(
				"capturesCleared" if not failed else "capturesPartiallyCleared",
				(
					cleanup.deletedCount,
					cleanup.skippedCount,
					cleanup.failedCount,
					cleanup.suspiciousCount,
				),
			),
			error=error,
			deleted=cleanup.deletedCount,
			skipped=cleanup.skippedCount,
			failed=cleanup.failedCount,
			suspicious=cleanup.suspiciousCount,
		)

	def actOnNewest(
		self,
		captureKind: CaptureKind,
		operation: Literal["copy", "reveal"],
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
	) -> bool:
		"""Discover, revalidate, and act on the newest committed matching output."""
		try:
			context = requireCompleteCorrelation(context)
		except (TypeError, ValueError):
			return False
		if context.generation != lifecycleGeneration or self._lifecycleGeneration != lifecycleGeneration:
			return False
		try:
			receipt = self._repository.newest(captureKind, context)
		except (AttributeError, OSError, ValueError):
			return False
		if receipt is None or not self._repository.revalidate(receipt, context):
			return False
		path = str(receipt.path)
		if operation == "copy":
			effect = self._clipboard.copyText(
				ClipboardRequest(path, self._actionIdFactory(), context),
			)
		else:
			effect = self._shell.revealFile(
				ShellRequest(path, self._confirmationRevision, context),
			)
		return effect.status.token == "ready" and effect.error is None
