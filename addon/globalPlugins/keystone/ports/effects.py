from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ..capability import PlainValue, requireNamedValues, requireOpaqueId, requirePlainValue
from ..domain.correlation import CorrelationContext, requireCompleteCorrelation
from ..domain.privacy import UNREDACTED_SCREENSHOT_WARNING


__all__ = (
	"ScreenshotPort",
	"ScreenshotTarget",
	"ScreenshotAttempt",
	"ScreenshotResult",
	"ClipboardPort",
	"ShellPort",
	"FeedbackPort",
	"SettingsPort",
	"CaptureManagementRequest",
	"CaptureManagementResult",
	"CaptureManagementPort",
)

type CaptureManagementOperation = Literal[
	"refresh",
	"clearAll",
	"copyCommittedPath",
	"openCommittedFolder",
	"revealCommittedFolder",
]


def _requireGeneration(context: CorrelationContext, generation: int) -> None:
	_ = requireCompleteCorrelation(context)
	if context.generation != generation:
		raise ValueError("request generation must match correlation context")


_CAPTURE_OPERATIONS = frozenset(
	("refresh", "clearAll", "copyCommittedPath", "openCommittedFolder", "revealCommittedFolder"),
)
_PATH_CAPTURE_OPERATIONS = frozenset(("copyCommittedPath", "openCommittedFolder", "revealCommittedFolder"))


@dataclass(frozen=True, slots=True)
class PortStatus:
	token: str
	revision: int

	def __post_init__(self) -> None:
		if self.token not in (
			"ready",
			"empty",
			"disabled",
			"unavailable",
			"starting",
			"clearing",
			"stale",
			"failed",
		):
			raise ValueError(f"unknown port status {self.token!r}")
		if self.revision < 0:
			raise ValueError("status revision must be nonnegative")


@dataclass(frozen=True, slots=True)
class PortOutcome:
	token: str
	arguments: tuple[PlainValue, ...] = ()

	def __post_init__(self) -> None:
		requireOpaqueId(self.token, "outcome token")
		requirePlainValue(self.arguments, "outcome arguments")


@dataclass(frozen=True, slots=True)
class PortError:
	code: str
	arguments: tuple[PlainValue, ...] = ()

	def __post_init__(self) -> None:
		requireOpaqueId(self.code, "error code")
		requirePlainValue(self.arguments, "error arguments")


@dataclass(frozen=True, slots=True)
class ScreenshotTarget:
	scopeKind: Literal["containingForeground"]
	scopeId: str
	geometry: tuple[int, int, int, int]

	def __post_init__(self) -> None:
		if self.scopeKind != "containingForeground":
			raise ValueError("screenshot target must be the containing foreground window")
		requireOpaqueId(self.scopeId, "screenshot target scopeId")
		requirePlainValue(self.geometry, "screenshot target geometry")
		if len(self.geometry) != 4 or any(type(value) is not int for value in self.geometry):
			raise ValueError("screenshot target geometry must contain four integers")


@dataclass(frozen=True, slots=True)
class ScreenshotAttempt:
	attemptId: str
	generation: int
	target: ScreenshotTarget
	context: CorrelationContext

	def __post_init__(self) -> None:
		requireOpaqueId(self.attemptId, "screenshot attemptId")
		if self.generation < 0:
			raise ValueError("screenshot generation must be nonnegative")
		_requireGeneration(self.context, self.generation)


@dataclass(frozen=True, slots=True)
class ScreenshotResult:
	attempt: ScreenshotAttempt
	status: Literal["value", "failed", "absent"]
	image: bytes | None
	capturedGeometry: tuple[int, int, int, int] | None
	succeededAt: str | None
	errorCode: str | None
	diagnosticId: str | None
	warning: str = UNREDACTED_SCREENSHOT_WARNING

	def __post_init__(self) -> None:
		if self.status == "value":
			if (
				not self.image
				or self.capturedGeometry is None
				or self.succeededAt is None
				or self.errorCode is not None
				or self.diagnosticId is not None
			):
				raise ValueError("successful screenshot result requires only current image evidence")
			requirePlainValue(self.image, "screenshot image")
			requirePlainValue(self.capturedGeometry, "captured screenshot geometry")
			if len(self.capturedGeometry) != 4 or any(
				type(value) is not int for value in self.capturedGeometry
			):
				raise ValueError("captured screenshot geometry must contain four integers")
		elif self.status in ("failed", "absent"):
			if (
				self.image is not None
				or self.capturedGeometry is not None
				or self.succeededAt is not None
				or self.errorCode is None
				or self.diagnosticId is None
			):
				raise ValueError("non-value screenshot result requires only typed failure evidence")
			requireOpaqueId(self.errorCode, "screenshot error code")
			requireOpaqueId(self.diagnosticId, "screenshot diagnosticId")
		else:
			raise ValueError("screenshot result status is not supported")
		if self.warning != UNREDACTED_SCREENSHOT_WARNING:
			raise ValueError("screenshot result requires the fixed visual warning")


@dataclass(frozen=True, slots=True)
class ClipboardRequest:
	text: str
	requestId: str
	context: CorrelationContext

	def __post_init__(self) -> None:
		requirePlainValue(self.text, "text")
		requireOpaqueId(self.requestId, "requestId")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ShellRequest:
	targetId: str
	statusRevision: int
	context: CorrelationContext

	def __post_init__(self) -> None:
		requireOpaqueId(self.targetId, "targetId")
		if self.statusRevision < 0:
			raise ValueError("statusRevision must be nonnegative")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class FeedbackRequest:
	messageId: str
	arguments: tuple[PlainValue, ...]
	context: CorrelationContext

	def __post_init__(self) -> None:
		requireOpaqueId(self.messageId, "messageId")
		requirePlainValue(self.arguments, "arguments")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class SettingsWriteRequest:
	startingRevision: int
	values: tuple[tuple[str, PlainValue], ...]
	context: CorrelationContext

	def __post_init__(self) -> None:
		if self.startingRevision < 0:
			raise ValueError("startingRevision must be nonnegative")
		requireNamedValues(self.values, "values")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class SettingsReadRequest:
	context: CorrelationContext

	def __post_init__(self) -> None:
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class EffectResult:
	status: PortStatus
	outcome: PortOutcome | None = None
	error: PortError | None = None

	def __post_init__(self) -> None:
		if self.status.token == "failed" and self.error is None:
			raise ValueError("failed effect results require an error")
		if self.status.token != "failed" and self.error is not None:
			raise ValueError("nonfailed effect results cannot carry an error")


@runtime_checkable
class ScreenshotPort(Protocol):
	def captureScreenshot(self, attempt: ScreenshotAttempt) -> ScreenshotResult: ...


@runtime_checkable
class ClipboardPort(Protocol):
	def copyText(self, request: ClipboardRequest) -> EffectResult: ...


@runtime_checkable
class ShellPort(Protocol):
	def openFolder(self, request: ShellRequest) -> EffectResult: ...

	def revealFile(self, request: ShellRequest) -> EffectResult: ...


@runtime_checkable
class FeedbackPort(Protocol):
	def announce(self, request: FeedbackRequest) -> EffectResult: ...


@runtime_checkable
class SettingsPort(Protocol):
	def readSettings(self, request: SettingsReadRequest) -> EffectResult: ...

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult: ...


@dataclass(frozen=True, slots=True)
class CaptureManagementRequest:
	operation: CaptureManagementOperation
	context: CorrelationContext
	lifecycleGeneration: int
	actionId: str | None = None
	confirmationRevision: int | None = None

	def __post_init__(self) -> None:
		if self.operation not in _CAPTURE_OPERATIONS:
			raise ValueError(f"unknown capture management operation {self.operation!r}")
		if self.lifecycleGeneration < 0:
			raise ValueError("lifecycleGeneration must be nonnegative")
		_requireGeneration(self.context, self.lifecycleGeneration)
		if self.operation == "refresh":
			if self.actionId is not None or self.confirmationRevision is not None:
				raise ValueError("refresh does not accept an actionId or confirmationRevision")
		elif self.operation == "clearAll":
			if self.actionId is not None or self.confirmationRevision is None:
				raise ValueError("clearAll requires only a confirmationRevision")
		elif self.operation in _PATH_CAPTURE_OPERATIONS:
			if self.actionId is None or self.confirmationRevision is not None:
				raise ValueError(f"{self.operation} requires only an approved opaque actionId")
			requireOpaqueId(self.actionId, "actionId")
		if self.confirmationRevision is not None and self.confirmationRevision < 0:
			raise ValueError("confirmationRevision must be nonnegative")


@dataclass(frozen=True, slots=True)
class CaptureManagementResult:
	operation: CaptureManagementOperation
	lifecycleGeneration: int
	status: PortStatus
	outcome: PortOutcome | None
	error: PortError | None
	recognizedCount: int
	suspiciousCount: int
	deletedCount: int
	skippedCount: int
	failedCount: int
	confirmationRevision: int
	copyActionId: str | None
	openActionId: str | None
	revealActionId: str | None

	def __post_init__(self) -> None:
		if self.operation not in _CAPTURE_OPERATIONS:
			raise ValueError(f"unknown capture management operation {self.operation!r}")
		if self.lifecycleGeneration < 0 or self.confirmationRevision < 0:
			raise ValueError("capture management generations and revisions must be nonnegative")
		counts = (
			self.recognizedCount,
			self.suspiciousCount,
			self.deletedCount,
			self.skippedCount,
			self.failedCount,
		)
		if any(count < 0 for count in counts):
			raise ValueError("capture management counts must be nonnegative")
		for fieldName, actionId in (
			("copyActionId", self.copyActionId),
			("openActionId", self.openActionId),
			("revealActionId", self.revealActionId),
		):
			if actionId is not None:
				requireOpaqueId(actionId, fieldName)
		if self.status.token == "failed" and self.error is None:
			raise ValueError("failed capture management results require an error")
		if self.status.token != "failed" and self.error is not None:
			raise ValueError("nonfailed capture management results cannot carry an error")


@runtime_checkable
class CaptureManagementPort(Protocol):
	def manageCaptures(self, request: CaptureManagementRequest) -> CaptureManagementResult: ...
