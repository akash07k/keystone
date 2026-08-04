from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol, cast

from ..capability import PlainValue, requireOpaqueId
from ..domain.privacy import (
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	transformValue,
)
from ..encoding.log_formats import (
	LogScalar,
	LogicalRecord,
	SafeException,
	SequenceAllocator,
	createRecord,
	validateEventFields,
)


class NvdaLogSink(Protocol):
	def emit(self, record: LogicalRecord) -> None: ...


@dataclass(frozen=True, slots=True)
class LogContext:
	sessionCorrelationId: str
	operationId: str | None
	jobId: str | None
	windowGeneration: int | None
	inspectorGeneration: int | None
	monitorGeneration: int | None
	nvdaPid: int
	threadIdentity: str


@dataclass(frozen=True, slots=True)
class LogFieldCandidate:
	name: str
	value: PlainValue
	fieldGroup: FieldGroup
	privacyClass: PrivacyClass
	protection: ProtectionEvidence
	sourceId: str

	def __post_init__(self) -> None:
		requireOpaqueId(self.name, "log field name")
		requireOpaqueId(self.sourceId, "log field source ID")
		if not isinstance(cast(object, self.fieldGroup), FieldGroup):
			raise TypeError("log field group must be registered")
		if not isinstance(cast(object, self.privacyClass), PrivacyClass):
			raise TypeError("log field privacy class must be registered")
		if not isinstance(cast(object, self.protection), ProtectionEvidence):
			raise TypeError("log field protection evidence must be registered")


@dataclass(frozen=True, slots=True)
class LogCandidate:
	timestamp: datetime
	code: str
	context: LogContext
	fields: tuple[LogFieldCandidate, ...]
	exception: SafeException | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.code, "log event code")
		names = tuple(item.name for item in self.fields)
		if len(names) != len(set(names)):
			raise ValueError("candidate log fields must be unique")


@dataclass(frozen=True, slots=True)
class LogEmissionResult:
	status: str
	record: LogicalRecord | None
	nvdaStatus: str
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("emitted", "admissionRejected"):
			raise ValueError("unknown logging result")
		if self.status == "emitted" and self.record is None:
			raise ValueError("emitted logging results require a logical record")
		if self.status == "admissionRejected" and self.record is not None:
			raise ValueError("rejected logging results cannot carry a logical record")
		if self.nvdaStatus not in ("emitted", "failed", "skipped"):
			raise ValueError("unknown NVDA logging status")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "logging error code")


def _logScalar(value: PlainValue) -> LogScalar:
	if isinstance(value, (str, bool, int)):
		return value
	raise ValueError("admitted log fields must be immutable scalars")


class LoggingService:
	__slots__ = ("_nvdaSink", "_privacyPolicy", "_sequenceAllocator")

	def __init__(
		self,
		*,
		nvdaSink: NvdaLogSink,
		sequenceAllocator: SequenceAllocator,
		privacyPolicy: PrivacyPolicy,
	) -> None:
		super().__init__()
		self._nvdaSink = nvdaSink
		self._sequenceAllocator = sequenceAllocator
		self._privacyPolicy = privacyPolicy

	def emit(self, candidate: LogCandidate) -> LogEmissionResult:
		try:
			self._validateCandidateShape(candidate)
			fields = self._admit(candidate.fields)
			validateEventFields(candidate.code, tuple(name for name, _value in fields))
			record = createRecord(
				sequence=1,
				timestamp=candidate.timestamp,
				code=candidate.code,
				sessionCorrelationId=candidate.context.sessionCorrelationId,
				operationId=candidate.context.operationId,
				jobId=candidate.context.jobId,
				windowGeneration=candidate.context.windowGeneration,
				inspectorGeneration=candidate.context.inspectorGeneration,
				monitorGeneration=candidate.context.monitorGeneration,
				nvdaPid=candidate.context.nvdaPid,
				threadIdentity=candidate.context.threadIdentity,
				fields=fields,
				exception=candidate.exception,
			)
		except (TypeError, ValueError, OverflowError):
			return LogEmissionResult(
				status="admissionRejected",
				record=None,
				nvdaStatus="skipped",
				errorCode="logAdmissionRejected",
			)

		try:
			record = replace(record, sequence=self._sequenceAllocator.next())
		except OverflowError:
			return LogEmissionResult(
				status="admissionRejected",
				record=None,
				nvdaStatus="skipped",
				errorCode="logAdmissionRejected",
			)

		try:
			self._nvdaSink.emit(record)
		except Exception:
			return LogEmissionResult(
				status="emitted",
				record=record,
				nvdaStatus="failed",
				errorCode="nvdaLogFailed",
			)
		return LogEmissionResult("emitted", record, "emitted")

	def forOperation(self, privacyPolicy: PrivacyPolicy) -> LoggingService:
		return LoggingService(
			nvdaSink=self._nvdaSink,
			sequenceAllocator=self._sequenceAllocator,
			privacyPolicy=privacyPolicy,
		)

	def replacePrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None:
		self._privacyPolicy = privacyPolicy

	@staticmethod
	def _validateCandidateShape(candidate: LogCandidate) -> None:
		if not isinstance(cast(object, candidate), LogCandidate):
			raise TypeError("logging candidates must use the closed candidate type")
		if not isinstance(cast(object, candidate.timestamp), datetime):
			raise TypeError("logging candidate timestamps must be datetime instances")
		if not isinstance(cast(object, candidate.context), LogContext):
			raise TypeError("logging candidates require a log context")
		if type(candidate.fields) is not tuple:
			raise TypeError("logging candidate fields must be a tuple")
		if candidate.exception is not None and not isinstance(
			cast(object, candidate.exception), SafeException
		):
			raise TypeError("logging candidate exceptions must be safe exceptions")
		for field in candidate.fields:
			if not isinstance(cast(object, field), LogFieldCandidate):
				raise TypeError("logging candidate fields must use the closed field type")

	def _admit(self, candidates: tuple[LogFieldCandidate, ...]) -> tuple[tuple[str, LogScalar], ...]:
		admitted: list[tuple[str, LogScalar]] = []
		for candidate in candidates:
			source = ObservedValue(
				fieldGroup=candidate.fieldGroup,
				value=candidate.value,
				privacyClass=candidate.privacyClass,
				protection=candidate.protection,
				sourceId=candidate.sourceId,
			)
			transformed = transformValue(source, SinkId.NVDA_LOG, self._privacyPolicy)
			if transformed.action is TransformAction.RETAIN:
				admitted.append((candidate.name, _logScalar(transformed.value)))
		return tuple(admitted)
