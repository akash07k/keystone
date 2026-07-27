from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..capability import PlainValue, requireOpaqueId, requirePlainValue
from ..domain.correlation import CorrelationContext, requireCompleteCorrelation


__all__ = (
	"ReadOnlyNodePort",
	"IdentityComparisonPort",
	"ProviderSessionPort",
	"ProviderFieldRequest",
	"ProviderChildrenRequest",
	"ProviderRelationRequest",
	"ProviderTextRequest",
	"ProviderMetadataRequest",
	"IdentityComparisonRequest",
	"ResourceReleaseRequest",
	"ProviderSessionCloseRequest",
)


@dataclass(frozen=True, slots=True)
class ReadBudget:
	maximumItems: int
	maximumTextLength: int
	maximumMilliseconds: int

	def __post_init__(self) -> None:
		for name in ("maximumItems", "maximumTextLength", "maximumMilliseconds"):
			value = getattr(self, name)
			if type(value) is not int or value <= 0:
				raise ValueError(f"{name} must be a positive integer")


def _requireNodeRef(value: str, name: str = "nodeRef") -> None:
	requireOpaqueId(value, name)


@dataclass(frozen=True, slots=True)
class ProviderFieldRequest:
	nodeRef: str
	fieldId: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.nodeRef)
		requireOpaqueId(self.fieldId, "fieldId")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderChildrenRequest:
	nodeRef: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.nodeRef)
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderRelationRequest:
	nodeRef: str
	relationId: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.nodeRef)
		requireOpaqueId(self.relationId, "relationId")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderTextRequest:
	nodeRef: str
	textReadId: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.nodeRef)
		requireOpaqueId(self.textReadId, "textReadId")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderMetadataRequest:
	nodeRef: str
	metadataId: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.nodeRef)
		requireOpaqueId(self.metadataId, "metadataId")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class IdentityComparisonRequest:
	firstNodeRef: str
	secondNodeRef: str
	providerScope: str
	processScope: str
	budget: ReadBudget
	context: CorrelationContext

	def __post_init__(self) -> None:
		_requireNodeRef(self.firstNodeRef, "firstNodeRef")
		_requireNodeRef(self.secondNodeRef, "secondNodeRef")
		requireOpaqueId(self.providerScope, "providerScope")
		requireOpaqueId(self.processScope, "processScope")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ResourceReleaseRequest:
	resourceToken: str
	context: CorrelationContext

	def __post_init__(self) -> None:
		requireOpaqueId(self.resourceToken, "resourceToken")
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderSessionCloseRequest:
	context: CorrelationContext

	def __post_init__(self) -> None:
		_ = requireCompleteCorrelation(self.context)


@dataclass(frozen=True, slots=True)
class ProviderReadResult:
	status: str
	value: PlainValue = None
	errorCode: str | None = None
	truncated: bool = False

	def __post_init__(self) -> None:
		if self.status not in ("value", "empty", "unsupported", "unavailable", "stale", "failed"):
			raise ValueError(f"unknown provider read status {self.status!r}")
		requirePlainValue(self.value)
		if self.status == "value" and self.value is None:
			raise ValueError("value results require a value")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")
		if self.status != "value" and (self.value is not None or self.truncated):
			raise ValueError(f"{self.status} results cannot carry a value or truncation")
		if self.status in ("value", "empty", "unsupported") and self.errorCode is not None:
			raise ValueError(f"{self.status} results cannot carry an errorCode")
		if self.status in ("unavailable", "stale", "failed") and self.errorCode is None:
			raise ValueError(f"{self.status} results require an errorCode")


@dataclass(frozen=True, slots=True)
class ProviderChildBatch:
	status: str
	nodeRefs: tuple[str, ...]
	observedCount: int
	truncated: bool
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("value", "empty", "unavailable", "stale", "failed"):
			raise ValueError(f"unknown child batch status {self.status!r}")
		if self.observedCount < len(self.nodeRefs) or self.observedCount < 0:
			raise ValueError("observedCount cannot be smaller than the returned nodeRefs")
		for nodeRef in self.nodeRefs:
			requireOpaqueId(nodeRef, "nodeRef")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")
		if self.status in ("empty", "unavailable", "stale") and (
			self.nodeRefs or self.observedCount or self.truncated
		):
			raise ValueError(f"{self.status} child batches cannot carry observed children")
		if self.status == "failed" and (self.nodeRefs or self.observedCount or self.truncated):
			raise ValueError("failed child batches must be total at the provider boundary")
		if self.status in ("value", "empty") and self.errorCode is not None:
			raise ValueError(f"{self.status} child batches cannot carry an errorCode")
		if self.status in ("unavailable", "stale", "failed") and self.errorCode is None:
			raise ValueError(f"{self.status} child batches require an errorCode")


@dataclass(frozen=True, slots=True)
class IdentityComparisonResult:
	status: str
	decision: str
	evidence: tuple[PlainValue, ...]
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("value", "unavailable", "stale", "failed"):
			raise ValueError(f"unknown identity comparison status {self.status!r}")
		if self.decision not in ("same", "different", "conflict", "ambiguous", "failed"):
			raise ValueError(f"unknown identity decision {self.decision!r}")
		requirePlainValue(self.evidence, "evidence")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")
		if self.status == "value" and self.errorCode is not None:
			raise ValueError("value identity comparisons cannot carry an errorCode")
		if self.status != "value" and self.evidence:
			raise ValueError(f"{self.status} identity comparisons cannot carry evidence")
		if self.status != "value" and self.errorCode is None:
			raise ValueError(f"{self.status} identity comparisons require an errorCode")


@dataclass(frozen=True, slots=True)
class ReleaseResult:
	status: str
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("released", "alreadyReleased", "stale", "failed"):
			raise ValueError(f"unknown release status {self.status!r}")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")
		if self.status in ("stale", "failed") and self.errorCode is None:
			raise ValueError(f"{self.status} release results require an errorCode")


@runtime_checkable
class ReadOnlyNodePort(Protocol):
	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult: ...

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch: ...

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch: ...

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult: ...

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult: ...

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult: ...


@runtime_checkable
class IdentityComparisonPort(Protocol):
	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult: ...


@runtime_checkable
class ProviderSessionPort(Protocol):
	def releaseResource(self, request: ResourceReleaseRequest) -> ReleaseResult: ...

	def closeSession(self, request: ProviderSessionCloseRequest) -> ReleaseResult: ...
