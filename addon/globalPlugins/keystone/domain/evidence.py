from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .status import (
	Confidence,
	EvidenceState,
	EvidenceValue,
	normalizeEvidenceValue,
	requireNonnegativeInteger,
	requireRfc3339Timestamp,
	requireToken,
)


type ProjectionMode = Literal["normalNvda", "rawUia", "offline", "derived"]
type PrivacyClassification = Literal["public", "sensitive", "protected", "unknown"]
_PROJECTION_MODES = ("normalNvda", "rawUia", "offline", "derived")
_PRIVACY_CLASSIFICATIONS = ("public", "sensitive", "protected", "unknown")


@dataclass(frozen=True, slots=True)
class Source:
	backend: str
	component: str
	symbol: str
	wrapperLoss: str | None = None

	def __post_init__(self) -> None:
		for fieldName in ("backend", "component", "symbol"):
			object.__setattr__(self, fieldName, requireToken(getattr(self, fieldName), fieldName))
		if self.wrapperLoss is not None:
			object.__setattr__(self, "wrapperLoss", requireToken(self.wrapperLoss, "wrapper loss"))


@dataclass(frozen=True, slots=True)
class Projection:
	mode: ProjectionMode
	method: str | None = None
	fallbackApplied: bool = False
	fallbackReasonCode: str | None = None

	def __post_init__(self) -> None:
		if self.mode not in _PROJECTION_MODES:
			raise ValueError("projection mode is not in the closed registry")
		if self.method is not None:
			object.__setattr__(self, "method", requireToken(self.method, "projection method"))
		if self.fallbackApplied != (self.fallbackReasonCode is not None):
			raise ValueError("fallback reason must be present exactly when fallback is applied")
		if self.fallbackReasonCode is not None:
			object.__setattr__(
				self,
				"fallbackReasonCode",
				requireToken(self.fallbackReasonCode, "fallback reason code"),
			)


@dataclass(frozen=True, slots=True)
class PrivacyReference:
	fieldGroup: str
	classification: PrivacyClassification
	effectiveTransform: str
	policyRevision: int

	def __post_init__(self) -> None:
		if self.classification not in _PRIVACY_CLASSIFICATIONS:
			raise ValueError("privacy classification is not in the closed registry")
		object.__setattr__(self, "fieldGroup", requireToken(self.fieldGroup, "field group"))
		object.__setattr__(
			self,
			"effectiveTransform",
			requireToken(self.effectiveTransform, "effective transform"),
		)
		if requireNonnegativeInteger(self.policyRevision, "policy revision") == 0:
			raise ValueError("policy revision must be positive")


@dataclass(frozen=True, slots=True)
class Truncation:
	limitType: str
	configuredLimit: int
	actualCount: int
	omittedCount: int
	reasonCode: str
	continuationAvailable: bool

	def __post_init__(self) -> None:
		object.__setattr__(self, "limitType", requireToken(self.limitType, "limit type"))
		object.__setattr__(self, "reasonCode", requireToken(self.reasonCode, "reason code"))
		for fieldName in ("configuredLimit", "actualCount", "omittedCount"):
			_ = requireNonnegativeInteger(getattr(self, fieldName), fieldName)
		if self.actualCount - self.configuredLimit != self.omittedCount:
			raise ValueError("omitted count must equal actual count minus configured limit")


@dataclass(frozen=True, slots=True)
class ErrorReference:
	code: str
	diagnosticId: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "code", requireToken(self.code, "error code"))
		object.__setattr__(self, "diagnosticId", requireToken(self.diagnosticId, "diagnostic ID"))


@dataclass(frozen=True, slots=True)
class Scope:
	scopeKind: str
	scopeId: str
	providerProcessId: int | None = None

	def __post_init__(self) -> None:
		object.__setattr__(self, "scopeKind", requireToken(self.scopeKind, "scope kind"))
		object.__setattr__(self, "scopeId", requireToken(self.scopeId, "scope ID"))
		if self.providerProcessId is not None:
			_ = requireNonnegativeInteger(self.providerProcessId, "provider process ID")


_VALUE_STATES = frozenset((EvidenceState.VALUE, EvidenceState.TRUNCATED, EvidenceState.MIXED))
_REQUIRED_ERROR_STATES = frozenset((EvidenceState.REJECTED, EvidenceState.FAILED))
_OPTIONAL_ERROR_STATES = frozenset(
	(EvidenceState.UNAVAILABLE, EvidenceState.STALE, EvidenceState.CANCELLED),
)


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
	status: EvidenceState
	source: Source
	projection: Projection
	confidence: Confidence
	privacy: PrivacyReference
	value: EvidenceValue | None = None
	truncation: Truncation | None = None
	errorRef: ErrorReference | None = None
	observedAt: str | None = None
	scope: Scope | None = None

	def __post_init__(self) -> None:
		if self.status in _VALUE_STATES:
			if self.value is None:
				raise ValueError(f"{self.status} evidence requires a value")
			object.__setattr__(self, "value", normalizeEvidenceValue(self.value))
		elif self.value is not None:
			raise ValueError(f"{self.status} evidence forbids a value")

		if self.status is EvidenceState.TRUNCATED:
			if self.truncation is None:
				raise ValueError("truncated evidence requires truncation details")
			if self.errorRef is not None:
				raise ValueError("truncated evidence forbids an error reference")
		elif self.truncation is not None:
			raise ValueError(f"{self.status} evidence forbids truncation details")

		if self.status in _REQUIRED_ERROR_STATES and self.errorRef is None:
			raise ValueError(f"{self.status} evidence requires an error reference")
		if (
			self.status not in _REQUIRED_ERROR_STATES
			and self.status not in _OPTIONAL_ERROR_STATES
			and self.errorRef is not None
		):
			raise ValueError(f"{self.status} evidence forbids an error reference")
		if (self.observedAt is None) != (self.scope is None):
			raise ValueError("observed time and scope must be provided together")
		if self.observedAt is not None:
			_ = requireRfc3339Timestamp(self.observedAt, "observed time")
