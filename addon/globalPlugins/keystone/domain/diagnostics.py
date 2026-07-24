from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .correlation import CorrelationContext
from .evidence import EvidenceEnvelope
from .status import EvidenceState, requireFiniteNumber, requireNonnegativeInteger, requireToken


DIAGNOSTIC_HEAD_LIMIT: Final = 250
DIAGNOSTIC_TAIL_LIMIT: Final = 50
DIAGNOSTIC_RETAINED_LIMIT: Final = DIAGNOSTIC_HEAD_LIMIT + DIAGNOSTIC_TAIL_LIMIT


class Severity(StrEnum):
	INFO = "info"
	WARNING = "warning"
	ERROR = "error"
	CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Timing:
	startMilliseconds: int | float
	endMilliseconds: int | float
	elapsedMilliseconds: int | float

	def __post_init__(self) -> None:
		start = requireFiniteNumber(self.startMilliseconds, "start milliseconds")
		end = requireFiniteNumber(self.endMilliseconds, "end milliseconds")
		elapsed = requireFiniteNumber(self.elapsedMilliseconds, "elapsed milliseconds")
		if start < 0 or end < 0 or elapsed < 0:
			raise ValueError("diagnostic timing values must be nonnegative")
		if end < start or abs((end - start) - elapsed) > 1e-9:
			raise ValueError("diagnostic elapsed time must equal end minus start")


@dataclass(frozen=True, slots=True)
class Diagnostic:
	diagnosticId: str
	code: str
	fieldPath: str
	safeBreadcrumb: tuple[str, ...]
	component: str
	provider: EvidenceEnvelope
	severity: Severity
	sanitizedDetail: str
	timing: Timing
	budget: EvidenceEnvelope
	fallback: EvidenceEnvelope
	correlation: CorrelationContext

	def __post_init__(self) -> None:
		object.__setattr__(self, "diagnosticId", requireToken(self.diagnosticId, "diagnostic ID"))
		object.__setattr__(self, "code", requireToken(self.code, "diagnostic code"))
		if self.fieldPath and not self.fieldPath.startswith("/"):
			raise ValueError("diagnostic field path must be a JSON Pointer")
		if len(self.safeBreadcrumb) > 64:
			raise ValueError("diagnostic breadcrumb must be bounded")
		normalizedBreadcrumb = tuple(
			requireToken(segment, "breadcrumb segment") for segment in self.safeBreadcrumb
		)
		object.__setattr__(self, "safeBreadcrumb", normalizedBreadcrumb)
		object.__setattr__(self, "component", requireToken(self.component, "diagnostic component"))
		if self.provider.status not in {EvidenceState.VALUE, EvidenceState.NOT_APPLICABLE}:
			raise ValueError("diagnostic provider must be a value or not applicable")
		if len(self.sanitizedDetail) > 1024:
			raise ValueError("diagnostic detail exceeds 1024 Unicode scalar values")
		for label, envelope in (("budget", self.budget), ("fallback", self.fallback)):
			if envelope.status not in {EvidenceState.VALUE, EvidenceState.NOT_APPLICABLE}:
				raise ValueError(f"diagnostic {label} must be a value or not applicable")

	@property
	def collapsed(self) -> tuple[Severity, str, str, tuple[str, ...]]:
		return self.severity, self.code, self.fieldPath, self.safeBreadcrumb


@dataclass(frozen=True, slots=True)
class DiagnosticBundle:
	diagnostics: tuple[Diagnostic, ...]
	diagnosticsTotal: int
	diagnosticsTruncated: bool

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.diagnosticsTotal, "diagnostics total")
		if self.diagnosticsTotal < len(self.diagnostics):
			raise ValueError("diagnostics total cannot be smaller than retained diagnostics")
		if self.diagnosticsTruncated != (self.diagnosticsTotal > len(self.diagnostics)):
			raise ValueError("diagnostics truncation flag must match retained count")
		if len(self.diagnostics) > DIAGNOSTIC_RETAINED_LIMIT:
			raise ValueError(f"at most {DIAGNOSTIC_RETAINED_LIMIT} diagnostics may be retained")
		ids = tuple(diagnostic.diagnosticId for diagnostic in self.diagnostics)
		if len(set(ids)) != len(ids):
			raise ValueError("diagnostic IDs must be unique")


def retainDiagnostics(diagnostics: tuple[Diagnostic, ...]) -> DiagnosticBundle:
	ids = tuple(diagnostic.diagnosticId for diagnostic in diagnostics)
	if len(set(ids)) != len(ids):
		raise ValueError("diagnostic IDs must be unique before retention")
	total = len(diagnostics)
	retained = (
		diagnostics
		if total <= DIAGNOSTIC_RETAINED_LIMIT
		else diagnostics[:DIAGNOSTIC_HEAD_LIMIT] + diagnostics[-DIAGNOSTIC_TAIL_LIMIT:]
	)
	return DiagnosticBundle(retained, total, total > len(retained))


@dataclass(frozen=True, slots=True)
class DiagnosticSnapshot:
	generation: int
	bundle: DiagnosticBundle

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.generation, "diagnostic generation")

	def get(self, expectedGeneration: int, index: int) -> Diagnostic:
		if expectedGeneration != self.generation:
			raise ValueError("diagnostic snapshot generation is stale")
		if index < 0 or index >= len(self.bundle.diagnostics):
			raise IndexError("diagnostic index is outside the completed snapshot")
		return self.bundle.diagnostics[index]
