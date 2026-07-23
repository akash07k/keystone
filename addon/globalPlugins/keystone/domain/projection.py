from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

type ProviderComparison = Literal["same", "different", "conflict"] | None
type StableKey = tuple[str, object]


class ProjectionStatus(StrEnum):
	NOT_REQUESTED = "notRequested"
	APPLIED = "applied"
	REJECTED = "rejected"
	DEGRADED = "degraded"
	REPLACED = "replaced"


class ProjectionMethod(StrEnum):
	NONE = "none"
	PYTHON_IDENTITY = "pythonIdentity"
	NVDA_EQUALITY = "nvdaEquality"
	PROVIDER_NATIVE = "providerNative"
	PROCESS_SCOPED_ACQUISITION = "processScopedAcquisition"
	WINDOW_SCOPED_ACQUISITION = "windowScopedAcquisition"
	STABLE_PROVIDER_KEY = "stableProviderKey"
	WHOLE_WINDOW = "wholeWindow"
	POSITION_AND_NAME = "positionAndName"


@dataclass(frozen=True, slots=True)
class ProjectionBudget:
	maximumCandidates: int
	maximumPropertyReads: int
	maximumMilliseconds: int
	maximumItems: int = 64

	def __post_init__(self) -> None:
		for name in (
			"maximumCandidates",
			"maximumPropertyReads",
			"maximumMilliseconds",
			"maximumItems",
		):
			value = getattr(self, name)
			if type(value) is not int or value <= 0:
				raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ProjectionRequest:
	requestId: str
	enabled: bool
	budget: ProjectionBudget
	allowWindowScoped: bool = True

	def __post_init__(self) -> None:
		if not self.requestId or self.requestId.strip() != self.requestId:
			raise ValueError("projection request ID must be nonempty canonical text")
		if type(self.allowWindowScoped) is not bool:
			raise ValueError("allowWindowScoped must be a boolean")

	@classmethod
	def explicit(
		cls,
		requestId: str,
		budget: ProjectionBudget,
		*,
		allowWindowScoped: bool = True,
	) -> ProjectionRequest:
		return cls(requestId, True, budget, allowWindowScoped)

	@classmethod
	def disabled(cls, requestId: str) -> ProjectionRequest:
		return cls(requestId, False, ProjectionBudget(1, 1, 1))


@dataclass(frozen=True, slots=True)
class IdentityProbe:
	pythonIdentity: bool = False
	nvdaEquality: bool | None = None
	providerComparison: ProviderComparison = None
	trustedAcquisition: bool = False
	windowScopedAcquisition: bool = False
	geometryGuidance: bool = False
	positionAndNameMatch: bool = False


@dataclass(frozen=True, slots=True)
class SelectedIdentity:
	providerProcessId: int
	providerScope: str
	role: str | None
	stableKeys: tuple[StableKey, ...]
	windowHandle: int | None
	wholeWindow: bool


@dataclass(frozen=True, slots=True)
class ProjectionCandidate:
	candidateId: str
	providerProcessId: int
	providerScope: str
	role: str | None
	stableKeys: tuple[StableKey, ...]
	windowHandle: int | None
	wholeWindow: bool
	probe: IdentityProbe

	def __post_init__(self) -> None:
		if not self.candidateId:
			raise ValueError("projection candidate ID must be nonempty")


@dataclass(frozen=True, slots=True)
class ProjectionEvidence:
	requested: bool
	requestId: str
	applied: bool
	status: ProjectionStatus
	method: ProjectionMethod
	providerScope: str
	confidence: Literal["direct", "strong", "indeterminate"]
	reasonCode: str
	candidateCount: int
	propertyReads: int
	completenessClaimed: bool = False

	def __post_init__(self) -> None:
		if not self.requestId:
			raise ValueError("projection evidence requires its request ID")
		if self.applied != (self.status is ProjectionStatus.APPLIED):
			raise ValueError("applied projection evidence must match status")
		if self.completenessClaimed:
			raise ValueError("raw completeness requires a separately proven generic threshold")
		if self.candidateCount < 0 or self.propertyReads < 0:
			raise ValueError("projection evidence counts must be nonnegative")


@dataclass(frozen=True, slots=True)
class ProjectionDecision:
	selectedCandidateId: str | None
	evidence: ProjectionEvidence


def _evidence(
	request: ProjectionRequest,
	status: ProjectionStatus,
	reasonCode: str,
	*,
	method: ProjectionMethod = ProjectionMethod.NONE,
	providerScope: str = "uia",
	candidateCount: int = 0,
	propertyReads: int = 0,
) -> ProjectionDecision:
	applied = status is ProjectionStatus.APPLIED
	return ProjectionDecision(
		None,
		ProjectionEvidence(
			request.enabled,
			request.requestId,
			applied,
			status,
			method,
			providerScope,
			"direct"
			if method
			in (
				ProjectionMethod.PYTHON_IDENTITY,
				ProjectionMethod.NVDA_EQUALITY,
				ProjectionMethod.PROVIDER_NATIVE,
				ProjectionMethod.PROCESS_SCOPED_ACQUISITION,
			)
			else "strong"
			if applied
			else "indeterminate",
			reasonCode,
			candidateCount,
			propertyReads,
		),
	)


def _matchingStableKey(selected: SelectedIdentity, candidate: ProjectionCandidate) -> bool:
	return any(
		selectedKey == candidateKey
		for selectedKey in selected.stableKeys
		for candidateKey in candidate.stableKeys
	)


def _candidateMethod(
	request: ProjectionRequest,
	selected: SelectedIdentity,
	candidate: ProjectionCandidate,
) -> tuple[ProjectionMethod | None, str]:
	probe = candidate.probe
	if probe.pythonIdentity:
		return ProjectionMethod.PYTHON_IDENTITY, "KS.RAW_UIA.PYTHON_IDENTITY"
	if probe.nvdaEquality is True:
		return ProjectionMethod.NVDA_EQUALITY, "KS.RAW_UIA.NVDA_EQUALITY"
	if probe.providerComparison == "same":
		return ProjectionMethod.PROVIDER_NATIVE, "KS.RAW_UIA.PROVIDER_NATIVE"
	if probe.providerComparison in ("different", "conflict"):
		return None, "KS.RAW_UIA.PROVIDER_CONFLICT"
	if probe.trustedAcquisition:
		return (
			ProjectionMethod.PROCESS_SCOPED_ACQUISITION,
			"KS.RAW_UIA.PROCESS_SCOPED_ACQUISITION",
		)
	if probe.positionAndNameMatch:
		return ProjectionMethod.POSITION_AND_NAME, "KS.RAW_UIA.POSITION_AND_NAME"
	if probe.windowScopedAcquisition:
		if not request.allowWindowScoped:
			return None, "KS.RAW_UIA.WINDOW_ONLY_TARGET"
		if selected.windowHandle is not None and selected.windowHandle == candidate.windowHandle:
			return (
				ProjectionMethod.WINDOW_SCOPED_ACQUISITION,
				"KS.RAW_UIA.WINDOW_SCOPED_ACQUISITION",
			)
		return None, "KS.RAW_UIA.WINDOW_SCOPE_MISMATCH"
	if _matchingStableKey(selected, candidate):
		if selected.role is not None and candidate.role is not None and selected.role != candidate.role:
			return None, "KS.RAW_UIA.STABLE_ROLE_CONFLICT"
		return ProjectionMethod.STABLE_PROVIDER_KEY, "KS.RAW_UIA.STABLE_PROVIDER_KEY"
	if (
		selected.wholeWindow
		and candidate.wholeWindow
		and selected.windowHandle is not None
		and selected.windowHandle == candidate.windowHandle
		and selected.role == candidate.role
	):
		return ProjectionMethod.WHOLE_WINDOW, "KS.RAW_UIA.WHOLE_WINDOW"
	if probe.geometryGuidance:
		return None, "KS.RAW_UIA.GEOMETRY_ONLY"
	return None, "KS.RAW_UIA.IDENTITY_UNPROVEN"


def decideProjection(
	request: ProjectionRequest,
	selected: SelectedIdentity,
	candidates: tuple[ProjectionCandidate, ...],
) -> ProjectionDecision:
	"""Resolve one request-scoped projection without treating weak hints as identity."""
	if not request.enabled:
		return _evidence(request, ProjectionStatus.NOT_REQUESTED, "KS.RAW_UIA.NOT_REQUESTED")
	if selected.providerProcessId < 0 or not selected.providerScope:
		return _evidence(request, ProjectionStatus.REJECTED, "KS.RAW_UIA.INVALID_SELECTED_IDENTITY")
	if len(candidates) > request.budget.maximumCandidates:
		return _evidence(
			request,
			ProjectionStatus.REJECTED,
			"KS.RAW_UIA.CANDIDATE_BUDGET",
			candidateCount=request.budget.maximumCandidates,
			propertyReads=0,
		)

	accepted: list[tuple[ProjectionCandidate, ProjectionMethod, str]] = []
	firstRejection = "KS.RAW_UIA.NO_CANDIDATE"
	propertyReads = 0
	for candidate in candidates:
		# PID and provider checks precede all optional identity evidence.
		propertyReads += 5
		if propertyReads > request.budget.maximumPropertyReads:
			return _evidence(
				request,
				ProjectionStatus.REJECTED,
				"KS.RAW_UIA.PROPERTY_BUDGET",
				candidateCount=len(candidates),
				propertyReads=request.budget.maximumPropertyReads,
			)
		if candidate.providerProcessId != selected.providerProcessId:
			firstRejection = "KS.RAW_UIA.CROSS_PROCESS"
			continue
		if candidate.providerScope != selected.providerScope:
			firstRejection = "KS.RAW_UIA.CROSS_PROVIDER"
			continue
		method, reason = _candidateMethod(request, selected, candidate)
		if method is None:
			firstRejection = reason
			continue
		accepted.append((candidate, method, reason))

	if len(accepted) != 1:
		reason = "KS.RAW_UIA.AMBIGUOUS" if len(accepted) > 1 else firstRejection
		return _evidence(
			request,
			ProjectionStatus.REJECTED,
			reason,
			providerScope=selected.providerScope,
			candidateCount=len(candidates),
			propertyReads=propertyReads,
		)
	candidate, method, reason = accepted[0]
	decision = _evidence(
		request,
		ProjectionStatus.APPLIED,
		reason,
		method=method,
		providerScope=selected.providerScope,
		candidateCount=len(candidates),
		propertyReads=propertyReads,
	)
	return ProjectionDecision(candidate.candidateId, decision.evidence)
