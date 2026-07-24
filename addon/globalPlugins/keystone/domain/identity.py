from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from .evidence import EvidenceEnvelope, Scope
from .status import Confidence, EvidenceState, requireNonnegativeInteger, requireToken


type IdentityCandidateKind = Literal[
	"uiaAutomationId",
	"uiaRuntimeId",
	"ia2WindowUniqueId",
	"msaaParentChildEvent",
	"jabVmLocal",
	"windowHandle",
	"providerStableKey",
]
_CANDIDATE_KIND_ORDER: tuple[IdentityCandidateKind, ...] = (
	"uiaAutomationId",
	"uiaRuntimeId",
	"ia2WindowUniqueId",
	"msaaParentChildEvent",
	"jabVmLocal",
	"windowHandle",
	"providerStableKey",
)


class IdentityDecision(StrEnum):
	CANDIDATE_ONLY = "candidateOnly"
	CONSISTENT = "consistent"
	AMBIGUOUS = "ambiguous"
	REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class IdentityCandidate:
	candidateId: str
	kind: IdentityCandidateKind
	value: EvidenceEnvelope
	scope: Scope
	confidence: Confidence

	def __post_init__(self) -> None:
		object.__setattr__(self, "candidateId", requireToken(self.candidateId, "candidate ID"))
		if self.kind not in _CANDIDATE_KIND_ORDER:
			raise ValueError("candidate kind is not in the closed registry")
		if self.value.status not in {
			EvidenceState.VALUE,
			EvidenceState.EMPTY,
			EvidenceState.UNAVAILABLE,
			EvidenceState.STALE,
			EvidenceState.REJECTED,
			EvidenceState.FAILED,
		}:
			raise ValueError("candidate value has an incompatible evidence state")

	@property
	def sortKey(self) -> tuple[int, bytes]:
		return _CANDIDATE_KIND_ORDER.index(self.kind), self.candidateId.encode("utf-8")


@dataclass(frozen=True, slots=True)
class IdentityConflict:
	leftCandidateId: str
	rightCandidateId: str
	reasonCode: str

	def __post_init__(self) -> None:
		object.__setattr__(
			self,
			"leftCandidateId",
			requireToken(self.leftCandidateId, "left candidate ID"),
		)
		object.__setattr__(
			self,
			"rightCandidateId",
			requireToken(self.rightCandidateId, "right candidate ID"),
		)
		object.__setattr__(self, "reasonCode", requireToken(self.reasonCode, "conflict reason code"))
		if self.leftCandidateId == self.rightCandidateId:
			raise ValueError("identity conflict must reference two different candidates")

	def validateAgainst(self, candidateIds: frozenset[str]) -> IdentityConflict:
		if self.leftCandidateId not in candidateIds or self.rightCandidateId not in candidateIds:
			raise ValueError("identity conflict references an unknown candidate")
		return self


@dataclass(frozen=True, slots=True)
class IdentityRecord:
	identityRecordVersion: int
	providerProcessId: EvidenceEnvelope
	logicalApplication: EvidenceEnvelope
	windowHandle: EvidenceEnvelope
	backend: EvidenceEnvelope
	overlayClasses: EvidenceEnvelope
	candidates: tuple[IdentityCandidate, ...]
	conflicts: tuple[IdentityConflict, ...]
	ambiguous: bool
	decision: IdentityDecision

	def __post_init__(self) -> None:
		if self.identityRecordVersion != 1:
			raise ValueError("identity record version must be 1")
		for label, envelope in (
			("provider process ID", self.providerProcessId),
			("window handle", self.windowHandle),
		):
			if envelope.status is EvidenceState.VALUE:
				if not isinstance(envelope.value, int) or isinstance(envelope.value, bool):
					raise ValueError(f"{label} evidence must contain an integer")
				_ = requireNonnegativeInteger(envelope.value, label)
		if self.backend.status is EvidenceState.VALUE and not isinstance(self.backend.value, str):
			raise ValueError("backend evidence must contain a string")
		if self.overlayClasses.status is EvidenceState.VALUE and (
			not isinstance(self.overlayClasses.value, tuple)
			or not all(isinstance(item, str) for item in self.overlayClasses.value)
		):
			raise ValueError("overlay-class evidence must contain an ordered string tuple")
		if tuple(sorted(self.candidates, key=lambda item: item.sortKey)) != self.candidates:
			raise ValueError("identity candidates must follow closed kind and ordinal byte order")
		candidateIds = tuple(candidate.candidateId for candidate in self.candidates)
		if len(set(candidateIds)) != len(candidateIds):
			raise ValueError("identity candidate IDs must be unique")
		knownIds = frozenset(candidateIds)
		for conflict in self.conflicts:
			_ = conflict.validateAgainst(knownIds)
		if self.ambiguous != bool(self.conflicts):
			raise ValueError("ambiguity must match retained identity conflicts")
		if self.ambiguous != (self.decision is IdentityDecision.AMBIGUOUS):
			raise ValueError("ambiguous identity must use the ambiguous decision")


@dataclass(frozen=True, slots=True)
class IndexInParent:
	source: Literal["provider", "ordinal", "unavailable"]
	value: int | None = None

	def __post_init__(self) -> None:
		if self.source == "unavailable":
			if self.value is not None:
				raise ValueError("unavailable index must not carry a value")
		elif self.value is None:
			raise ValueError("available index requires a value")
		else:
			_ = requireNonnegativeInteger(self.value, "index in parent")


def resolveIndexInParent(
	providerValue: EvidenceEnvelope,
	*,
	successfulChildOrdinal: int | None,
) -> IndexInParent:
	if providerValue.status is EvidenceState.VALUE:
		if not isinstance(providerValue.value, int) or isinstance(providerValue.value, bool):
			raise ValueError("provider index must be an integer")
		return IndexInParent("provider", providerValue.value)
	if successfulChildOrdinal is not None:
		return IndexInParent("ordinal", successfulChildOrdinal)
	return IndexInParent("unavailable")
