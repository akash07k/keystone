from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .status import requireNonnegativeInteger


class CaptureState(StrEnum):
	ACQUIRING_TARGET = "acquiringTarget"
	BASELINE_CAPTURE = "baselineCapture"
	COLLECTING = "collecting"
	YIELDED = "yielded"
	TRANSFORMING = "transforming"
	NO_CHANGE_PENDING_PUBLICATION = "noChangePendingPublication"
	SCREENSHOT = "screenshot"
	SERIALIZING = "serializing"
	STAGING = "staging"
	VALIDATING = "validating"
	READY_TO_COMMIT = "readyToCommit"
	CANCELLATION_REQUESTED = "cancellationRequested"
	COMMITTING = "committing"
	COMPLETED = "completed"
	COMPLETED_TRUNCATED = "completedTruncated"
	COMPLETED_PARTIAL_SCREENSHOT = "completedPartialScreenshot"
	BASELINE_CREATED = "baselineCreated"
	NO_CHANGE = "noChange"
	CANCELLED = "cancelled"
	FAILED = "failed"


_ACTIVE_CAPTURE_STATES = frozenset(
	(
		CaptureState.ACQUIRING_TARGET,
		CaptureState.BASELINE_CAPTURE,
		CaptureState.COLLECTING,
		CaptureState.YIELDED,
		CaptureState.TRANSFORMING,
		CaptureState.NO_CHANGE_PENDING_PUBLICATION,
		CaptureState.SCREENSHOT,
		CaptureState.SERIALIZING,
		CaptureState.STAGING,
		CaptureState.VALIDATING,
		CaptureState.READY_TO_COMMIT,
	),
)
_COMMITTED_CAPTURE_STATES = frozenset(
	(
		CaptureState.COMPLETED,
		CaptureState.COMPLETED_TRUNCATED,
		CaptureState.COMPLETED_PARTIAL_SCREENSHOT,
		CaptureState.BASELINE_CREATED,
		CaptureState.NO_CHANGE,
	),
)
_TERMINAL_CAPTURE_STATES = _COMMITTED_CAPTURE_STATES | {
	CaptureState.CANCELLED,
	CaptureState.FAILED,
}
_CAPTURE_ADVANCES: dict[CaptureState, frozenset[CaptureState]] = {
	CaptureState.ACQUIRING_TARGET: frozenset((CaptureState.BASELINE_CAPTURE, CaptureState.COLLECTING)),
	CaptureState.BASELINE_CAPTURE: frozenset((CaptureState.COLLECTING,)),
	CaptureState.COLLECTING: frozenset((CaptureState.YIELDED, CaptureState.TRANSFORMING)),
	CaptureState.YIELDED: frozenset((CaptureState.COLLECTING, CaptureState.TRANSFORMING)),
	CaptureState.TRANSFORMING: frozenset(
		(CaptureState.SCREENSHOT, CaptureState.NO_CHANGE_PENDING_PUBLICATION),
	),
	CaptureState.NO_CHANGE_PENDING_PUBLICATION: frozenset((CaptureState.SCREENSHOT,)),
	CaptureState.SCREENSHOT: frozenset((CaptureState.SERIALIZING,)),
	CaptureState.SERIALIZING: frozenset((CaptureState.STAGING,)),
	CaptureState.STAGING: frozenset((CaptureState.VALIDATING,)),
	CaptureState.VALIDATING: frozenset((CaptureState.READY_TO_COMMIT,)),
}


@dataclass(frozen=True, slots=True)
class CaptureLifecycle:
	state: CaptureState
	operationGeneration: int
	publicationCommitted: bool = False

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.operationGeneration, "operation generation")
		if self.publicationCommitted != (self.state in _COMMITTED_CAPTURE_STATES):
			raise ValueError("publication commit flag must match a committed terminal state")

	@classmethod
	def start(cls, operationGeneration: int) -> CaptureLifecycle:
		return cls(CaptureState.ACQUIRING_TARGET, operationGeneration)

	@property
	def isTerminal(self) -> bool:
		return self.state in _TERMINAL_CAPTURE_STATES

	def advance(self, nextState: CaptureState) -> CaptureLifecycle:
		if nextState not in _CAPTURE_ADVANCES.get(self.state, frozenset()):
			raise ValueError(f"cannot advance capture from {self.state} to {nextState}")
		return CaptureLifecycle(nextState, self.operationGeneration)

	def requestCancellation(self) -> CaptureLifecycle:
		if self.state not in _ACTIVE_CAPTURE_STATES:
			raise ValueError(f"cannot request cancellation from {self.state}")
		return CaptureLifecycle(CaptureState.CANCELLATION_REQUESTED, self.operationGeneration)

	def finishCancellation(self) -> CaptureLifecycle:
		if self.state is not CaptureState.CANCELLATION_REQUESTED:
			raise ValueError(f"cannot finish cancellation from {self.state}")
		return CaptureLifecycle(CaptureState.CANCELLED, self.operationGeneration)

	def beginCommit(self) -> CaptureLifecycle:
		if self.state is not CaptureState.READY_TO_COMMIT:
			raise ValueError(f"cannot begin commit from {self.state}")
		return CaptureLifecycle(CaptureState.COMMITTING, self.operationGeneration)

	def finishCommit(self, outcome: CaptureState) -> CaptureLifecycle:
		if self.state is not CaptureState.COMMITTING:
			raise ValueError(f"cannot finish commit from {self.state}")
		if outcome not in _COMMITTED_CAPTURE_STATES:
			raise ValueError("commit outcome must be a committed terminal state")
		return CaptureLifecycle(outcome, self.operationGeneration, publicationCommitted=True)

	def fail(self) -> CaptureLifecycle:
		if self.state in _TERMINAL_CAPTURE_STATES:
			raise ValueError(f"cannot fail terminal capture state {self.state}")
		return CaptureLifecycle(CaptureState.FAILED, self.operationGeneration)


class PublicationState(StrEnum):
	STAGING = "staging"
	READY = "ready"
	RENAMING = "renaming"
	COMMITTED = "committed"
	CANCELLED = "cancelled"
	FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PublicationLifecycle:
	state: PublicationState
	generation: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.generation, "publication generation")

	@property
	def committed(self) -> bool:
		return self.state is PublicationState.COMMITTED

	def markReady(self) -> PublicationLifecycle:
		if self.state is not PublicationState.STAGING:
			raise ValueError(f"cannot mark publication ready from {self.state}")
		return PublicationLifecycle(PublicationState.READY, self.generation)

	def beginRename(self) -> PublicationLifecycle:
		if self.state is not PublicationState.READY:
			raise ValueError(f"cannot begin rename from {self.state}")
		return PublicationLifecycle(PublicationState.RENAMING, self.generation)

	def renameSucceeded(self) -> PublicationLifecycle:
		if self.state is not PublicationState.RENAMING:
			raise ValueError(f"cannot complete rename from {self.state}")
		return PublicationLifecycle(PublicationState.COMMITTED, self.generation)

	def cancel(self) -> PublicationLifecycle:
		if self.state not in {PublicationState.STAGING, PublicationState.READY}:
			raise ValueError(f"cannot cancel publication from {self.state}")
		return PublicationLifecycle(PublicationState.CANCELLED, self.generation)

	def fail(self) -> PublicationLifecycle:
		if self.state in {PublicationState.COMMITTED, PublicationState.CANCELLED, PublicationState.FAILED}:
			raise ValueError(f"cannot fail terminal publication state {self.state}")
		return PublicationLifecycle(PublicationState.FAILED, self.generation)
