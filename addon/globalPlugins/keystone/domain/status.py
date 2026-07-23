from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import math
import re
from typing import cast, Protocol
import unicodedata


_RFC3339_TIMESTAMP = re.compile(
	r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
)


class EvidenceState(StrEnum):
	VALUE = "value"
	EMPTY = "empty"
	UNSUPPORTED = "unsupported"
	NOT_APPLICABLE = "notApplicable"
	UNAVAILABLE = "unavailable"
	STALE = "stale"
	REJECTED = "rejected"
	REDACTED = "redacted"
	TRUNCATED = "truncated"
	CANCELLED = "cancelled"
	FAILED = "failed"
	MIXED = "mixed"

	@classmethod
	def parse(cls, token: str) -> EvidenceState:
		try:
			return cls(token)
		except ValueError as error:
			raise ValueError(f"unknown evidence state: {token!r}") from error

	@property
	def labelKey(self) -> str:
		return f"evidenceState.{self.value}"


class Confidence(StrEnum):
	DIRECT = "direct"
	DERIVED = "derived"
	FLATTENED_BY_WRAPPER = "flattenedByWrapper"
	INDETERMINATE = "indeterminate"


type EvidenceValue = bool | int | float | str | bytes | tuple[EvidenceValue, ...]

_MAX_EVIDENCE_TUPLE_DEPTH = 64
_TUPLE_COMPLETE = object()


def requireToken(value: object, label: str) -> str:
	if not isinstance(value, str) or not value or value.strip() != value:
		raise ValueError(f"{label} must be a nonempty trimmed string")
	return unicodedata.normalize("NFC", value)


def requireRfc3339Timestamp(value: object, label: str) -> datetime:
	if not isinstance(value, str) or _RFC3339_TIMESTAMP.fullmatch(value) is None:
		raise ValueError(f"{label} must be an RFC 3339 timestamp with an offset")
	try:
		return datetime.fromisoformat(value)
	except ValueError as error:
		raise ValueError(f"{label} must be an RFC 3339 timestamp with an offset") from error


def requireNonnegativeInteger(value: object, label: str) -> int:
	if not isinstance(value, int) or isinstance(value, bool) or value < 0:
		raise ValueError(f"{label} must be a nonnegative integer")
	return value


def requireFiniteNumber(value: object, label: str) -> int | float:
	if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
		raise ValueError(f"{label} must be a finite number")
	return value


def normalizeEvidenceValue(value: object) -> EvidenceValue:
	pending: list[tuple[object, int, frozenset[int], int | None]] = [
		(value, 0, frozenset(), None),
	]
	normalized: list[EvidenceValue] = []
	while pending:
		currentValue, currentDepth, activeTuples, completedTupleLength = pending.pop()
		if completedTupleLength is not None:
			start = len(normalized) - completedTupleLength
			normalized[start:] = [tuple(normalized[start:])]
			continue
		if currentDepth > _MAX_EVIDENCE_TUPLE_DEPTH:
			raise ValueError("evidence value exceeds the tuple depth limit")
		if currentValue is _TUPLE_COMPLETE:
			raise AssertionError("tuple completion marker requires a length")
		if isinstance(currentValue, bool):
			normalized.append(currentValue)
		elif isinstance(currentValue, int):
			normalized.append(currentValue)
		elif isinstance(currentValue, float):
			if not math.isfinite(currentValue):
				raise TypeError("evidence values must not contain non-finite numbers")
			normalized.append(currentValue)
		elif isinstance(currentValue, str):
			normalized.append(unicodedata.normalize("NFC", currentValue))
		elif isinstance(currentValue, bytes):
			normalized.append(currentValue)
		elif isinstance(currentValue, tuple):
			tupleValue = cast(tuple[object, ...], currentValue)
			tupleId = id(tupleValue)
			if tupleId in activeTuples:
				raise ValueError("evidence value contains a cyclic tuple structure")
			pending.append((_TUPLE_COMPLETE, 0, frozenset(), len(tupleValue)))
			childActiveTuples = activeTuples | frozenset((tupleId,))
			for index in range(len(tupleValue) - 1, -1, -1):
				pending.append((tupleValue[index], currentDepth + 1, childActiveTuples, None))
		else:
			raise TypeError(f"unsupported or mutable evidence value: {type(currentValue).__name__}")
	return normalized[0]


class _StatusBearing(Protocol):
	@property
	def status(self) -> EvidenceState: ...


@dataclass(frozen=True, slots=True)
class EvidenceStateCounts:
	items: tuple[tuple[EvidenceState, int], ...]

	def __post_init__(self) -> None:
		if tuple(state for state, _count in self.items) != tuple(EvidenceState):
			raise ValueError("state counts must follow the complete evidence-state registry")
		for _state, count in self.items:
			_ = requireNonnegativeInteger(count, "state count")

	@classmethod
	def fromEnvelopes(cls, envelopes: Iterable[_StatusBearing]) -> EvidenceStateCounts:
		counts = {state: 0 for state in EvidenceState}
		for envelope in envelopes:
			counts[envelope.status] += 1
		return cls(tuple((state, counts[state]) for state in EvidenceState))

	def count(self, state: EvidenceState) -> int:
		return dict(self.items)[state]


@dataclass(frozen=True, slots=True)
class OutcomeSummary:
	outcomeToken: str
	stateCounts: EvidenceStateCounts
	successfulAreas: tuple[str, ...] = ()
	failedAreas: tuple[str, ...] = ()
	errorCode: str | None = None
	diagnosticId: str | None = None

	def __post_init__(self) -> None:
		object.__setattr__(self, "outcomeToken", requireToken(self.outcomeToken, "outcome token"))
		for label, areas in (("successful area", self.successfulAreas), ("failed area", self.failedAreas)):
			normalized = tuple(requireToken(area, label) for area in areas)
			if len(set(normalized)) != len(normalized):
				raise ValueError(f"{label} values must be unique")
			object.__setattr__(
				self,
				"successfulAreas" if label == "successful area" else "failedAreas",
				normalized,
			)
		if (self.errorCode is None) != (self.diagnosticId is None):
			raise ValueError("error code and diagnostic ID must be present together")
		if self.outcomeToken == "failed" and self.errorCode is None:
			raise ValueError("failed outcomes require an error code and diagnostic ID")
		if self.errorCode is not None:
			object.__setattr__(self, "errorCode", requireToken(self.errorCode, "error code"))
			object.__setattr__(self, "diagnosticId", requireToken(self.diagnosticId or "", "diagnostic ID"))

	@property
	def isPartial(self) -> bool:
		return bool(self.successfulAreas and self.failedAreas)
