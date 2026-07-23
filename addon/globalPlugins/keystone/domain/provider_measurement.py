from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import json
import math
from typing import Literal, Protocol, cast

from .status import requireNonnegativeInteger


type BackendId = Literal[
	"nvdaSelected",
	"uia",
	"ia2Msaa",
	"javaAccessBridge",
	"offline",
]
type OperationId = Literal[
	"fieldRead",
	"childrenRead",
	"relationRead",
	"textRead",
	"metadataRead",
	"identityCompare",
	"release",
	"poll",
	"offlineAdmission",
]
type MeasurementOutcome = Literal[
	"success",
	"unsupported",
	"notApplicable",
	"empty",
	"stale",
	"malformed",
	"slow",
	"blocked",
	"cancelled",
	"failed",
	"releaseFailed",
]
type MetadataKey = Literal["attempt", "batchSize", "budget", "generation"]
type SafeMetadataValue = bool | int

BACKEND_IDS: tuple[BackendId, ...] = (
	"nvdaSelected",
	"uia",
	"ia2Msaa",
	"javaAccessBridge",
	"offline",
)
OPERATION_IDS: tuple[OperationId, ...] = (
	"fieldRead",
	"childrenRead",
	"relationRead",
	"textRead",
	"metadataRead",
	"identityCompare",
	"release",
	"poll",
	"offlineAdmission",
)
MEASUREMENT_OUTCOMES: tuple[MeasurementOutcome, ...] = (
	"success",
	"unsupported",
	"notApplicable",
	"empty",
	"stale",
	"malformed",
	"slow",
	"blocked",
	"cancelled",
	"failed",
	"releaseFailed",
)
METADATA_KEYS: tuple[MetadataKey, ...] = ("attempt", "batchSize", "budget", "generation")
HISTOGRAM_LIMITS_MICROSECONDS = (1_000, 10_000, 100_000, 1_000_000)
MAXIMUM_DURATION_MICROSECONDS = (1 << 63) - 1
ARTIFACT_SCHEMA_VERSION = 1
GENERATOR_VERSION = "1.0"
CONTRACT_DIGEST = hashlib.sha256(
	repr(
		(
			BACKEND_IDS,
			OPERATION_IDS,
			MEASUREMENT_OUTCOMES,
			METADATA_KEYS,
			HISTOGRAM_LIMITS_MICROSECONDS,
			ARTIFACT_SCHEMA_VERSION,
		),
	).encode(),
).hexdigest()


def _digest(value: object, label: str) -> str:
	if (
		not isinstance(value, str)
		or len(value) != 64
		or any(character not in "0123456789abcdef" for character in value)
	):
		raise ValueError(f"{label} must be a lowercase SHA-256 digest")
	return value


@dataclass(frozen=True, slots=True)
class MeasurementProvenance:
	sourceDigest: str
	contractDigest: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "sourceDigest", _digest(self.sourceDigest, "source digest"))
		object.__setattr__(self, "contractDigest", _digest(self.contractDigest, "contract digest"))


@dataclass(frozen=True, slots=True)
class MeasurementObservation:
	backend: BackendId
	operation: OperationId
	outcome: MeasurementOutcome
	durationMicroseconds: int
	itemCount: int
	budget: int
	provenance: MeasurementProvenance
	metadata: tuple[tuple[MetadataKey, SafeMetadataValue], ...] = ()

	def __post_init__(self) -> None:
		if self.backend not in BACKEND_IDS:
			raise ValueError("measurement backend is not in the closed registry")
		if self.operation not in OPERATION_IDS:
			raise ValueError("measurement operation is not in the closed registry")
		if self.outcome not in MEASUREMENT_OUTCOMES:
			raise ValueError("measurement outcome is not in the closed registry")
		duration = requireNonnegativeInteger(self.durationMicroseconds, "duration")
		if duration > MAXIMUM_DURATION_MICROSECONDS:
			raise ValueError("measurement duration exceeds the signed 64-bit bound")
		_ = requireNonnegativeInteger(self.itemCount, "item count")
		_ = requireNonnegativeInteger(self.budget, "budget")
		keys = tuple(key for key, _value in self.metadata)
		if len(set(keys)) != len(keys) or any(key not in METADATA_KEYS for key in keys):
			raise ValueError("measurement metadata must use unique closed keys")
		for _key, value in cast(tuple[tuple[object, object], ...], self.metadata):
			if not isinstance(value, (bool, int)):
				raise TypeError("measurement metadata accepts only booleans and integers")


class MonotonicClock(Protocol):
	def nowMicroseconds(self) -> int: ...


@dataclass(frozen=True, slots=True)
class MeasurementRecorder:
	clock: MonotonicClock

	def observe(
		self,
		backend: BackendId,
		operation: OperationId,
		outcome: MeasurementOutcome,
		provenance: MeasurementProvenance,
		action: Callable[[], None],
		*,
		itemCount: int = 0,
		budget: int = 0,
		metadata: tuple[tuple[MetadataKey, SafeMetadataValue], ...] = (),
	) -> MeasurementObservation:
		start = self.clock.nowMicroseconds()
		action()
		end = self.clock.nowMicroseconds()
		if end < start:
			raise ValueError("monotonic clock moved backwards")
		return MeasurementObservation(
			backend,
			operation,
			outcome,
			end - start,
			itemCount,
			budget,
			provenance,
			metadata,
		)


@dataclass(frozen=True, slots=True)
class Distribution:
	count: int
	minimum: int | None
	maximum: int | None
	median: int | None
	p90: int | None
	p95: int | None
	p99: int | None
	histogram: tuple[tuple[int | None, int], ...]


@dataclass(frozen=True, slots=True)
class FaultSummary:
	counts: tuple[tuple[MeasurementOutcome, int], ...]


@dataclass(frozen=True, slots=True)
class MeasurementAggregate:
	backend: BackendId
	operation: OperationId
	distribution: Distribution
	faults: FaultSummary


def _nearestRank(sortedValues: tuple[int, ...], percentile: int) -> int | None:
	if not sortedValues:
		return None
	index = max(0, math.ceil((percentile / 100) * len(sortedValues)) - 1)
	return sortedValues[index]


def distribution(durations: Iterable[int]) -> Distribution:
	values = tuple(sorted(durations))
	for value in values:
		_ = requireNonnegativeInteger(value, "duration")
	if not values:
		return Distribution(
			0,
			None,
			None,
			None,
			None,
			None,
			None,
			tuple((limit, 0) for limit in (*HISTOGRAM_LIMITS_MICROSECONDS, None)),
		)
	histogramCounts = [0] * (len(HISTOGRAM_LIMITS_MICROSECONDS) + 1)
	for value in values:
		for index, limit in enumerate(HISTOGRAM_LIMITS_MICROSECONDS):
			if value <= limit:
				histogramCounts[index] += 1
				break
		else:
			histogramCounts[-1] += 1
	return Distribution(
		len(values),
		values[0],
		values[-1],
		_nearestRank(values, 50),
		_nearestRank(values, 90),
		_nearestRank(values, 95),
		_nearestRank(values, 99),
		tuple(zip((*HISTOGRAM_LIMITS_MICROSECONDS, None), histogramCounts, strict=True)),
	)


def aggregateMeasurements(
	observations: Iterable[MeasurementObservation],
) -> tuple[MeasurementAggregate, ...]:
	groups: dict[tuple[BackendId, OperationId], list[MeasurementObservation]] = {}
	for observation in observations:
		groups.setdefault((observation.backend, observation.operation), []).append(observation)
	result: list[MeasurementAggregate] = []
	for backend, operation in sorted(groups):
		group = groups[(backend, operation)]
		faultCounts: tuple[tuple[MeasurementOutcome, int], ...] = tuple(
			(outcome, sum(item.outcome == outcome for item in group)) for outcome in MEASUREMENT_OUTCOMES
		)
		result.append(
			MeasurementAggregate(
				backend,
				operation,
				distribution(item.durationMicroseconds for item in group),
				FaultSummary(faultCounts),
			),
		)
	return tuple(result)


@dataclass(frozen=True, slots=True)
class CandidateThreshold:
	backend: BackendId
	operation: OperationId
	status: Literal["candidate", "noCandidate"]
	valueMicroseconds: int | None
	reasonCode: str
	sampleCount: int
	faultCount: int
	distribution: Distribution


def proposeThreshold(aggregate: MeasurementAggregate) -> CandidateThreshold:
	sampleCount = aggregate.distribution.count
	faultCount = sum(count for outcome, count in aggregate.faults.counts if outcome != "success")
	if sampleCount < 3:
		return CandidateThreshold(
			aggregate.backend,
			aggregate.operation,
			"noCandidate",
			None,
			"insufficientSamples",
			sampleCount,
			faultCount,
			aggregate.distribution,
		)
	if faultCount * 2 > sampleCount:
		return CandidateThreshold(
			aggregate.backend,
			aggregate.operation,
			"noCandidate",
			None,
			"excessiveFaultRatio",
			sampleCount,
			faultCount,
			aggregate.distribution,
		)
	return CandidateThreshold(
		aggregate.backend,
		aggregate.operation,
		"candidate",
		aggregate.distribution.p95,
		"p95Observation",
		sampleCount,
		faultCount,
		aggregate.distribution,
	)


def _distributionObject(value: Distribution) -> dict[str, object]:
	return {
		"count": value.count,
		"histogram": [{"count": count, "upperBoundMicroseconds": limit} for limit, count in value.histogram],
		"maximum": value.maximum,
		"median": value.median,
		"minimum": value.minimum,
		"p90": value.p90,
		"p95": value.p95,
		"p99": value.p99,
	}


def candidateArtifact(
	aggregates: tuple[MeasurementAggregate, ...],
	sourceDigest: str,
	contractDigest: str,
) -> bytes:
	document = {
		"contractDigest": _digest(contractDigest, "contract digest"),
		"generatorVersion": GENERATOR_VERSION,
		"groups": [
			{
				"backend": candidate.backend,
				"distribution": _distributionObject(candidate.distribution),
				"faultCount": candidate.faultCount,
				"faults": dict(aggregate.faults.counts),
				"operation": candidate.operation,
				"reasonCode": candidate.reasonCode,
				"sampleCount": candidate.sampleCount,
				"status": candidate.status,
				"valueMicroseconds": candidate.valueMicroseconds,
			}
			for aggregate in aggregates
			for candidate in (proposeThreshold(aggregate),)
		],
		"schemaVersion": ARTIFACT_SCHEMA_VERSION,
		"sourceDigest": _digest(sourceDigest, "source digest"),
		"status": "candidateOnly",
	}
	return (json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def validateCandidateArtifact(data: bytes) -> None:
	if data.startswith(b"\xef\xbb\xbf") or not data.endswith(b"\n"):
		raise ValueError("candidate artifact must be UTF-8 without BOM and end with LF")
	try:
		parsed = json.loads(data)
	except (UnicodeDecodeError, json.JSONDecodeError) as error:
		raise ValueError("candidate artifact is not valid UTF-8 JSON") from error
	if not isinstance(parsed, dict):
		raise ValueError("candidate artifact root must be an object")
	document = cast(dict[str, object], parsed)
	if set(document) != {
		"contractDigest",
		"generatorVersion",
		"groups",
		"schemaVersion",
		"sourceDigest",
		"status",
	}:
		raise ValueError("candidate artifact fields do not match the closed schema")
	if document["schemaVersion"] != ARTIFACT_SCHEMA_VERSION or document["status"] != "candidateOnly":
		raise ValueError("candidate artifact version or authority status is invalid")
	_ = _digest(document["sourceDigest"], "source digest")
	_ = _digest(document["contractDigest"], "contract digest")
	if candidateArtifactFromDocument(document) != data:
		raise ValueError("candidate artifact bytes are not canonical")


def candidateArtifactFromDocument(document: dict[str, object]) -> bytes:
	return (json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sourceDigest(observations: tuple[MeasurementObservation, ...]) -> str:
	safeRows = tuple(
		(
			item.backend,
			item.operation,
			item.outcome,
			item.durationMicroseconds,
			item.itemCount,
			item.budget,
			item.metadata,
		)
		for item in observations
	)
	return hashlib.sha256(repr(safeRows).encode()).hexdigest()
