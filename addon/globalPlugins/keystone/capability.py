from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, cast, runtime_checkable


__all__ = (
	"InspectionCapabilityFacade",
	"CapabilityRequest",
	"CapabilityReceipt",
	"CapabilityResult",
	"CapabilitySnapshot",
)

type PlainValue = None | bool | int | float | str | bytes | tuple[PlainValue, ...]

_MAX_BOUNDARY_STRING_LENGTH = 16_384
_MAX_BOUNDARY_BYTES_LENGTH = 16 * 1024 * 1024
_MAX_BOUNDARY_TUPLE_LENGTH = 4_096
# Match the provider normalizer's maximum nesting depth.
_MAX_BOUNDARY_TUPLE_DEPTH = 64
_CAPABILITY_IDS = (
	"nvdaCompatibility",
	"providerThreadAffinity",
	"providerStallProtection",
	"uiaInspection",
	"ia2Inspection",
	"javaAccessBridgeInspection",
	"officeInspection",
	"overlayPreservation",
	"rawUiaInspection",
	"userInterface",
	"eventMonitoring",
	"captureStorage",
	"screenCapture",
	"offlineAnalysis",
	"audioFeedback",
)


def requireOpaqueId(value: object, fieldName: str) -> None:
	if not isinstance(value, str) or not value or len(value) > 256 or value.strip() != value:
		raise ValueError(f"{fieldName} must be a nonblank bounded opaque identifier")


def requirePlainValue(value: PlainValue, fieldName: str = "value") -> None:
	_requirePlainValue(value, fieldName)


def _requirePlainValue(value: object, fieldName: str) -> None:
	pending: list[tuple[object, str, int, frozenset[int]]] = [(value, fieldName, 0, frozenset())]
	while pending:
		currentValue, currentFieldName, currentDepth, activeTuples = pending.pop()
		if currentDepth > _MAX_BOUNDARY_TUPLE_DEPTH:
			raise ValueError(f"{currentFieldName} exceeds the boundary tuple depth limit")
		valueType = type(currentValue)
		if currentValue is None or valueType in (bool, int):
			continue
		elif valueType is float:
			floatValue = cast(float, currentValue)
			if not math.isfinite(floatValue):
				raise ValueError(f"{currentFieldName} must be finite")
			continue
		elif valueType is str:
			stringValue = cast(str, currentValue)
			if len(stringValue) > _MAX_BOUNDARY_STRING_LENGTH:
				raise ValueError(f"{currentFieldName} exceeds the boundary string limit")
			continue
		elif valueType is bytes:
			byteValue = cast(bytes, currentValue)
			if len(byteValue) > _MAX_BOUNDARY_BYTES_LENGTH:
				raise ValueError(f"{currentFieldName} exceeds the boundary byte limit")
			continue
		elif valueType is tuple:
			tupleValue = cast(tuple[object, ...], currentValue)
			if len(tupleValue) > _MAX_BOUNDARY_TUPLE_LENGTH:
				raise ValueError(f"{currentFieldName} exceeds the boundary tuple limit")
			tupleId = id(tupleValue)
			if tupleId in activeTuples:
				raise ValueError(f"{currentFieldName} contains a cyclic tuple structure")
			childActiveTuples = activeTuples | frozenset((tupleId,))
			for index in range(len(tupleValue) - 1, -1, -1):
				pending.append(
					(
						tupleValue[index],
						f"{currentFieldName}[{index}]",
						currentDepth + 1,
						childActiveTuples,
					),
				)
		else:
			raise TypeError(f"{currentFieldName} must contain only recursively immutable plain values")


def requireNamedValues(values: tuple[tuple[str, PlainValue], ...], fieldName: str) -> None:
	seen: set[str] = set()
	for index, entry in enumerate(values):
		if type(entry) is not tuple or len(entry) != 2:
			raise TypeError(f"{fieldName}[{index}] must be a name/value tuple")
		name, value = entry
		requireOpaqueId(name, f"{fieldName}[{index}].name")
		if name in seen:
			raise ValueError(f"{fieldName} contains duplicate name {name!r}")
		seen.add(name)
		requirePlainValue(value, f"{fieldName}[{index}].value")


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
	operation: str
	requestId: str
	lifecycleGeneration: int
	arguments: tuple[tuple[str, PlainValue], ...] = ()

	def __post_init__(self) -> None:
		requireOpaqueId(self.operation, "operation")
		requireOpaqueId(self.requestId, "requestId")
		if self.lifecycleGeneration < 0:
			raise ValueError("lifecycleGeneration must be nonnegative")
		requireNamedValues(self.arguments, "arguments")


@dataclass(frozen=True, slots=True)
class CapabilityReceipt:
	operation: str
	requestId: str
	operationId: str | None
	lifecycleGeneration: int
	status: str
	errorCode: str | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.operation, "operation")
		requireOpaqueId(self.requestId, "requestId")
		if self.operationId is not None:
			requireOpaqueId(self.operationId, "operationId")
		if self.lifecycleGeneration < 0:
			raise ValueError("lifecycleGeneration must be nonnegative")
		if self.status not in ("accepted", "rejected"):
			raise ValueError("receipt status must be accepted or rejected")
		if self.status == "accepted" and (self.operationId is None or self.errorCode is not None):
			raise ValueError("accepted receipts require an operationId and no errorCode")
		if self.status == "rejected" and (self.operationId is not None or self.errorCode is None):
			raise ValueError("rejected receipts require an errorCode and no operationId")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")


@dataclass(frozen=True, slots=True)
class CapabilityResult:
	operation: str
	operationId: str
	lifecycleGeneration: int
	status: str
	values: tuple[tuple[str, PlainValue], ...] = ()
	errorCode: str | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.operation, "operation")
		requireOpaqueId(self.operationId, "operationId")
		requireOpaqueId(self.status, "status")
		if self.lifecycleGeneration < 0:
			raise ValueError("lifecycleGeneration must be nonnegative")
		requireNamedValues(self.values, "values")
		if self.errorCode is not None:
			requireOpaqueId(self.errorCode, "errorCode")


@dataclass(frozen=True, slots=True)
class CapabilityState:
	capabilityId: str
	status: str
	gateId: str
	reasonCode: str
	fallbackCode: str

	def __post_init__(self) -> None:
		if self.capabilityId not in _CAPABILITY_IDS:
			raise ValueError(f"unknown capabilityId {self.capabilityId!r}")
		if self.status not in ("enabled", "unavailable", "heldClosed", "disabled", "unclaimed"):
			raise ValueError(f"unknown capability status {self.status!r}")
		requireOpaqueId(self.gateId, "gateId")
		requireOpaqueId(self.reasonCode, "reasonCode")
		requireOpaqueId(self.fallbackCode, "fallbackCode")


@runtime_checkable
class CapabilitySnapshot(Protocol):
	@property
	def records(self) -> tuple[CapabilityState, ...]: ...


@dataclass(frozen=True, slots=True)
class _HeldClosedCapabilitySnapshot:
	records: tuple[CapabilityState, ...]

	def __post_init__(self) -> None:
		if tuple(record.capabilityId for record in self.records) != _CAPABILITY_IDS:
			raise ValueError("capability snapshot must contain all capability IDs in registry order")


defaultCapabilitySnapshot: CapabilitySnapshot = _HeldClosedCapabilitySnapshot(
	tuple(
		CapabilityState(
			capabilityId=capabilityId,
			status="heldClosed",
			gateId=capabilityId,
			reasonCode="evidencePending",
			fallbackCode="capabilityDisabled",
		)
		for capabilityId in _CAPABILITY_IDS
	),
)


@runtime_checkable
class InspectionCapabilityFacade(Protocol):
	def acceptRequest(self, request: CapabilityRequest) -> CapabilityReceipt: ...

	def readResult(self, operationId: str, lifecycleGeneration: int) -> CapabilityResult: ...
