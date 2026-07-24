from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Literal, cast
import unicodedata

from ..capability import PlainValue
from .privacy import (
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	classify,
	transformValue,
)


type CustomDeclaredType = Literal["unknown", "int", "bool", "string", "double", "point", "element", "enum"]
type CustomValueStatus = Literal[
	"value",
	"empty",
	"unsupported",
	"unavailable",
	"mismatch",
	"failed",
	"redacted",
	"truncated",
	"unknownVariant",
]


@dataclass(frozen=True, slots=True)
class CustomValueLimits:
	maximumTextScalars: int
	maximumTextBytes: int
	maximumElementRuntimeIds: int

	def __post_init__(self) -> None:
		if min(self.maximumTextScalars, self.maximumTextBytes, self.maximumElementRuntimeIds) <= 0:
			raise ValueError("custom value limits must be positive")


@dataclass(frozen=True, slots=True)
class ElementReference:
	"""A capture-local reference or bounded external metadata, never a durable UIA identity."""

	captureNodeKey: str | None
	scopedReference: str
	runtimeIdMetadata: tuple[int, ...] = ()
	providerProcessId: int | None = None

	def __post_init__(self) -> None:
		if self.captureNodeKey is not None and not self.captureNodeKey:
			raise ValueError("capture-local element keys must not be empty")
		if self.captureNodeKey is not None and (self.runtimeIdMetadata or self.providerProcessId is not None):
			raise ValueError(
				"capture-local element references cannot include external runtime or process metadata"
			)
		if not self.scopedReference:
			raise ValueError("element references require a scoped correlation token")
		if any(type(item) is not int for item in self.runtimeIdMetadata):
			raise TypeError("runtime ID metadata must contain only integers")
		if self.providerProcessId is not None and (
			type(self.providerProcessId) is not int or self.providerProcessId < 0
		):
			raise ValueError("provider process IDs must be nonnegative integers")

	def asPlainValue(self, maximumRuntimeIds: int) -> PlainValue:
		if self.captureNodeKey is not None:
			return ("captureLocal", self.captureNodeKey, self.scopedReference)
		retained = self.runtimeIdMetadata[:maximumRuntimeIds]
		return (
			"external",
			self.scopedReference,
			("providerProcessId", self.providerProcessId)
			if self.providerProcessId is not None
			else ("providerProcessIdUnavailable",),
			("runtimeIdMetadata", retained),
			("runtimeIdMetadataTruncated", len(retained) != len(self.runtimeIdMetadata)),
		)


@dataclass(frozen=True, slots=True)
class CustomValueEvidence:
	status: CustomValueStatus
	declaredType: CustomDeclaredType
	observedShape: str
	effectivePrivacy: PrivacyClass
	value: PlainValue = None
	errorCode: str | None = None
	scalarCount: int | None = None
	byteCount: int | None = None

	def __post_init__(self) -> None:
		if self.status in ("value", "truncated") and self.value is None:
			raise ValueError("custom value evidence requires a value")
		if self.status not in ("value", "truncated") and self.value is not None:
			raise ValueError("non-value custom evidence cannot retain a value")
		if self.status in ("failed", "unavailable", "mismatch", "unknownVariant") and self.errorCode is None:
			raise ValueError(f"{self.status} custom evidence requires a safe error code")
		if (
			self.status not in ("failed", "unavailable", "mismatch", "unknownVariant")
			and self.errorCode is not None
		):
			raise ValueError(f"{self.status} custom evidence cannot carry an error code")
		if (self.scalarCount is None) != (self.byteCount is None):
			raise ValueError("custom string counts must be present together")
		if self.scalarCount is not None and (
			self.status not in ("value", "truncated") or type(self.value) is not str
		):
			raise ValueError("custom string counts apply only to retained text values")

	def asPlainValue(self) -> PlainValue:
		return (
			("status", self.status),
			("declaredType", self.declaredType),
			("observedShape", self.observedShape),
			("privacy", self.effectivePrivacy.value),
			("value", self.value) if self.value is not None else ("noValue",),
			("errorCode", self.errorCode) if self.errorCode is not None else ("noError",),
			("scalarCount", self.scalarCount) if self.scalarCount is not None else ("noScalarCount",),
			("byteCount", self.byteCount) if self.byteCount is not None else ("noByteCount",),
		)


def _privacyClass(configured: str) -> PrivacyClass:
	if configured == "unknown":
		return PrivacyClass.UNKNOWN
	if configured == "sensitive":
		return PrivacyClass.SENSITIVE
	if configured == "protected":
		return PrivacyClass.PROTECTED
	raise ValueError("custom property privacy is outside the closed registry")


def _observedShape(value: object) -> str:
	if value is None:
		return "null"
	if type(value) is bool:
		return "bool"
	if type(value) is int:
		return "int"
	if type(value) is float:
		return "double"
	if isinstance(value, str):
		return "string"
	if isinstance(value, ElementReference):
		return "element"
	if type(value) in (tuple, list):
		items = cast(tuple[object, ...] | list[object], value)
		if len(items) == 2 and all(type(item) in (int, float) for item in items):
			return "point"
		return "array"
	if isinstance(value, (bytes, bytearray, memoryview)):
		return "blob"
	return "unknownVariant"


def _truncateString(value: str, limits: CustomValueLimits) -> tuple[str, bool, int, int]:
	normalized = unicodedata.normalize("NFC", value)
	scalarCount = len(normalized)
	byteCount = len(normalized.encode("utf-8"))
	retained = normalized[: limits.maximumTextScalars]
	while len(retained.encode("utf-8")) > limits.maximumTextBytes:
		retained = retained[:-1]
	return retained, retained != normalized, scalarCount, byteCount


def _normalizedValue(
	declaredType: CustomDeclaredType,
	value: object,
	limits: CustomValueLimits,
) -> tuple[CustomValueStatus, PlainValue, str | None, int | None, int | None]:
	shape = _observedShape(value)
	if shape in ("blob", "array", "unknownVariant"):
		return "unknownVariant", None, "KS.CUSTOM_UIA.UNKNOWN_VARIANT", None, None
	if value is None:
		return "empty", None, None, None, None
	normalizationType = cast(CustomDeclaredType, shape) if declaredType == "unknown" else declaredType
	if normalizationType != shape and not (
		(normalizationType == "double" and shape == "int") or (normalizationType == "enum" and shape == "int")
	):
		return "mismatch", None, "KS.CUSTOM_UIA.DECLARED_TYPE_MISMATCH", None, None
	if normalizationType == "bool":
		return "value", cast(bool, value), None, None, None
	if normalizationType in ("int", "enum"):
		return "value", cast(int, value), None, None, None
	if normalizationType == "double":
		number = float(cast(int | float, value))
		if math.isnan(number):
			return "value", ("nonFinite", "nan"), None, None, None
		if math.isinf(number):
			tag = "positiveInfinity" if number > 0 else "negativeInfinity"
			return "value", ("nonFinite", tag), None, None, None
		return "value", number, None, None, None
	if normalizationType == "point":
		items = cast(tuple[int | float, int | float] | list[int | float], value)
		coordinates = (float(items[0]), float(items[1]))
		if not all(math.isfinite(item) for item in coordinates):
			return "unknownVariant", None, "KS.CUSTOM_UIA.NONFINITE_POINT", None, None
		return "value", coordinates, None, None, None
	if normalizationType == "element":
		element = cast(ElementReference, value)
		return "value", element.asPlainValue(limits.maximumElementRuntimeIds), None, None, None
	text, truncated, scalarCount, byteCount = _truncateString(cast(str, value), limits)
	return ("truncated" if truncated else "value"), text, None, scalarCount, byteCount


def nonvalueCustomEvidence(
	declaredType: CustomDeclaredType,
	status: Literal["empty", "unsupported", "unavailable", "failed"],
	configuredPrivacy: str,
	protection: ProtectionEvidence,
	errorCode: str | None = None,
) -> CustomValueEvidence:
	effective = classify(_privacyClass(configuredPrivacy), protection)
	safeErrorCode = (
		errorCode or f"KS.CUSTOM_UIA.{status.upper()}" if status in ("unavailable", "failed") else None
	)
	return CustomValueEvidence(
		status,
		declaredType,
		"null" if status == "empty" else status,
		effective,
		errorCode=safeErrorCode,
	)


def normalizeCustomValue(
	declaredType: CustomDeclaredType,
	value: object,
	*,
	configuredPrivacy: str,
	protection: ProtectionEvidence,
	policy: PrivacyPolicy,
	limits: CustomValueLimits,
	sourceId: str,
) -> CustomValueEvidence:
	status, normalized, errorCode, scalarCount, byteCount = _normalizedValue(declaredType, value, limits)
	observedShape = _observedShape(value)
	metadataClass = _privacyClass(configuredPrivacy)
	if status not in ("value", "truncated"):
		effective = classify(metadataClass, protection)
		return CustomValueEvidence(
			status,
			declaredType,
			observedShape,
			effective,
			errorCode=errorCode,
			scalarCount=scalarCount,
			byteCount=byteCount,
		)
	transformed = transformValue(
		ObservedValue(
			FieldGroup.CUSTOM,
			normalized,
			metadataClass,
			protection,
			sourceId,
		),
		SinkId.CUSTOM,
		policy,
	)
	if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
		return CustomValueEvidence("redacted", declaredType, observedShape, transformed.effectiveClass)
	return CustomValueEvidence(
		status,
		declaredType,
		observedShape,
		transformed.effectiveClass,
		transformed.value,
		scalarCount=scalarCount,
		byteCount=byteCount,
	)
