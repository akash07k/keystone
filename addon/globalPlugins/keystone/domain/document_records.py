from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from .evidence import (
	ErrorReference,
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Scope,
	Source,
	Truncation,
)
from .privacy import UNREDACTED_SCREENSHOT_WARNING
from .status import (
	Confidence,
	EvidenceState,
	EvidenceValue,
	requireFiniteNumber,
	requireNonnegativeInteger,
	requireRfc3339Timestamp,
	requireToken,
)


type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | JsonArray | JsonObject
type CaptureDocumentKind = Literal[
	"snapshot",
	"navigatorSnapshot",
	"snapshotSummary",
	"navigatorSummary",
]


@dataclass(frozen=True, slots=True)
class JsonArray:
	items: tuple[JsonValue, ...]


@dataclass(frozen=True, slots=True)
class JsonObject:
	items: tuple[tuple[str, JsonValue], ...]


COMMON_NODE_FIELDS = (
	"name",
	"role",
	"roleText",
	"states",
	"description",
	"value",
	"geometry",
	"windowHandle",
	"windowClass",
	"windowControlId",
	"childCount",
	"indexInParent",
	"keyboardShortcut",
	"position",
	"table",
	"pythonClass",
	"classHierarchy",
	"backend",
	"process",
	"focusable",
	"focused",
	"stableIds",
	"privacy",
	"validation",
	"placeholder",
	"landmark",
	"currentState",
	"descriptionSource",
	"liveRegion",
	"math",
	"annotations",
	"developerInformation",
	"apiDetails",
	"diagnostics",
	"children",
)
PROVIDER_SECTION_FIELDS = ("status", "identity", "properties")
PROVIDER_SECTIONS = ("generic", "uia", "ia2Msaa", "jab", "overlay", "rawUia", "customUia")


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
	if not isinstance(value, JsonObject):
		raise ValueError(f"{label} must be an object")
	return dict(value.items)


def _closed(value: JsonValue, fields: tuple[str, ...], label: str) -> dict[str, JsonValue]:
	result = _mapping(value, label)
	if set(result) != set(fields) or len(result) != len(fields):
		raise ValueError(f"{label} must match its closed field registry")
	return result


def _closedOptional(
	value: JsonValue,
	required: tuple[str, ...],
	optional: tuple[str, ...],
	label: str,
) -> dict[str, JsonValue]:
	result = _mapping(value, label)
	actual = set(result)
	if not set(required).issubset(actual) or not actual.issubset(set(required) | set(optional)):
		raise ValueError(f"{label} must match its closed field registry")
	return result


def _array(value: JsonValue, label: str) -> tuple[JsonValue, ...]:
	if not isinstance(value, JsonArray):
		raise ValueError(f"{label} must be an array")
	return value.items


def _string(value: JsonValue, label: str, *, empty: bool = False) -> str:
	if not isinstance(value, str) or (not empty and not value):
		raise ValueError(f"{label} must be {'a string' if empty else 'a nonempty string'}")
	if value.strip() != value and not empty:
		raise ValueError(f"{label} must be trimmed")
	return value


def _boolean(value: JsonValue, label: str) -> bool:
	if not isinstance(value, bool):
		raise ValueError(f"{label} must be a boolean")
	return value


def _nonnegative(value: JsonValue, label: str) -> int:
	return requireNonnegativeInteger(value, label)


def _evidenceValue(value: JsonValue) -> EvidenceValue:
	if isinstance(value, JsonArray):
		return tuple(_evidenceValue(item) for item in value.items)
	if isinstance(value, JsonObject) or value is None:
		raise ValueError("evidence value must be an immutable JSON scalar or array")
	return value


def _source(value: JsonValue) -> Source:
	fields = _closedOptional(value, ("backend", "component", "symbol"), ("wrapperLoss",), "source")
	return Source(
		_string(fields["backend"], "source backend"),
		_string(fields["component"], "source component"),
		_string(fields["symbol"], "source symbol"),
		_string(fields["wrapperLoss"], "wrapper loss") if "wrapperLoss" in fields else None,
	)


def _projection(value: JsonValue) -> Projection:
	fields = _closedOptional(
		value,
		("mode", "fallbackApplied"),
		("method", "fallbackReasonCode"),
		"projection",
	)
	mode = _string(fields["mode"], "projection mode")
	if mode not in {"normalNvda", "rawUia", "offline", "derived"}:
		raise ValueError("projection mode is not in the closed registry")
	return Projection(
		cast(AnyProjectionMode, mode),
		_string(fields["method"], "projection method") if "method" in fields else None,
		_boolean(fields["fallbackApplied"], "fallback applied"),
		_string(fields["fallbackReasonCode"], "fallback reason") if "fallbackReasonCode" in fields else None,
	)


type AnyProjectionMode = Literal["normalNvda", "rawUia", "offline", "derived"]


def _privacy(value: JsonValue) -> PrivacyReference:
	fields = _closed(
		value,
		("fieldGroup", "classification", "effectiveTransform", "policyRevision"),
		"privacy reference",
	)
	classification = _string(fields["classification"], "privacy classification")
	if classification not in {"public", "sensitive", "protected", "unknown"}:
		raise ValueError("privacy classification is not in the closed registry")
	return PrivacyReference(
		_string(fields["fieldGroup"], "field group"),
		cast(AnyPrivacyClassification, classification),
		_string(fields["effectiveTransform"], "effective transform"),
		_nonnegative(fields["policyRevision"], "policy revision"),
	)


type AnyPrivacyClassification = Literal["public", "sensitive", "protected", "unknown"]


def _truncation(value: JsonValue) -> Truncation:
	fields = _closed(
		value,
		(
			"limitType",
			"configuredLimit",
			"actualCount",
			"omittedCount",
			"reasonCode",
			"continuationAvailable",
		),
		"truncation",
	)
	return Truncation(
		_string(fields["limitType"], "limit type"),
		_nonnegative(fields["configuredLimit"], "configured limit"),
		_nonnegative(fields["actualCount"], "actual count"),
		_nonnegative(fields["omittedCount"], "omitted count"),
		_string(fields["reasonCode"], "reason code"),
		_boolean(fields["continuationAvailable"], "continuation available"),
	)


def _errorReference(value: JsonValue) -> ErrorReference:
	fields = _closed(value, ("code", "diagnosticId"), "error reference")
	return ErrorReference(
		_string(fields["code"], "error code"),
		_string(fields["diagnosticId"], "diagnostic ID"),
	)


def _scope(value: JsonValue) -> Scope:
	fields = _closedOptional(value, ("scopeKind", "scopeId"), ("providerProcessId",), "scope")
	return Scope(
		_string(fields["scopeKind"], "scope kind"),
		_string(fields["scopeId"], "scope ID"),
		_nonnegative(fields["providerProcessId"], "provider process ID")
		if "providerProcessId" in fields
		else None,
	)


def parseEvidenceEnvelope(value: JsonValue) -> EvidenceEnvelope:
	base = ("status", "source", "projection", "confidence", "privacy")
	fields = _closedOptional(
		value,
		base,
		("value", "truncation", "errorRef", "observedAt", "scope"),
		"evidence envelope",
	)
	statusToken = _string(fields["status"], "evidence status")
	status = EvidenceState.parse(statusToken)
	confidenceToken = _string(fields["confidence"], "evidence confidence")
	try:
		confidence = Confidence(confidenceToken)
	except ValueError as error:
		raise ValueError("evidence confidence is not in the closed registry") from error
	return EvidenceEnvelope(
		status=status,
		source=_source(fields["source"]),
		projection=_projection(fields["projection"]),
		confidence=confidence,
		privacy=_privacy(fields["privacy"]),
		value=_evidenceValue(fields["value"]) if "value" in fields else None,
		truncation=_truncation(fields["truncation"]) if "truncation" in fields else None,
		errorRef=_errorReference(fields["errorRef"]) if "errorRef" in fields else None,
		observedAt=_string(fields["observedAt"], "observed time") if "observedAt" in fields else None,
		scope=_scope(fields["scope"]) if "scope" in fields else None,
	)


def _jsonEvidenceValue(value: EvidenceValue) -> JsonValue:
	if isinstance(value, bytes):
		raise ValueError("binary evidence cannot be encoded directly in JSON")
	if isinstance(value, tuple):
		return JsonArray(tuple(_jsonEvidenceValue(item) for item in value))
	return value


def evidenceObject(envelope: EvidenceEnvelope) -> JsonObject:
	items: list[tuple[str, JsonValue]] = [
		("status", envelope.status.value),
		("source", sourceObject(envelope.source)),
		("projection", projectionObject(envelope.projection)),
		("confidence", envelope.confidence.value),
		("privacy", privacyObject(envelope.privacy)),
	]
	if envelope.value is not None:
		items.append(("value", _jsonEvidenceValue(envelope.value)))
	if envelope.truncation is not None:
		items.append(("truncation", truncationObject(envelope.truncation)))
	if envelope.errorRef is not None:
		items.append(
			(
				"errorRef",
				JsonObject(
					(
						("code", envelope.errorRef.code),
						("diagnosticId", envelope.errorRef.diagnosticId),
					),
				),
			),
		)
	if envelope.observedAt is not None:
		items.append(("observedAt", envelope.observedAt))
	if envelope.scope is not None:
		scopeItems: list[tuple[str, JsonValue]] = [
			("scopeKind", envelope.scope.scopeKind),
			("scopeId", envelope.scope.scopeId),
		]
		if envelope.scope.providerProcessId is not None:
			scopeItems.append(("providerProcessId", envelope.scope.providerProcessId))
		items.append(("scope", JsonObject(tuple(scopeItems))))
	return JsonObject(tuple(items))


def sourceObject(source: Source) -> JsonObject:
	items: list[tuple[str, JsonValue]] = [
		("backend", source.backend),
		("component", source.component),
		("symbol", source.symbol),
	]
	if source.wrapperLoss is not None:
		items.append(("wrapperLoss", source.wrapperLoss))
	return JsonObject(tuple(items))


def projectionObject(projection: Projection) -> JsonObject:
	items: list[tuple[str, JsonValue]] = [
		("mode", projection.mode),
		("fallbackApplied", projection.fallbackApplied),
	]
	if projection.method is not None:
		items.append(("method", projection.method))
	if projection.fallbackReasonCode is not None:
		items.append(("fallbackReasonCode", projection.fallbackReasonCode))
	return JsonObject(tuple(items))


def privacyObject(privacy: PrivacyReference) -> JsonObject:
	return JsonObject(
		(
			("fieldGroup", privacy.fieldGroup),
			("classification", privacy.classification),
			("effectiveTransform", privacy.effectiveTransform),
			("policyRevision", privacy.policyRevision),
		),
	)


def truncationObject(truncation: Truncation) -> JsonObject:
	return JsonObject(
		(
			("limitType", truncation.limitType),
			("configuredLimit", truncation.configuredLimit),
			("actualCount", truncation.actualCount),
			("omittedCount", truncation.omittedCount),
			("reasonCode", truncation.reasonCode),
			("continuationAvailable", truncation.continuationAvailable),
		),
	)


@dataclass(frozen=True, slots=True)
class StandaloneConventions:
	schemaName: str
	schemaVersion: str
	requiredFieldPolicy: str
	nonValuePolicy: str
	geometryPolicy: str
	nodeOrdering: str
	childOrdering: str

	def __post_init__(self) -> None:
		for fieldName in (
			"schemaName",
			"schemaVersion",
			"requiredFieldPolicy",
			"nonValuePolicy",
			"geometryPolicy",
			"nodeOrdering",
			"childOrdering",
		):
			object.__setattr__(self, fieldName, requireToken(getattr(self, fieldName), fieldName))
		if tuple(getattr(self, fieldName) for fieldName in CONVENTION_FIELDS) != CONVENTION_VALUES:
			raise ValueError("standalone conventions must match the supported semantic registry")

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple((fieldName, cast(str, getattr(self, fieldName))) for fieldName in CONVENTION_FIELDS),
		)


CONVENTION_FIELDS = (
	"schemaName",
	"schemaVersion",
	"requiredFieldPolicy",
	"nonValuePolicy",
	"geometryPolicy",
	"nodeOrdering",
	"childOrdering",
)
CONVENTION_VALUES = (
	"keystone.capture",
	"2.0",
	"required fields are never omitted",
	"status is independent from value",
	"signed half-open virtual-screen pixels",
	"capture traversal order",
	"provider child order",
)


def _conventions(value: JsonValue) -> StandaloneConventions:
	fields = _closed(value, CONVENTION_FIELDS, "standalone conventions")
	return StandaloneConventions(*(_string(fields[name], name) for name in CONVENTION_FIELDS))


@dataclass(frozen=True, slots=True)
class ScreenshotMetadata:
	attempted: bool
	result: EvidenceEnvelope
	warning: str

	def __post_init__(self) -> None:
		if not self.attempted and self.result.status is not EvidenceState.NOT_APPLICABLE:
			raise ValueError("an unattempted screenshot requires not-applicable result evidence")
		if self.attempted and self.result.status is EvidenceState.NOT_APPLICABLE:
			raise ValueError("an attempted screenshot requires current result evidence")
		object.__setattr__(self, "warning", requireToken(self.warning, "screenshot warning"))

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("attempted", self.attempted),
				("result", evidenceObject(self.result)),
				("warning", self.warning),
			),
		)


@dataclass(frozen=True, slots=True)
class DiagnosticMetadata:
	retained: int
	total: int
	truncated: bool

	def __post_init__(self) -> None:
		retained = requireNonnegativeInteger(self.retained, "retained diagnostics")
		total = requireNonnegativeInteger(self.total, "total diagnostics")
		if retained > 300 or total < retained or self.truncated != (total > retained):
			raise ValueError("diagnostic metadata is inconsistent")

	def asObject(self) -> JsonObject:
		return JsonObject((("retained", self.retained), ("total", self.total), ("truncated", self.truncated)))


@dataclass(frozen=True, slots=True)
class CaptureDetails:
	generatedAt: str
	sourcePath: EvidenceEnvelope
	outputPath: EvidenceEnvelope
	captureKind: CaptureDocumentKind
	rawUiaEnabled: bool
	containingForeground: EvidenceEnvelope
	screenshot: ScreenshotMetadata
	diagnostics: DiagnosticMetadata
	conventions: StandaloneConventions

	def __post_init__(self) -> None:
		_ = requireRfc3339Timestamp(self.generatedAt, "capture generation time")
		_ = _boolean(self.rawUiaEnabled, "raw UIA enabled")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("generatedAt", self.generatedAt),
				("sourcePath", evidenceObject(self.sourcePath)),
				("outputPath", evidenceObject(self.outputPath)),
				("captureKind", self.captureKind),
				("rawUiaEnabled", self.rawUiaEnabled),
				("containingForeground", evidenceObject(self.containingForeground)),
				("screenshot", self.screenshot.asObject()),
				("diagnostics", self.diagnostics.asObject()),
				("conventions", self.conventions.asObject()),
			),
		)


@dataclass(frozen=True, slots=True)
class EnvironmentMetadata:
	keystoneVersion: EvidenceEnvelope
	nvdaVersion: EvidenceEnvelope
	windowsVersion: EvidenceEnvelope
	architecture: EvidenceEnvelope
	dpi: EvidenceEnvelope
	monitors: EvidenceEnvelope
	backends: EvidenceEnvelope

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple(
				(name, evidenceObject(cast(EvidenceEnvelope, getattr(self, name))))
				for name in ENVIRONMENT_FIELDS
			),
		)


ENVIRONMENT_FIELDS = (
	"keystoneVersion",
	"nvdaVersion",
	"windowsVersion",
	"architecture",
	"dpi",
	"monitors",
	"backends",
)


@dataclass(frozen=True, slots=True)
class CaptureLimits:
	maximumDepth: int
	maximumNodes: int
	maximumStringScalars: int
	maximumCollectionItems: int

	def __post_init__(self) -> None:
		for name in LIMIT_FIELDS:
			_ = requireNonnegativeInteger(getattr(self, name), name)

	def asObject(self) -> JsonObject:
		return JsonObject(tuple((name, cast(int, getattr(self, name))) for name in LIMIT_FIELDS))


LIMIT_FIELDS = ("maximumDepth", "maximumNodes", "maximumStringScalars", "maximumCollectionItems")


@dataclass(frozen=True, slots=True)
class CaptureCounts:
	visited: int
	emitted: int
	failed: int
	truncated: int

	def __post_init__(self) -> None:
		for name in COUNT_FIELDS:
			_ = requireNonnegativeInteger(getattr(self, name), name)
		if self.visited < self.emitted + self.failed:
			raise ValueError("visited count cannot be smaller than emitted plus failed")

	def asObject(self) -> JsonObject:
		return JsonObject(tuple((name, cast(int, getattr(self, name))) for name in COUNT_FIELDS))


COUNT_FIELDS = ("visited", "emitted", "failed", "truncated")


@dataclass(frozen=True, slots=True)
class CaptureDuration:
	elapsedMilliseconds: int | float

	def __post_init__(self) -> None:
		if requireFiniteNumber(self.elapsedMilliseconds, "elapsed milliseconds") < 0:
			raise ValueError("elapsed milliseconds must be nonnegative")

	def asObject(self) -> JsonObject:
		return JsonObject((("elapsedMilliseconds", self.elapsedMilliseconds),))


@dataclass(frozen=True, slots=True)
class ProjectionMetadata:
	name: str
	revision: int

	def __post_init__(self) -> None:
		object.__setattr__(self, "name", requireToken(self.name, "projection name"))
		_ = requireNonnegativeInteger(self.revision, "projection revision")

	def asObject(self) -> JsonObject:
		return JsonObject((("name", self.name), ("revision", self.revision)))


@dataclass(frozen=True, slots=True)
class RedactionMetadata:
	enabled: bool
	policy: str
	revision: int

	def __post_init__(self) -> None:
		_ = _boolean(self.enabled, "redaction enabled")
		object.__setattr__(self, "policy", requireToken(self.policy, "redaction policy"))
		_ = requireNonnegativeInteger(self.revision, "redaction revision")

	def asObject(self) -> JsonObject:
		return JsonObject((("enabled", self.enabled), ("policy", self.policy), ("revision", self.revision)))


@dataclass(frozen=True, slots=True)
class CaptureMetadata:
	capture: CaptureDetails
	environment: EnvironmentMetadata
	limits: CaptureLimits
	counts: CaptureCounts
	duration: CaptureDuration
	projection: ProjectionMetadata
	redaction: RedactionMetadata

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("capture", self.capture.asObject()),
				("environment", self.environment.asObject()),
				("limits", self.limits.asObject()),
				("counts", self.counts.asObject()),
				("duration", self.duration.asObject()),
				("projection", self.projection.asObject()),
				("redaction", self.redaction.asObject()),
			),
		)


def parseCaptureMetadata(value: JsonValue, kind: CaptureDocumentKind) -> CaptureMetadata:
	fields = _closed(
		value,
		("capture", "environment", "limits", "counts", "duration", "projection", "redaction"),
		"capture metadata",
	)
	captureFields = _closed(
		fields["capture"],
		(
			"generatedAt",
			"sourcePath",
			"outputPath",
			"captureKind",
			"rawUiaEnabled",
			"containingForeground",
			"screenshot",
			"diagnostics",
			"conventions",
		),
		"capture details",
	)
	captureKind = _string(captureFields["captureKind"], "capture kind")
	if captureKind != kind:
		raise ValueError("capture metadata kind must match document kind")
	screenshotFields = _closed(
		captureFields["screenshot"],
		("attempted", "result", "warning"),
		"screenshot metadata",
	)
	diagnosticFields = _closed(
		captureFields["diagnostics"],
		("retained", "total", "truncated"),
		"diagnostic metadata",
	)
	capture = CaptureDetails(
		_string(captureFields["generatedAt"], "capture generation time"),
		parseEvidenceEnvelope(captureFields["sourcePath"]),
		parseEvidenceEnvelope(captureFields["outputPath"]),
		cast(CaptureDocumentKind, captureKind),
		_boolean(captureFields["rawUiaEnabled"], "raw UIA enabled"),
		parseEvidenceEnvelope(captureFields["containingForeground"]),
		ScreenshotMetadata(
			_boolean(screenshotFields["attempted"], "screenshot attempted"),
			parseEvidenceEnvelope(screenshotFields["result"]),
			_string(screenshotFields["warning"], "screenshot warning"),
		),
		DiagnosticMetadata(
			_nonnegative(diagnosticFields["retained"], "retained diagnostics"),
			_nonnegative(diagnosticFields["total"], "total diagnostics"),
			_boolean(diagnosticFields["truncated"], "diagnostics truncated"),
		),
		_conventions(captureFields["conventions"]),
	)
	environmentFields = _closed(fields["environment"], ENVIRONMENT_FIELDS, "environment metadata")
	limitsFields = _closed(fields["limits"], LIMIT_FIELDS, "capture limits")
	countFields = _closed(fields["counts"], COUNT_FIELDS, "capture counts")
	durationFields = _closed(fields["duration"], ("elapsedMilliseconds",), "capture duration")
	projectionFields = _closed(fields["projection"], ("name", "revision"), "projection metadata")
	redactionFields = _closed(fields["redaction"], ("enabled", "policy", "revision"), "redaction metadata")
	return CaptureMetadata(
		capture,
		EnvironmentMetadata(
			*(parseEvidenceEnvelope(environmentFields[name]) for name in ENVIRONMENT_FIELDS),
		),
		CaptureLimits(*(_nonnegative(limitsFields[name], name) for name in LIMIT_FIELDS)),
		CaptureCounts(*(_nonnegative(countFields[name], name) for name in COUNT_FIELDS)),
		CaptureDuration(requireFiniteNumber(durationFields["elapsedMilliseconds"], "elapsed milliseconds")),
		ProjectionMetadata(
			_string(projectionFields["name"], "projection name"),
			_nonnegative(projectionFields["revision"], "projection revision"),
		),
		RedactionMetadata(
			_boolean(redactionFields["enabled"], "redaction enabled"),
			_string(redactionFields["policy"], "redaction policy"),
			_nonnegative(redactionFields["revision"], "redaction revision"),
		),
	)


@dataclass(frozen=True, slots=True)
class NodeStructure:
	parentKey: str | None
	depth: int
	childKeys: tuple[str, ...]
	cycleDetected: bool
	truncated: bool
	childFetchFailed: bool

	def __post_init__(self) -> None:
		if self.parentKey is not None:
			object.__setattr__(self, "parentKey", requireToken(self.parentKey, "parent key"))
		_ = requireNonnegativeInteger(self.depth, "node depth")
		normalized = tuple(requireToken(key, "child key") for key in self.childKeys)
		if len(set(normalized)) != len(normalized):
			raise ValueError("child keys must be unique")
		object.__setattr__(self, "childKeys", normalized)
		for name in ("cycleDetected", "truncated", "childFetchFailed"):
			if not isinstance(getattr(self, name), bool):
				raise ValueError(f"{name} must be a boolean")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("parentKey", self.parentKey),
				("depth", self.depth),
				("childKeys", JsonArray(self.childKeys)),
				("cycleDetected", self.cycleDetected),
				("truncated", self.truncated),
				("childFetchFailed", self.childFetchFailed),
			),
		)


@dataclass(frozen=True, slots=True)
class ProviderSectionRecord:
	status: EvidenceEnvelope
	identity: EvidenceEnvelope
	properties: EvidenceEnvelope

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("status", evidenceObject(self.status)),
				("identity", evidenceObject(self.identity)),
				("properties", evidenceObject(self.properties)),
			),
		)


@dataclass(frozen=True, slots=True)
class ProviderSections:
	items: tuple[tuple[str, ProviderSectionRecord], ...]

	def __post_init__(self) -> None:
		if tuple(name for name, _section in self.items) != PROVIDER_SECTIONS:
			raise ValueError("provider sections must follow the complete closed registry")

	def asObject(self) -> JsonObject:
		return JsonObject(tuple((name, section.asObject()) for name, section in self.items))


@dataclass(frozen=True, slots=True)
class NodeRecord:
	key: str
	structure: NodeStructure
	fields: tuple[tuple[str, EvidenceEnvelope], ...]
	providers: ProviderSections

	def __post_init__(self) -> None:
		object.__setattr__(self, "key", requireToken(self.key, "node key"))
		if tuple(name for name, _value in self.fields) != COMMON_NODE_FIELDS:
			raise ValueError("node fields must follow the complete common-field registry")
		children = self.field("children")
		if children.status is EvidenceState.VALUE and children.value != self.structure.childKeys:
			raise ValueError("node child evidence must agree with structural child keys")

	def field(self, name: str) -> EvidenceEnvelope:
		try:
			return dict(self.fields)[name]
		except KeyError as error:
			raise KeyError(f"unknown common node field: {name}") from error

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("key", self.key),
				("structure", self.structure.asObject()),
				*((name, evidenceObject(value)) for name, value in self.fields),
				("providers", self.providers.asObject()),
			),
		)


def _nodeStructure(value: JsonValue) -> NodeStructure:
	fields = _closed(
		value,
		("parentKey", "depth", "childKeys", "cycleDetected", "truncated", "childFetchFailed"),
		"node structure",
	)
	parent = fields["parentKey"]
	if parent is not None and not isinstance(parent, str):
		raise ValueError("parent key must be a string or null")
	return NodeStructure(
		parent,
		_nonnegative(fields["depth"], "node depth"),
		tuple(_string(item, "child key") for item in _array(fields["childKeys"], "child keys")),
		_boolean(fields["cycleDetected"], "cycle detected"),
		_boolean(fields["truncated"], "node truncated"),
		_boolean(fields["childFetchFailed"], "child fetch failed"),
	)


def _providerSections(value: JsonValue) -> ProviderSections:
	fields = _closed(value, PROVIDER_SECTIONS, "provider sections")
	sections: list[tuple[str, ProviderSectionRecord]] = []
	for name in PROVIDER_SECTIONS:
		sectionFields = _closed(fields[name], PROVIDER_SECTION_FIELDS, f"{name} provider section")
		sections.append(
			(
				name,
				ProviderSectionRecord(
					parseEvidenceEnvelope(sectionFields["status"]),
					parseEvidenceEnvelope(sectionFields["identity"]),
					parseEvidenceEnvelope(sectionFields["properties"]),
				),
			),
		)
	return ProviderSections(tuple(sections))


def parseNodeRecord(value: JsonValue) -> NodeRecord:
	fields = _closed(
		value,
		("key", "structure", *COMMON_NODE_FIELDS, "providers"),
		"node record",
	)
	return NodeRecord(
		_string(fields["key"], "node key"),
		_nodeStructure(fields["structure"]),
		tuple((name, parseEvidenceEnvelope(fields[name])) for name in COMMON_NODE_FIELDS),
		_providerSections(fields["providers"]),
	)


@dataclass(frozen=True, slots=True)
class SummaryNode:
	key: str
	name: EvidenceEnvelope
	role: EvidenceEnvelope
	states: EvidenceEnvelope
	protection: EvidenceEnvelope
	children: EvidenceEnvelope
	cycleDetected: bool
	truncated: bool
	childFetchFailed: bool

	def __post_init__(self) -> None:
		object.__setattr__(self, "key", requireToken(self.key, "summary node key"))
		for fieldName in ("cycleDetected", "truncated", "childFetchFailed"):
			if not isinstance(getattr(self, fieldName), bool):
				raise ValueError(f"{fieldName} must be a boolean")

	@property
	def childKeys(self) -> tuple[str, ...]:
		if self.children.status is not EvidenceState.VALUE or not isinstance(self.children.value, tuple):
			return ()
		if any(not isinstance(key, str) for key in self.children.value):
			raise ValueError("summary child evidence must contain only node keys")
		return cast(tuple[str, ...], self.children.value)

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("key", self.key),
				("name", evidenceObject(self.name)),
				("role", evidenceObject(self.role)),
				("states", evidenceObject(self.states)),
				("protection", evidenceObject(self.protection)),
				("children", evidenceObject(self.children)),
				("cycleDetected", self.cycleDetected),
				("truncated", self.truncated),
				("childFetchFailed", self.childFetchFailed),
			),
		)


@dataclass(frozen=True, slots=True)
class SummaryCounts:
	roots: int
	nodes: int
	cycles: int
	truncated: int
	childFetchFailures: int

	def __post_init__(self) -> None:
		for name in SUMMARY_COUNT_FIELDS:
			_ = requireNonnegativeInteger(getattr(self, name), name)

	def asObject(self) -> JsonObject:
		return JsonObject(tuple((name, cast(int, getattr(self, name))) for name in SUMMARY_COUNT_FIELDS))


SUMMARY_COUNT_FIELDS = ("roots", "nodes", "cycles", "truncated", "childFetchFailures")


@dataclass(frozen=True, slots=True)
class SummaryRecord:
	sourceDocumentId: str
	sourceKind: Literal["snapshot", "navigatorSnapshot"]
	rootKeys: tuple[str, ...]
	nodes: tuple[SummaryNode, ...]
	counts: SummaryCounts

	def __post_init__(self) -> None:
		sourceDocumentId = requireToken(self.sourceDocumentId, "source document ID")
		try:
			parsed = UUID(sourceDocumentId)
		except ValueError as error:
			raise ValueError("summary source document ID must be a UUID") from error
		if sourceDocumentId != str(parsed):
			raise ValueError("summary source document ID must use canonical lowercase UUID text")
		object.__setattr__(self, "sourceDocumentId", sourceDocumentId)
		normalizedRoots = tuple(requireToken(key, "summary root key") for key in self.rootKeys)
		if len(set(normalizedRoots)) != len(normalizedRoots):
			raise ValueError("summary roots must be unique")
		object.__setattr__(self, "rootKeys", normalizedRoots)
		keys = tuple(node.key for node in self.nodes)
		if len(set(keys)) != len(keys):
			raise ValueError("summary node keys must be unique")
		if any(key not in keys for key in normalizedRoots):
			raise ValueError("every summary root must resolve to a node")
		if any(child not in keys for node in self.nodes for child in node.childKeys):
			raise ValueError("every summary child must resolve to a node")
		expected = SummaryCounts(
			len(normalizedRoots),
			len(self.nodes),
			sum(node.cycleDetected for node in self.nodes),
			sum(node.truncated for node in self.nodes),
			sum(node.childFetchFailed for node in self.nodes),
		)
		if self.counts != expected:
			raise ValueError("summary counts must agree with the complete summary")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("sourceDocumentId", self.sourceDocumentId),
				("sourceKind", self.sourceKind),
				("rootKeys", JsonArray(self.rootKeys)),
				("nodes", JsonArray(tuple(node.asObject() for node in self.nodes))),
				("counts", self.counts.asObject()),
			),
		)


def _summaryNode(value: JsonValue) -> SummaryNode:
	fields = _closed(
		value,
		(
			"key",
			"name",
			"role",
			"states",
			"protection",
			"children",
			"cycleDetected",
			"truncated",
			"childFetchFailed",
		),
		"summary node",
	)
	return SummaryNode(
		_string(fields["key"], "summary node key"),
		parseEvidenceEnvelope(fields["name"]),
		parseEvidenceEnvelope(fields["role"]),
		parseEvidenceEnvelope(fields["states"]),
		parseEvidenceEnvelope(fields["protection"]),
		parseEvidenceEnvelope(fields["children"]),
		_boolean(fields["cycleDetected"], "cycle detected"),
		_boolean(fields["truncated"], "summary node truncated"),
		_boolean(fields["childFetchFailed"], "summary child fetch failed"),
	)


def parseSummaryRecord(
	value: JsonValue,
	sourceKind: Literal["snapshot", "navigatorSnapshot"],
) -> SummaryRecord:
	fields = _closed(
		value,
		("sourceDocumentId", "sourceKind", "rootKeys", "nodes", "counts"),
		"summary record",
	)
	actualKind = _string(fields["sourceKind"], "summary source kind")
	if actualKind != sourceKind:
		raise ValueError("summary source kind must match document family")
	countFields = _closed(fields["counts"], SUMMARY_COUNT_FIELDS, "summary counts")
	return SummaryRecord(
		_string(fields["sourceDocumentId"], "source document ID"),
		sourceKind,
		tuple(_string(item, "summary root key") for item in _array(fields["rootKeys"], "summary roots")),
		tuple(_summaryNode(item) for item in _array(fields["nodes"], "summary nodes")),
		SummaryCounts(*(_nonnegative(countFields[name], name) for name in SUMMARY_COUNT_FIELDS)),
	)


@dataclass(frozen=True, slots=True)
class DocumentConventions:
	schemaName: str
	schemaVersion: str
	requiredFieldPolicy: str
	nonValuePolicy: str
	orderingPolicy: str

	def __post_init__(self) -> None:
		expected = (
			"keystone.document",
			"2.0",
			"required fields are never omitted",
			"status is independent from value",
			"document semantic order",
		)
		if tuple(getattr(self, name) for name in DOCUMENT_CONVENTION_FIELDS) != expected:
			raise ValueError("document conventions must match the supported semantic registry")

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple((name, cast(str, getattr(self, name))) for name in DOCUMENT_CONVENTION_FIELDS),
		)


DOCUMENT_CONVENTION_FIELDS = (
	"schemaName",
	"schemaVersion",
	"requiredFieldPolicy",
	"nonValuePolicy",
	"orderingPolicy",
)


@dataclass(frozen=True, slots=True)
class DocumentGeneration:
	generatedAt: str
	operationId: str
	sourceDocumentIds: tuple[str, ...]
	conventions: DocumentConventions

	def __post_init__(self) -> None:
		_ = _validateTimestamp(self.generatedAt, "document generation time")
		object.__setattr__(self, "operationId", requireToken(self.operationId, "operation ID"))
		ids = tuple(_canonicalUuid(item, "source document ID") for item in self.sourceDocumentIds)
		if not ids or len(set(ids)) != len(ids):
			raise ValueError("source document IDs must be nonempty and unique")
		object.__setattr__(self, "sourceDocumentIds", ids)

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("generatedAt", self.generatedAt),
				("operationId", self.operationId),
				("sourceDocumentIds", JsonArray(self.sourceDocumentIds)),
				("conventions", self.conventions.asObject()),
			),
		)


@dataclass(frozen=True, slots=True)
class DocumentEnvironment:
	keystoneVersion: str
	nvdaVersion: str
	windowsVersion: str

	def __post_init__(self) -> None:
		for name in DOCUMENT_ENVIRONMENT_FIELDS:
			object.__setattr__(self, name, requireToken(getattr(self, name), name))

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple((name, cast(str, getattr(self, name))) for name in DOCUMENT_ENVIRONMENT_FIELDS),
		)


DOCUMENT_ENVIRONMENT_FIELDS = ("keystoneVersion", "nvdaVersion", "windowsVersion")


@dataclass(frozen=True, slots=True)
class DocumentLimits:
	maximumItems: int

	def __post_init__(self) -> None:
		if requireNonnegativeInteger(self.maximumItems, "maximum items") == 0:
			raise ValueError("maximum items must be positive")

	def asObject(self) -> JsonObject:
		return JsonObject((("maximumItems", self.maximumItems),))


@dataclass(frozen=True, slots=True)
class DocumentCounts:
	emitted: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.emitted, "emitted count")

	def asObject(self) -> JsonObject:
		return JsonObject((("emitted", self.emitted),))


@dataclass(frozen=True, slots=True)
class PersistedDocumentMetadata:
	capture: DocumentGeneration
	environment: DocumentEnvironment
	limits: DocumentLimits
	counts: DocumentCounts
	duration: CaptureDuration
	projection: ProjectionMetadata
	redaction: RedactionMetadata

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("capture", self.capture.asObject()),
				("environment", self.environment.asObject()),
				("limits", self.limits.asObject()),
				("counts", self.counts.asObject()),
				("duration", self.duration.asObject()),
				("projection", self.projection.asObject()),
				("redaction", self.redaction.asObject()),
			),
		)


def parsePersistedDocumentMetadata(value: JsonValue) -> PersistedDocumentMetadata:
	fields = _closed(
		value,
		("capture", "environment", "limits", "counts", "duration", "projection", "redaction"),
		"document metadata",
	)
	captureFields = _closed(
		fields["capture"],
		("generatedAt", "operationId", "sourceDocumentIds", "conventions"),
		"document generation",
	)
	conventionFields = _closed(
		captureFields["conventions"],
		DOCUMENT_CONVENTION_FIELDS,
		"document conventions",
	)
	environmentFields = _closed(
		fields["environment"],
		DOCUMENT_ENVIRONMENT_FIELDS,
		"document environment",
	)
	limitsFields = _closed(fields["limits"], ("maximumItems",), "document limits")
	countFields = _closed(fields["counts"], ("emitted",), "document counts")
	durationFields = _closed(fields["duration"], ("elapsedMilliseconds",), "document duration")
	projectionFields = _closed(fields["projection"], ("name", "revision"), "document projection")
	redactionFields = _closed(fields["redaction"], ("enabled", "policy", "revision"), "document redaction")
	return PersistedDocumentMetadata(
		DocumentGeneration(
			_string(captureFields["generatedAt"], "document generation time"),
			_string(captureFields["operationId"], "operation ID"),
			tuple(
				_string(item, "source document ID")
				for item in _array(captureFields["sourceDocumentIds"], "source document IDs")
			),
			DocumentConventions(
				*(_string(conventionFields[name], name) for name in DOCUMENT_CONVENTION_FIELDS),
			),
		),
		DocumentEnvironment(
			*(_string(environmentFields[name], name) for name in DOCUMENT_ENVIRONMENT_FIELDS),
		),
		DocumentLimits(_nonnegative(limitsFields["maximumItems"], "maximum items")),
		DocumentCounts(_nonnegative(countFields["emitted"], "emitted count")),
		CaptureDuration(requireFiniteNumber(durationFields["elapsedMilliseconds"], "elapsed milliseconds")),
		ProjectionMetadata(
			_string(projectionFields["name"], "projection name"),
			_nonnegative(projectionFields["revision"], "projection revision"),
		),
		RedactionMetadata(
			_boolean(redactionFields["enabled"], "redaction enabled"),
			_string(redactionFields["policy"], "redaction policy"),
			_nonnegative(redactionFields["revision"], "redaction revision"),
		),
	)


@dataclass(frozen=True, slots=True)
class AdmissionRecord:
	admitted: bool
	code: str | None

	def __post_init__(self) -> None:
		_ = _boolean(self.admitted, "admitted")
		if self.admitted != (self.code is None):
			raise ValueError("admission code must exist exactly when admission failed")
		if self.code is not None:
			object.__setattr__(self, "code", requireToken(self.code, "admission code"))

	def asObject(self) -> JsonObject:
		return JsonObject((("admitted", self.admitted), ("code", self.code)))


@dataclass(frozen=True, slots=True)
class DocumentReference:
	documentId: str
	documentKind: str
	schemaMajor: int
	schemaMinor: int
	projection: str
	privacyRevision: int
	admission: AdmissionRecord

	def __post_init__(self) -> None:
		object.__setattr__(self, "documentId", _canonicalUuid(self.documentId, "referenced document ID"))
		object.__setattr__(self, "documentKind", requireToken(self.documentKind, "referenced document kind"))
		if self.schemaMajor != 2 or self.schemaMinor < 0:
			raise ValueError("referenced document schema is unsupported")
		object.__setattr__(self, "projection", requireToken(self.projection, "referenced projection"))
		_ = requireNonnegativeInteger(self.privacyRevision, "privacy revision")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("documentId", self.documentId),
				("documentKind", self.documentKind),
				("schema", JsonObject((("major", self.schemaMajor), ("minor", self.schemaMinor)))),
				("projection", self.projection),
				("privacyRevision", self.privacyRevision),
				("admission", self.admission.asObject()),
			),
		)


DiffChangeKind = Literal["added", "removed", "modified", "nested"]


@dataclass(frozen=True, slots=True)
class DiffChange:
	changeKind: DiffChangeKind
	ancestorPath: tuple[str, ...]
	before: EvidenceEnvelope | None
	after: EvidenceEnvelope | None
	changes: tuple[DiffChange, ...]

	def __post_init__(self) -> None:
		path = tuple(requireToken(item, "diff ancestor path segment") for item in self.ancestorPath)
		if not path:
			raise ValueError("diff ancestor path must be nonempty")
		object.__setattr__(self, "ancestorPath", path)
		if self.changeKind == "added":
			valid = self.before is None and self.after is not None and not self.changes
		elif self.changeKind == "removed":
			valid = self.before is not None and self.after is None and not self.changes
		elif self.changeKind == "modified":
			valid = self.before is not None and self.after is not None and not self.changes
		else:
			valid = self.before is None and self.after is None and bool(self.changes)
		if not valid:
			raise ValueError("diff change discriminator contradicts its evidence")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("changeKind", self.changeKind),
				("ancestorPath", JsonArray(self.ancestorPath)),
				("before", evidenceObject(self.before) if self.before is not None else None),
				("after", evidenceObject(self.after) if self.after is not None else None),
				("changes", JsonArray(tuple(change.asObject() for change in self.changes))),
			),
		)


def parseDocumentReference(value: JsonValue) -> DocumentReference:
	fields = _closed(
		value,
		("documentId", "documentKind", "schema", "projection", "privacyRevision", "admission"),
		"document reference",
	)
	schema = _closed(fields["schema"], ("major", "minor"), "referenced schema")
	admission = _closed(fields["admission"], ("admitted", "code"), "admission record")
	code = admission["code"]
	if code is not None and not isinstance(code, str):
		raise ValueError("admission code must be a string or null")
	return DocumentReference(
		_string(fields["documentId"], "referenced document ID"),
		_string(fields["documentKind"], "referenced document kind"),
		_nonnegative(schema["major"], "schema major"),
		_nonnegative(schema["minor"], "schema minor"),
		_string(fields["projection"], "referenced projection"),
		_nonnegative(fields["privacyRevision"], "privacy revision"),
		AdmissionRecord(_boolean(admission["admitted"], "admitted"), code),
	)


def parseDiffChange(value: JsonValue) -> DiffChange:
	fields = _closed(
		value,
		("changeKind", "ancestorPath", "before", "after", "changes"),
		"diff change",
	)
	kind = _string(fields["changeKind"], "diff change kind")
	if kind not in {"added", "removed", "modified", "nested"}:
		raise ValueError("diff change kind is not in the closed registry")
	before = fields["before"]
	after = fields["after"]
	return DiffChange(
		cast(DiffChangeKind, kind),
		tuple(_string(item, "diff path segment") for item in _array(fields["ancestorPath"], "diff path")),
		None if before is None else parseEvidenceEnvelope(before),
		None if after is None else parseEvidenceEnvelope(after),
		tuple(parseDiffChange(item) for item in _array(fields["changes"], "nested diff changes")),
	)


@dataclass(frozen=True, slots=True)
class EventSettingsProvenance:
	revision: int
	redactionEnabled: bool
	eventDetailCharacters: int

	def __post_init__(self) -> None:
		if requireNonnegativeInteger(self.revision, "settings revision") == 0:
			raise ValueError("settings revision must be positive")
		_ = _boolean(self.redactionEnabled, "event redaction enabled")
		_ = requireNonnegativeInteger(self.eventDetailCharacters, "event detail characters")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("revision", self.revision),
				("redactionEnabled", self.redactionEnabled),
				("eventDetailCharacters", self.eventDetailCharacters),
			),
		)


@dataclass(frozen=True, slots=True)
class EventTargetScope:
	scopeKind: str
	scopeId: str
	providerProcessId: int | None

	def __post_init__(self) -> None:
		object.__setattr__(self, "scopeKind", requireToken(self.scopeKind, "event scope kind"))
		object.__setattr__(self, "scopeId", requireToken(self.scopeId, "event scope ID"))
		if self.providerProcessId is not None:
			_ = requireNonnegativeInteger(self.providerProcessId, "provider process ID")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("scopeKind", self.scopeKind),
				("scopeId", self.scopeId),
				("providerProcessId", self.providerProcessId),
			),
		)


@dataclass(frozen=True, slots=True)
class EventRecord:
	eventId: str
	eventName: str
	receivedAt: str
	processedAt: str
	propertyReadAt: str
	source: EvidenceEnvelope
	settings: EventSettingsProvenance
	target: EventTargetScope
	sanitizedDetail: EvidenceEnvelope

	def __post_init__(self) -> None:
		object.__setattr__(self, "eventId", requireToken(self.eventId, "event ID"))
		object.__setattr__(self, "eventName", requireToken(self.eventName, "event name"))
		received = _validateTimestamp(self.receivedAt, "event receipt time")
		processed = _validateTimestamp(self.processedAt, "event processing time")
		propertyRead = _validateTimestamp(self.propertyReadAt, "event property-read time")
		if not received <= propertyRead <= processed:
			raise ValueError("event timestamps must preserve receipt, property-read, and processing order")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("eventId", self.eventId),
				("eventName", self.eventName),
				("receivedAt", self.receivedAt),
				("processedAt", self.processedAt),
				("propertyReadAt", self.propertyReadAt),
				("source", evidenceObject(self.source)),
				("settings", self.settings.asObject()),
				("target", self.target.asObject()),
				("sanitizedDetail", evidenceObject(self.sanitizedDetail)),
			),
		)


@dataclass(frozen=True, slots=True)
class DropCounter:
	count: int
	reasonCode: str | None

	def __post_init__(self) -> None:
		count = requireNonnegativeInteger(self.count, "drop count")
		if (count == 0) != (self.reasonCode is None):
			raise ValueError("drop reason must exist exactly when drops occurred")
		if self.reasonCode is not None:
			object.__setattr__(self, "reasonCode", requireToken(self.reasonCode, "drop reason code"))

	def asObject(self) -> JsonObject:
		return JsonObject((("count", self.count), ("reasonCode", self.reasonCode)))


@dataclass(frozen=True, slots=True)
class EventDrops:
	receipt: DropCounter
	pendingQueue: DropCounter
	processing: DropCounter
	propertyRead: DropCounter
	retainedRows: DropCounter
	export: DropCounter

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple((name, cast(DropCounter, getattr(self, name)).asObject()) for name in EVENT_DROP_FIELDS),
		)


EVENT_DROP_FIELDS = (
	"receipt",
	"pendingQueue",
	"processing",
	"propertyRead",
	"retainedRows",
	"export",
)


def _eventSettings(value: JsonValue) -> EventSettingsProvenance:
	fields = _closed(
		value,
		("revision", "redactionEnabled", "eventDetailCharacters"),
		"event settings provenance",
	)
	return EventSettingsProvenance(
		_nonnegative(fields["revision"], "settings revision"),
		_boolean(fields["redactionEnabled"], "event redaction enabled"),
		_nonnegative(fields["eventDetailCharacters"], "event detail characters"),
	)


def _eventTarget(value: JsonValue) -> EventTargetScope:
	fields = _closed(value, ("scopeKind", "scopeId", "providerProcessId"), "event target scope")
	processId = fields["providerProcessId"]
	if processId is not None and (not isinstance(processId, int) or isinstance(processId, bool)):
		raise ValueError("provider process ID must be an integer or null")
	return EventTargetScope(
		_string(fields["scopeKind"], "event scope kind"),
		_string(fields["scopeId"], "event scope ID"),
		processId,
	)


def parseEventRecord(value: JsonValue) -> EventRecord:
	fields = _closed(
		value,
		(
			"eventId",
			"eventName",
			"receivedAt",
			"processedAt",
			"propertyReadAt",
			"source",
			"settings",
			"target",
			"sanitizedDetail",
		),
		"event record",
	)
	return EventRecord(
		_string(fields["eventId"], "event ID"),
		_string(fields["eventName"], "event name"),
		_string(fields["receivedAt"], "event receipt time"),
		_string(fields["processedAt"], "event processing time"),
		_string(fields["propertyReadAt"], "event property-read time"),
		parseEvidenceEnvelope(fields["source"]),
		_eventSettings(fields["settings"]),
		_eventTarget(fields["target"]),
		parseEvidenceEnvelope(fields["sanitizedDetail"]),
	)


def _dropCounter(value: JsonValue) -> DropCounter:
	fields = _closed(value, ("count", "reasonCode"), "drop counter")
	reason = fields["reasonCode"]
	if reason is not None and not isinstance(reason, str):
		raise ValueError("drop reason code must be a string or null")
	return DropCounter(_nonnegative(fields["count"], "drop count"), reason)


def parseEventDrops(value: JsonValue) -> EventDrops:
	fields = _closed(value, EVENT_DROP_FIELDS, "event drops")
	return EventDrops(*(_dropCounter(fields[name]) for name in EVENT_DROP_FIELDS))


@dataclass(frozen=True, slots=True)
class DiagnosticTiming:
	startMilliseconds: int | float
	endMilliseconds: int | float
	elapsedMilliseconds: int | float

	def __post_init__(self) -> None:
		start = requireFiniteNumber(self.startMilliseconds, "diagnostic start")
		end = requireFiniteNumber(self.endMilliseconds, "diagnostic end")
		elapsed = requireFiniteNumber(self.elapsedMilliseconds, "diagnostic elapsed")
		if start < 0 or end < start or elapsed < 0 or abs(end - start - elapsed) > 1e-9:
			raise ValueError("diagnostic timing is inconsistent")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("startMilliseconds", self.startMilliseconds),
				("endMilliseconds", self.endMilliseconds),
				("elapsedMilliseconds", self.elapsedMilliseconds),
			),
		)


@dataclass(frozen=True, slots=True)
class DiagnosticCorrelation:
	sessionCorrelationId: str
	operationCorrelationId: str
	documentCorrelationId: str

	def __post_init__(self) -> None:
		for name in DIAGNOSTIC_CORRELATION_FIELDS:
			object.__setattr__(self, name, requireToken(getattr(self, name), name))

	def asObject(self) -> JsonObject:
		return JsonObject(
			tuple((name, cast(str, getattr(self, name))) for name in DIAGNOSTIC_CORRELATION_FIELDS),
		)


DIAGNOSTIC_CORRELATION_FIELDS = (
	"sessionCorrelationId",
	"operationCorrelationId",
	"documentCorrelationId",
)


@dataclass(frozen=True, slots=True)
class DiagnosticRecord:
	diagnosticId: str
	code: str
	fieldPath: str
	safeBreadcrumb: tuple[str, ...]
	component: str
	provider: EvidenceEnvelope
	severity: str
	sanitizedDetail: str
	timing: DiagnosticTiming
	budget: EvidenceEnvelope
	fallback: EvidenceEnvelope
	correlation: DiagnosticCorrelation

	def __post_init__(self) -> None:
		object.__setattr__(self, "diagnosticId", requireToken(self.diagnosticId, "diagnostic ID"))
		object.__setattr__(self, "code", requireToken(self.code, "diagnostic code"))
		if self.fieldPath and not self.fieldPath.startswith("/"):
			raise ValueError("diagnostic field path must be a JSON Pointer")
		breadcrumb = tuple(requireToken(item, "breadcrumb segment") for item in self.safeBreadcrumb)
		if len(breadcrumb) > 64:
			raise ValueError("diagnostic breadcrumb must be bounded")
		object.__setattr__(self, "safeBreadcrumb", breadcrumb)
		object.__setattr__(self, "component", requireToken(self.component, "diagnostic component"))
		if self.severity not in {"info", "warning", "error", "critical"}:
			raise ValueError("diagnostic severity is not in the closed registry")
		if len(self.sanitizedDetail) > 1024:
			raise ValueError("diagnostic detail exceeds 1024 Unicode scalar values")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("diagnosticId", self.diagnosticId),
				("code", self.code),
				("fieldPath", self.fieldPath),
				("safeBreadcrumb", JsonArray(self.safeBreadcrumb)),
				("component", self.component),
				("provider", evidenceObject(self.provider)),
				("severity", self.severity),
				("sanitizedDetail", self.sanitizedDetail),
				("timing", self.timing.asObject()),
				("budget", evidenceObject(self.budget)),
				("fallback", evidenceObject(self.fallback)),
				("correlation", self.correlation.asObject()),
			),
		)


def parseDiagnosticRecord(value: JsonValue) -> DiagnosticRecord:
	fields = _closed(
		value,
		(
			"diagnosticId",
			"code",
			"fieldPath",
			"safeBreadcrumb",
			"component",
			"provider",
			"severity",
			"sanitizedDetail",
			"timing",
			"budget",
			"fallback",
			"correlation",
		),
		"diagnostic record",
	)
	timing = _closed(
		fields["timing"],
		("startMilliseconds", "endMilliseconds", "elapsedMilliseconds"),
		"diagnostic timing",
	)
	correlation = _closed(
		fields["correlation"],
		DIAGNOSTIC_CORRELATION_FIELDS,
		"diagnostic correlation",
	)
	return DiagnosticRecord(
		_string(fields["diagnosticId"], "diagnostic ID"),
		_string(fields["code"], "diagnostic code"),
		_string(fields["fieldPath"], "diagnostic field path", empty=True),
		tuple(
			_string(item, "diagnostic breadcrumb segment")
			for item in _array(fields["safeBreadcrumb"], "diagnostic breadcrumb")
		),
		_string(fields["component"], "diagnostic component"),
		parseEvidenceEnvelope(fields["provider"]),
		_string(fields["severity"], "diagnostic severity"),
		_string(fields["sanitizedDetail"], "sanitized diagnostic detail", empty=True),
		DiagnosticTiming(
			requireFiniteNumber(timing["startMilliseconds"], "diagnostic start"),
			requireFiniteNumber(timing["endMilliseconds"], "diagnostic end"),
			requireFiniteNumber(timing["elapsedMilliseconds"], "diagnostic elapsed"),
		),
		parseEvidenceEnvelope(fields["budget"]),
		parseEvidenceEnvelope(fields["fallback"]),
		DiagnosticCorrelation(
			*(_string(correlation[name], name) for name in DIAGNOSTIC_CORRELATION_FIELDS),
		),
	)


def _canonicalUuid(value: str, label: str) -> str:
	token = requireToken(value, label)
	try:
		parsed = UUID(token)
	except ValueError as error:
		raise ValueError(f"{label} must be a UUID") from error
	if token != str(parsed):
		raise ValueError(f"{label} must use canonical lowercase UUID text")
	return token


def _validateTimestamp(value: str, label: str) -> datetime:
	return requireRfc3339Timestamp(value, label)


@dataclass(frozen=True, slots=True)
class SettingsValueRecord:
	settingId: str
	kind: str
	value: bool | int | str

	def __post_init__(self) -> None:
		object.__setattr__(self, "settingId", requireToken(self.settingId, "setting ID"))
		object.__setattr__(self, "kind", requireToken(self.kind, "setting kind"))

	def asObject(self) -> JsonObject:
		return JsonObject((("settingId", self.settingId), ("kind", self.kind), ("value", self.value)))


@dataclass(frozen=True, slots=True)
class ValidationProvenance:
	status: str
	validator: str
	validatedAt: str

	def __post_init__(self) -> None:
		if self.status != "validated":
			raise ValueError("settings snapshot must carry validated provenance")
		object.__setattr__(self, "validator", requireToken(self.validator, "settings validator"))
		_ = _validateTimestamp(self.validatedAt, "settings validation time")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(("status", self.status), ("validator", self.validator), ("validatedAt", self.validatedAt)),
		)


@dataclass(frozen=True, slots=True)
class SettingsSnapshotRecord:
	scope: str
	revision: int
	values: tuple[SettingsValueRecord, ...]
	validation: ValidationProvenance
	correlationId: str

	def __post_init__(self) -> None:
		if self.scope != "global":
			raise ValueError("settings snapshot scope must be global")
		if requireNonnegativeInteger(self.revision, "settings revision") == 0:
			raise ValueError("settings revision must be positive")
		ids = tuple(item.settingId for item in self.values)
		if not ids or len(set(ids)) != len(ids):
			raise ValueError("settings snapshot values must be nonempty and unique")
		object.__setattr__(self, "correlationId", requireToken(self.correlationId, "settings correlation ID"))

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("scope", self.scope),
				("revision", self.revision),
				("values", JsonArray(tuple(item.asObject() for item in self.values))),
				("validation", self.validation.asObject()),
				("correlationId", self.correlationId),
			),
		)


def parseSettingsSnapshotRecord(value: JsonValue) -> SettingsSnapshotRecord:
	fields = _closed(
		value,
		("scope", "revision", "values", "validation", "correlationId"),
		"settings snapshot record",
	)
	validation = _closed(
		fields["validation"],
		("status", "validator", "validatedAt"),
		"settings validation provenance",
	)
	values: list[SettingsValueRecord] = []
	for item in _array(fields["values"], "settings values"):
		valueFields = _closed(item, ("settingId", "kind", "value"), "settings value")
		settingValue = valueFields["value"]
		if not isinstance(settingValue, (bool, int, str)):
			raise ValueError("setting value must be a boolean, integer, or string")
		values.append(
			SettingsValueRecord(
				_string(valueFields["settingId"], "setting ID"),
				_string(valueFields["kind"], "setting kind"),
				settingValue,
			),
		)
	return SettingsSnapshotRecord(
		_string(fields["scope"], "settings scope"),
		_nonnegative(fields["revision"], "settings revision"),
		tuple(values),
		ValidationProvenance(
			_string(validation["status"], "validation status"),
			_string(validation["validator"], "settings validator"),
			_string(validation["validatedAt"], "settings validation time"),
		),
		_string(fields["correlationId"], "settings correlation ID"),
	)


@dataclass(frozen=True, slots=True)
class CustomUiaDefinitionRecord:
	definitionId: str
	guid: str
	name: str
	valueType: str
	privacyClassification: str
	targets: tuple[str, ...]

	def __post_init__(self) -> None:
		object.__setattr__(self, "definitionId", requireToken(self.definitionId, "definition ID"))
		object.__setattr__(self, "guid", _canonicalUuid(self.guid, "custom UIA GUID"))
		object.__setattr__(self, "name", requireToken(self.name, "custom UIA name"))
		object.__setattr__(self, "valueType", requireToken(self.valueType, "custom UIA value type"))
		object.__setattr__(
			self,
			"privacyClassification",
			requireToken(self.privacyClassification, "custom UIA privacy classification"),
		)
		targets = tuple(requireToken(item, "custom UIA target") for item in self.targets)
		if not targets or len(set(targets)) != len(targets):
			raise ValueError("custom UIA targets must be nonempty and unique")
		object.__setattr__(self, "targets", targets)

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("definitionId", self.definitionId),
				("guid", self.guid),
				("name", self.name),
				("valueType", self.valueType),
				("privacyClassification", self.privacyClassification),
				("targets", JsonArray(self.targets)),
			),
		)


@dataclass(frozen=True, slots=True)
class ConfigurationValidation:
	status: str
	code: str | None
	validatedAt: str

	def __post_init__(self) -> None:
		if self.status not in {"validated", "rejected"}:
			raise ValueError("configuration validation status is unsupported")
		if (self.status == "validated") != (self.code is None):
			raise ValueError("configuration validation code contradicts status")
		if self.code is not None:
			object.__setattr__(self, "code", requireToken(self.code, "configuration validation code"))
		_ = _validateTimestamp(self.validatedAt, "configuration validation time")

	def asObject(self) -> JsonObject:
		return JsonObject((("status", self.status), ("code", self.code), ("validatedAt", self.validatedAt)))


@dataclass(frozen=True, slots=True)
class CustomUiaConfigurationRecord:
	configurationId: str
	definitions: tuple[CustomUiaDefinitionRecord, ...]
	allowedTargets: tuple[str, ...]
	allowedValueTypes: tuple[str, ...]
	allowedPrivacyClassifications: tuple[str, ...]
	validation: ConfigurationValidation
	restartRequired: bool

	def __post_init__(self) -> None:
		object.__setattr__(self, "configurationId", requireToken(self.configurationId, "configuration ID"))
		ids = tuple(item.definitionId for item in self.definitions)
		guids = tuple(item.guid for item in self.definitions)
		if not ids or len(set(ids)) != len(ids) or len(set(guids)) != len(guids):
			raise ValueError("custom UIA definitions must be nonempty with unique IDs and GUIDs")
		for name in (
			"allowedTargets",
			"allowedValueTypes",
			"allowedPrivacyClassifications",
		):
			items = tuple(requireToken(item, name) for item in getattr(self, name))
			if not items or len(set(items)) != len(items):
				raise ValueError(f"{name} must be nonempty and unique")
			object.__setattr__(self, name, items)
		for definition in self.definitions:
			if (
				definition.valueType not in self.allowedValueTypes
				or definition.privacyClassification not in self.allowedPrivacyClassifications
				or not set(definition.targets).issubset(self.allowedTargets)
			):
				raise ValueError("custom UIA definition exceeds the allowed configuration")
		_ = _boolean(self.restartRequired, "restart required")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("configurationId", self.configurationId),
				("definitions", JsonArray(tuple(item.asObject() for item in self.definitions))),
				("allowedTargets", JsonArray(self.allowedTargets)),
				("allowedValueTypes", JsonArray(self.allowedValueTypes)),
				("allowedPrivacyClassifications", JsonArray(self.allowedPrivacyClassifications)),
				("validation", self.validation.asObject()),
				("restartRequired", self.restartRequired),
			),
		)


def parseCustomUiaConfigurationRecord(value: JsonValue) -> CustomUiaConfigurationRecord:
	fields = _closed(
		value,
		(
			"configurationId",
			"definitions",
			"allowedTargets",
			"allowedValueTypes",
			"allowedPrivacyClassifications",
			"validation",
			"restartRequired",
		),
		"custom UIA configuration",
	)
	definitions: list[CustomUiaDefinitionRecord] = []
	for item in _array(fields["definitions"], "custom UIA definitions"):
		itemFields = _closed(
			item,
			("definitionId", "guid", "name", "valueType", "privacyClassification", "targets"),
			"custom UIA definition",
		)
		definitions.append(
			CustomUiaDefinitionRecord(
				_string(itemFields["definitionId"], "definition ID"),
				_string(itemFields["guid"], "custom UIA GUID"),
				_string(itemFields["name"], "custom UIA name"),
				_string(itemFields["valueType"], "custom UIA value type"),
				_string(itemFields["privacyClassification"], "custom UIA privacy classification"),
				tuple(
					_string(target, "custom UIA target")
					for target in _array(itemFields["targets"], "custom UIA targets")
				),
			),
		)
	validation = _closed(
		fields["validation"],
		("status", "code", "validatedAt"),
		"configuration validation",
	)
	code = validation["code"]
	if code is not None and not isinstance(code, str):
		raise ValueError("configuration validation code must be a string or null")
	return CustomUiaConfigurationRecord(
		_string(fields["configurationId"], "configuration ID"),
		tuple(definitions),
		tuple(
			_string(item, "allowed target") for item in _array(fields["allowedTargets"], "allowed targets")
		),
		tuple(
			_string(item, "allowed value type")
			for item in _array(fields["allowedValueTypes"], "allowed value types")
		),
		tuple(
			_string(item, "allowed privacy classification")
			for item in _array(fields["allowedPrivacyClassifications"], "allowed privacy classifications")
		),
		ConfigurationValidation(
			_string(validation["status"], "configuration validation status"),
			code,
			_string(validation["validatedAt"], "configuration validation time"),
		),
		_boolean(fields["restartRequired"], "restart required"),
	)


@dataclass(frozen=True, slots=True)
class ScreenshotTarget:
	scopeKind: str
	scopeId: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "scopeKind", requireToken(self.scopeKind, "screenshot target scope"))
		object.__setattr__(self, "scopeId", requireToken(self.scopeId, "screenshot target ID"))

	def asObject(self) -> JsonObject:
		return JsonObject((("scopeKind", self.scopeKind), ("scopeId", self.scopeId)))


@dataclass(frozen=True, slots=True)
class ScreenshotAttempt:
	requestId: str
	generation: int
	target: ScreenshotTarget
	requestedAt: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "requestId", requireToken(self.requestId, "screenshot request ID"))
		_ = requireNonnegativeInteger(self.generation, "screenshot generation")
		_ = _validateTimestamp(self.requestedAt, "screenshot request time")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("requestId", self.requestId),
				("generation", self.generation),
				("target", self.target.asObject()),
				("requestedAt", self.requestedAt),
			),
		)


@dataclass(frozen=True, slots=True)
class ScreenshotImageRecord:
	storage: str
	mediaType: str
	value: EvidenceEnvelope
	sha256: str
	byteLength: int
	width: int
	height: int
	capturedAt: str

	def __post_init__(self) -> None:
		if self.storage not in {"path", "embedded"}:
			raise ValueError("screenshot storage is not in the closed registry")
		if self.mediaType != "image/png":
			raise ValueError("screenshot media type must be image/png")
		if self.value.status is not EvidenceState.VALUE:
			raise ValueError("successful screenshot requires value evidence")
		_validateSha256(self.sha256, "screenshot hash")
		if requireNonnegativeInteger(self.byteLength, "screenshot byte length") == 0:
			raise ValueError("screenshot byte length must be positive")
		if requireNonnegativeInteger(self.width, "screenshot width") == 0:
			raise ValueError("screenshot width must be positive")
		if requireNonnegativeInteger(self.height, "screenshot height") == 0:
			raise ValueError("screenshot height must be positive")
		_ = _validateTimestamp(self.capturedAt, "screenshot capture time")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("storage", self.storage),
				("mediaType", self.mediaType),
				("value", evidenceObject(self.value)),
				("sha256", self.sha256),
				("byteLength", self.byteLength),
				("width", self.width),
				("height", self.height),
				("capturedAt", self.capturedAt),
			),
		)


@dataclass(frozen=True, slots=True)
class ScreenshotErrorRecord:
	code: str
	diagnosticId: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "code", requireToken(self.code, "screenshot error code"))
		object.__setattr__(self, "diagnosticId", requireToken(self.diagnosticId, "screenshot diagnostic ID"))

	def asObject(self) -> JsonObject:
		return JsonObject((("code", self.code), ("diagnosticId", self.diagnosticId)))


@dataclass(frozen=True, slots=True)
class ScreenshotDocumentResult:
	attempt: ScreenshotAttempt
	status: str
	image: ScreenshotImageRecord | None
	error: ScreenshotErrorRecord | None
	warning: str

	def __post_init__(self) -> None:
		if self.status == "value":
			valid = self.image is not None and self.error is None
		elif self.status in {"failed", "absent"}:
			valid = self.image is None and self.error is not None
		else:
			raise ValueError("screenshot status is not in the closed registry")
		if not valid:
			raise ValueError("screenshot status contradicts current image and error evidence")
		if self.warning != UNREDACTED_SCREENSHOT_WARNING:
			raise ValueError("screenshot result requires the fixed visual warning")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("attempt", self.attempt.asObject()),
				("status", self.status),
				("image", self.image.asObject() if self.image is not None else None),
				("error", self.error.asObject() if self.error is not None else None),
				("warning", self.warning),
			),
		)


def parseScreenshotDocumentResult(value: JsonValue) -> ScreenshotDocumentResult:
	fields = _closed(value, ("attempt", "status", "image", "error", "warning"), "screenshot result")
	attempt = _closed(
		fields["attempt"],
		("requestId", "generation", "target", "requestedAt"),
		"screenshot attempt",
	)
	target = _closed(attempt["target"], ("scopeKind", "scopeId"), "screenshot target")
	imageValue = fields["image"]
	image: ScreenshotImageRecord | None = None
	if imageValue is not None:
		imageFields = _closed(
			imageValue,
			("storage", "mediaType", "value", "sha256", "byteLength", "width", "height", "capturedAt"),
			"screenshot image",
		)
		image = ScreenshotImageRecord(
			_string(imageFields["storage"], "screenshot storage"),
			_string(imageFields["mediaType"], "screenshot media type"),
			parseEvidenceEnvelope(imageFields["value"]),
			_string(imageFields["sha256"], "screenshot hash"),
			_nonnegative(imageFields["byteLength"], "screenshot byte length"),
			_nonnegative(imageFields["width"], "screenshot width"),
			_nonnegative(imageFields["height"], "screenshot height"),
			_string(imageFields["capturedAt"], "screenshot capture time"),
		)
	errorValue = fields["error"]
	error: ScreenshotErrorRecord | None = None
	if errorValue is not None:
		errorFields = _closed(errorValue, ("code", "diagnosticId"), "screenshot error")
		error = ScreenshotErrorRecord(
			_string(errorFields["code"], "screenshot error code"),
			_string(errorFields["diagnosticId"], "screenshot diagnostic ID"),
		)
	return ScreenshotDocumentResult(
		ScreenshotAttempt(
			_string(attempt["requestId"], "screenshot request ID"),
			_nonnegative(attempt["generation"], "screenshot generation"),
			ScreenshotTarget(
				_string(target["scopeKind"], "screenshot target scope"),
				_string(target["scopeId"], "screenshot target ID"),
			),
			_string(attempt["requestedAt"], "screenshot request time"),
		),
		_string(fields["status"], "screenshot status"),
		image,
		error,
		_string(fields["warning"], "screenshot warning"),
	)


@dataclass(frozen=True, slots=True)
class CommittedFileRecord:
	name: str
	sha256: str
	byteLength: int

	def __post_init__(self) -> None:
		object.__setattr__(self, "name", requireToken(self.name, "committed file name"))
		if "/" in self.name or "\\" in self.name:
			raise ValueError("committed file name must be a single path component")
		_validateSha256(self.sha256, "committed file hash")
		_ = requireNonnegativeInteger(self.byteLength, "committed file byte length")

	def asObject(self) -> JsonObject:
		return JsonObject(
			(("name", self.name), ("sha256", self.sha256), ("byteLength", self.byteLength)),
		)


@dataclass(frozen=True, slots=True)
class PublicationTargetIdentity:
	applicationName: str
	folderName: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "applicationName", requireToken(self.applicationName, "application name"))
		object.__setattr__(self, "folderName", requireToken(self.folderName, "publication folder name"))

	def asObject(self) -> JsonObject:
		return JsonObject((("applicationName", self.applicationName), ("folderName", self.folderName)))


@dataclass(frozen=True, slots=True)
class PublicationRecord:
	publicationId: str
	captureKind: str
	committedFiles: tuple[CommittedFileRecord, ...]
	metadataHash: str
	committedAt: str
	targetIdentity: PublicationTargetIdentity
	commitReceipt: str

	def __post_init__(self) -> None:
		object.__setattr__(self, "publicationId", requireToken(self.publicationId, "publication ID"))
		if self.captureKind not in {"snapshot", "navigatorSnapshot", "diff"}:
			raise ValueError("publication capture kind is unsupported")
		names = tuple(item.name for item in self.committedFiles)
		if not names or len(set(names)) != len(names):
			raise ValueError("committed files must be nonempty and unique")
		_validateSha256(self.metadataHash, "publication metadata hash")
		_ = _validateTimestamp(self.committedAt, "publication commit time")
		object.__setattr__(self, "commitReceipt", requireToken(self.commitReceipt, "commit receipt"))

	def asObject(self) -> JsonObject:
		return JsonObject(
			(
				("publicationId", self.publicationId),
				("captureKind", self.captureKind),
				("committedFiles", JsonArray(tuple(item.asObject() for item in self.committedFiles))),
				("metadataHash", self.metadataHash),
				("committedAt", self.committedAt),
				("targetIdentity", self.targetIdentity.asObject()),
				("commitReceipt", self.commitReceipt),
			),
		)


def parsePublicationRecord(value: JsonValue) -> PublicationRecord:
	fields = _closed(
		value,
		(
			"publicationId",
			"captureKind",
			"committedFiles",
			"metadataHash",
			"committedAt",
			"targetIdentity",
			"commitReceipt",
		),
		"publication record",
	)
	files: list[CommittedFileRecord] = []
	for item in _array(fields["committedFiles"], "committed files"):
		fileFields = _closed(item, ("name", "sha256", "byteLength"), "committed file")
		files.append(
			CommittedFileRecord(
				_string(fileFields["name"], "committed file name"),
				_string(fileFields["sha256"], "committed file hash"),
				_nonnegative(fileFields["byteLength"], "committed file byte length"),
			),
		)
	target = _closed(
		fields["targetIdentity"],
		("applicationName", "folderName"),
		"publication target identity",
	)
	return PublicationRecord(
		_string(fields["publicationId"], "publication ID"),
		_string(fields["captureKind"], "publication capture kind"),
		tuple(files),
		_string(fields["metadataHash"], "publication metadata hash"),
		_string(fields["committedAt"], "publication commit time"),
		PublicationTargetIdentity(
			_string(target["applicationName"], "application name"),
			_string(target["folderName"], "publication folder name"),
		),
		_string(fields["commitReceipt"], "commit receipt"),
	)


def _validateSha256(value: str, label: str) -> None:
	if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
		raise ValueError(f"{label} must be lowercase SHA-256 text")
