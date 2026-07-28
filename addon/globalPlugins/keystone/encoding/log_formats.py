from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
import json
import re
import threading
from typing import cast
import unicodedata
from uuid import UUID


type LogScalar = str | int | bool

_UINT64_MAX = (1 << 64) - 1
NVDA_MESSAGE_MAXIMUM = 4096
_MONTHS = (
	"January",
	"February",
	"March",
	"April",
	"May",
	"June",
	"July",
	"August",
	"September",
	"October",
	"November",
	"December",
)
_CODE_PATTERN = re.compile(r"^KS\.[A-Z0-9_]+\.[A-Z0-9_]+$")
_TOKEN_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_WORKER_PATTERN = re.compile(r"^worker:[1-9][0-9]*$")
_THREAD_IDENTITIES = frozenset(("main", "gui", "uia", "jab"))
_BOOLEAN_FIELDS = frozenset(
	(
		"collisionDetected",
		"existingFrameReused",
		"normalizedValueApplied",
		"ownershipNoncePresent",
		"programmaticNamePresent",
		"providerPidMatch",
		"rawEventsEnabled",
		"boundedMode",
		"redactionEnabled",
	),
)
_INTEGER_FIELDS = frozenset(("depth", "processedNodes"))
_INTEGER_SUFFIXES = (
	"Bytes",
	"Count",
	"Depth",
	"Generation",
	"Height",
	"Limit",
	"Major",
	"Ms",
	"Ordinal",
	"Revision",
	"Width",
)
_BIDI_CONTROLS = frozenset(
	(
		"\u200e",
		"\u200f",
		"\u202a",
		"\u202b",
		"\u202c",
		"\u202d",
		"\u202e",
		"\u2066",
		"\u2067",
		"\u2068",
		"\u2069",
	),
)


class Severity(IntEnum):
	DEBUG = 10
	INFO = 20
	WARNING = 30
	ERROR = 40
	CRITICAL = 50


def _validateText(value: str, label: str, *, maximum: int = 2048) -> str:
	if len(value) > maximum:
		raise ValueError(f"{label} must be a bounded string")
	normalized = unicodedata.normalize("NFC", value)
	for character in normalized:
		codePoint = ord(character)
		if 0xD800 <= codePoint <= 0xDFFF or codePoint & 0xFFFF in (0xFFFE, 0xFFFF):
			raise ValueError(f"{label} contains an invalid Unicode scalar")
	return normalized


@dataclass(frozen=True, slots=True)
class EventDefinition:
	code: str
	defaultSeverity: Severity
	component: str
	message: str
	requiredFields: tuple[str, ...]
	optionalFields: tuple[str, ...]
	fieldTypes: tuple[tuple[str, str], ...]

	def __post_init__(self) -> None:
		if not _CODE_PATTERN.fullmatch(self.code):
			raise ValueError("event code must use the closed Keystone grammar")
		if not _TOKEN_PATTERN.fullmatch(self.component):
			raise ValueError("event component must be a bounded safe token")
		_ = _validateText(self.message, "event message", maximum=256)
		fields = self.requiredFields + self.optionalFields
		if len(fields) != len(set(fields)):
			raise ValueError("event fields must be unique")
		for name in fields:
			if not _TOKEN_PATTERN.fullmatch(name):
				raise ValueError("event field names must be bounded safe tokens")
		if tuple(name for name, _kind in self.fieldTypes) != fields:
			raise ValueError("event field types must cover the closed field order")
		if any(kind not in ("boolean", "integer", "string") for _name, kind in self.fieldTypes):
			raise ValueError("event field type is not closed")


_REGISTRY_DATA = """\
KS.LIFECYCLE.SESSION_STARTED|INFO|lifecycle|boundaryReason,addonVersion,nvdaVersion,windowsBuild,processArchitecture,redactionEnabled,configurationScope,settingsRevision,sessionStartTime,schemaMajor,policyRevision|designSetId
KS.LIFECYCLE.PLUGIN_INITIALIZED|INFO|lifecycle|addonVersion|durationMs
KS.LIFECYCLE.PLUGIN_TERMINATING|INFO|lifecycle|resourceCount|pendingJobCount
KS.LIFECYCLE.PLUGIN_TERMINATED|INFO|lifecycle|releasedCount,failedReleaseCount|durationMs
KS.LIFECYCLE.SECURE_STATE_ENTERED|WARNING|lifecycle|lifecycleGeneration|invalidatedCount
KS.LIFECYCLE.SECURE_STATE_EXITED|INFO|lifecycle|lifecycleGeneration|
KS.LIFECYCLE.RESOURCE_RELEASE_FAILED|ERROR|lifecycle|resourceKind,reasonCode|releaseOrdinal,remainingCount
KS.COMMAND.LAYER_ENTERED|INFO|command|layerGeneration|
KS.COMMAND.LAYER_EXITED|INFO|command|layerGeneration,exitReason|
KS.COMMAND.LAYER_INVALID_KEY|WARNING|command|layerGeneration,keyClass|
KS.COMMAND.REQUEST_ACCEPTED|INFO|command|commandId,operationKind|captureKind
KS.COMMAND.REQUEST_REJECTED|WARNING|command|commandId,reasonCode|activeOperationKind
KS.COMMAND.OUTPUT_PATH_COPIED|INFO|command|outputKind|ageMs
KS.COMMAND.OUTPUT_REVEAL_REQUESTED|INFO|command|outputKind|shellResultCode
KS.COMMAND.HELP_OPENED|INFO|command|helpSurface|
KS.CAPTURE.STARTED|INFO|capture|captureKind,boundedMode|configuredNodeLimit,configuredDepthLimit,configuredTimeMs
KS.CAPTURE.PROGRESS|DEBUG|capture|captureKind,processedNodes|elapsedMs,pendingWorkCount,phase
KS.CAPTURE.CANCEL_REQUESTED|INFO|capture|captureKind,activeState|
KS.CAPTURE.CANCELLED|INFO|capture|captureKind,terminalState|processedNodes,elapsedMs
KS.CAPTURE.COMPLETED|INFO|capture|captureKind,nodeCount,publicationStatus|elapsedMs,cycleCount
KS.CAPTURE.COMPLETED_TRUNCATED|WARNING|capture|captureKind,nodeCount,limitType|configuredLimit,actualCount,elapsedMs
KS.CAPTURE.COMPLETED_PARTIAL_SCREENSHOT|WARNING|capture|nodeCount,screenshotCode|captureKind,elapsedMs
KS.CAPTURE.FAILED|ERROR|capture|captureKind,phase,reasonCode|processedNodes,elapsedMs
KS.CAPTURE.BASELINE_CREATED|INFO|capture|captureKind,nodeCount|elapsedMs
KS.TRAVERSAL.LIMIT_REACHED|WARNING|traversal|limitType,configuredLimit|actualCount,omittedCount
KS.TRAVERSAL.CYCLE_DETECTED|WARNING|traversal|providerKind,depth|cycleCount
KS.TRAVERSAL.CHILD_READ_FAILED|WARNING|traversal|providerKind,reasonCode|depth,childOrdinal
KS.TRAVERSAL.LOGICAL_CHILD_MERGED|DEBUG|traversal|providerKind,deduplicationOutcome|depth
KS.TRAVERSAL.PROVIDER_CALL_SLOW|WARNING|traversal|providerKind,operationClass,durationMs|thresholdMs
KS.TRAVERSAL.PROVIDER_CIRCUIT_OPENED|WARNING|traversal|providerKind,reasonCode,resetCondition|sampleCount
KS.TRAVERSAL.PROVIDER_CIRCUIT_RESET|INFO|traversal|providerKind,resetCondition|priorFailureCount
KS.PROVIDER.CAPABILITY_UNSUPPORTED|DEBUG|provider|providerKind,capabilityId|
KS.PROVIDER.READ_FAILED|WARNING|provider|providerKind,fieldId,reasonCode|durationMs,fallbackId
KS.PROVIDER.STALE_OBJECT|WARNING|provider|providerKind,fieldId|reasonCode
KS.PROVIDER.VALUE_REJECTED|WARNING|provider|providerKind,fieldId,reasonCode|observedShape,configuredLimit
KS.PROVIDER.CACHE_BUILD_FAILED|WARNING|provider|providerKind,reasonCode|requestedFieldCount
KS.PROVIDER.FALLBACK_APPLIED|WARNING|provider|providerKind,fallbackId,reasonCode|lostCapabilityCount
KS.CUSTOM_UIA.POLL_STARTED|DEBUG|customUia|pollKind,scope|candidateLimit,elapsedLimitMs
KS.CUSTOM_UIA.POLL_COMPLETED|INFO|customUia|pollKind,candidateCount|valueReadCount,elapsedMs
KS.CUSTOM_UIA.POLL_TRUNCATED|WARNING|customUia|pollKind,limitType,configuredLimit|actualCount,elapsedMs
KS.CUSTOM_UIA.REGISTRATION_SUCCEEDED|INFO|customUia|stableKey,declaredType|runtimeId,registrationOrdinal
KS.CUSTOM_UIA.REGISTRATION_FAILED|ERROR|customUia|stableKey,reasonCode|hresultCode,registrationOrdinal
KS.CUSTOM_UIA.CONFIG_RESTART_REQUIRED|WARNING|customUia|changedEntryCount|settingsRevision
KS.CUSTOM_UIA.VALUE_REJECTED|WARNING|customUia|stableKey,reasonCode,observedShape|configuredLimit
KS.CUSTOM_UIA.PATTERN_METADATA_ONLY|INFO|customUia|potentialId,scope|programmaticNamePresent
KS.PROJECTION.RAW_UIA_REQUESTED|INFO|projection|targetKind,requestedMode|
KS.PROJECTION.RAW_UIA_APPLIED|INFO|projection|targetKind,projectionMethod|providerPidMatch
KS.PROJECTION.RAW_UIA_REJECTED|WARNING|projection|targetKind,reasonCode|providerPidMatch
KS.PROJECTION.RAW_UIA_FALLBACK|WARNING|projection|targetKind,reasonCode,fallbackProvider|
KS.PROJECTION.TARGET_AMBIGUOUS|WARNING|projection|targetKind,conflictCount,reasonCode|candidateCount
KS.PRIVACY.REDACTION_APPLIED|DEBUG|privacy|sinkId,classification,transform|omittedFieldCount
KS.PRIVACY.REDACTION_DISABLED|WARNING|privacy|policyRevision,settingsRevision|
KS.PRIVACY.PROTECTION_INDETERMINATE|WARNING|privacy|sourceId,conservativeClass|evidenceCount
KS.PRIVACY.SINK_VALUE_BLOCKED|WARNING|privacy|sinkId,classification,reasonCode|blockedFieldCount
KS.PRIVACY.SCREENSHOT_UNREDACTED|WARNING|privacy|screenshotPolicy,warningId|screenshotStatus
KS.DIFF.STARTED|INFO|diff|baselineStatus,targetAdmission|
KS.DIFF.BASELINE_MISSING|INFO|diff|targetAdmission|
KS.DIFF.TARGET_REJECTED|WARNING|diff|reasonCode,conflictCount|candidateCount
KS.DIFF.NO_CHANGE|INFO|diff|comparedNodeCount|elapsedMs
KS.DIFF.COMPLETED|INFO|diff|addedCount,removedCount,modifiedCount,screenshotStatus|elapsedMs
KS.DIFF.FAILED|ERROR|diff|phase,reasonCode|elapsedMs
KS.SCREENSHOT.STARTED|DEBUG|screenshot|captureMethod,geometrySource|requestedWidth,requestedHeight
KS.SCREENSHOT.COMPLETED|INFO|screenshot|captureMethod,clippedWidth,clippedHeight|durationMs
KS.SCREENSHOT.BOUNDS_REJECTED|WARNING|screenshot|reasonCode,geometrySource|requestedWidth,requestedHeight
KS.SCREENSHOT.FAILED|ERROR|screenshot|phase,reasonCode|durationMs
KS.PERSISTENCE.STAGING_CREATED|DEBUG|persistence|artifactSet,ownershipNoncePresent|expectedArtifactCount
KS.PERSISTENCE.ARTIFACT_WRITTEN|DEBUG|persistence|artifactKind,byteCount|durationMs
KS.PERSISTENCE.VALIDATION_FAILED|ERROR|persistence|artifactKind,reasonCode|failedRuleCount
KS.PERSISTENCE.COMMIT_STARTED|DEBUG|persistence|artifactSet,secureState|
KS.PERSISTENCE.COMMIT_COMPLETED|INFO|persistence|artifactSet,committedArtifactCount|durationMs
KS.PERSISTENCE.COMMIT_FAILED|ERROR|persistence|phase,reasonCode|collisionDetected
KS.PERSISTENCE.DISCOVERY_FAILED|WARNING|persistence|reasonCode,entryClass|inspectedCount
KS.CLEANUP.STARTED|INFO|cleanup|cleanupClass,requestedCount|
KS.CLEANUP.ITEM_REMOVED|INFO|cleanup|cleanupClass,itemKind|ageMs
KS.CLEANUP.ITEM_SKIPPED_REPARSE|WARNING|cleanup|cleanupClass,reasonCode,reparseClass|
KS.CLEANUP.COMPLETED|INFO|cleanup|cleanupClass,removedCount,skippedCount|failedCount
KS.CLEANUP.FAILED|ERROR|cleanup|cleanupClass,reasonCode|removedCount,skippedCount
KS.INSPECTOR.OPENED|INFO|inspector|providerMode,targetKind|existingFrameReused
KS.INSPECTOR.RETARGETED|INFO|inspector|providerMode,targetKind|priorGeneration
KS.INSPECTOR.OFFLINE_LOAD_STARTED|INFO|inspector|expectedKind,byteCount|byteLimit
KS.INSPECTOR.OFFLINE_LOAD_REJECTED|WARNING|inspector|reasonCode,observedKind|byteCount,schemaMajor
KS.INSPECTOR.NODE_FETCH_FAILED|WARNING|inspector|providerMode,fetchKind,reasonCode|childOrdinal
KS.INSPECTOR.CLOSED|INFO|inspector|closeReason,cancelledCallbackCount|failedReleaseCount
KS.INSPECTOR.STALE_RESULT_REJECTED|DEBUG|inspector|resultKind,mismatchScope|resultGeneration,currentGeneration
KS.EVENT.MONITOR_STARTED|INFO|event|scopeKind,rawEventsEnabled|retainedLimit,pendingLimit
KS.EVENT.MONITOR_STOPPED|INFO|event|stopReason,retainedCount|pendingDropCount,rowDropCount
KS.EVENT.BROAD_SCOPE_ENABLED|WARNING|event|scopeKind,warningId|
KS.EVENT.PENDING_DROPPED|WARNING|event|droppedCount,pendingLimit|eventTypeClass
KS.EVENT.ROW_DROPPED|WARNING|event|droppedCount,retainedLimit|
KS.EVENT.EXPORT_COMPLETED|INFO|event|exportedCount,pendingDropCount,rowDropCount|truncationState
KS.EVENT.EXPORT_FAILED|ERROR|event|phase,reasonCode|exportedCount
KS.EVENT.SOURCE_UNSUBSCRIBE_FAILED|ERROR|event|sourceKind,reasonCode|remainingSourceCount
KS.SOUND.PLAY_REQUESTED|DEBUG|sound|transitionId,motifCount|soundGeneration
KS.SOUND.PLAY_SUPPRESSED|DEBUG|sound|transitionId,suppressionReason|soundGeneration
KS.SOUND.ASSET_MISSING|WARNING|sound|assetId,transitionId|packageVersion
KS.SOUND.PLAY_FAILED|WARNING|sound|transitionId,reasonCode|assetId
KS.SOUND.STALE_REQUEST_REJECTED|DEBUG|sound|transitionId,mismatchScope|requestGeneration,currentGeneration
KS.SETTINGS.VALIDATION_REJECTED|WARNING|settings|settingId,reasonCode|normalizedValueApplied
KS.SETTINGS.GLOBAL_CHANGED|INFO|settings|settingsRevision,policyRevision|changedSettingCount
KS.SETTINGS.CUSTOM_UIA_RESTART_REQUIRED|WARNING|settings|changedEntryCount|settingsRevision
KS.PACKAGE.ASSET_MISSING|ERROR|package|assetKind,assetId|packageVersion
KS.PACKAGE.MANIFEST_INVALID|CRITICAL|package|reasonCode,manifestField|packageVersion
KS.PACKAGE.ARCHIVE_INVALID|CRITICAL|package|reasonCode,invalidEntryCount|packageVersion
KS.PACKAGE.RUNTIME_SMOKE_FAILED|ERROR|package|smokeStep,reasonCode,nvdaVersion|windowsBuild
"""


def _messageFor(code: str) -> str:
	if code == "KS.CAPTURE.COMPLETED_PARTIAL_SCREENSHOT":
		return "Capture completed with screenshot failure"
	domain, event = code.split(".")[1:]
	words = event.lower().split("_")
	return f"{domain.title()} {' '.join(words)}"


def _names(value: str) -> tuple[str, ...]:
	return () if not value else tuple(value.split(","))


def _fieldType(name: str) -> str:
	if name in _BOOLEAN_FIELDS:
		return "boolean"
	if name in _INTEGER_FIELDS or name.endswith(_INTEGER_SUFFIXES):
		return "integer"
	return "string"


def _buildRegistry() -> tuple[EventDefinition, ...]:
	result: list[EventDefinition] = []
	for row in _REGISTRY_DATA.splitlines():
		code, level, component, required, optional = row.split("|")
		requiredFields = _names(required)
		optionalFields = _names(optional)
		result.append(
			EventDefinition(
				code=code,
				defaultSeverity=Severity[level],
				component=component,
				message=_messageFor(code),
				requiredFields=requiredFields,
				optionalFields=optionalFields,
				fieldTypes=tuple((name, _fieldType(name)) for name in requiredFields + optionalFields),
			),
		)
	if len(result) != 104 or len({entry.code for entry in result}) != len(result):
		raise RuntimeError("event registry is incomplete or contains duplicate codes")
	return tuple(result)


EVENT_REGISTRY = _buildRegistry()
_EVENT_BY_CODE = {entry.code: entry for entry in EVENT_REGISTRY}


def validateEventFields(code: str, names: tuple[str, ...]) -> None:
	definition = _EVENT_BY_CODE.get(code)
	if definition is None:
		raise ValueError("unknown event code")
	actual = frozenset(names)
	if len(actual) != len(names):
		raise ValueError("record fields must be unique")
	required = frozenset(definition.requiredFields)
	if not required.issubset(actual):
		raise ValueError("record is missing required event fields")
	if not actual.issubset(required | frozenset(definition.optionalFields)):
		raise ValueError("record contains an unregistered event field")


def _validateEventValues(
	definition: EventDefinition,
	fields: tuple[tuple[str, LogScalar], ...],
) -> None:
	kinds = dict(definition.fieldTypes)
	for name, value in fields:
		kind = kinds[name]
		if kind == "boolean":
			valid = isinstance(value, bool)
		elif kind == "integer":
			valid = isinstance(value, int) and not isinstance(value, bool) and value >= 0
		else:
			valid = isinstance(value, str)
		if not valid:
			raise ValueError(f"event field {name} does not match its registered type")


def _validateUuid(value: str, label: str) -> str:
	if not isinstance(cast(object, value), str):
		raise TypeError(f"{label} must be UUID text")
	if value != value.lower():
		raise ValueError(f"{label} must use lowercase canonical UUID text")
	try:
		parsed = UUID(value)
	except ValueError as error:
		raise ValueError(f"{label} must be a UUID") from error
	if str(parsed) != value:
		raise ValueError(f"{label} must use canonical UUID text")
	return value


def _validateUnsigned(value: int | None, label: str, *, positive: bool = False) -> None:
	if value is None:
		return
	if isinstance(value, bool):
		raise TypeError(f"{label} must be an integer")
	minimum = 1 if positive else 0
	if not minimum <= value <= _UINT64_MAX:
		raise ValueError(f"{label} is outside its unsigned range")


def _normalizeScalar(value: object) -> LogScalar:
	if isinstance(value, str):
		return _validateText(value, "log field")
	if isinstance(value, bool) or isinstance(value, int):
		return value
	raise ValueError("log fields accept only immutable string, integer, or boolean values")


_SAFE_EXCEPTION_DETAILS = {
	("OperationFailure", "operationFailed"): ("The operation could not be completed.", ""),
	("OperationFailure", "operationCancelled"): ("The operation was cancelled.", ""),
	("TimeoutFailure", "operationTimedOut"): ("The operation timed out.", ""),
	("ValidationFailure", "invalidInput"): ("The operation input was invalid.", ""),
}


@dataclass(frozen=True, slots=True)
class SafeException:
	type: str
	message: str
	code: str
	stack: str

	def __post_init__(self) -> None:
		expected = _SAFE_EXCEPTION_DETAILS.get((self.type, self.code))
		if expected is None or (self.message, self.stack) != expected:
			raise ValueError("safe exceptions must use a registered static diagnostic")


@dataclass(frozen=True, slots=True)
class LogicalRecord:
	sequence: int
	timestamp: datetime
	severity: Severity
	code: str
	component: str
	message: str
	sessionCorrelationId: str
	operationId: str | None
	jobId: str | None
	windowGeneration: int | None
	inspectorGeneration: int | None
	monitorGeneration: int | None
	nvdaPid: int
	threadIdentity: str
	fields: tuple[tuple[str, LogScalar], ...]
	exception: SafeException | None

	def __post_init__(self) -> None:
		_validateUnsigned(self.sequence, "sequence", positive=True)
		if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
			raise ValueError("log timestamps must be aware instants")
		definition = _EVENT_BY_CODE.get(self.code)
		if definition is None:
			raise ValueError("unknown event code")
		if (
			self.severity is not definition.defaultSeverity
			or self.component != definition.component
			or self.message != definition.message
		):
			raise ValueError("record identity must match its registered event")
		_ = _validateUuid(self.sessionCorrelationId, "sessionCorrelationId")
		for label, value in (("operationId", self.operationId), ("jobId", self.jobId)):
			if value is not None:
				_ = _validateUuid(value, label)
		for label, value in (
			("windowGeneration", self.windowGeneration),
			("inspectorGeneration", self.inspectorGeneration),
			("monitorGeneration", self.monitorGeneration),
		):
			_validateUnsigned(value, label)
		_validateUnsigned(self.nvdaPid, "nvdaPid", positive=True)
		if self.threadIdentity not in _THREAD_IDENTITIES and not _WORKER_PATTERN.fullmatch(
			self.threadIdentity,
		):
			raise ValueError("thread identity is not a closed safe value")
		names = tuple(name for name, _value in self.fields)
		if names != tuple(sorted(names)) or len(names) != len(set(names)):
			raise ValueError("record fields must be unique and in ordinal order")
		validateEventFields(self.code, names)
		_validateEventValues(definition, self.fields)
		_validateSessionHeader(self)


class SequenceAllocator:
	__slots__ = ("_current", "_lock", "_maximum")

	def __init__(self, *, start: int = 1, maximum: int = _UINT64_MAX) -> None:
		super().__init__()
		_validateUnsigned(start, "sequence start", positive=True)
		_validateUnsigned(maximum, "sequence maximum", positive=True)
		if start > maximum:
			raise ValueError("sequence start cannot exceed its maximum")
		self._current = start
		self._maximum = maximum
		self._lock = threading.Lock()

	def next(self) -> int:
		with self._lock:
			if self._current > self._maximum:
				raise OverflowError("log sequence is exhausted")
			value = self._current
			self._current += 1
			return value


def createRecord(
	*,
	sequence: int,
	timestamp: datetime,
	code: str,
	sessionCorrelationId: str,
	nvdaPid: int,
	threadIdentity: str,
	fields: tuple[tuple[str, LogScalar], ...] = (),
	exception: SafeException | None = None,
	operationId: str | None = None,
	jobId: str | None = None,
	windowGeneration: int | None = None,
	inspectorGeneration: int | None = None,
	monitorGeneration: int | None = None,
) -> LogicalRecord:
	definition = _EVENT_BY_CODE.get(code)
	if definition is None:
		raise ValueError("unknown event code")
	normalizedFields = tuple(
		sorted(
			(
				(_validateText(name, "log field name", maximum=128), _normalizeScalar(value))
				for name, value in fields
			),
			key=lambda item: item[0],
		),
	)
	return LogicalRecord(
		sequence=sequence,
		timestamp=timestamp,
		severity=definition.defaultSeverity,
		code=definition.code,
		component=definition.component,
		message=definition.message,
		sessionCorrelationId=sessionCorrelationId,
		operationId=operationId,
		jobId=jobId,
		windowGeneration=windowGeneration,
		inspectorGeneration=inspectorGeneration,
		monitorGeneration=monitorGeneration,
		nvdaPid=nvdaPid,
		threadIdentity=threadIdentity,
		fields=normalizedFields,
		exception=exception,
	)


def _validateSessionHeader(record: LogicalRecord) -> None:
	if record.code != "KS.LIFECYCLE.SESSION_STARTED":
		return
	fields = dict(record.fields)
	for field, accepted in (
		("boundaryReason", frozenset(("open", "settingsChange"))),
		("processArchitecture", frozenset(("x86", "x64", "arm64"))),
	):
		if fields[field] not in accepted:
			raise ValueError(f"session header {field} is outside its closed values")
	if fields["configurationScope"] != "global":
		raise ValueError("session header configuration scope must be global")
	for field in ("settingsRevision", "policyRevision", "schemaMajor"):
		value = fields[field]
		if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
			raise ValueError(f"session header {field} must be a positive integer")
	if not isinstance(fields["redactionEnabled"], bool):
		raise ValueError("session header redaction state must be boolean")
	try:
		instant = datetime.fromisoformat(cast(str, fields["sessionStartTime"]))
	except (TypeError, ValueError) as error:
		raise ValueError("session header start time must be an ISO timestamp") from error
	if instant.tzinfo is None or instant.utcoffset() is None:
		raise ValueError("session header start time must be aware")


def _jsonString(value: str) -> str:
	rendered = json.dumps(value, ensure_ascii=False, allow_nan=False)
	for character in ("\x7f", "\u2028", "\u2029", *_BIDI_CONTROLS):
		rendered = rendered.replace(character, f"\\u{ord(character):04X}")
	return rendered


def _textScalar(value: LogScalar) -> str:
	if isinstance(value, str):
		return _jsonString(value)
	if isinstance(value, bool):
		return '"true"' if value else '"false"'
	return f'"{value}"'


def _suffixes(record: LogicalRecord) -> tuple[tuple[str, LogScalar], ...]:
	values: list[tuple[str, LogScalar]] = [("sessionCorrelationId", record.sessionCorrelationId)]
	for name, value in (
		("operationId", record.operationId),
		("jobId", record.jobId),
		("windowGeneration", record.windowGeneration),
		("inspectorGeneration", record.inspectorGeneration),
		("monitorGeneration", record.monitorGeneration),
	):
		if value is not None:
			values.append((name, value))
	values.extend((("nvdaPid", record.nvdaPid), ("threadIdentity", record.threadIdentity)))
	values.extend(record.fields)
	if record.exception is not None:
		values.extend(
			(
				("exception.type", record.exception.type),
				("exception.message", record.exception.message),
				("exception.code", record.exception.code),
				("exception.stack", record.exception.stack),
			),
		)
	return tuple(values)


def renderNvdaMessage(record: LogicalRecord) -> str:
	message = (
		f"{record.code} {record.message} seq={record.sequence} component={_jsonString(record.component)}"
	)
	for name, value in _suffixes(record):
		suffix = f" {name}={_textScalar(value)}"
		if len((message + suffix).encode("utf-8")) > NVDA_MESSAGE_MAXIMUM:
			truncated = ' fieldsTruncated="true"'
			if len((message + truncated).encode("utf-8")) <= NVDA_MESSAGE_MAXIMUM:
				message += truncated
			break
		message += suffix
	return message
