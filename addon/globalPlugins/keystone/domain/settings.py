from __future__ import annotations

from dataclasses import dataclass, fields, replace
from enum import StrEnum
from typing import cast

from ..capability import PlainValue


class SettingId(StrEnum):
	MAXIMUM_NODES = "maximumNodes"
	MAXIMUM_DEPTH = "maximumDepth"
	CAPTURE_TIME_SECONDS = "captureTimeSeconds"
	MAXIMUM_TEXT_CHARACTERS = "maximumTextCharacters"
	PROGRESS_INTERVAL_SECONDS = "progressIntervalSeconds"
	JSON_FULL_TAB_INDENTATION = "jsonFullTabIndentation"
	EVENT_DETAIL_CHARACTERS = "eventDetailCharacters"
	EVENT_ROWS = "eventRows"
	OFFLINE_FILE_MEGABYTES = "offlineFileMegabytes"
	PROPERTY_INTERVAL_MILLISECONDS = "propertyIntervalMilliseconds"
	SWAP_PROPERTY_ACTIONS = "swapPropertyActions"
	REDACT_PROTECTED_TEXT = "redactProtectedText"
	FORCE_RAW_UIA = "forceRawUia"
	SOUNDS_ENABLED = "soundsEnabled"


class SettingKind(StrEnum):
	INTEGER = "integer"
	BOOLEAN = "boolean"
	CHOICE = "choice"
	HELD_CLOSED_BOOLEAN = "heldClosedBoolean"


@dataclass(frozen=True, slots=True)
class SettingDefinition:
	settingId: SettingId
	attributeName: str
	kind: SettingKind
	default: PlainValue
	minimum: int | None = None
	maximum: int | None = None
	choices: tuple[str, ...] = ()

	def __post_init__(self) -> None:
		if self.kind is SettingKind.INTEGER:
			if (
				not isinstance(self.default, int)
				or isinstance(self.default, bool)
				or self.minimum is None
				or self.maximum is None
				or not self.minimum <= self.default <= self.maximum
				or self.choices
			):
				raise ValueError("integer setting definition is inconsistent")
		elif self.kind in (SettingKind.BOOLEAN, SettingKind.HELD_CLOSED_BOOLEAN):
			if (
				not isinstance(self.default, bool)
				or self.minimum is not None
				or self.maximum is not None
				or self.choices
			):
				raise ValueError("boolean setting definition is inconsistent")
		elif (
			not isinstance(self.default, str)
			or self.default not in self.choices
			or self.minimum is not None
			or self.maximum is not None
		):
			raise ValueError("choice setting definition is inconsistent")


SETTING_DEFINITIONS = (
	SettingDefinition(SettingId.MAXIMUM_NODES, "maximumNodes", SettingKind.INTEGER, 6_000, 100, 1_000_000),
	SettingDefinition(SettingId.MAXIMUM_DEPTH, "maximumDepth", SettingKind.INTEGER, 40, 1, 1_000),
	SettingDefinition(
		SettingId.CAPTURE_TIME_SECONDS,
		"captureTimeSeconds",
		SettingKind.INTEGER,
		45,
		1,
		3_600,
	),
	SettingDefinition(
		SettingId.MAXIMUM_TEXT_CHARACTERS,
		"maximumTextCharacters",
		SettingKind.INTEGER,
		20_000,
		100,
		100_000_000,
	),
	SettingDefinition(
		SettingId.PROGRESS_INTERVAL_SECONDS,
		"progressIntervalSeconds",
		SettingKind.INTEGER,
		3,
		1,
		30,
	),
	SettingDefinition(
		SettingId.JSON_FULL_TAB_INDENTATION,
		"jsonFullTabIndentation",
		SettingKind.BOOLEAN,
		False,
	),
	SettingDefinition(
		SettingId.EVENT_DETAIL_CHARACTERS,
		"eventDetailCharacters",
		SettingKind.INTEGER,
		100,
		0,
		1_000_000,
	),
	SettingDefinition(SettingId.EVENT_ROWS, "eventRows", SettingKind.INTEGER, 2_000, 0, 1_000_000),
	SettingDefinition(
		SettingId.OFFLINE_FILE_MEGABYTES,
		"offlineFileMegabytes",
		SettingKind.INTEGER,
		100,
		0,
		100_000,
	),
	SettingDefinition(
		SettingId.PROPERTY_INTERVAL_MILLISECONDS,
		"propertyIntervalMilliseconds",
		SettingKind.INTEGER,
		1_000,
		250,
		5_000,
	),
	SettingDefinition(SettingId.SWAP_PROPERTY_ACTIONS, "swapPropertyActions", SettingKind.BOOLEAN, False),
	SettingDefinition(SettingId.REDACT_PROTECTED_TEXT, "redactProtectedText", SettingKind.BOOLEAN, False),
	SettingDefinition(
		SettingId.FORCE_RAW_UIA,
		"forceRawUia",
		SettingKind.HELD_CLOSED_BOOLEAN,
		False,
	),
	SettingDefinition(SettingId.SOUNDS_ENABLED, "soundsEnabled", SettingKind.BOOLEAN, True),
)
INTEGER_SETTING_DEFINITIONS = tuple(
	definition for definition in SETTING_DEFINITIONS if definition.kind is SettingKind.INTEGER
)
_DEFINITION_BY_ID = {definition.settingId: definition for definition in SETTING_DEFINITIONS}

_FIXED_CAPTURE_LIMITS = (
	("visibleUiaRanges", 50),
	("selectionRanges", 50),
	("uiaElementArrayEntries", 200),
	("ia2Hyperlinks", 200),
	("focusMatchNodes", 150),
	("focusMatchDepth", 40),
	("workSliceMilliseconds", 150),
	("yieldMilliseconds", 10),
)


@dataclass(frozen=True, slots=True)
class SettingsCandidate:
	startingRevision: int
	maximumNodes: object
	maximumDepth: object
	captureTimeSeconds: object
	maximumTextCharacters: object
	progressIntervalSeconds: object
	jsonFullTabIndentation: object
	eventDetailCharacters: object
	eventRows: object
	offlineFileMegabytes: object
	propertyIntervalMilliseconds: object
	swapPropertyActions: object
	redactProtectedText: object
	forceRawUia: object
	soundsEnabled: object

	def value(self, settingId: SettingId) -> object:
		return getattr(self, _DEFINITION_BY_ID[settingId].attributeName)

	def withValue(self, settingId: SettingId, value: object) -> SettingsCandidate:
		return replace(self, **{_DEFINITION_BY_ID[settingId].attributeName: value})

	def namedValues(self) -> tuple[tuple[str, PlainValue], ...]:
		validation = validateCandidate(self)
		if not validation.isValid:
			raise ValueError("invalid settings candidate has no writable value representation")
		return tuple(
			(definition.settingId.value, cast(PlainValue, self.value(definition.settingId)))
			for definition in SETTING_DEFINITIONS
		)

	def toSnapshot(self, settingsRevision: int) -> SettingsSnapshot:
		validation = validateCandidate(self)
		if not validation.isValid:
			raise ValueError("invalid settings candidate cannot become a snapshot")
		return SettingsSnapshot(
			settingsRevision=settingsRevision,
			maximumNodes=cast(int, self.maximumNodes),
			maximumDepth=cast(int, self.maximumDepth),
			captureTimeSeconds=cast(int, self.captureTimeSeconds),
			maximumTextCharacters=cast(int, self.maximumTextCharacters),
			progressIntervalSeconds=cast(int, self.progressIntervalSeconds),
			jsonFullTabIndentation=cast(bool, self.jsonFullTabIndentation),
			eventDetailCharacters=cast(int, self.eventDetailCharacters),
			eventRows=cast(int, self.eventRows),
			offlineFileMegabytes=cast(int, self.offlineFileMegabytes),
			propertyIntervalMilliseconds=cast(int, self.propertyIntervalMilliseconds),
			swapPropertyActions=cast(bool, self.swapPropertyActions),
			redactProtectedText=cast(bool, self.redactProtectedText),
			forceRawUia=cast(bool, self.forceRawUia),
			soundsEnabled=cast(bool, self.soundsEnabled),
		)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
	settingId: SettingId | str
	reasonCode: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
	candidate: SettingsCandidate
	issues: tuple[ValidationIssue, ...]

	@property
	def isValid(self) -> bool:
		return not self.issues

	@property
	def firstInvalidSettingId(self) -> SettingId | str | None:
		return None if not self.issues else self.issues[0].settingId


def _reason(definition: SettingDefinition, value: object) -> str | None:
	if definition.kind is SettingKind.INTEGER:
		if not isinstance(value, int) or isinstance(value, bool):
			return "integerRequired"
		assert definition.minimum is not None
		assert definition.maximum is not None
		if not definition.minimum <= value <= definition.maximum:
			return "outsideAllowedRange"
	elif definition.kind is SettingKind.BOOLEAN:
		if not isinstance(value, bool):
			return "booleanRequired"
	elif definition.kind is SettingKind.HELD_CLOSED_BOOLEAN:
		if not isinstance(value, bool):
			return "booleanRequired"
	elif not isinstance(value, str) or value not in definition.choices:
		return "choiceRequired"
	return None


def _isPositiveInteger(value: object) -> bool:
	return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validateCandidate(candidate: SettingsCandidate) -> ValidationResult:
	issues: list[ValidationIssue] = []
	if not _isPositiveInteger(candidate.startingRevision):
		issues.append(ValidationIssue("settingsRevision", "positiveRevisionRequired"))
	for definition in SETTING_DEFINITIONS:
		reason = _reason(definition, candidate.value(definition.settingId))
		if reason is not None:
			issues.append(ValidationIssue(definition.settingId, reason))
	return ValidationResult(candidate, tuple(issues))


@dataclass(frozen=True, slots=True)
class SettingsSnapshot:
	settingsRevision: int
	maximumNodes: int
	maximumDepth: int
	captureTimeSeconds: int
	maximumTextCharacters: int
	progressIntervalSeconds: int
	jsonFullTabIndentation: bool
	eventDetailCharacters: int
	eventRows: int
	offlineFileMegabytes: int
	propertyIntervalMilliseconds: int
	swapPropertyActions: bool
	redactProtectedText: bool
	forceRawUia: bool
	soundsEnabled: bool

	def __post_init__(self) -> None:
		validation = validateCandidate(self.asCandidate())
		if not validation.isValid:
			raise ValueError("settings snapshot must contain a complete valid global configuration")

	@classmethod
	def defaults(cls, *, settingsRevision: int) -> SettingsSnapshot:
		values = {definition.attributeName: definition.default for definition in SETTING_DEFINITIONS}
		return cls(settingsRevision=settingsRevision, **values)  # type: ignore[arg-type]

	@staticmethod
	def fixedCaptureLimits() -> tuple[tuple[str, int], ...]:
		return _FIXED_CAPTURE_LIMITS

	def asCandidate(self) -> SettingsCandidate:
		values = {
			field.name: getattr(self, field.name)
			for field in fields(self)
			if field.name != "settingsRevision"
		}
		return SettingsCandidate(startingRevision=self.settingsRevision, **values)


def restoreDefaultCandidate(current: SettingsSnapshot) -> SettingsCandidate:
	return SettingsSnapshot.defaults(settingsRevision=current.settingsRevision).asCandidate()


class SaveStatus(StrEnum):
	UPDATED = "updated"
	REJECTED = "rejected"
	FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SaveResult:
	status: SaveStatus
	snapshot: SettingsSnapshot
	issues: tuple[ValidationIssue, ...] = ()
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status is SaveStatus.UPDATED and (self.issues or self.errorCode is not None):
			raise ValueError("updated settings result cannot carry issues or an error")
		if self.status is SaveStatus.REJECTED and (not self.issues or self.errorCode is not None):
			raise ValueError("rejected settings result requires issues only")
		if self.status is SaveStatus.FAILED and (self.issues or self.errorCode is None):
			raise ValueError("failed settings result requires a safe error code only")
