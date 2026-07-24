from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast
import unicodedata

from ..capability import PlainValue, requireOpaqueId, requirePlainValue


class PrivacyClass(StrEnum):
	PUBLIC = "public"
	UNKNOWN = "unknown"
	SENSITIVE = "sensitive"
	PROTECTED = "protected"


_PRIVACY_PRECEDENCE = {
	PrivacyClass.PUBLIC: 0,
	PrivacyClass.UNKNOWN: 1,
	PrivacyClass.SENSITIVE: 2,
	PrivacyClass.PROTECTED: 3,
}


class FieldGroup(StrEnum):
	NODE = "node"
	TEXT = "text"
	CUSTOM = "custom"
	RELATION = "relation"
	DIAGNOSTIC = "diagnostic"
	EVENT = "event"
	PROCESS = "process"
	SCREENSHOT = "screenshot"
	BASELINE = "baseline"
	SUMMARY = "summary"
	GUI = "gui"
	COPY = "copy"
	EVENT_EXPORT = "eventExport"
	LOG = "log"


class SinkId(StrEnum):
	NODE = "node"
	TEXT = "text"
	CUSTOM = "custom"
	RELATION = "relation"
	DIAGNOSTIC = "diagnostic"
	EVENT = "event"
	PROCESS = "process"
	SCREENSHOT = "screenshot"
	BASELINE = "baseline"
	SUMMARY = "summary"
	GUI = "gui"
	COPY_JSON = "copyJson"
	COPY_TEXT = "copyText"
	COPY_MARKDOWN = "copyMarkdown"
	EVENT_EXPORT = "eventExport"
	NVDA_LOG = "nvdaLog"


FIELD_GROUPS = tuple(FieldGroup)
SINKS = tuple(SinkId)

UNREDACTED_SCREENSHOT_WARNING = (
	"Screenshot pixels are unredacted visual evidence and may contain sensitive visible content."
)


@dataclass(frozen=True, slots=True)
class ProtectionEvidence:
	protected: bool | None = None

	def __post_init__(self) -> None:
		rawValue = cast(object, self.protected)
		if rawValue is not None and type(rawValue) is not bool:
			raise TypeError("protection evidence must be boolean or indeterminate")

	@classmethod
	def allClear(cls) -> ProtectionEvidence:
		return cls(False)


def classify(metadataClass: PrivacyClass, protection: ProtectionEvidence) -> PrivacyClass:
	if protection.protected is True:
		return PrivacyClass.PROTECTED
	if protection.protected is None:
		return max((metadataClass, PrivacyClass.UNKNOWN), key=_PRIVACY_PRECEDENCE.__getitem__)
	return metadataClass


@dataclass(frozen=True, slots=True)
class PrivacyPolicy:
	policyRevision: int
	settingsRevision: int
	redactProtectedText: bool

	def __post_init__(self) -> None:
		for value in (self.policyRevision, self.settingsRevision):
			if type(value) is not int or value <= 0:
				raise ValueError("privacy and settings revisions must be positive integers")
		if type(cast(object, self.redactProtectedText)) is not bool:
			raise TypeError("redaction state must be boolean")


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
	policyRevision: int
	settingsRevision: int
	redactionEnabled: bool

	def __post_init__(self) -> None:
		for value in (self.policyRevision, self.settingsRevision):
			if type(value) is not int or value <= 0:
				raise ValueError("policy provenance revisions must be positive integers")
		if type(cast(object, self.redactionEnabled)) is not bool:
			raise TypeError("policy provenance redaction state must be boolean")

	@classmethod
	def fromPolicy(cls, policy: PrivacyPolicy) -> PolicyProvenance:
		return cls(
			policy.policyRevision,
			policy.settingsRevision,
			policy.redactProtectedText,
		)


def _normalizePlainValue(value: PlainValue) -> PlainValue:
	if isinstance(value, str):
		return unicodedata.normalize("NFC", value)
	if isinstance(value, tuple):
		return tuple(_normalizePlainValue(item) for item in cast(tuple[PlainValue, ...], value))
	return value


@dataclass(frozen=True, slots=True)
class ObservedValue:
	fieldGroup: FieldGroup
	value: PlainValue
	privacyClass: PrivacyClass
	protection: ProtectionEvidence
	sourceId: str

	def __post_init__(self) -> None:
		requirePlainValue(self.value, "observed value")
		object.__setattr__(self, "value", _normalizePlainValue(self.value))
		requireOpaqueId(self.sourceId, "sourceId")

	@property
	def effectiveClass(self) -> PrivacyClass:
		return classify(self.privacyClass, self.protection)


class TransformAction(StrEnum):
	RETAIN = "retain"
	REDACT = "redact"
	OMIT = "omit"
	RETAIN_UNREDACTED = "retainUnredacted"


@dataclass(frozen=True, slots=True)
class TransformedValue:
	fieldGroup: FieldGroup
	sinkId: SinkId
	sourceId: str
	originalClass: PrivacyClass
	effectiveClass: PrivacyClass
	action: TransformAction
	value: PlainValue
	provenance: PolicyProvenance
	warning: str | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.sourceId, "sourceId")
		requirePlainValue(self.value, "transformed value")
		if self.action in (TransformAction.REDACT, TransformAction.OMIT) and self.value is not None:
			raise ValueError("redacted and omitted transforms cannot retain source content")
		if self.action is TransformAction.RETAIN_UNREDACTED:
			if self.fieldGroup is not FieldGroup.SCREENSHOT or self.sinkId is not SinkId.SCREENSHOT:
				raise ValueError("only screenshot evidence may use the unredacted visual transform")
			if self.warning != UNREDACTED_SCREENSHOT_WARNING:
				raise ValueError("unredacted screenshot evidence requires the fixed warning")
		elif self.warning is not None:
			raise ValueError("only screenshot evidence carries the visual warning")


def transformValue(
	source: ObservedValue,
	sinkId: SinkId,
	policy: PrivacyPolicy,
) -> TransformedValue:
	"""Apply the one redaction decision every sink shares.

	Redaction is a single opt-in preference: with it off, protected and sensitive values reach every
	evidence sink -- the Inspector, Events, captures, exports, custom UIA, diffs, and the NVDA log --
	because a debugging session that silently hides the value under investigation is worse than one
	that shows it. With it on, every one of those sinks withholds the same values. The exception is
	structural rather than privacy-driven: screenshot pixels cannot be selectively redacted at
	all and carry an explicit warning instead.
	"""

	effectiveClass = source.effectiveClass
	action: TransformAction
	value: PlainValue
	warning: str | None = None
	if (source.fieldGroup is FieldGroup.SCREENSHOT) != (sinkId is SinkId.SCREENSHOT):
		action = TransformAction.OMIT
		value = None
	elif source.fieldGroup is FieldGroup.SCREENSHOT:
		action = TransformAction.RETAIN_UNREDACTED
		value = source.value
		warning = UNREDACTED_SCREENSHOT_WARNING
	elif policy.redactProtectedText and effectiveClass is not PrivacyClass.PUBLIC:
		action = TransformAction.REDACT
		value = None
	else:
		action = TransformAction.RETAIN
		value = source.value
	return TransformedValue(
		fieldGroup=source.fieldGroup,
		sinkId=sinkId,
		sourceId=source.sourceId,
		originalClass=source.privacyClass,
		effectiveClass=effectiveClass,
		action=action,
		value=value,
		provenance=PolicyProvenance.fromPolicy(policy),
		warning=warning,
	)
