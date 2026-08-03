"""Live and offline Inspector sources behind one shared read-only protocol.

Both backends present ``ports.inspector.InspectorSource`` so the application service and native
workspace never learn which one answered:

* :class:`OfflineInspectorSource` adapts a stored ``SnapshotView`` capture bundle. Its evidence was
  privacy-transformed at capture time, so rendering a stored envelope is already safe. It maps
  structural parent/child keys to the ancestor-only spine and lazy child enumeration, and maps the
  closed common-field and provider-section registries to the ten property categories.
* :class:`LiveInspectorSource` wraps a :class:`LiveNodeReader` seam that must itself return only
  privacy-safe facets and rows read on the owner thread. Keeping the live provider/navigator walk
  behind an injected protocol keeps this adapter free of any host or COM object and fully testable
  with a fake reader, while the concrete NVDA-backed reader is wired by the runtime.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from importlib import import_module
from typing import Protocol, cast, runtime_checkable

from ...capability import PlainValue
from ...domain.correlation import CorrelationContext
from ...domain.document_records import ProviderSectionRecord
from ...domain.evidence import EvidenceEnvelope
from ...domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	annotationConversionFailure,
	ChildState,
	InspectorSourceIdentity,
	InspectorSourceKind,
	NodeFacet,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	StructuredPropertyNode,
)
from ..providers.common import (
	AnnotationTargetIdentity,
	collectAnnotations,
)
from ...domain.privacy import (
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	transformValue,
)
from ...domain.snapshot_bundle import SnapshotNodeView, SnapshotView
from ...domain.status import EvidenceState, EvidenceValue
from ...ports.inspector import ChildFetch, PropertyFetch
from ...ports.providers import (
	IdentityComparisonRequest,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ReadBudget,
)
from .selected_objects import SelectedObjectSession

__all__ = [
	"LiveInspectorSource",
	"LiveNodeReader",
	"LiveSessionNodeReader",
	"OfflineInspectorSource",
	"SnapshotNodeReader",
]

_REDACTED_ANNOTATION_TEXT = "(redacted)"
_UIA_ANNOTATION_TYPE_NAMES = {
	"AnnotationType_Comment": "Comment",
	"AnnotationType_SpellingError": "Spelling error",
	"AnnotationType_GrammarError": "Grammar error",
	"AnnotationType_InsertionChange": "Insertion change",
	"AnnotationType_DeletionChange": "Deletion change",
	"AnnotationType_TrackChanges": "Track change",
	"AnnotationType_Author": "Author",
	"AnnotationType_Footnote": "Footnote",
	"AnnotationType_Endnote": "Endnote",
}


@runtime_checkable
class _AnnotationReader(Protocol):
	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]: ...


class _UiaTextRange(Protocol):
	def getAttributeValue(self, attributeId: int) -> object: ...


class _UiaTextInfo(Protocol):
	text: object

	def copy(self) -> _UiaTextInfo: ...
	def expand(self, unit: object) -> None: ...


class _UiaElementArray(Protocol):
	length: int

	def getElement(self, index: int) -> object: ...


class _UiaQueryable(Protocol):
	def QueryInterface(self, interface: object) -> object: ...


class _UiaConstants(Protocol):
	UIA_AnnotationTypesAttributeId: int
	UIA_AnnotationObjectsAttributeId: int
	UIA_AnnotationAnnotationTypeIdPropertyId: int
	UIA_NamePropertyId: int
	UIA_AnnotationAuthorPropertyId: int
	UIA_AnnotationDateTimePropertyId: int
	IUIAutomationElementArray: object


def _rangeObject(info: _UiaTextInfo) -> _UiaTextRange:
	return cast(_UiaTextRange, getattr(info, "_rangeObj"))


def _annotationText(
	value: object,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
) -> str | None:
	if value is None:
		return None
	text = " ".join(_renderPlainScalar(value).split())
	if not text:
		return None
	text = " ".join(privacyTransform(text).split())
	if not text:
		return None
	return text[: budget.maximumTextLength].rstrip() or None


def _annotationTypeLabels(uia: object, target: object) -> dict[int, str]:
	labels: dict[int, str] = {}
	for name, label in _UIA_ANNOTATION_TYPE_NAMES.items():
		value: object = getattr(uia, name, None)
		if type(value) is int:
			labels[value] = label
	customTypes: object = getattr(target, "_UIACustomAnnotationTypes", None)
	if customTypes is not None:
		for name in dir(customTypes):
			try:
				value = getattr(customTypes, name)
				typeId = getattr(value, "id", None)
			except Exception:
				continue
			if type(typeId) is int and typeId not in labels:
				labels[typeId] = name.replace("_", " ").strip() or "Custom UIA annotation"
	return labels


def _annotationTypeIds(value: object) -> tuple[int, ...]:
	values = (
		tuple(cast(Iterable[object], value))
		if isinstance(value, Iterable) and not isinstance(value, (str, bytes))
		else (value,)
	)
	return tuple(item for item in values if type(item) is int)


def _rangeAnnotationElements(
	value: object,
	uia: object,
	budget: ReadBudget,
) -> tuple[tuple[object, ...], bool]:
	try:
		constants = cast(_UiaConstants, uia)
		array = cast(
			_UiaElementArray,
			cast(_UiaQueryable, value).QueryInterface(constants.IUIAutomationElementArray),
		)
		length = max(0, int(array.length))
		retainedLength = min(length, budget.maximumItems)
		return (
			tuple(array.getElement(index) for index in range(retainedLength)),
			length > retainedLength,
		)
	except (AttributeError, LookupError, NotImplementedError):
		return (), False


def _textRangeAnnotationObjects(
	value: object,
	*,
	rangeKey: str,
	uia: object,
	labels: dict[int, str],
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
) -> tuple[tuple[AnnotationRecord, ...], bool]:
	records: list[AnnotationRecord] = []
	constants = cast(_UiaConstants, uia)
	elements, truncated = _rangeAnnotationElements(value, uia, budget)
	for index, element in enumerate(elements):
		try:
			cache = getattr(getattr(uia, "handler", None), "baseCacheRequest", None)
			updater = getattr(element, "buildUpdatedCache", None)
			if callable(updater) and cache is not None:
				element = updater(cache)
			read = cast(Callable[[int], object], getattr(element, "GetCurrentPropertyValue"))
			typeId = read(constants.UIA_AnnotationAnnotationTypeIdPropertyId)
			name = read(constants.UIA_NamePropertyId)
			author = read(constants.UIA_AnnotationAuthorPropertyId)
			dateTime = read(constants.UIA_AnnotationDateTimePropertyId)
		except Exception:
			records.append(
				AnnotationRecord(
					key=f"{rangeKey}-object-{index}-failed",
					status=AnnotationStatus.FAILED,
					typeName="UIA annotation object",
					source="UIA text range",
				),
			)
			continue
		if type(typeId) is not int:
			continue
		typeText = _annotationText(typeId, budget, privacyTransform)
		if typeText is None:
			continue
		records.append(
			AnnotationRecord(
				key=f"{rangeKey}-object-{index}",
				status=AnnotationStatus.VALUE,
				typeName=labels.get(typeId, "Custom UIA annotation"),
				typeId=typeText,
				source="UIA text range",
				summary=_annotationText(name, budget, privacyTransform),
				author=_annotationText(author, budget, privacyTransform),
				dateTime=_annotationText(dateTime, budget, privacyTransform),
				relationship="textRangeObject",
			),
		)
	return tuple(records), truncated


def _deduplicateTextRangeAnnotations(
	records: Iterable[AnnotationRecord],
	budget: ReadBudget,
	*,
	truncated: bool,
) -> tuple[AnnotationRecord, ...]:
	unique: dict[tuple[object, ...], AnnotationRecord] = {}
	for record in records:
		if record.relationship == "textRange":
			key = (record.source, record.relationship, record.typeId)
			previous = unique.get(key)
			if previous is not None and bool(previous.summary) >= bool(record.summary):
				continue
		else:
			key = (
				record.status,
				record.source,
				record.typeId,
				record.typeName,
				record.summary,
				record.author,
				record.dateTime,
				record.targetIdentity,
				record.relationship,
			)
			if key in unique:
				continue
		unique[key] = record
	truncated = truncated or len(unique) > budget.maximumItems
	if not truncated:
		return tuple(unique.values())
	return (
		*tuple(unique.values())[: budget.maximumItems - 1],
		AnnotationRecord(
			key="uia-text-annotations-truncated",
			status=AnnotationStatus.TRUNCATED,
			typeName="UIA text annotations",
			source="UIA text range",
		),
	)


def _textRangeAnnotations(
	target: object,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
) -> tuple[AnnotationRecord, ...]:
	"""Collect bounded UIA annotation evidence from caret, selection, and character ranges."""

	if getattr(target, "UIAElement", None) is None:
		return ()
	caller = getattr(target, "makeTextInfo", None)
	if not callable(caller):
		return ()
	try:
		textInfos = import_module("textInfos")
		uia = import_module("UIAHandler")
	except ImportError:
		return ()
	records: list[AnnotationRecord] = []
	truncated = False
	constants = cast(_UiaConstants, uia)
	labels = _annotationTypeLabels(uia, target)
	ranges: list[tuple[str, _UiaTextInfo]] = []
	caller = cast(Callable[[object], _UiaTextInfo], caller)
	for name, position in (
		("caret", getattr(textInfos, "POSITION_CARET", None)),
		("selection", getattr(textInfos, "POSITION_SELECTION", None)),
	):
		if position is None:
			continue
		try:
			info = caller(position)
		except (AttributeError, LookupError, NotImplementedError):
			continue
		except Exception:
			records.append(
				AnnotationRecord(
					key=f"uia-text-{name}-failed",
					status=AnnotationStatus.FAILED,
					typeName="UIA text annotations",
					source="UIA text range",
				),
			)
			continue
		ranges.append((name, info))
		try:
			character = info.copy()
			character.expand(textInfos.UNIT_CHARACTER)
		except (AttributeError, LookupError, NotImplementedError):
			continue
		except Exception:
			records.append(
				AnnotationRecord(
					key=f"uia-text-{name}-character-failed",
					status=AnnotationStatus.FAILED,
					typeName="UIA text annotations",
					source="UIA text range",
				),
			)
			continue
		ranges.append((f"{name}-character", character))
	for rangeName, info in ranges:
		rangeKey = f"uia-text-{rangeName}"
		rangeObject = _rangeObject(info)
		try:
			typeIds = _annotationTypeIds(
				rangeObject.getAttributeValue(constants.UIA_AnnotationTypesAttributeId),
			)
		except (AttributeError, LookupError, NotImplementedError):
			typeIds = ()
		except Exception:
			records.append(
				AnnotationRecord(
					key=f"{rangeKey}-types-failed",
					status=AnnotationStatus.FAILED,
					typeName="UIA text annotations",
					source="UIA text range",
				),
			)
			typeIds = ()
		try:
			objects = rangeObject.getAttributeValue(constants.UIA_AnnotationObjectsAttributeId)
		except (AttributeError, LookupError, NotImplementedError):
			objectRecords = ()
		except Exception:
			records.append(
				AnnotationRecord(
					key=f"{rangeKey}-objects-failed",
					status=AnnotationStatus.FAILED,
					typeName="UIA annotation objects",
					source="UIA text range",
				),
			)
			objectRecords = ()
		else:
			objectRecords, objectTruncated = _textRangeAnnotationObjects(
				objects,
				rangeKey=rangeKey,
				uia=uia,
				labels=labels,
				budget=budget,
				privacyTransform=privacyTransform,
			)
			truncated = truncated or objectTruncated
		records.extend(objectRecords)
		objectTypes = {record.typeId for record in objectRecords if record.typeId is not None}
		truncated = truncated or len(typeIds) > budget.maximumItems
		for index, typeId in enumerate(typeIds[: budget.maximumItems]):
			typeText = _annotationText(typeId, budget, privacyTransform)
			if typeText is None or typeText in objectTypes:
				continue
			records.append(
				AnnotationRecord(
					key=f"{rangeKey}-{index}",
					status=AnnotationStatus.VALUE,
					typeName=labels.get(typeId, "Custom UIA annotation"),
					typeId=typeText,
					source="UIA text range",
					summary=_annotationText(getattr(info, "text", None), budget, privacyTransform),
					relationship="textRange",
				),
			)
	return _deduplicateTextRangeAnnotations(records, budget, truncated=truncated)


_STATE_TO_STATUS: dict[EvidenceState, PropertyStatus] = {
	EvidenceState.VALUE: PropertyStatus.VALUE,
	EvidenceState.EMPTY: PropertyStatus.EMPTY,
	EvidenceState.UNSUPPORTED: PropertyStatus.UNSUPPORTED,
	EvidenceState.NOT_APPLICABLE: PropertyStatus.NOT_APPLICABLE,
	EvidenceState.UNAVAILABLE: PropertyStatus.UNAVAILABLE,
	EvidenceState.STALE: PropertyStatus.STALE,
	EvidenceState.REJECTED: PropertyStatus.REJECTED,
	EvidenceState.REDACTED: PropertyStatus.REDACTED,
	EvidenceState.TRUNCATED: PropertyStatus.TRUNCATED,
	EvidenceState.CANCELLED: PropertyStatus.UNAVAILABLE,
	EvidenceState.FAILED: PropertyStatus.FAILED,
	EvidenceState.MIXED: PropertyStatus.VALUE,
}

_CORE_FIELDS = (
	"name",
	"role",
	"roleText",
	"states",
	"description",
	"value",
	"geometry",
	"childCount",
	"indexInParent",
	"keyboardShortcut",
	"backend",
	"process",
	"focusable",
	"focused",
)
_QUICK_FIELDS = ("name", "role", "states", "value", "description")
_DEVELOPER_FIELDS = (
	"pythonClass",
	"classHierarchy",
	"windowClass",
	"windowHandle",
	"windowControlId",
	"developerInformation",
	"apiDetails",
)
_DIAGNOSTIC_FIELDS = ("diagnostics", "validation", "privacy")
_CATEGORY_SECTION: dict[PropertyCategory, str] = {
	PropertyCategory.SUPPORTED_UIA_PATTERNS: "uia",
	PropertyCategory.UIA: "uia",
	PropertyCategory.IA2_MSAA: "ia2Msaa",
	PropertyCategory.JAB: "jab",
}
_PROVIDER_SECTION_IDS = ("generic", "uia", "ia2Msaa", "jab", "overlay", "rawUia", "customUia")
_OTHER_API_SECTION_IDS = ("generic", "overlay", "rawUia", "customUia")
_TEXT_PATTERN_EVIDENCE_SUFFIXES = frozenset(
	("PatternObject", "DocumentText", "VisibleRanges", "SelectionRanges", "AggregateAttributes"),
)


def _supportedPatternFields(
	datums: tuple[tuple[str, ProviderReadResult], ...],
) -> tuple[tuple[str, ProviderReadResult], ...]:
	patternNames: set[str] = set()
	for fieldId, _result in datums:
		if not (fieldId.startswith("Is") and fieldId.endswith("Available")):
			continue
		fullName = fieldId[2 : -len("Available")]
		marker = fullName.rfind("Pattern")
		if marker < 0:
			continue
		suffix = fullName[marker + len("Pattern") :]
		if suffix and not suffix.isdigit():
			continue
		patternNames.add(fullName[:marker] + suffix)
	supported = {
		fieldId
		for fieldId, result in datums
		if fieldId in patternNames and result.status == "value" and result.value is True
	}
	return tuple(
		(fieldId, result)
		for fieldId, result in datums
		if fieldId in supported
		or any(
			fieldId == f"{patternName}{suffix}"
			for patternName in supported.intersection(("Text", "Text2"))
			for suffix in _TEXT_PATTERN_EVIDENCE_SUFFIXES
		)
	)


def _renderScalar(value: EvidenceValue) -> str:
	if isinstance(value, bool):
		return "true" if value else "false"
	if isinstance(value, str):
		return value
	if isinstance(value, bytes):
		return value.decode("utf-8", "replace")
	if isinstance(value, (int, float)):
		return str(value)
	return ", ".join(_renderScalar(item) for item in value)


def _renderPlainScalar(value: object) -> str:
	if value is None:
		return ""
	if isinstance(value, bool):
		return "true" if value else "false"
	if isinstance(value, str):
		return value
	if isinstance(value, bytes):
		return value.decode("utf-8", "replace")
	if isinstance(value, (int, float)):
		return str(value)
	if isinstance(value, tuple):
		return ", ".join(_renderPlainScalar(item) for item in cast(tuple[object, ...], value))
	raise TypeError("live provider value must be plain")


def _fieldLabel(fieldKey: str) -> str:
	pieces: list[str] = []
	current = ""
	for character in fieldKey:
		if character.isupper() and current:
			pieces.append(current)
			current = character.lower()
		else:
			current += character
	if current:
		pieces.append(current)
	return " ".join(pieces).capitalize()


def _customUiaTupleField(value: object, name: str) -> object | None:
	"""Read one named field from the tuple format used for provider-safe metadata."""

	if not isinstance(value, tuple):
		return None
	for item in cast(tuple[object, ...], value):
		if not isinstance(item, tuple):
			continue
		parts = cast(tuple[object, ...], item)
		if len(parts) == 2 and parts[0] == name:
			return parts[1]
	return None


def _customUiaFallbackLabel(stableKey: str) -> str:
	"""Keep a legacy configuration readable when it predates its display-name metadata."""

	return "Custom UIA property"


def _customUiaEnumValues(value: object) -> dict[int, str]:
	if not isinstance(value, tuple):
		return {}
	values: dict[int, str] = {}
	for rawItem in cast(tuple[object, ...], value):
		if not isinstance(rawItem, tuple):
			continue
		item = cast(tuple[object, ...], rawItem)
		if len(item) != 2:
			continue
		number, name = item
		if type(number) is int and isinstance(name, str):
			values[number] = name
	return values


def _customUiaCurrentRow(
	stableKey: str,
	displayName: str,
	result: ProviderReadResult,
	enumValues: dict[int, str],
) -> PropertyRow:
	"""Convert one normalized configured Custom UIA value into an Inspector row."""

	statusValue = _customUiaTupleField(result.value, "status") if result.status == "value" else None
	statusName = statusValue if isinstance(statusValue, str) else None
	if statusName is None and result.status == "value":
		return PropertyRow(
			f"customUia.known.{stableKey}.current",
			displayName,
			PropertyStatus.VALUE,
			_renderPlainScalar(result.value),
			"live",
		)
	if statusName is None:
		return PropertyRow(
			f"customUia.known.{stableKey}.current",
			displayName,
			PropertyStatus.FAILED,
			None,
			"live",
		)
	statuses: dict[str, PropertyStatus] = {
		"value": PropertyStatus.VALUE,
		"truncated": PropertyStatus.TRUNCATED,
		"empty": PropertyStatus.EMPTY,
		"unsupported": PropertyStatus.UNSUPPORTED,
		"unavailable": PropertyStatus.UNAVAILABLE,
		"redacted": PropertyStatus.REDACTED,
		"failed": PropertyStatus.FAILED,
		"mismatch": PropertyStatus.FAILED,
		"unknownVariant": PropertyStatus.FAILED,
	}
	status = statuses.get(statusName, PropertyStatus.FAILED)
	value = (
		_customUiaTupleField(result.value, "value")
		if status
		in (
			PropertyStatus.VALUE,
			PropertyStatus.TRUNCATED,
		)
		else None
	)
	if type(value) is int and value in enumValues:
		renderedValue = f"{enumValues[value]} ({value})"
	else:
		renderedValue = _renderPlainScalar(value) if value is not None else None
	return PropertyRow(
		f"customUia.known.{stableKey}.current",
		displayName,
		status,
		renderedValue,
		"live",
	)


def _customUiaDefinitionDetails(
	result: ProviderReadResult,
) -> tuple[str, str, dict[int, str]] | None:
	"""Read a configured property's presentation metadata from compact definition data."""

	if not isinstance(result.value, tuple):
		return None
	parts = cast(tuple[object, ...], result.value)
	if len(parts) < 2 or not isinstance(parts[0], str) or not isinstance(parts[1], str):
		return None
	displayName = parts[2] if len(parts) > 2 else None
	enumValues = _customUiaEnumValues(parts[3]) if len(parts) > 3 else {}
	if isinstance(displayName, str) and displayName:
		return parts[0], displayName, enumValues
	return parts[0], f"Custom UIA property ({parts[1]})", enumValues


def _configuredCustomUiaRows(
	datums: tuple[tuple[str, ProviderReadResult], ...],
) -> tuple[PropertyRow, ...]:
	"""Render configured current values without admitting discovery metadata."""

	names: dict[str, str] = {}
	enumValues: dict[str, dict[int, str]] = {}
	currentReads: list[tuple[str, ProviderReadResult]] = []
	for fieldId, result in datums:
		if not fieldId.startswith("known."):
			continue
		stableKey, separator, kind = fieldId[len("known.") :].rpartition(".")
		if not separator:
			continue
		if kind == "registration":
			displayName = _customUiaTupleField(result.value, "displayName")
			if isinstance(displayName, str) and displayName:
				names[stableKey] = displayName
			rawEnumValues = _customUiaTupleField(result.value, "enumValues")
			enumValues[stableKey] = _customUiaEnumValues(rawEnumValues)
		elif kind == "definition":
			definition = _customUiaDefinitionDetails(result)
			if definition is not None:
				names[definition[0]] = definition[1]
				enumValues[definition[0]] = definition[2]
		elif kind == "current":
			currentReads.append((stableKey, result))
	return tuple(
		_customUiaCurrentRow(
			stableKey,
			names.get(stableKey, _customUiaFallbackLabel(stableKey)),
			result,
			enumValues.get(stableKey, {}),
		)
		for stableKey, result in currentReads
	)


def _decodeProviderResult(value: object) -> ProviderReadResult | None:
	if not isinstance(value, tuple):
		return None
	parts = cast(tuple[object, ...], value)
	if len(parts) != 4:
		return None
	status, resultValue, errorCode, truncated = parts
	if not isinstance(status, str) or (errorCode is not None and not isinstance(errorCode, str)):
		return None
	if not isinstance(truncated, bool):
		return None
	try:
		return ProviderReadResult(status, cast(PlainValue, resultValue), errorCode, truncated)
	except (TypeError, ValueError):
		return None


def _decodeProviderDatum(value: object) -> tuple[str, ProviderReadResult] | None:
	if not isinstance(value, tuple):
		return None
	parts = cast(tuple[object, ...], value)
	if len(parts) != 5:
		return None
	fieldId, status, valueMarker, errorMarker, truncated = parts
	if not isinstance(fieldId, str) or not isinstance(status, str) or not isinstance(truncated, bool):
		return None
	if not isinstance(valueMarker, tuple):
		return None
	valueParts = cast(tuple[object, ...], valueMarker)
	if valueParts and valueParts[0] == "value" and len(valueParts) == 2:
		resultValue: object = valueParts[1]
	elif valueParts == ("noValue",):
		resultValue = None
	else:
		return None
	if not isinstance(errorMarker, tuple):
		return None
	errorParts = cast(tuple[object, ...], errorMarker)
	if errorParts and errorParts[0] == "error" and len(errorParts) == 2 and isinstance(errorParts[1], str):
		errorCode = errorParts[1]
	elif errorParts == ("noError",):
		errorCode = None
	else:
		return None
	try:
		return fieldId, ProviderReadResult(
			status,
			cast(PlainValue, resultValue),
			errorCode,
			truncated,
		)
	except (TypeError, ValueError):
		return None


def providerSectionDatums(
	value: object,
	sectionId: str,
) -> tuple[ProviderReadResult, tuple[tuple[str, ProviderReadResult], ...]] | None:
	return _providerSectionDatums(value, sectionId, datumIndex=3)


def providerSectionIdentityDatums(
	value: object,
	sectionId: str,
) -> tuple[ProviderReadResult, tuple[tuple[str, ProviderReadResult], ...]] | None:
	"""Decode the identity records from one provider section's metadata transport."""

	return _providerSectionDatums(value, sectionId, datumIndex=2)


def _providerSectionDatums(
	value: object,
	sectionId: str,
	*,
	datumIndex: int,
) -> tuple[ProviderReadResult, tuple[tuple[str, ProviderReadResult], ...]] | None:
	if not isinstance(value, tuple):
		return None
	for encodedSection in cast(tuple[object, ...], value):
		if not isinstance(encodedSection, tuple):
			continue
		sectionParts = cast(tuple[object, ...], encodedSection)
		if len(sectionParts) != 4:
			continue
		if sectionParts[0] != sectionId:
			continue
		sectionStatus = _decodeProviderResult(sectionParts[1])
		datumsResult = _decodeProviderResult(sectionParts[datumIndex])
		if sectionStatus is None or datumsResult is None:
			return None
		if datumsResult.status != "value":
			return sectionStatus, ()
		if not isinstance(datumsResult.value, tuple):
			return None
		datums: list[tuple[str, ProviderReadResult]] = []
		for encodedDatum in cast(tuple[object, ...], datumsResult.value):
			decoded = _decodeProviderDatum(encodedDatum)
			if decoded is None:
				return None
			datums.append(decoded)
		return sectionStatus, tuple(datums)
	return None


def _categoryFields(category: PropertyCategory) -> tuple[str, ...] | None:
	if category is PropertyCategory.QUICK:
		return _QUICK_FIELDS
	if category is PropertyCategory.CORE:
		return _CORE_FIELDS
	if category is PropertyCategory.DEVELOPER_INFO:
		return _DEVELOPER_FIELDS
	if category is PropertyCategory.DIAGNOSTICS:
		return _DIAGNOSTIC_FIELDS
	return None


def _rowFromEnvelope(fieldKey: str, envelope: EvidenceEnvelope) -> PropertyRow:
	status = _STATE_TO_STATUS.get(envelope.status, PropertyStatus.FAILED)
	value: str | None = None
	if status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED):
		value = _renderScalar(envelope.value) if envelope.value is not None else ""
		if not value:
			status = PropertyStatus.EMPTY
			value = None
	return PropertyRow(
		fieldKey=fieldKey,
		name=_fieldLabel(fieldKey),
		status=status,
		value=value,
		source="capture",
		confidence=envelope.confidence,
	)


def _rowFromProviderDatum(
	sectionName: str,
	fieldId: str,
	result: ProviderReadResult,
	*,
	source: str,
) -> PropertyRow:
	statuses = {
		"value": PropertyStatus.VALUE,
		"truncated": PropertyStatus.TRUNCATED,
		"empty": PropertyStatus.EMPTY,
		"unsupported": PropertyStatus.UNSUPPORTED,
		"unavailable": PropertyStatus.UNAVAILABLE,
		"redacted": PropertyStatus.REDACTED,
		"failed": PropertyStatus.FAILED,
	}
	status = statuses.get(result.status, PropertyStatus.FAILED)
	if status is PropertyStatus.VALUE and result.truncated:
		status = PropertyStatus.TRUNCATED
	value = (
		_renderPlainScalar(result.value)
		if status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED) and result.value is not None
		else None
	)
	if status is PropertyStatus.VALUE and not value:
		status = PropertyStatus.EMPTY
		value = None
	return PropertyRow(
		fieldKey=f"{sectionName}.{fieldId}",
		name=_fieldLabel(fieldId),
		status=status,
		value=value,
		source=source,
	)


def _structuredFromEnvelope(fieldKey: str, envelope: EvidenceEnvelope) -> StructuredPropertyNode:
	status = _STATE_TO_STATUS.get(envelope.status, PropertyStatus.FAILED)
	label = _fieldLabel(fieldKey)
	if status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED) and isinstance(envelope.value, tuple):
		children = tuple(
			StructuredPropertyNode(
				key=f"{fieldKey}[{index}]",
				label=f"Item {index + 1}",
				status=PropertyStatus.VALUE,
				value=_renderScalar(item),
			)
			for index, item in enumerate(envelope.value)
		)
		if children:
			return StructuredPropertyNode(
				key=fieldKey,
				label=label,
				status=PropertyStatus.VALUE,
				children=children,
			)
		return StructuredPropertyNode(key=fieldKey, label=label, status=PropertyStatus.EMPTY)
	row = _rowFromEnvelope(fieldKey, envelope)
	return StructuredPropertyNode(key=fieldKey, label=label, status=row.status, value=row.value)


class OfflineInspectorSource:
	"""Adapt a stored capture bundle view to the shared read-only Inspector source protocol."""

	def __init__(
		self,
		view: SnapshotView,
		targetKey: str,
		*,
		label: str,
		executable: str = "offline capture",
		processId: int = 0,
		backend: str = "capture",
	) -> None:
		super().__init__()
		self._view = view
		self._targetKey = targetKey
		self._label = label
		self._executable = executable
		self._processId = processId
		self._backend = backend
		self._nodes: dict[str, SnapshotNodeView] = {node.key: node for node in view.captureNodes}
		if targetKey not in self._nodes:
			raise KeyError(f"capture bundle has no node keyed {targetKey!r}")

	def identity(self) -> InspectorSourceIdentity:
		return InspectorSourceIdentity(
			kind=InspectorSourceKind.OFFLINE,
			label=self._label,
			executable=self._executable,
			processId=self._processId,
			backend=self._backend,
			nodeCount=len(self._nodes),
		)

	def roots(self) -> tuple[NodeFacet, ...]:
		spine: list[SnapshotNodeView] = []
		visited: set[str] = set()
		current: str | None = self._targetKey
		while current is not None and current in self._nodes and current not in visited:
			visited.add(current)
			node = self._nodes[current]
			spine.append(node)
			current = node.structure.parentKey
		spine.reverse()
		return tuple(self._facet(node) for node in spine)

	def children(self, nodeId: str) -> ChildFetch:
		node = self._nodes.get(nodeId)
		if node is None:
			return ChildFetch(parentId=nodeId, state=ChildState.FAILED, note="Children unavailable")
		structure = node.structure
		if structure.childFetchFailed:
			return ChildFetch(parentId=nodeId, state=ChildState.FAILED, note="Children unavailable")
		presentKeys = tuple(key for key in structure.childKeys if key in self._nodes)
		if not presentKeys:
			state = ChildState.TRUNCATED if structure.truncated else ChildState.EMPTY
			note = "Some children were not captured" if structure.truncated else "No children"
			return ChildFetch(parentId=nodeId, state=state, note=note)
		facets = tuple(self._facet(self._nodes[key]) for key in presentKeys)
		state = ChildState.TRUNCATED if structure.truncated else ChildState.LOADED
		note = "Some children were not captured" if structure.truncated else None
		return ChildFetch(parentId=nodeId, state=state, children=facets, note=note)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		node = self._nodes.get(nodeId)
		if node is None:
			return PropertyFetch(nodeId=nodeId, category=category, note="Node unavailable")
		fields = dict(node.fields)
		if category is PropertyCategory.ALL_PROPERTIES:
			return PropertyFetch(
				nodeId=nodeId,
				category=category,
				structured=self._allProperties(node, fields),
			)
		if category in _CATEGORY_SECTION:
			if category is PropertyCategory.UIA:
				standard = self._sectionFetch(nodeId, category, node, _CATEGORY_SECTION[category])
				customRows = self._configuredCustomUiaRows(node)
				return PropertyFetch(nodeId=nodeId, category=category, rows=customRows + standard.rows)
			return self._sectionFetch(nodeId, category, node, _CATEGORY_SECTION[category])
		selection = self._categoryFields(category)
		if selection is None:
			return PropertyFetch(
				nodeId=nodeId,
				category=category,
				rows=(
					PropertyRow(
						fieldKey="section",
						name="Section",
						status=PropertyStatus.NOT_APPLICABLE,
						source="capture",
					),
				),
			)
		rows = tuple(
			_rowFromEnvelope(fieldKey, fields[fieldKey]) for fieldKey in selection if fieldKey in fields
		)
		return PropertyFetch(nodeId=nodeId, category=category, rows=rows)

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		view = self._view
		return view.annotations(nodeId) if isinstance(view, _AnnotationReader) else ()

	def close(self) -> None:
		self._nodes = {}

	# -- internal helpers --------------------------------------------------

	def _facet(self, node: SnapshotNodeView) -> NodeFacet:
		fields = dict(node.fields)
		name = self._value(fields.get("name"))
		role = self._value(fields.get("role"))
		if not name:
			name = self._uiaFacetValue(node, "Name")
		if not role:
			role = self._uiaFacetValue(node, "LocalizedControlType")
		return NodeFacet(
			nodeId=node.key,
			parentId=node.structure.parentKey,
			depth=node.structure.depth,
			name=name,
			hasName=bool(name),
			role=role or "object",
			childHint=bool(node.structure.childKeys),
		)

	@classmethod
	def _uiaFacetValue(cls, node: SnapshotNodeView, fieldId: str) -> str:
		"""Recover UIA display fields when an NVDA object did not expose core equivalents."""

		section = cls._section(node, "uia")
		if section is None or section.properties.status is not EvidenceState.VALUE:
			return ""
		properties = section.properties.value
		if not isinstance(properties, tuple):
			return ""
		for datum in properties:
			decoded = _decodeProviderDatum(datum)
			if decoded is None or decoded[0] != fieldId:
				continue
			result = decoded[1]
			if result.status in ("value", "truncated") and result.value is not None:
				return _renderPlainScalar(result.value)
		return ""

	@staticmethod
	def _value(envelope: EvidenceEnvelope | None) -> str:
		if envelope is None or envelope.status is not EvidenceState.VALUE:
			return ""
		if envelope.value is None:
			return ""
		return _renderScalar(envelope.value)

	@staticmethod
	def _categoryFields(category: PropertyCategory) -> tuple[str, ...] | None:
		return _categoryFields(category)

	def _sectionFetch(
		self,
		nodeId: str,
		category: PropertyCategory,
		node: SnapshotNodeView,
		sectionName: str,
	) -> PropertyFetch:
		section = self._section(node, sectionName)
		if section is None or self._sectionAbsent(section):
			return PropertyFetch(
				nodeId=nodeId,
				category=category,
				rows=(
					PropertyRow(
						fieldKey=f"{sectionName}.section",
						name=_fieldLabel(sectionName),
						status=PropertyStatus.NOT_APPLICABLE,
						source="capture",
					),
				),
			)
		datums = self._sectionDatums(section)
		if category is PropertyCategory.SUPPORTED_UIA_PATTERNS:
			datums = _supportedPatternFields(datums)
		if datums:
			return PropertyFetch(
				nodeId=nodeId,
				category=category,
				rows=tuple(
					_rowFromProviderDatum(sectionName, fieldId, result, source="capture")
					for fieldId, result in datums
				),
			)
		rows = tuple(
			_rowFromEnvelope(f"{sectionName}.{field}", getattr(section, field))
			for field in ("status", "identity", "properties")
		)
		return PropertyFetch(nodeId=nodeId, category=category, rows=rows)

	def _allProperties(
		self,
		node: SnapshotNodeView,
		fields: dict[str, EvidenceEnvelope],
	) -> tuple[StructuredPropertyNode, ...]:
		nodes = [_structuredFromEnvelope(fieldKey, envelope) for fieldKey, envelope in fields.items()]
		providerChildren: list[StructuredPropertyNode] = []
		for sectionName in ("generic", "uia", "ia2Msaa", "jab", "overlay", "rawUia", "customUia"):
			section = self._section(node, sectionName)
			if section is None or self._sectionAbsent(section):
				continue
			providerChildren.append(
				StructuredPropertyNode(
					key=f"providers.{sectionName}",
					label=_fieldLabel(sectionName),
					status=PropertyStatus.VALUE,
					children=tuple(
						_structuredFromEnvelope(f"{sectionName}.{field}", getattr(section, field))
						for field in ("status", "identity", "properties")
					),
				),
			)
		if providerChildren:
			nodes.append(
				StructuredPropertyNode(
					key="providers",
					label="Providers",
					status=PropertyStatus.VALUE,
					children=tuple(providerChildren),
				),
			)
		return tuple(nodes)

	@staticmethod
	def _section(node: SnapshotNodeView, sectionName: str) -> ProviderSectionRecord | None:
		for name, section in node.providers.items:
			if name == sectionName:
				return section
		return None

	@staticmethod
	def _sectionDatums(section: ProviderSectionRecord) -> tuple[tuple[str, ProviderReadResult], ...]:
		"""Decode captured provider fields, preferring current properties over identity duplicates."""

		decoded: list[tuple[str, ProviderReadResult]] = []
		seen: set[str] = set()
		for envelope in (section.properties, section.identity):
			if envelope.status is not EvidenceState.VALUE or not isinstance(envelope.value, tuple):
				continue
			for rawDatum in envelope.value:
				datum = _decodeProviderDatum(rawDatum)
				if datum is None or datum[0] in seen:
					continue
				seen.add(datum[0])
				decoded.append(datum)
		return tuple(decoded)

	def _configuredCustomUiaRows(self, node: SnapshotNodeView) -> tuple[PropertyRow, ...]:
		section = self._section(node, "customUia")
		if section is None or self._sectionAbsent(section):
			return ()
		return _configuredCustomUiaRows(self._sectionDatums(section))

	@staticmethod
	def _sectionAbsent(section: ProviderSectionRecord) -> bool:
		return all(
			getattr(section, field).status in (EvidenceState.NOT_APPLICABLE, EvidenceState.UNSUPPORTED)
			for field in ("status", "identity", "properties")
		)


@runtime_checkable
class LiveNodeReader(Protocol):
	"""Owner-thread live reader that already returns privacy-safe facets and rows.

	The reader owns every host and provider interaction; this seam only ever exchanges immutable,
	privacy-transformed records, so no NVDA or COM object crosses into the source, service, or wx.
	"""

	def identity(self) -> InspectorSourceIdentity: ...

	def roots(self) -> tuple[NodeFacet, ...]: ...

	def children(self, nodeId: str) -> ChildFetch: ...

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch: ...

	def applyPrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None: ...

	def close(self) -> None: ...


class LiveInspectorSource:
	"""Adapt an owner-thread :class:`LiveNodeReader` to the shared Inspector source protocol."""

	def __init__(self, reader: LiveNodeReader, *, onClose: Callable[[], None] | None = None) -> None:
		super().__init__()
		self._reader: LiveNodeReader | None = reader
		self._onClose = onClose

	def _requireReader(self) -> LiveNodeReader:
		reader = self._reader
		if reader is None:
			raise RuntimeError("the live Inspector source is closed")
		return reader

	def identity(self) -> InspectorSourceIdentity:
		return self._requireReader().identity()

	def roots(self) -> tuple[NodeFacet, ...]:
		return self._requireReader().roots()

	def children(self, nodeId: str) -> ChildFetch:
		return self._requireReader().children(nodeId)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		return self._requireReader().properties(nodeId, category)

	def applyPrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None:
		"""Adopt a committed privacy policy for nodes and properties read from here onwards.

		Rows the Inspector has already loaded were transformed when they were read and keep the
		policy that produced them; only reads that happen after this call use the new one.
		"""

		reader = self._reader
		if reader is None:
			return
		reader.applyPrivacyPolicy(privacyPolicy)

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		reader = self._requireReader()
		return reader.annotations(nodeId) if isinstance(reader, _AnnotationReader) else ()

	def retarget(
		self,
		target: object,
		foreground: object,
		focusAncestors: tuple[object, ...],
	) -> tuple[NodeFacet, ...] | None:
		"""Retarget the existing owner-thread session when the foreground identity is unchanged."""

		reader = self._requireReader()
		if not isinstance(reader, LiveSessionNodeReader):
			return None
		return reader.retarget(target, foreground, focusAncestors)

	def liveObject(self, nodeId: str) -> object:
		"""Resolve one selected live node through the source's owning session."""

		reader = self._requireReader()
		if not isinstance(reader, LiveSessionNodeReader):
			raise LookupError("Inspector source does not expose live objects")
		return reader.liveObject(nodeId)

	def close(self) -> None:
		reader = self._reader
		self._reader = None
		callback = self._onClose
		self._onClose = None
		if reader is not None:
			reader.close()
		if callback is not None:
			callback()


class LiveSessionNodeReader:
	"""Project one owner-thread selected-object session as a privacy-safe live tree."""

	def __init__(
		self,
		session: SelectedObjectSession,
		context: CorrelationContext,
		identity: InspectorSourceIdentity,
		*,
		foregroundRef: str,
		targetRef: str,
		focusAncestorRefs: tuple[str, ...],
		providerScope: str,
		processScope: str,
		privacyPolicy: PrivacyPolicy,
		diagnostic: Callable[[str], None] | None = None,
		retargetable: bool = True,
	) -> None:
		super().__init__()
		self._session = session
		self._context = context
		self._identity = identity
		self._foregroundRef = foregroundRef
		self._targetRef = targetRef
		self._focusAncestorRefs = focusAncestorRefs
		self._providerScope = providerScope
		self._processScope = processScope
		self._privacyPolicy = privacyPolicy
		self._session.applyPrivacyPolicy(privacyPolicy)
		self._diagnostic = diagnostic
		self._retargetable = retargetable
		self._depths: dict[str, int] = {foregroundRef: 0}
		self._children: dict[str, ProviderChildBatch] = {}
		self._spine: tuple[str, ...] | None = None
		self._closed = False

	def identity(self) -> InspectorSourceIdentity:
		return self._identity

	def applyPrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None:
		"""Read later nodes and properties under a newly committed policy."""

		self._privacyPolicy = privacyPolicy
		self._session.applyPrivacyPolicy(privacyPolicy)

	def liveObject(self, nodeId: str) -> object:
		if self._closed:
			raise LookupError("Inspector source is closed")
		return self._session._target(  # pyright: ignore[reportPrivateUsage]
			nodeId,
			self._context,
		)

	def roots(self) -> tuple[NodeFacet, ...]:
		spine = self._initialSpine()
		return tuple(
			self._facet(nodeRef, None if index == 0 else spine[index - 1], index)
			for index, nodeRef in enumerate(spine)
		)

	def retarget(
		self,
		target: object,
		foreground: object,
		focusAncestors: tuple[object, ...],
	) -> tuple[NodeFacet, ...] | None:
		"""Reuse stable session refs for a focus move inside the current foreground window."""

		if self._closed or not self._retargetable:
			return None
		foregroundRef = self._session.retain(foreground)
		if not self._same(foregroundRef, self._foregroundRef):
			return None
		previous = (
			self._targetRef,
			self._focusAncestorRefs,
			self._spine,
			self._depths.copy(),
			self._children.copy(),
		)
		try:
			self._targetRef = self._session.retain(target)
			self._focusAncestorRefs = tuple(self._session.retain(ancestor) for ancestor in focusAncestors)
			self._spine = None
			return self.roots()
		except Exception:
			(
				self._targetRef,
				self._focusAncestorRefs,
				self._spine,
				self._depths,
				self._children,
			) = previous
			raise

	def children(self, nodeId: str) -> ChildFetch:
		if self._closed:
			return ChildFetch(nodeId, ChildState.FAILED, note="Children unavailable")
		batch = self._childRefs(nodeId)
		nodeRefs = self._childRefsForDisclosure(nodeId, batch)
		providerFailed = batch.status in ("unavailable", "stale", "failed")
		if providerFailed and not nodeRefs:
			return ChildFetch(nodeId, ChildState.FAILED, note="Children unavailable")
		if not nodeRefs:
			state = ChildState.TRUNCATED if batch.truncated else ChildState.EMPTY
			note = "Some children were unavailable" if batch.truncated else "No children"
			return ChildFetch(nodeId, state, note=note)
		depth = self._depths.get(nodeId, 0) + 1
		truncated = batch.truncated or providerFailed
		return ChildFetch(
			nodeId,
			ChildState.TRUNCATED if truncated else ChildState.LOADED,
			tuple(self._facet(childRef, nodeId, depth, deferChildProbe=True) for childRef in nodeRefs),
			"Some children were unavailable" if truncated else None,
		)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		if self._closed:
			return PropertyFetch(nodeId, category, note="Node unavailable")
		protection = self._protection(nodeId)
		if category is PropertyCategory.ALL_PROPERTIES:
			rows = self._rows(nodeId, (*_CORE_FIELDS, *_DEVELOPER_FIELDS, *_DIAGNOSTIC_FIELDS), protection)
			providerNodes = self._providerStructured(nodeId, protection)
			return PropertyFetch(
				nodeId,
				category,
				structured=tuple(
					StructuredPropertyNode(
						key=row.fieldKey,
						label=row.name,
						status=row.status,
						value=row.value,
					)
					for row in rows
				)
				+ providerNodes,
			)
		if category is PropertyCategory.OTHER_API:
			return self._otherApi(nodeId, protection)
		if category is PropertyCategory.UIA:
			return self._uiaPresentation(nodeId, protection)
		if category in _CATEGORY_SECTION:
			return self._providerSection(nodeId, category, protection)
		fields = self._categoryFields(category)
		if fields is None:
			return PropertyFetch(
				nodeId,
				category,
				rows=(
					PropertyRow(
						fieldKey="section",
						name="Section",
						status=PropertyStatus.NOT_APPLICABLE,
						source="live",
					),
				),
			)
		return PropertyFetch(nodeId, category, rows=self._rows(nodeId, fields, protection))

	def _uiaPresentation(self, nodeId: str, protection: ProtectionEvidence) -> PropertyFetch:
		"""Place configured custom UIA evidence before standard UIA properties."""
		standard = self._providerSection(nodeId, PropertyCategory.UIA, protection)
		metadata = self._providerMetadata(nodeId)
		customRows: tuple[PropertyRow, ...] = ()
		if metadata.status == "value":
			definitions = providerSectionIdentityDatums(metadata.value, "customUia")
			currents = providerSectionDatums(metadata.value, "customUia")
			if definitions is not None or currents is not None:
				definitionDatums = definitions[1] if definitions is not None else ()
				currentDatums = currents[1] if currents is not None else ()
				customRows = self._configuredCustomUiaRows((*definitionDatums, *currentDatums))
		return PropertyFetch(nodeId, PropertyCategory.UIA, rows=customRows + standard.rows)

	@staticmethod
	def _configuredCustomUiaRows(
		datums: tuple[tuple[str, ProviderReadResult], ...],
	) -> tuple[PropertyRow, ...]:
		return _configuredCustomUiaRows(datums)

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		if self._closed:
			return ()
		try:
			target = self.liveObject(nodeId)
		except LookupError:
			# Raw UIA node references belong to the raw provider, not the NVDA object session used by
			# annotation APIs. They have no annotation surface until that provider exposes one.
			return ()
		protection = self._protection(nodeId)

		def privacyTransform(value: str) -> str:
			transformed = transformValue(
				ObservedValue(
					FieldGroup.RELATION,
					value,
					PrivacyClass.PUBLIC,
					protection,
					"live-annotation",
				),
				SinkId.GUI,
				self._privacyPolicy,
			)
			if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
				return _REDACTED_ANNOTATION_TEXT
			return _renderPlainScalar(transformed.value)

		def identityResolver(candidate: object) -> AnnotationTargetIdentity | None:
			candidateRef = self._session.retain(candidate)
			_ = self._initialSpine()
			matches = tuple(nodeRef for nodeRef in self._depths if self._same(candidateRef, nodeRef))
			if len(matches) != 1:
				return None
			return AnnotationTargetIdentity(
				nodeId=matches[0],
				description="Matched current Inspector hierarchy node",
				proven=True,
			)

		try:
			records = collectAnnotations(
				target,
				self._budget(),
				privacyTransform=privacyTransform,
				identityResolver=identityResolver,
			)
			rangeRecords = _textRangeAnnotations(target, self._budget(), privacyTransform)
			return (
				tuple(
					record
					for record in (*records, *rangeRecords)
					if record.status is not AnnotationStatus.NO_DATA
				)
				or records
			)
		except Exception:
			failure = annotationConversionFailure(nodeId, source="NVDA")
			if self._diagnostic is not None and failure.errorRef is not None:
				self._diagnostic(
					f"Keystone Inspector: annotation conversion failed; code={failure.errorRef.code}; diagnosticId={failure.errorRef.diagnosticId}",
				)
			return (failure,)

	def _providerMetadata(self, nodeId: str) -> ProviderReadResult:
		return self._session.readMetadata(
			ProviderMetadataRequest(nodeId, "providerSections", self._budget(), self._context),
		)

	def _providerStructured(
		self,
		nodeId: str,
		protection: ProtectionEvidence,
	) -> tuple[StructuredPropertyNode, ...]:
		metadata = self._providerMetadata(nodeId)
		if metadata.status != "value":
			return ()
		sections: list[StructuredPropertyNode] = []
		for sectionId in _PROVIDER_SECTION_IDS:
			decoded = providerSectionDatums(metadata.value, sectionId)
			if decoded is None:
				continue
			sectionStatus, datums = decoded
			if not datums and sectionStatus.status in ("empty", "unsupported"):
				continue
			rows = tuple(self._resultRow(fieldId, result, protection) for fieldId, result in datums)
			children = tuple(
				StructuredPropertyNode(
					key=f"{sectionId}.{row.fieldKey}",
					label=row.name,
					status=row.status,
					value=row.value,
				)
				for row in rows
			)
			if not children:
				statusRow = self._resultRow(f"{sectionId}.section", sectionStatus, protection)
				children = (
					StructuredPropertyNode(
						key=statusRow.fieldKey,
						label="Status",
						status=statusRow.status,
						value=statusRow.value,
					),
				)
			sections.append(
				StructuredPropertyNode(
					key=f"providers.{sectionId}",
					label=_fieldLabel(sectionId),
					status=PropertyStatus.VALUE,
					children=children,
				),
			)
		if not sections:
			return ()
		return (
			StructuredPropertyNode(
				key="providers",
				label="Providers",
				status=PropertyStatus.VALUE,
				children=tuple(sections),
			),
		)

	def _otherApi(self, nodeId: str, protection: ProtectionEvidence) -> PropertyFetch:
		metadata = self._providerMetadata(nodeId)
		if metadata.status != "value":
			return PropertyFetch(
				nodeId,
				PropertyCategory.OTHER_API,
				rows=(self._resultRow("otherApi.section", metadata, protection),),
			)
		rows: list[PropertyRow] = []
		for sectionId in ("generic", "overlay", "rawUia"):
			decoded = providerSectionDatums(metadata.value, sectionId)
			if decoded is None:
				continue
			sectionStatus, datums = decoded
			if not datums and sectionStatus.status in ("empty", "unsupported"):
				continue
			rows.extend(
				self._resultRow(f"{sectionId}.{fieldId}", result, protection) for fieldId, result in datums
			)
		if not rows:
			rows.append(
				PropertyRow(
					fieldKey="otherApi.section",
					name="Other API",
					status=PropertyStatus.NOT_APPLICABLE,
					source="live",
				),
			)
		return PropertyFetch(nodeId, PropertyCategory.OTHER_API, rows=tuple(rows))

	def close(self) -> None:
		if self._closed:
			return
		self._closed = True
		self._children.clear()
		self._depths.clear()
		self._session.close()

	def _initialSpine(self) -> tuple[str, ...]:
		if self._spine is not None:
			return self._spine
		chain = (*self._focusAncestorRefs, self._targetRef)
		start = next(
			(index for index, candidate in enumerate(chain) if self._same(candidate, self._foregroundRef)),
			None,
		)
		if start is None:
			fallback, examined = self._spatialPathToTarget()
			unresolvedLink = fallback is None and not self._same(self._foregroundRef, self._targetRef)
			self._spine = fallback or (
				(self._foregroundRef, self._targetRef) if unresolvedLink else (self._foregroundRef,)
			)
			self._recordSpineDepths()
			self._traceSpine(
				len(chain),
				self._same(self._spine[-1], self._targetRef),
				fallback is not None,
				examined,
				unresolvedLink,
			)
			return self._spine
		current = self._foregroundRef
		spine = [current]
		index = start + 1
		while index < len(chain):
			if self._same(current, chain[index]):
				index += 1
				continue
			children = self._childRefs(current).nodeRefs
			match: tuple[str, int] | None = None
			for candidateIndex in range(index, len(chain)):
				candidate = chain[candidateIndex]
				for childRef in children:
					if self._same(childRef, candidate):
						match = (childRef, candidateIndex)
						break
				if match is not None:
					break
			if match is None:
				break
			current, index = match[0], match[1] + 1
			self._depths[current] = len(spine)
			spine.append(current)
		fallbackUsed = False
		unresolvedLink = False
		examined = 0
		if not self._same(spine[-1], self._targetRef):
			fallback, examined = self._spatialPathToTarget()
			if fallback is not None:
				spine = list(fallback)
				fallbackUsed = True
			else:
				spine.append(self._targetRef)
				unresolvedLink = True
		self._spine = tuple(spine)
		self._recordSpineDepths()
		self._traceSpine(
			len(chain),
			self._same(self._spine[-1], self._targetRef),
			fallbackUsed,
			examined,
			unresolvedLink,
		)
		return self._spine

	def _recordSpineDepths(self) -> None:
		for depth, nodeRef in enumerate(self._spine or ()):
			self._depths[nodeRef] = depth

	def _traceSpine(
		self,
		chainCount: int,
		targetMatched: bool,
		fallbackUsed: bool,
		examined: int,
		unresolvedLink: bool,
	) -> None:
		if self._diagnostic is None:
			return
		self._diagnostic(
			"Keystone Inspector: spine.resolved; "
			+ f"chainCount={chainCount}, examined={examined}, fallbackUsed={str(fallbackUsed).lower()}, "
			+ f"spineDepth={len(self._spine or ())}, targetMatched={str(targetMatched).lower()}, "
			+ f"unresolvedLink={str(unresolvedLink).lower()}",
		)

	@staticmethod
	def _plainRect(value: object) -> tuple[int, int, int, int] | None:
		if not isinstance(value, tuple):
			return None
		plainParts = cast(tuple[object, ...], value)
		if len(plainParts) != 4:
			return None
		parts = plainParts
		if not all(type(part) in (int, float) for part in parts):
			return None
		left, top, width, height = cast(
			tuple[int | float, int | float, int | float, int | float],
			parts,
		)
		if width <= 0 or height <= 0:
			return None
		return int(left), int(top), int(width), int(height)

	def _nodeRect(self, nodeRef: str) -> tuple[int, int, int, int] | None:
		result = self._field(nodeRef, "geometry")
		return self._plainRect(result.value) if result.status == "value" else None

	def _spatialPathToTarget(self) -> tuple[tuple[str, ...] | None, int]:
		targetRect = self._nodeRect(self._targetRef)
		if targetRect is None:
			return None, 0
		targetPoint = (
			targetRect[0] + targetRect[2] // 2,
			targetRect[1] + targetRect[3] // 2,
		)
		stack: list[tuple[str, tuple[str, ...], int]] = [
			(self._foregroundRef, (self._foregroundRef,), 0),
		]
		visited: set[str] = set()
		examined = 0
		while stack and examined < 300:
			nodeRef, path, depth = stack.pop()
			if nodeRef in visited:
				continue
			visited.add(nodeRef)
			examined += 1
			if self._same(nodeRef, self._targetRef):
				for index, pathRef in enumerate(path):
					self._depths[pathRef] = index
				return path, examined
			if depth >= 24:
				continue
			children = self._childRefs(nodeRef).nodeRefs
			for childRef in reversed(children):
				rect = self._nodeRect(childRef)
				containsTarget = rect is None or (
					rect[0] <= targetPoint[0] < rect[0] + rect[2]
					and rect[1] <= targetPoint[1] < rect[1] + rect[3]
				)
				if containsTarget:
					stack.append((childRef, (*path, childRef), depth + 1))
		return None, examined

	def _same(self, firstRef: str, secondRef: str) -> bool:
		result = self._session.compareIdentity(
			IdentityComparisonRequest(
				firstRef,
				secondRef,
				self._providerScope,
				self._processScope,
				self._budget(),
				self._context,
			),
		)
		return result.status == "value" and result.decision == "same"

	def _childRefs(self, nodeRef: str) -> ProviderChildBatch:
		cached = self._children.get(nodeRef)
		if cached is not None:
			return cached
		request = ProviderChildrenRequest(nodeRef, self._budget(), self._context)
		ordinary = self._session.readChildren(request)
		logical = self._session.readLogicalFirstChild(request)
		nodeRefs = list(ordinary.nodeRefs if ordinary.status in ("value", "empty") else ())
		for logicalRef in logical.nodeRefs if logical.status in ("value", "empty") else ():
			if not any(self._same(existingRef, logicalRef) for existingRef in nodeRefs):
				nodeRefs.append(logicalRef)
		if nodeRefs:
			batch = ProviderChildBatch(
				"value",
				tuple(nodeRefs),
				max(ordinary.observedCount, len(ordinary.nodeRefs)) + len(nodeRefs) - len(ordinary.nodeRefs),
				ordinary.truncated or logical.truncated,
			)
		elif ordinary.status not in ("value", "empty"):
			batch = ordinary
		else:
			batch = ProviderChildBatch(
				"empty",
				(),
				ordinary.observedCount,
				ordinary.truncated or logical.truncated,
			)
		if batch.status in ("value", "empty"):
			self._children[nodeRef] = batch
			depth = self._depths.get(nodeRef, 0) + 1
			for childRef in batch.nodeRefs:
				_ = self._depths.setdefault(childRef, depth)
		return batch

	def _childRefsForDisclosure(
		self,
		nodeRef: str,
		batch: ProviderChildBatch,
	) -> tuple[str, ...]:
		nodeRefs = list(batch.nodeRefs if batch.status in ("value", "empty") else ())
		spine = self._initialSpine()
		try:
			index = spine.index(nodeRef)
		except ValueError:
			return tuple(nodeRefs)
		if index + 1 >= len(spine):
			return tuple(nodeRefs)
		successor = spine[index + 1]
		for childIndex, childRef in enumerate(nodeRefs):
			if self._same(childRef, successor):
				nodeRefs[childIndex] = successor
				break
		else:
			nodeRefs.append(successor)
		return tuple(nodeRefs)

	def _facet(
		self,
		nodeRef: str,
		parentRef: str | None,
		depth: int,
		*,
		deferChildProbe: bool = False,
	) -> NodeFacet:
		protection = self._protection(nodeRef)
		name = self._row(nodeRef, "name", protection)
		role = self._row(nodeRef, "role", protection)
		childCount = self._field(nodeRef, "childCount")
		childHint = (
			childCount.status == "value"
			and isinstance(childCount.value, int)
			and not isinstance(childCount.value, bool)
			and childCount.value > 0
		)
		if not childHint:
			if deferChildProbe:
				# Keep the expander available so an explicit request can discover logical children.
				childHint = True
			else:
				children = self._childRefs(nodeRef)
				childHint = bool(children.nodeRefs) or children.truncated
		return NodeFacet(
			nodeRef,
			parentRef,
			depth,
			name.value or "",
			name.status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED) and bool(name.value),
			role.value or "object",
			childHint,
		)

	def _protection(self, nodeRef: str) -> ProtectionEvidence:
		result = self._field(nodeRef, "protection")
		if result.status == "value" and result.value is True:
			return ProtectionEvidence(True)
		if result.status == "value" and result.value is False:
			return ProtectionEvidence.allClear()
		return ProtectionEvidence()

	def _field(self, nodeRef: str, fieldId: str):
		return self._session.readField(
			ProviderFieldRequest(nodeRef, fieldId, self._budget(), self._context),
		)

	def _rows(
		self,
		nodeRef: str,
		fields: tuple[str, ...],
		protection: ProtectionEvidence,
	) -> tuple[PropertyRow, ...]:
		return tuple(self._row(nodeRef, fieldId, protection) for fieldId in fields)

	def _row(
		self,
		nodeRef: str,
		fieldId: str,
		protection: ProtectionEvidence,
	) -> PropertyRow:
		result = self._field(nodeRef, fieldId)
		status = {
			"value": PropertyStatus.TRUNCATED if result.truncated else PropertyStatus.VALUE,
			"empty": PropertyStatus.EMPTY,
			"unsupported": PropertyStatus.UNSUPPORTED,
			"unavailable": PropertyStatus.UNAVAILABLE,
			"stale": PropertyStatus.STALE,
			"failed": PropertyStatus.FAILED,
		}[result.status]
		value: str | None = None
		if result.status == "value":
			transformed = transformValue(
				ObservedValue(
					FieldGroup.TEXT if fieldId in ("name", "description", "value") else FieldGroup.NODE,
					result.value,
					PrivacyClass.PUBLIC,
					protection,
					f"live-{fieldId}",
				),
				SinkId.GUI,
				self._privacyPolicy,
			)
			if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
				status = PropertyStatus.REDACTED
			else:
				value = _renderPlainScalar(transformed.value)
				if not value:
					status = PropertyStatus.EMPTY
					value = None
		return PropertyRow(fieldId, _fieldLabel(fieldId), status, value, "live")

	def _providerSection(
		self,
		nodeId: str,
		category: PropertyCategory,
		protection: ProtectionEvidence,
	) -> PropertyFetch:
		section = _CATEGORY_SECTION[category]
		result = self._providerMetadata(nodeId)
		if result.status == "value":
			decoded = providerSectionDatums(result.value, section)
			if decoded is None:
				result = ProviderReadResult("failed", errorCode="KS.PROVIDER.SECTIONS_MALFORMED")
			else:
				sectionStatus, datums = decoded
				if category is PropertyCategory.SUPPORTED_UIA_PATTERNS:
					datums = _supportedPatternFields(datums)
				if datums:
					return PropertyFetch(
						nodeId,
						category,
						rows=tuple(self._resultRow(fieldId, datum, protection) for fieldId, datum in datums),
					)
				result = (
					ProviderReadResult("empty")
					if category is PropertyCategory.SUPPORTED_UIA_PATTERNS
					else sectionStatus
				)
		return PropertyFetch(
			nodeId,
			category,
			rows=(self._resultRow(f"{section}.section", result, protection),),
		)

	def _resultRow(
		self,
		fieldId: str,
		result: ProviderReadResult,
		protection: ProtectionEvidence,
	) -> PropertyRow:
		status = {
			"value": PropertyStatus.TRUNCATED if result.truncated else PropertyStatus.VALUE,
			"empty": PropertyStatus.EMPTY,
			"unsupported": PropertyStatus.UNSUPPORTED,
			"unavailable": PropertyStatus.UNAVAILABLE,
			"stale": PropertyStatus.STALE,
			"failed": PropertyStatus.FAILED,
		}[result.status]
		value: str | None = None
		if result.status == "value":
			transformed = transformValue(
				ObservedValue(
					FieldGroup.NODE,
					result.value,
					PrivacyClass.PUBLIC,
					protection,
					f"live-{fieldId}",
				),
				SinkId.GUI,
				self._privacyPolicy,
			)
			if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
				status = PropertyStatus.REDACTED
			else:
				value = _renderPlainScalar(transformed.value)
				if not value:
					status = PropertyStatus.EMPTY
					value = None
		return PropertyRow(fieldId, _fieldLabel(fieldId), status, value, "live")

	@staticmethod
	def _categoryFields(category: PropertyCategory) -> tuple[str, ...] | None:
		return _categoryFields(category)

	@staticmethod
	def _budget() -> ReadBudget:
		return ReadBudget(128, 4_096, 250)


class SnapshotNodeReader:
	"""Concrete :class:`LiveNodeReader` backed by an in-memory capture of the live target.

	The runtime captures the currently selected object through the real read-only provider seam
	(nothing written to disk, nothing published, no baseline replaced) and hands the resulting
	in-memory ``SnapshotView`` here. Every envelope in that view was already privacy-transformed at
	capture time, so projecting it is safe. Structure and property projection therefore reuse the
	validated offline projection unchanged, while this reader presents a *live* identity so the
	service keeps Follow Focus available and neither the service nor the workspace ever learns it is
	reading a materialised capture rather than walking the tree itself.
	"""

	def __init__(
		self,
		view: SnapshotView,
		targetKey: str,
		*,
		label: str,
		executable: str,
		processId: int,
		backend: str,
		rawApplied: bool = False,
		rawReason: str | None = None,
	) -> None:
		super().__init__()
		self._identity = InspectorSourceIdentity(
			kind=InspectorSourceKind.LIVE,
			label=label,
			executable=executable,
			processId=processId,
			backend=backend,
			rawApplied=rawApplied,
			rawReason=rawReason,
		)
		self._projection = OfflineInspectorSource(
			view,
			targetKey,
			label=label,
			executable=executable,
			processId=processId,
			backend=backend,
		)

	def identity(self) -> InspectorSourceIdentity:
		return self._identity

	def applyPrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None:
		"""Ignore later policy changes: a snapshot is evidence that was already transformed.

		Its rows carry the redaction that produced them, and re-transforming them now would relabel
		stored evidence with a policy that was not in force when it was captured.
		"""

		_ = privacyPolicy

	def roots(self) -> tuple[NodeFacet, ...]:
		return self._projection.roots()

	def children(self, nodeId: str) -> ChildFetch:
		return self._projection.children(nodeId)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		return self._projection.properties(nodeId, category)

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		return self._projection.annotations(nodeId)

	def close(self) -> None:
		self._projection.close()
