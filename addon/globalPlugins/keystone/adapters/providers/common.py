from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from math import isfinite
from time import monotonic_ns
from typing import Protocol, cast

from ...capability import PlainValue
from ...domain.document_records import PROVIDER_SECTIONS
from ...domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	annotationRecordsPlain,
)
from ...ports.providers import ProviderReadResult, ReadBudget


PROVIDER_SECTIONS_METADATA_ID = "providerSections"
_MAXIMUM_PLAIN_ITEMS = 4_096
_MAXIMUM_PLAIN_TEXT_LENGTH = 16_384
_MAXIMUM_PLAIN_DEPTH = 64
_MAXIMUM_ANNOTATION_DEPTH = 4

_COMMON_ATTRIBUTES: dict[str, str] = {
	"name": "name",
	"role": "role",
	"roleText": "roleText",
	"states": "states",
	"description": "description",
	"value": "value",
	"geometry": "location",
	"windowHandle": "windowHandle",
	"windowClass": "windowClassName",
	"windowControlId": "windowControlID",
	"childCount": "childCount",
	"indexInParent": "indexInParent",
	"keyboardShortcut": "keyboardShortcut",
	"position": "positionInfo",
	"table": "table",
	"process": "processID",
	"focusable": "isFocusable",
	"focused": "hasFocus",
	"privacy": "isProtected",
	"validation": "validationStatus",
	"placeholder": "placeholder",
	"landmark": "landmark",
	"currentState": "current",
	"descriptionSource": "descriptionSource",
	"liveRegion": "liveRegionPoliteness",
	"math": "mathMl",
	"annotations": "annotations",
	"developerInformation": "devInfo",
	"apiDetails": "apiDetails",
	"protection": "isProtected",
}

_GENERIC_METADATA_ATTRIBUTES: tuple[tuple[str, str], ...] = (
	("namedActions", "actionNames"),
	("defaultAction", "defaultAction"),
	("textInfoDocument", "textInfoDocument"),
	("textInfoSelection", "textInfoSelection"),
	("relations", "relations"),
)

_ALLOWED_OBJECT_ATTRIBUTES = frozenset(_COMMON_ATTRIBUTES.values()) | frozenset(
	name for _field, name in _GENERIC_METADATA_ATTRIBUTES
)


@dataclass(frozen=True, slots=True)
class ObjectRead:
	status: str
	value: object | None = None
	errorCode: str | None = None
	hresult: int | None = None

	def __post_init__(self) -> None:
		if self.status not in ("value", "empty", "unsupported", "unavailable", "stale", "failed"):
			raise ValueError("object read status is not supported")
		if self.status == "value" and self.value is None:
			raise ValueError("value object reads require a live value")
		if self.status != "value" and self.value is not None:
			raise ValueError("non-value object reads cannot expose a live value")
		if self.status in ("unavailable", "stale", "failed") and self.errorCode is None:
			raise ValueError(f"{self.status} object reads require an error code")
		if self.hresult is not None and type(self.hresult) is not int:
			raise ValueError("object read HRESULT must be an integer")


@dataclass(frozen=True, slots=True)
class ObjectBatch:
	status: str
	values: tuple[object, ...]
	observedCount: int
	truncated: bool
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("value", "empty", "unavailable", "stale", "failed"):
			raise ValueError("object batch status is not supported")
		if self.observedCount < len(self.values) or self.observedCount < 0:
			raise ValueError("observed object count cannot be smaller than retained values")
		if self.status in ("unavailable", "stale", "failed") and self.errorCode is None:
			raise ValueError(f"{self.status} object batches require an error code")
		if self.status in ("unavailable", "stale") and (self.values or self.observedCount or self.truncated):
			raise ValueError(f"{self.status} object batches cannot carry observed children")
		if self.status == "failed" and self.values and not self.truncated:
			raise ValueError("failed object batches with retained children must be truncated")


class ObjectGetterPort(Protocol):
	def readAttribute(self, target: object, member: str, budget: ReadBudget) -> ProviderReadResult: ...

	def readChildren(self, target: object, budget: ReadBudget) -> ObjectBatch: ...

	def readLogicalFirstChild(self, target: object, budget: ReadBudget) -> ObjectBatch: ...


@dataclass(frozen=True, slots=True)
class AnnotationTargetIdentity:
	"""Identity already proven by the Inspector source that owns the target object."""

	nodeId: str
	description: str
	proven: bool


type AnnotationIdentityResolver = Callable[[object], AnnotationTargetIdentity | None]
type MonotonicMilliseconds = Callable[[], int]


class _ReadBudgetExceeded(Exception):
	pass


def _milliseconds() -> int:
	return monotonic_ns() // 1_000_000


class _ElapsedReadBudget:
	def __init__(
		self,
		maximumMilliseconds: int | None,
		clockMilliseconds: MonotonicMilliseconds,
	) -> None:
		super().__init__()
		self._maximumMilliseconds = maximumMilliseconds
		self._clock = clockMilliseconds
		self._started = clockMilliseconds()

	def requireTimeRemaining(self) -> None:
		if self._maximumMilliseconds is None:
			return
		elapsed = max(0, self._clock() - self._started)
		if elapsed >= self._maximumMilliseconds:
			raise _ReadBudgetExceeded


def _boundedValues(
	values: Iterable[object],
	maximumItems: int,
	timeBudget: _ElapsedReadBudget,
) -> Iterator[object]:
	iterator = iter(values)
	for _ in range(maximumItems):
		timeBudget.requireTimeRemaining()
		try:
			value = next(iterator)
		except StopIteration:
			return
		timeBudget.requireTimeRemaining()
		yield value


def _nextValue(values: Iterator[object], timeBudget: _ElapsedReadBudget) -> object | None:
	timeBudget.requireTimeRemaining()
	try:
		value = next(values)
	except StopIteration:
		return None
	timeBudget.requireTimeRemaining()
	return value


def _enumValue(value: Enum) -> PlainValue:
	raw = value.value
	if type(raw) is float and not isfinite(raw):
		raise ValueError("provider value must be finite")
	if type(raw) in (bool, int, float, str):
		return cast(PlainValue, raw)
	return value.name


def normalizeProviderValue(
	value: object,
	*,
	maximumItems: int,
	maximumTextLength: int,
	maximumMilliseconds: int | None = None,
	clockMilliseconds: MonotonicMilliseconds = _milliseconds,
) -> tuple[PlainValue, bool]:
	"""Convert a provider value without repr, dispatch, or live-object escape."""
	try:
		return _normalizeProviderValue(
			value,
			maximumItems=maximumItems,
			maximumTextLength=maximumTextLength,
			timeBudget=_ElapsedReadBudget(maximumMilliseconds, clockMilliseconds),
			depth=0,
			activeContainers=set(),
		)
	except _ReadBudgetExceeded:
		return (), True


def _normalizeProviderValue(
	value: object,
	*,
	maximumItems: int,
	maximumTextLength: int,
	timeBudget: _ElapsedReadBudget,
	depth: int,
	activeContainers: set[int],
) -> tuple[PlainValue, bool]:
	timeBudget.requireTimeRemaining()
	if depth > _MAXIMUM_PLAIN_DEPTH:
		raise ValueError("provider value exceeds the depth limit")
	itemLimit = min(maximumItems, _MAXIMUM_PLAIN_ITEMS)
	textLimit = min(maximumTextLength, _MAXIMUM_PLAIN_TEXT_LENGTH)
	if type(value) is float and not isfinite(value):
		raise ValueError("provider value must be finite")
	if value is None or type(value) in (bool, int, float):
		return cast(PlainValue, value), False
	if isinstance(value, str):
		return value[:textLimit], len(value) > textLimit
	if isinstance(value, bytes):
		limit = min(maximumTextLength, 16 * 1024 * 1024)
		return value[:limit], len(value) > limit
	if isinstance(value, Enum):
		return _enumValue(value), False
	if isinstance(value, dict):
		mapping = cast(Mapping[object, object], value)
		containerId = id(mapping)
		if containerId in activeContainers:
			raise ValueError("provider value contains a cycle")
		activeContainers.add(containerId)
		try:
			items: list[PlainValue] = []
			try:
				stringKeys: list[str] = []
				for key in mapping:
					timeBudget.requireTimeRemaining()
					if isinstance(key, str):
						stringKeys.append(key)
				timeBudget.requireTimeRemaining()
				stringKeys.sort(key=lambda item: item.encode("utf-8"))
				timeBudget.requireTimeRemaining()
			except _ReadBudgetExceeded:
				return tuple(items), True
			truncated = len(mapping) > itemLimit or len(stringKeys) != len(mapping)
			normalizedKeys: set[str] = set()
			for key in stringKeys[:itemLimit]:
				try:
					normalized, childTruncated = _normalizeProviderValue(
						mapping[key],
						maximumItems=itemLimit,
						maximumTextLength=textLimit,
						timeBudget=timeBudget,
						depth=depth + 1,
						activeContainers=activeContainers,
					)
				except _ReadBudgetExceeded:
					return tuple(items), True
				normalizedKey = key[:textLimit]
				if normalizedKey in normalizedKeys:
					raise ValueError("provider mapping keys collide after truncation")
				normalizedKeys.add(normalizedKey)
				items.append((normalizedKey, normalized))
				truncated = truncated or childTruncated or len(key) > textLimit
			return tuple(items), truncated
		finally:
			activeContainers.remove(containerId)
	if isinstance(value, Iterable):
		if isinstance(value, (str, bytes)):
			raise AssertionError("text values must be normalized before iterable values")
		iterable = cast(Iterable[object], value)
		containerId = id(iterable)
		if containerId in activeContainers:
			raise ValueError("provider value contains a cycle")
		activeContainers.add(containerId)
		try:
			items = []
			truncated = False
			try:
				iterator = iter(iterable)
				while len(items) < itemLimit:
					timeBudget.requireTimeRemaining()
					try:
						item = next(iterator)
					except StopIteration:
						break
					normalized, childTruncated = _normalizeProviderValue(
						item,
						maximumItems=itemLimit,
						maximumTextLength=textLimit,
						timeBudget=timeBudget,
						depth=depth + 1,
						activeContainers=activeContainers,
					)
					items.append(normalized)
					truncated = truncated or childTruncated
				if len(items) == itemLimit:
					timeBudget.requireTimeRemaining()
					try:
						_ = next(iterator)
					except StopIteration:
						pass
					else:
						truncated = True
			except _ReadBudgetExceeded:
				return tuple(items), True
			return tuple(items), truncated
		finally:
			activeContainers.remove(containerId)
	raise TypeError("provider value is not safely normalizable")


def normalizeProviderRead(value: object, budget: ReadBudget) -> ProviderReadResult:
	if value is None:
		return ProviderReadResult("empty")
	plain, truncated = normalizeProviderValue(
		value,
		maximumItems=budget.maximumItems,
		maximumTextLength=budget.maximumTextLength,
		maximumMilliseconds=budget.maximumMilliseconds,
	)
	return ProviderReadResult("value", plain, truncated=truncated)


def _nvdaEnumLabel(value: object) -> object:
	"""Prefer NVDA's localized label for its role and state enums."""
	if not isinstance(value, Enum):
		return value
	displayString = getattr(value, "displayString", None)
	if isinstance(displayString, str) and displayString:
		return displayString
	return value.name


def _nvdaSemanticValue(member: str, value: object) -> object:
	if member == "role":
		return _nvdaEnumLabel(value)
	if member != "states" or isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
		return value
	return tuple(_nvdaEnumLabel(item) for item in cast(Iterable[object], value))


def _annotationStatus(error: Exception) -> AnnotationStatus:
	if isinstance(error, ReferenceError):
		return AnnotationStatus.STALE
	if isinstance(error, LookupError):
		return AnnotationStatus.UNAVAILABLE
	return AnnotationStatus.FAILED


def _annotationText(
	value: object,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
) -> str | None:
	if value is None:
		return None
	value = _nvdaEnumLabel(value)
	if not isinstance(value, str):
		value = str(value) if isinstance(value, (bool, int, float)) else None
	if value is None:
		return None
	normalized = " ".join(value.split())
	if not normalized:
		return None
	transformed = " ".join(privacyTransform(normalized).split())
	if not transformed:
		return None
	limit = min(budget.maximumTextLength, _MAXIMUM_PLAIN_TEXT_LENGTH)
	if len(transformed) <= limit:
		return transformed
	if limit <= 3:
		return "." * limit
	return transformed[: limit - 3].rstrip() + "..."


def _annotationKey(path: str, localKey: str) -> str:
	return f"{path}/{localKey}" if path else localKey


def _annotationAttribute(target: object, primary: str, fallback: str) -> object:
	missing = object()
	value = getattr(target, primary, missing)
	return getattr(target, fallback, None) if value is missing else value


def _annotationTargetRecord(
	target: object,
	*,
	key: str,
	typeId: str | None,
	typeName: object,
	source: str,
	summary: object = None,
	relationship: object = None,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
	identityResolver: AnnotationIdentityResolver | None,
	depth: int,
	visited: set[int],
	timeBudget: _ElapsedReadBudget,
) -> AnnotationRecord:
	timeBudget.requireTimeRemaining()
	name = _annotationText(
		_annotationAttribute(target, "name", "currentName"),
		budget,
		privacyTransform,
	)
	timeBudget.requireTimeRemaining()
	role = _annotationText(
		_annotationAttribute(target, "role", "currentControlType"),
		budget,
		privacyTransform,
	)
	timeBudget.requireTimeRemaining()
	identity = identityResolver(target) if identityResolver is not None else None
	timeBudget.requireTimeRemaining()
	related = (
		_collectAnnotationValues(
			target,
			budget=budget,
			privacyTransform=privacyTransform,
			identityResolver=identityResolver,
			depth=depth + 1,
			visited=visited,
			includeEmpty=False,
			path=key,
			timeBudget=timeBudget,
		)
		if depth < _MAXIMUM_ANNOTATION_DEPTH
		else ()
	)
	timeBudget.requireTimeRemaining()
	resolvedTypeId = _annotationText(typeId, budget, privacyTransform)
	resolvedTypeName = _annotationText(typeName, budget, privacyTransform) or "Annotation"
	resolvedSummary = _annotationText(summary, budget, privacyTransform)
	timeBudget.requireTimeRemaining()
	author = _annotationText(
		_annotationAttribute(target, "author", "annotationAuthor"),
		budget,
		privacyTransform,
	)
	timeBudget.requireTimeRemaining()
	dateTime = _annotationText(
		_annotationAttribute(target, "dateTime", "annotationDateTime"),
		budget,
		privacyTransform,
	)
	timeBudget.requireTimeRemaining()
	targetIdentity = (
		_annotationText(identity.description, budget, privacyTransform) if identity is not None else None
	)
	timeBudget.requireTimeRemaining()
	resolvedRelationship = _annotationText(relationship, budget, privacyTransform)
	return AnnotationRecord(
		key=key,
		status=AnnotationStatus.VALUE,
		typeId=resolvedTypeId,
		typeName=resolvedTypeName,
		source=source,
		summary=resolvedSummary,
		author=author,
		dateTime=dateTime,
		targetName=name,
		targetRole=role,
		targetIdentity=targetIdentity,
		targetNodeId=identity.nodeId if identity is not None and identity.proven else None,
		targetIdentityProven=bool(identity is not None and identity.proven),
		relationship=resolvedRelationship,
		related=related,
	)


def _appendAnnotationTargetRecord(
	records: list[AnnotationRecord],
	build: Callable[[], AnnotationRecord],
	*,
	key: str,
	typeName: str,
	source: str,
	timeBudget: _ElapsedReadBudget,
) -> None:
	try:
		timeBudget.requireTimeRemaining()
		records.append(build())
	except _ReadBudgetExceeded:
		raise
	except Exception as error:
		records.append(
			_exceptionRecord(
				error,
				key=key,
				typeName=typeName,
				source=source,
			),
		)


def _exceptionRecord(
	error: Exception,
	*,
	key: str,
	typeName: str,
	source: str,
) -> AnnotationRecord:
	return AnnotationRecord(
		key=key,
		status=_annotationStatus(error),
		typeName=typeName,
		source=source,
	)


def _boundedAnnotationRecords(
	records: list[AnnotationRecord],
	*,
	budget: ReadBudget,
	path: str,
	depth: int,
) -> tuple[AnnotationRecord, ...]:
	if len(records) <= budget.maximumItems:
		return tuple(records)
	return (
		*records[: budget.maximumItems - 1],
		AnnotationRecord(
			key=_annotationKey(path, f"annotations-{depth}-truncated"),
			status=AnnotationStatus.TRUNCATED,
			typeName="Annotations",
			source="NVDA annotations",
		),
	)


def _annotationsTruncated(records: tuple[AnnotationRecord, ...]) -> bool:
	return any(
		record.status is AnnotationStatus.TRUNCATED or _annotationsTruncated(record.related)
		for record in records
	)


def _collectAnnotationValues(
	target: object,
	*,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
	identityResolver: AnnotationIdentityResolver | None,
	depth: int,
	visited: set[int],
	includeEmpty: bool,
	path: str,
	timeBudget: _ElapsedReadBudget,
) -> tuple[AnnotationRecord, ...]:
	objectIdentity = id(target)
	if objectIdentity in visited:
		return ()
	visited.add(objectIdentity)
	records: list[AnnotationRecord] = []
	try:
		return _collectAnnotationValuesInner(
			target,
			budget=budget,
			privacyTransform=privacyTransform,
			identityResolver=identityResolver,
			depth=depth,
			visited=visited,
			includeEmpty=includeEmpty,
			path=path,
			timeBudget=timeBudget,
			records=records,
		)
	except _ReadBudgetExceeded:
		if len(records) < budget.maximumItems:
			records.append(
				AnnotationRecord(
					key=_annotationKey(path, f"annotations-{depth}-timeout"),
					status=AnnotationStatus.FAILED,
					typeName="Annotations",
					source="NVDA annotations",
				),
			)
		return _boundedAnnotationRecords(records, budget=budget, path=path, depth=depth)


def _collectAnnotationValuesInner(
	target: object,
	*,
	budget: ReadBudget,
	privacyTransform: Callable[[str], str],
	identityResolver: AnnotationIdentityResolver | None,
	depth: int,
	visited: set[int],
	includeEmpty: bool,
	path: str,
	timeBudget: _ElapsedReadBudget,
	records: list[AnnotationRecord],
) -> tuple[AnnotationRecord, ...]:
	supportedSurfaces = 0

	timeBudget.requireTimeRemaining()
	try:
		origin = getattr(target, "annotations")
	except (AttributeError, NotImplementedError):
		origin = None
	except _ReadBudgetExceeded:
		raise
	except Exception as error:
		supportedSurfaces += 1
		records.append(
			_exceptionRecord(
				error,
				key=_annotationKey(path, f"annotations-{depth}-failed"),
				typeName="Annotations",
				source="NVDA annotations",
			),
		)
	else:
		supportedSurfaces += 1
		if origin is not None:
			try:
				hasAnnotations = bool(origin)
				timeBudget.requireTimeRemaining()
				targets = cast(Iterable[object], origin.targets) if hasAnnotations else ()
				timeBudget.requireTimeRemaining()
				roles = iter(cast(Iterable[object], origin.roles)) if hasAnnotations else iter(())
				for index, annotationTarget in enumerate(
					_boundedValues(targets, budget.maximumItems, timeBudget),
				):
					key = _annotationKey(path, f"nvda-{depth}-{index}")
					relationship = _nextValue(roles, timeBudget)
					_appendAnnotationTargetRecord(
						records,
						lambda: _annotationTargetRecord(
							cast(object, getattr(annotationTarget, "targetObject")),
							key=_annotationKey(path, f"nvda-{depth}-{index}"),
							typeId=None,
							typeName=getattr(annotationTarget, "role", "Annotation"),
							source="NVDA annotations",
							summary=getattr(annotationTarget, "summary", None),
							relationship=relationship,
							budget=budget,
							privacyTransform=privacyTransform,
							identityResolver=identityResolver,
							depth=depth,
							visited=visited,
							timeBudget=timeBudget,
						),
						key=key,
						typeName="Annotations",
						source="NVDA annotations",
						timeBudget=timeBudget,
					)
			except _ReadBudgetExceeded:
				raise
			except Exception as error:
				records.append(
					_exceptionRecord(
						error,
						key=_annotationKey(path, f"annotations-{depth}-failed"),
						typeName="Annotations",
						source="NVDA annotations",
					),
				)

	timeBudget.requireTimeRemaining()
	try:
		annotationObjects = getattr(target, "UIAAnnotationObjects")
	except (AttributeError, NotImplementedError):
		annotationObjects = None
	except _ReadBudgetExceeded:
		raise
	except Exception as error:
		supportedSurfaces += 1
		records.append(
			_exceptionRecord(
				error,
				key=_annotationKey(path, f"uia-objects-{depth}-failed"),
				typeName="UIA annotation objects",
				source="UIA AnnotationObjects",
			),
		)
	else:
		if annotationObjects is not None:
			supportedSurfaces += 1
			if isinstance(annotationObjects, Mapping):
				items = cast(Iterable[object], cast(Mapping[object, object], annotationObjects).items())
			else:
				items = cast(Iterable[object], enumerate(cast(Iterable[object], annotationObjects)))
			for index, item in enumerate(_boundedValues(items, budget.maximumItems, timeBudget)):
				typeId, annotationTarget = cast(tuple[object, object], item)
				key = _annotationKey(path, f"uia-{depth}-{index}")
				_appendAnnotationTargetRecord(
					records,
					lambda: _annotationTargetRecord(
						annotationTarget,
						key=_annotationKey(path, f"uia-{depth}-{index}"),
						typeId=str(typeId),
						typeName=getattr(annotationTarget, "annotationTypeName", "UIA annotation"),
						source="UIA AnnotationObjects",
						summary=getattr(annotationTarget, "summary", None),
						relationship="annotationObject",
						budget=budget,
						privacyTransform=privacyTransform,
						identityResolver=identityResolver,
						depth=depth,
						visited=visited,
						timeBudget=timeBudget,
					),
					key=key,
					typeName="UIA annotation objects",
					source="UIA AnnotationObjects",
					timeBudget=timeBudget,
				)

	for member in ("textRunAnnotationTypes", "UIAAnnotationTypes"):
		timeBudget.requireTimeRemaining()
		try:
			textTypes = getattr(target, member)
		except (AttributeError, NotImplementedError):
			continue
		except _ReadBudgetExceeded:
			raise
		except Exception as error:
			supportedSurfaces += 1
			records.append(
				_exceptionRecord(
					error,
					key=_annotationKey(path, f"text-{depth}-failed"),
					typeName="Text-run annotations",
					source="UIA text",
				),
			)
			break
		supportedSurfaces += 1
		if isinstance(textTypes, (str, bytes)) or not isinstance(textTypes, Iterable):
			continue
		for index, annotationType in enumerate(
			_boundedValues(cast(Iterable[object], textTypes), budget.maximumItems, timeBudget),
		):
			try:
				typeName = _annotationText(annotationType, budget, privacyTransform)
				if typeName is not None:
					records.append(
						AnnotationRecord(
							key=_annotationKey(path, f"text-{depth}-{index}"),
							status=AnnotationStatus.VALUE,
							typeId=typeName,
							typeName=typeName,
							source="UIA text",
							relationship="textRun",
						),
					)
			except Exception as error:
				records.append(
					_exceptionRecord(
						error,
						key=_annotationKey(path, f"text-{depth}-{index}"),
						typeName="Text-run annotations",
						source="UIA text",
					),
				)
		break

	for relation, member in (
		("labelledBy", "labeledBy"),
		("controllerFor", "controllerFor"),
		("flowsFrom", "flowsFrom"),
		("flowsTo", "flowsTo"),
		("details", "detailsRelations"),
		("error", "errorMessage"),
	):
		timeBudget.requireTimeRemaining()
		try:
			value = getattr(target, member)
		except (AttributeError, NotImplementedError):
			continue
		except _ReadBudgetExceeded:
			raise
		except Exception as error:
			supportedSurfaces += 1
			records.append(
				_exceptionRecord(
					error,
					key=_annotationKey(path, f"relation-{relation}-{depth}-failed"),
					typeName="Relationship",
					source="NVDA relations",
				),
			)
			continue
		supportedSurfaces += 1
		values = (
			cast(Iterable[object], value)
			if isinstance(value, Iterable) and not isinstance(value, (str, bytes))
			else (value,)
			if value is not None
			else ()
		)
		for index, relatedTarget in enumerate(_boundedValues(values, budget.maximumItems, timeBudget)):
			key = _annotationKey(path, f"relation-{relation}-{depth}-{index}")
			_appendAnnotationTargetRecord(
				records,
				lambda: _annotationTargetRecord(
					relatedTarget,
					key=_annotationKey(path, f"relation-{relation}-{depth}-{index}"),
					typeId=relation,
					typeName="Relationship",
					source="NVDA relations",
					relationship=relation,
					budget=budget,
					privacyTransform=privacyTransform,
					identityResolver=identityResolver,
					depth=depth,
					visited=visited,
					timeBudget=timeBudget,
				),
				key=key,
				typeName="Relationship",
				source="NVDA relations",
				timeBudget=timeBudget,
			)

	ia2Relations: object | None = None
	timeBudget.requireTimeRemaining()
	try:
		ia2Relations = getattr(target, "_getIA2RelationTargetsOfType")
	except (AttributeError, NotImplementedError):
		ia2Relations = None
	except _ReadBudgetExceeded:
		raise
	except Exception as error:
		supportedSurfaces += 1
		records.append(
			_exceptionRecord(
				error,
				key=_annotationKey(path, f"ia2-relations-{depth}-failed"),
				typeName="IAccessible2 relationships",
				source="IAccessible2 relations",
			),
		)
	ia2RelationReader = (
		cast(Callable[[str], Iterable[object]], ia2Relations) if callable(ia2Relations) else None
	)
	if ia2RelationReader is not None:
		supportedSurfaces += 1
		for relation in ("containingDocument", "detailsFor", "errorFor"):
			timeBudget.requireTimeRemaining()
			try:
				values = ia2RelationReader(relation)
			except _ReadBudgetExceeded:
				raise
			except Exception as error:
				records.append(
					_exceptionRecord(
						error,
						key=_annotationKey(path, f"ia2-{relation}-{depth}-failed"),
						typeName="IAccessible2 relationship",
						source="IAccessible2 relations",
					),
				)
				continue
			for index, relatedTarget in enumerate(_boundedValues(values, budget.maximumItems, timeBudget)):
				key = _annotationKey(path, f"ia2-{relation}-{depth}-{index}")
				_appendAnnotationTargetRecord(
					records,
					lambda: _annotationTargetRecord(
						relatedTarget,
						key=_annotationKey(path, f"ia2-{relation}-{depth}-{index}"),
						typeId=relation,
						typeName="IAccessible2 relationship",
						source="IAccessible2 relations",
						relationship=relation,
						budget=budget,
						privacyTransform=privacyTransform,
						identityResolver=identityResolver,
						depth=depth,
						visited=visited,
						timeBudget=timeBudget,
					),
					key=key,
					typeName="IAccessible2 relationship",
					source="IAccessible2 relations",
					timeBudget=timeBudget,
				)

	if records:
		return _boundedAnnotationRecords(records, budget=budget, path=path, depth=depth)
	if not includeEmpty:
		return ()
	return (
		AnnotationRecord(
			key=_annotationKey(path, "annotations-status"),
			status=AnnotationStatus.NO_DATA if supportedSurfaces else AnnotationStatus.UNSUPPORTED,
			typeName="Annotations",
			source="NVDA",
		),
	)


def collectAnnotations(
	target: object,
	budget: ReadBudget,
	*,
	privacyTransform: Callable[[str], str],
	identityResolver: AnnotationIdentityResolver | None = None,
	clockMilliseconds: MonotonicMilliseconds = _milliseconds,
) -> tuple[AnnotationRecord, ...]:
	"""Collect bounded annotation metadata without allowing a live provider object to escape."""

	return _collectAnnotationValues(
		target,
		budget=budget,
		privacyTransform=privacyTransform,
		identityResolver=identityResolver,
		depth=0,
		visited=set(),
		includeEmpty=True,
		path="",
		timeBudget=_ElapsedReadBudget(budget.maximumMilliseconds, clockMilliseconds),
	)


def readClassHierarchy(target: object, budget: ReadBudget) -> ProviderReadResult:
	return normalizeProviderRead(
		tuple(f"{item.__module__}.{item.__qualname__}" for item in type(target).__mro__),
		budget,
	)


class NvdaObjectGetter:
	"""Narrow read-only access to an already-selected NVDA object."""

	@staticmethod
	def readAttribute(target: object, member: str, budget: ReadBudget) -> ProviderReadResult:
		if member.startswith("_") or member not in _ALLOWED_OBJECT_ATTRIBUTES:
			return ProviderReadResult("unsupported")
		if member == "annotations":
			try:
				records = collectAnnotations(target, budget, privacyTransform=lambda value: value)
				return ProviderReadResult(
					"value",
					cast(PlainValue, annotationRecordsPlain(records)),
					truncated=_annotationsTruncated(records),
				)
			except Exception:
				return ProviderReadResult("failed", errorCode="KS.PROVIDER.ANNOTATIONS_FAILED")
		try:
			value = target.__getattribute__(member)
		except (AttributeError, NotImplementedError):
			return ProviderReadResult("unsupported")
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.NVDA_GETTER_FAILED")
		try:
			return normalizeProviderRead(_nvdaSemanticValue(member, value), budget)
		except (TypeError, ValueError):
			return ProviderReadResult("unsupported")
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.NVDA_GETTER_FAILED")

	@staticmethod
	def _objects(
		value: object,
		budget: ReadBudget,
		*,
		clockMilliseconds: MonotonicMilliseconds = _milliseconds,
	) -> ObjectBatch:
		if value is None:
			return ObjectBatch("empty", (), 0, False)
		if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
			return ObjectBatch("failed", (), 0, False, "KS.PROVIDER.CHILDREN_MALFORMED")
		iterable = cast(Iterable[object], value)
		timeBudget = _ElapsedReadBudget(budget.maximumMilliseconds, clockMilliseconds)
		retained: list[object] = []
		observed = 0
		try:
			iterator = iter(iterable)
			while True:
				timeBudget.requireTimeRemaining()
				try:
					item = next(iterator)
				except StopIteration:
					break
				observed += 1
				timeBudget.requireTimeRemaining()
				if len(retained) >= budget.maximumItems:
					break
				retained.append(item)
		except _ReadBudgetExceeded:
			return ObjectBatch(
				"value" if retained else "empty",
				tuple(retained),
				observed,
				True,
			)
		except Exception:
			return ObjectBatch(
				"failed",
				tuple(retained),
				observed,
				True,
				"KS.PROVIDER.CHILDREN_FAILED",
			)
		return ObjectBatch(
			"value" if observed else "empty",
			tuple(retained),
			observed,
			observed > len(retained),
		)

	@classmethod
	def readChildren(
		cls,
		target: object,
		budget: ReadBudget,
		*,
		clockMilliseconds: MonotonicMilliseconds = _milliseconds,
	) -> ObjectBatch:
		try:
			return cls._objects(
				target.__getattribute__("children"),
				budget,
				clockMilliseconds=clockMilliseconds,
			)
		except (AttributeError, NotImplementedError):
			return ObjectBatch("empty", (), 0, False)
		except Exception:
			return ObjectBatch("failed", (), 0, False, "KS.PROVIDER.CHILDREN_FAILED")

	@staticmethod
	def readLogicalFirstChild(target: object, budget: ReadBudget) -> ObjectBatch:
		try:
			child = target.__getattribute__("firstChild")
		except (AttributeError, NotImplementedError):
			return ObjectBatch("empty", (), 0, False)
		except Exception:
			return ObjectBatch("failed", (), 0, False, "KS.PROVIDER.LOGICAL_CHILD_FAILED")
		if child is None:
			return ObjectBatch("empty", (), 0, False)
		return ObjectBatch("value", (child,), 1, False)


@dataclass(frozen=True, slots=True)
class ProviderDatum:
	fieldId: str
	result: ProviderReadResult

	def asPlainValue(self) -> PlainValue:
		return (
			self.fieldId,
			self.result.status,
			("value", self.result.value) if self.result.value is not None else ("noValue",),
			("error", self.result.errorCode) if self.result.errorCode is not None else ("noError",),
			self.result.truncated,
		)


@dataclass(frozen=True, slots=True)
class ProviderSectionData:
	sectionId: str
	status: ProviderReadResult
	identity: tuple[ProviderDatum, ...] = ()
	properties: tuple[ProviderDatum, ...] = ()

	def __post_init__(self) -> None:
		if self.sectionId not in PROVIDER_SECTIONS:
			raise ValueError("provider section is not in the closed registry")

	@staticmethod
	def _collection(values: tuple[ProviderDatum, ...], applicable: bool) -> ProviderReadResult:
		if not applicable:
			return ProviderReadResult("unsupported")
		if not values:
			return ProviderReadResult("empty")
		return ProviderReadResult("value", tuple(value.asPlainValue() for value in values))

	def asPlainValue(self) -> PlainValue:
		applicable = self.status.status in ("value", "empty")
		identity = self._collection(self.identity, applicable)
		properties = self._collection(self.properties, applicable)
		return (
			self.sectionId,
			_resultPlain(self.status),
			_resultPlain(identity),
			_resultPlain(properties),
		)


def _resultPlain(result: ProviderReadResult) -> PlainValue:
	return result.status, result.value, result.errorCode, result.truncated


def encodeProviderSections(sections: tuple[ProviderSectionData, ...]) -> PlainValue:
	byName = {section.sectionId: section for section in sections}
	if len(byName) != len(sections):
		raise ValueError("provider sections must be unique")
	unsupported = ProviderSectionData("generic", ProviderReadResult("unsupported"))
	return tuple(
		byName.get(name, ProviderSectionData(name, unsupported.status)).asPlainValue()
		for name in PROVIDER_SECTIONS
	)


class CommonProviderAdapter:
	def __init__(self, getter: ObjectGetterPort) -> None:
		super().__init__()
		self._getter = getter

	def readField(self, target: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		if fieldId == "pythonClass":
			classType = type(target)
			return normalizeProviderRead(
				f"{classType.__module__}.{classType.__qualname__}",
				budget,
			)
		if fieldId == "classHierarchy":
			return readClassHierarchy(target, budget)
		if fieldId == "backend":
			names = {item.__name__ for item in type(target).__mro__}
			backend = (
				"uia"
				if "UIA" in names
				else "jab"
				if "JAB" in names
				else "ia2Msaa"
				if "IAccessible" in names
				else "generic"
			)
			return ProviderReadResult("value", backend)
		if fieldId == "stableIds":
			return ProviderReadResult("unsupported")
		member = _COMMON_ATTRIBUTES.get(fieldId)
		if member is None:
			return ProviderReadResult("unsupported")
		return self._getter.readAttribute(target, member, budget)

	def collect(self, target: object, budget: ReadBudget) -> ProviderSectionData:
		identity = tuple(
			ProviderDatum(fieldId, self.readField(target, fieldId, budget))
			for fieldId in ("process", "windowHandle", "classHierarchy", "backend")
		)
		properties = tuple(
			ProviderDatum(fieldId, self._getter.readAttribute(target, member, budget))
			for fieldId, member in _GENERIC_METADATA_ATTRIBUTES
		)
		return ProviderSectionData(
			"generic",
			ProviderReadResult("value", "available"),
			identity,
			properties,
		)
