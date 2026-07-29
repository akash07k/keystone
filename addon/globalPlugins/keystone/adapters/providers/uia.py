from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from ...capability import PlainValue
from ...ports.providers import ProviderReadResult, ReadBudget
from .common import (
	ObjectRead,
	ProviderDatum,
	ProviderSectionData,
	normalizeProviderRead,
	normalizeProviderValue,
)

#: Matches a UIA_...PatternId constant name (including versioned patterns like
#: "UIA_TextPattern2Id"), capturing the "<Name>Pattern[2]" segment shared by the
#: pattern ID, its availability property, and its comtypes interface name. Never
#: matches a PropertyId/ControlTypeId/AttributeId constant, since none of those
#: contain a "Pattern" segment immediately before the trailing "Id".
_PATTERN_ID_RE = re.compile(r"^UIA_(.+Pattern\d*)Id$")

_RELATED_ELEMENT_MARKER = "<relatedElementUnavailable>"
_UNRECOGNIZED_REFERENCE_MARKER = "<unrecognizedReference>"
_MAX_RELATED_DEPTH = 2
_TEXT_PATTERN_SHORT_NAMES = frozenset(("Text", "Text2"))


def _derivePatternInfo(constantName: str) -> tuple[str, str, str] | None:
	"""Derive a pattern's short name, availability property name and interface name.

	:param constantName: a "UIA_...PatternId"-shaped module attribute name, e.g.
		"UIA_TogglePatternId" or "UIA_TextPattern2Id".
	:return: (shortName, availabilityPropertyShortName, comtypesInterfaceName), e.g.
		("Toggle", "IsTogglePatternAvailable", "IUIAutomationTogglePattern"), or
		None if constantName is not a pattern ID constant.
	"""
	match = _PATTERN_ID_RE.match(constantName)
	if match is None:
		return None
	fullName = match.group(1)  # e.g. "TogglePattern" or "TextPattern2"
	shortName = re.sub(r"Pattern(\d*)$", r"\1", fullName)  # e.g. "Toggle" or "Text2"
	return shortName, f"Is{fullName}Available", f"IUIAutomation{fullName}"


@dataclass(frozen=True, slots=True)
class UiaIdentifier:
	name: str
	value: int


@dataclass(frozen=True, slots=True)
class UiaPatternInfo:
	shortName: str
	patternId: int
	availabilityName: str
	interfaceName: str


@dataclass(frozen=True, slots=True)
class UiaScanPlan:
	properties: tuple[UiaIdentifier, ...]
	patternAvailability: tuple[UiaIdentifier, ...]
	patterns: tuple[UiaPatternInfo, ...]
	controlTypes: tuple[UiaIdentifier, ...]
	textAttributes: tuple[UiaIdentifier, ...]

	@classmethod
	def discover(cls, installed: tuple[tuple[str, int], ...]) -> UiaScanPlan:
		unique = {name: value for name, value in installed if type(value) is int and value > 0}
		ordered = sorted(unique.items(), key=lambda item: item[0].encode("utf-8"))

		patterns: list[UiaPatternInfo] = []
		for name, value in ordered:
			derived = _derivePatternInfo(name)
			if derived is None:
				continue
			shortName, availabilityName, interfaceName = derived
			patterns.append(UiaPatternInfo(shortName, value, availabilityName, interfaceName))
		# Derived from the discovered patterns themselves (rather than a separate regex)
		# so versioned availability properties (e.g. "UIA_IsTextPattern2AvailablePropertyId")
		# are matched exactly as reliably as their versioned pattern IDs are.
		availabilityPropertyNames = frozenset(
			f"UIA_{pattern.availabilityName}PropertyId" for pattern in patterns
		)

		def stripped(suffix: str, names: tuple[str, ...]) -> tuple[UiaIdentifier, ...]:
			return tuple(UiaIdentifier(name[len("UIA_") : -len(suffix)], unique[name]) for name in names)

		propertyNames = tuple(name for name, _value in ordered if name.endswith("PropertyId"))
		properties = stripped(
			"PropertyId",
			tuple(name for name in propertyNames if name not in availabilityPropertyNames),
		)
		patternAvailability = stripped(
			"PropertyId",
			tuple(name for name in propertyNames if name in availabilityPropertyNames),
		)
		controlTypes = stripped(
			"ControlTypeId",
			tuple(name for name, _value in ordered if name.endswith("ControlTypeId")),
		)
		textAttributes = stripped(
			"AttributeId",
			tuple(name for name, _value in ordered if name.endswith("AttributeId")),
		)
		return cls(properties, patternAvailability, tuple(patterns), controlTypes, textAttributes)

	def asReadResult(self, budget: ReadBudget) -> ProviderReadResult:
		evidence: PlainValue = (
			("properties", tuple((item.name, item.value) for item in self.properties)),
			(
				"patternAvailability",
				tuple((item.name, item.value) for item in self.patternAvailability),
			),
			("patterns", tuple((item.shortName, item.patternId) for item in self.patterns)),
			("controlTypes", tuple((item.name, item.value) for item in self.controlTypes)),
			("textAttributes", tuple((item.name, item.value) for item in self.textAttributes)),
		)
		return normalizeProviderRead(evidence, budget)


class UiaGetterPort(Protocol):
	def installedIdentifiers(self) -> tuple[tuple[str, int], ...]: ...

	def acquireElement(self, target: object) -> ObjectRead: ...

	def createCacheRequest(self, propertyIds: tuple[int, ...]) -> ObjectRead: ...

	def buildUpdatedCache(self, element: object, cacheRequest: object) -> ObjectRead: ...

	def readCachedProperty(
		self,
		cachedElement: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult: ...

	def readCurrentProperty(
		self,
		element: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult: ...

	def acquirePattern(self, element: object, patternId: int, interfaceName: str) -> ObjectRead: ...

	def readTextPatternEvidence(
		self,
		patternObject: object,
		textAttributes: tuple[UiaIdentifier, ...],
		budget: ReadBudget,
	) -> tuple[ProviderDatum, ...]: ...

	def releaseResource(self, resource: object) -> None: ...


def _call(target: object, member: str, *args: object) -> object:
	value = getattr(target, member)
	if not callable(value):
		raise TypeError("UIA getter member is not callable")
	return value(*args)


def _tryAttribute(target: object, name: str) -> object | None:
	try:
		return getattr(target, name)
	except Exception:
		return None


def _plainScalar(value: object) -> PlainValue:
	if value is None or type(value) in (bool, int, float, str):
		return cast(PlainValue, value)
	return None


def _readTextRangeGroup(
	patternObject: object,
	method: str,
	fieldId: str,
	maxChars: int,
	maximumItems: int,
) -> ProviderDatum:
	"""Read a group of text ranges (visible ranges or the current selection).

	Each range's text is fetched independently: a single unreadable range is
	reported inline as a stable marker rather than discarding every other
	range already read successfully.
	"""
	try:
		ranges = _call(patternObject, method)
	except (AttributeError, NotImplementedError):
		return ProviderDatum(fieldId, ProviderReadResult("unsupported"))
	except Exception:
		return ProviderDatum(
			fieldId,
			ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_TEXT_RANGE_FAILED"),
		)
	count = _tryAttribute(ranges, "length")
	if type(count) is not int or count < 0:
		return ProviderDatum(
			fieldId,
			ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_TEXT_RANGE_FAILED"),
		)
	if count == 0:
		return ProviderDatum(fieldId, ProviderReadResult("empty"))
	limit = min(count, maximumItems)
	texts: list[str] = []
	truncated = count > limit
	for index in range(limit):
		try:
			element = _call(ranges, "GetElement", index)
			text = _call(element, "GetText", maxChars)
			if isinstance(text, str):
				texts.append(text[:maxChars])
				truncated = truncated or len(text) >= maxChars
			else:
				texts.append("<rangeUnavailable>")
		except Exception:
			texts.append("<rangeUnavailable>")
	return ProviderDatum(fieldId, ProviderReadResult("value", tuple(texts), truncated=truncated))


class NvdaUiaGetter:
	"""Live UIA getter facade; imported only inside an installed NVDA process."""

	def __init__(self) -> None:
		super().__init__()
		self._controlTypeNames: dict[int, str] | None = None

	def _handlerModule(self) -> object:
		return importlib.import_module("UIAHandler")

	def installedIdentifiers(self) -> tuple[tuple[str, int], ...]:
		module = self._handlerModule()
		sources: list[Mapping[str, object]] = [cast(Mapping[str, object], vars(module))]
		try:
			uia = module.__getattribute__("UIA")
		except AttributeError:
			uia = None
		if uia is not None:
			sources.append(cast(Mapping[str, object], vars(uia)))
		values: dict[str, int] = {}
		for source in sources:
			for name, value in source.items():
				if not name.startswith("UIA_") or type(value) is not int:
					continue
				if name.endswith(("PropertyId", "ControlTypeId", "AttributeId")) or _derivePatternInfo(
					name,
				):
					values[name] = value
		return tuple(sorted(values.items(), key=lambda item: item[0].encode("utf-8")))

	def acquireElement(self, target: object) -> ObjectRead:
		try:
			return ObjectRead("value", target.__getattribute__("UIAElement"))
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception:
			return ObjectRead("failed", errorCode="KS.PROVIDER.UIA_ACQUIRE_FAILED")

	def createCacheRequest(self, propertyIds: tuple[int, ...]) -> ObjectRead:
		try:
			module = self._handlerModule()
			handler = module.__getattribute__("handler")
			client = handler.__getattribute__("clientObject")
			request = _call(client, "createCacheRequest")
		except Exception:
			return ObjectRead("failed", errorCode="KS.PROVIDER.UIA_CACHE_REQUEST_FAILED")
		for propertyId in propertyIds:
			try:
				_ = _call(request, "addProperty", propertyId)
			except Exception:
				# Identifier inventories can include properties introduced after the
				# installed Windows UIA client. One unsupported property must not
				# invalidate the otherwise usable shared cache request.
				continue
		return ObjectRead("value", request)

	def buildUpdatedCache(self, element: object, cacheRequest: object) -> ObjectRead:
		try:
			return ObjectRead("value", _call(element, "buildUpdatedCache", cacheRequest))
		except Exception:
			return ObjectRead("failed", errorCode="KS.PROVIDER.UIA_CACHE_BUILD_FAILED")

	def _controlTypeNameMap(self) -> dict[int, str]:
		if self._controlTypeNames is None:
			names: dict[int, str] = {}
			for name, value in self.installedIdentifiers():
				if name.endswith("ControlTypeId"):
					names[value] = name[len("UIA_") : -len("ControlTypeId")]
			self._controlTypeNames = names
		return self._controlTypeNames

	def _asRelatedElement(self, value: object) -> object | None:
		if hasattr(value, "currentName") and hasattr(value, "currentControlType"):
			return value  # Already a directly usable element.
		try:
			iface = self._handlerModule().__getattribute__("IUIAutomationElement")
		except AttributeError:
			return None
		try:
			return _call(value, "QueryInterface", iface)
		except Exception:
			return None  # Not actually an element reference.

	def _asRelatedElementArray(self, value: object) -> object | None:
		if hasattr(value, "length") and hasattr(value, "getElement"):
			return value  # Already directly usable.
		try:
			iface = self._handlerModule().__getattribute__("IUIAutomationElementArray")
		except AttributeError:
			return None
		try:
			return _call(value, "QueryInterface", iface)
		except Exception:
			return None

	def _relatedElementSummary(self, element: object) -> PlainValue:
		controlTypeId = _tryAttribute(element, "currentControlType")
		controlTypeName = (
			self._controlTypeNameMap().get(controlTypeId) if type(controlTypeId) is int else None
		)
		return (
			("name", _plainScalar(_tryAttribute(element, "currentName"))),
			("automationId", _plainScalar(_tryAttribute(element, "currentAutomationId"))),
			("controlType", _plainScalar(controlTypeId)),
			("controlTypeName", controlTypeName),
			("className", _plainScalar(_tryAttribute(element, "currentClassName"))),
			("process", _plainScalar(_tryAttribute(element, "currentProcessId"))),
		)

	def _relatedElementArraySummary(self, array: object, budget: ReadBudget, depth: int) -> PlainValue:
		count = _tryAttribute(array, "length")
		if type(count) is not int or count < 0:
			return _RELATED_ELEMENT_MARKER
		limit = min(count, budget.maximumItems)
		items: list[PlainValue] = []
		for index in range(limit):
			try:
				item = _call(array, "getElement", index)
			except Exception:
				items.append(_RELATED_ELEMENT_MARKER)
				continue
			items.append(self._convertRelatedValue(item, budget, depth + 1))
		if count > limit:
			return (("items", tuple(items)), ("truncated", True))
		return tuple(items)

	def _convertRelatedValue(self, value: object, budget: ReadBudget, depth: int = 0) -> PlainValue:
		"""Convert an unrecognized UIA value into a bounded, readable summary.

		Only reached once ``normalizeProviderValue`` has already rejected ``value``
		outright, i.e. it is neither a plain scalar nor an ordinary container - so
		this only ever sees live COM references (a related element, an array of
		them, or something this adapter has no reader for at all).
		"""
		if value is None:
			return None
		if depth < _MAX_RELATED_DEPTH:
			element = self._asRelatedElement(value)
			if element is not None:
				return self._relatedElementSummary(element)
			array = self._asRelatedElementArray(value)
			if array is not None:
				return self._relatedElementArraySummary(array, budget, depth)
		return _UNRECOGNIZED_REFERENCE_MARKER

	def _normalize(
		self,
		value: object,
		budget: ReadBudget,
	) -> ProviderReadResult:
		module = self._handlerModule()
		handler = module.__getattribute__("handler")
		try:
			if (value == handler.__getattribute__("reservedNotSupportedValue")) is True:
				return ProviderReadResult("unsupported")
			if (value == handler.__getattribute__("ReservedMixedAttributeValue")) is True:
				return ProviderReadResult("value", ("mixed",))
		except Exception:
			pass
		try:
			return normalizeProviderRead(value, budget)
		except (TypeError, ValueError):
			converted = self._convertRelatedValue(value, budget)
			if converted is None:
				return ProviderReadResult("empty")
			try:
				return normalizeProviderRead(converted, budget)
			except (TypeError, ValueError):
				return ProviderReadResult("unsupported")

	def readCachedProperty(
		self,
		cachedElement: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult:
		try:
			return self._normalize(_call(cachedElement, "getCachedPropertyValueEx", propertyId, True), budget)
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_CACHED_READ_FAILED")

	def readCurrentProperty(
		self,
		element: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult:
		try:
			return self._normalize(_call(element, "getCurrentPropertyValueEx", propertyId, True), budget)
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_CURRENT_READ_FAILED")

	def acquirePattern(self, element: object, patternId: int, interfaceName: str) -> ObjectRead:
		try:
			iface = self._handlerModule().__getattribute__(interfaceName)
		except AttributeError:
			return ObjectRead("unsupported")
		try:
			punk = _call(element, "GetCurrentPattern", patternId)
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception:
			return ObjectRead("failed", errorCode="KS.PROVIDER.UIA_PATTERN_ACQUIRE_FAILED")
		if punk is None:
			return ObjectRead("empty")
		try:
			patternObject = _call(punk, "QueryInterface", iface)
		except Exception:
			return ObjectRead("failed", errorCode="KS.PROVIDER.UIA_PATTERN_QUERY_FAILED")
		if patternObject is None:
			return ObjectRead("empty")
		return ObjectRead("value", patternObject)

	def _readDocumentText(self, patternObject: object, maxChars: int) -> tuple[ProviderDatum, object | None]:
		try:
			docRange = getattr(patternObject, "DocumentRange")
		except (AttributeError, NotImplementedError):
			return ProviderDatum("DocumentText", ProviderReadResult("unsupported")), None
		except Exception:
			return (
				ProviderDatum(
					"DocumentText",
					ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_DOCUMENT_RANGE_FAILED"),
				),
				None,
			)
		try:
			text = _call(docRange, "GetText", maxChars)
		except Exception:
			return (
				ProviderDatum(
					"DocumentText",
					ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_DOCUMENT_TEXT_FAILED"),
				),
				docRange,
			)
		if not isinstance(text, str):
			return ProviderDatum("DocumentText", ProviderReadResult("unsupported")), docRange
		return (
			ProviderDatum(
				"DocumentText",
				ProviderReadResult("value", text[:maxChars], truncated=len(text) >= maxChars),
			),
			docRange,
		)

	def _readAggregateAttributes(
		self,
		docRange: object | None,
		textAttributes: tuple[UiaIdentifier, ...],
		budget: ReadBudget,
	) -> ProviderDatum:
		if docRange is None:
			return ProviderDatum("AggregateAttributes", ProviderReadResult("unsupported"))
		try:
			handler = self._handlerModule().__getattribute__("handler")
		except Exception:
			handler = None
		limit = budget.maximumItems
		items: list[tuple[str, PlainValue]] = []
		truncated = len(textAttributes) > limit
		for identifier in textAttributes[:limit]:
			try:
				value = _call(docRange, "GetAttributeValue", identifier.value)
			except Exception:
				continue
			if value is None:
				continue
			if handler is not None:
				try:
					if (value == handler.__getattribute__("reservedNotSupportedValue")) is True:
						continue
					if (value == handler.__getattribute__("ReservedMixedAttributeValue")) is True:
						items.append((identifier.name, "mixed"))
						continue
				except Exception:
					pass
			try:
				plain, valueTruncated = normalizeProviderValue(
					value,
					maximumItems=limit,
					maximumTextLength=budget.maximumTextLength,
				)
			except (TypeError, ValueError):
				continue
			items.append((identifier.name, plain))
			truncated = truncated or valueTruncated
		if not items:
			return ProviderDatum("AggregateAttributes", ProviderReadResult("empty"))
		return ProviderDatum(
			"AggregateAttributes",
			ProviderReadResult("value", tuple(items), truncated=truncated),
		)

	def readTextPatternEvidence(
		self,
		patternObject: object,
		textAttributes: tuple[UiaIdentifier, ...],
		budget: ReadBudget,
	) -> tuple[ProviderDatum, ...]:
		"""Independently extract Text/Text2 pattern evidence via its own COM methods.

		Text/Text2 content (unlike most other pattern data) is only available
		through the pattern's own COM methods, not as a cacheable UIA property.
		Each field below is read and reported independently, so one failing
		sub-read (e.g. no selection is active) never erases sibling evidence
		that was read successfully (e.g. the document text).
		"""
		maxChars = budget.maximumTextLength
		documentDatum, docRange = self._readDocumentText(patternObject, maxChars)
		visibleDatum = _readTextRangeGroup(
			patternObject,
			"GetVisibleRanges",
			"VisibleRanges",
			maxChars,
			budget.maximumItems,
		)
		selectionDatum = _readTextRangeGroup(
			patternObject,
			"GetSelection",
			"SelectionRanges",
			maxChars,
			budget.maximumItems,
		)
		attributesDatum = self._readAggregateAttributes(docRange, textAttributes, budget)
		return (documentDatum, visibleDatum, selectionDatum, attributesDatum)

	@staticmethod
	def releaseResource(resource: object) -> None:
		_ = resource
		# Python/comtypes drops these owning-apartment references when the adapter's
		# bounded call returns. No live value is retained or exported.
		return None


_IDENTITY_FIELD_NAMES = frozenset(("AutomationId", "ProcessId", "NativeWindowHandle"))


class UiaProviderAdapter:
	def __init__(self, getter: UiaGetterPort) -> None:
		super().__init__()
		self._getter = getter
		try:
			installed = getter.installedIdentifiers()
		except Exception:
			installed = ()
		self._plan = UiaScanPlan.discover(installed)

	@property
	def scanPlan(self) -> UiaScanPlan:
		return self._plan

	def _readPatternDatums(
		self,
		element: object,
		pattern: UiaPatternInfo,
		availability: ProviderReadResult | None,
		budget: ReadBudget,
	) -> tuple[ProviderDatum, ...]:
		if availability is None:
			patternStatus = ProviderReadResult(
				"unavailable",
				errorCode="KS.PROVIDER.UIA_PROPERTY_BUDGET_EXHAUSTED",
			)
			available = False
		elif availability.status != "value":
			patternStatus = ProviderReadResult(
				availability.status,
				errorCode=availability.errorCode,
			)
			available = False
		elif type(availability.value) is not bool:
			patternStatus = ProviderReadResult("unsupported")
			available = False
		else:
			available = availability.value
			patternStatus = ProviderReadResult("value", available)
		datums = (ProviderDatum(pattern.shortName, patternStatus),)
		if not available or pattern.shortName not in _TEXT_PATTERN_SHORT_NAMES:
			return datums
		patternRead = self._getter.acquirePattern(element, pattern.patternId, pattern.interfaceName)
		if patternRead.status != "value":
			return (
				*datums,
				ProviderDatum(
					f"{pattern.shortName}PatternObject",
					ProviderReadResult(patternRead.status, errorCode=patternRead.errorCode),
				),
			)
		assert patternRead.value is not None
		try:
			textDatums = self._getter.readTextPatternEvidence(
				patternRead.value,
				self._plan.textAttributes,
				budget,
			)
		finally:
			self._getter.releaseResource(patternRead.value)
		return (
			*datums,
			*(ProviderDatum(f"{pattern.shortName}{datum.fieldId}", datum.result) for datum in textDatums),
		)

	def collect(self, target: object, budget: ReadBudget) -> ProviderSectionData:
		elementRead = self._getter.acquireElement(target)
		if elementRead.status != "value":
			return ProviderSectionData(
				"uia",
				ProviderReadResult(elementRead.status, errorCode=elementRead.errorCode),
			)
		assert elementRead.value is not None
		element = elementRead.value

		# Identity remains available even when the installed property inventory is
		# larger than the caller's read budget. Pattern availability follows, then
		# ordinary properties. Unread pattern availability is reported as unavailable
		# below rather than being converted into a false support claim.
		identityIdentifiers = tuple(
			item for item in self._plan.properties if item.name in _IDENTITY_FIELD_NAMES
		)
		ordinaryIdentifiers = tuple(
			item for item in self._plan.properties if item.name not in _IDENTITY_FIELD_NAMES
		)
		propertyIdentifiers = (
			*identityIdentifiers,
			*self._plan.patternAvailability,
			*ordinaryIdentifiers,
		)
		truncatedProperties = len(propertyIdentifiers) > budget.maximumItems
		readIdentifiers = propertyIdentifiers[: budget.maximumItems]
		ids = tuple(item.value for item in readIdentifiers)

		cacheRead = self._getter.createCacheRequest(ids)
		cache: object | None = None
		properties: list[ProviderDatum] = []
		resultsByName: dict[str, ProviderReadResult] = {}
		try:
			if cacheRead.status == "value":
				assert cacheRead.value is not None
				cacheRequest = cacheRead.value
				built = self._getter.buildUpdatedCache(element, cacheRequest)
				if built.status == "value":
					cache = built.value
				else:
					properties.append(
						ProviderDatum(
							"cache",
							ProviderReadResult(built.status, errorCode=built.errorCode),
						),
					)
			else:
				properties.append(
					ProviderDatum(
						"cache",
						ProviderReadResult(cacheRead.status, errorCode=cacheRead.errorCode),
					),
				)

			properties.append(
				ProviderDatum(
					"propertyInventory",
					ProviderReadResult(
						"value",
						len(propertyIdentifiers),
						truncated=truncatedProperties,
					),
				),
			)
			for identifier in readIdentifiers:
				result = (
					self._getter.readCachedProperty(cache, identifier.value, budget)
					if cache is not None
					else self._getter.readCurrentProperty(element, identifier.value, budget)
				)
				properties.append(ProviderDatum(identifier.name, result))
				resultsByName[identifier.name] = result

			patternInfos = self._plan.patterns
			truncatedPatterns = len(patternInfos) > budget.maximumItems
			readPatterns = patternInfos[: budget.maximumItems]
			properties.append(
				ProviderDatum(
					"patternInventory",
					ProviderReadResult("value", len(patternInfos), truncated=truncatedPatterns),
				),
			)
			for pattern in readPatterns:
				availabilityResult = resultsByName.get(pattern.availabilityName)
				properties.extend(
					self._readPatternDatums(
						element,
						pattern,
						availabilityResult,
						budget,
					),
				)
		finally:
			if cache is not None:
				self._getter.releaseResource(cache)
			if cacheRead.status == "value" and cacheRead.value is not None:
				self._getter.releaseResource(cacheRead.value)

		identity = tuple(item for item in properties if item.fieldId in _IDENTITY_FIELD_NAMES)
		return ProviderSectionData(
			"uia",
			ProviderReadResult("value", "available"),
			identity,
			tuple(properties),
		)
