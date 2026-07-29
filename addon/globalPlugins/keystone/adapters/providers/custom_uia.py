from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import hashlib
import importlib
from time import monotonic_ns
from typing import Protocol, cast
import unicodedata

from ...domain.custom_uia import CustomUiaProperty
from ...domain.custom_uia_values import (
	CustomDeclaredType,
	CustomValueLimits,
	ElementReference,
	nonvalueCustomEvidence,
	normalizeCustomValue,
)
from ...domain.privacy import PrivacyPolicy, ProtectionEvidence
from ...domain.provider_measurement import (
	CONTRACT_DIGEST,
	MeasurementObservation,
	MeasurementProvenance,
)
from ...ports.providers import ProviderReadResult
from ..nvda.custom_uia_registry import RegistrationStatus
from .common import ObjectRead, ProviderDatum, ProviderSectionData


_MEASUREMENT_PROVENANCE = MeasurementProvenance(
	hashlib.sha256(b"keystone.custom-uia-provider.v1").hexdigest(),
	CONTRACT_DIGEST,
)


@dataclass(frozen=True, slots=True)
class CustomUiaBudget:
	maximumNodes: int
	maximumCalls: int
	maximumCandidates: int
	maximumValueReads: int
	maximumMilliseconds: int
	valueLimits: CustomValueLimits

	def __post_init__(self) -> None:
		if (
			min(
				self.maximumNodes,
				self.maximumCalls,
				self.maximumCandidates,
				self.maximumValueReads,
				self.maximumMilliseconds,
			)
			<= 0
		):
			raise ValueError("custom UIA budgets must be independently positive")

	@classmethod
	def defaults(cls) -> CustomUiaBudget:
		return cls(25, 256, 128, 32, 250, CustomValueLimits(4_096, 16_384, 16))


class CustomUiaCaptureMode(Enum):
	"""Select the deliberately small normal capture or an explicit diagnostic collection."""

	NORMAL = "normal"
	DIAGNOSTIC_EXPORT = "diagnosticExport"


class CustomUiaGetterPort(Protocol):
	def acquireElement(self, target: object) -> ObjectRead: ...

	def pollPotentialProperties(self, element: object) -> ObjectRead: ...

	def pollPotentialPatterns(self, element: object) -> ObjectRead: ...

	def createCacheRequest(self) -> ObjectRead: ...

	def addPropertyToCache(self, request: object, propertyId: int) -> ProviderReadResult: ...

	def buildUpdatedCache(self, element: object, request: object) -> ObjectRead: ...

	def readCachedProperty(self, element: object, propertyId: int) -> ObjectRead: ...

	def readCurrentProperty(self, element: object, propertyId: int) -> ObjectRead: ...

	def readElementReference(
		self,
		value: object,
		maximumRuntimeIds: int,
		scopedReference: str,
		providerProcessId: int,
	) -> ObjectRead: ...

	def releaseResource(self, resource: object) -> None: ...


def _call(target: object, member: str, *args: object) -> object:
	value = getattr(target, member)
	if not callable(value):
		raise TypeError("custom UIA member is not callable")
	return value(*args)


class NvdaCustomUiaGetter:
	"""Narrow live facade over UIA polling and property value APIs."""

	@staticmethod
	def _module() -> object:
		return importlib.import_module("UIAHandler")

	@classmethod
	def _client(cls) -> object:
		return cls._module().__getattribute__("handler").__getattribute__("clientObject")

	@classmethod
	def _normalizeRaw(cls, value: object) -> ObjectRead:
		handler = cls._module().__getattribute__("handler")
		try:
			if (value == handler.__getattribute__("reservedNotSupportedValue")) is True:
				return ObjectRead("unsupported")
		except Exception:
			pass
		if value is None:
			return ObjectRead("empty")
		return ObjectRead("value", value)

	def acquireElement(self, target: object) -> ObjectRead:
		try:
			return ObjectRead("value", target.__getattribute__("UIAElement"))
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.ELEMENT_ACQUIRE_FAILED")

	def pollPotentialProperties(self, element: object) -> ObjectRead:
		try:
			return ObjectRead("value", _call(self._client(), "PollForPotentialSupportedProperties", element))
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception:
			return ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.PROPERTY_POLL_UNAVAILABLE")

	def pollPotentialPatterns(self, element: object) -> ObjectRead:
		try:
			return ObjectRead("value", _call(self._client(), "PollForPotentialSupportedPatterns", element))
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception:
			return ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.PATTERN_POLL_UNAVAILABLE")

	def createCacheRequest(self) -> ObjectRead:
		try:
			return ObjectRead("value", _call(self._client(), "createCacheRequest"))
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.CACHE_REQUEST_FAILED")

	@staticmethod
	def addPropertyToCache(request: object, propertyId: int) -> ProviderReadResult:
		try:
			_ = _call(request, "addProperty", propertyId)
			return ProviderReadResult("value", True)
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.CUSTOM_UIA.CACHE_ADD_FAILED")

	@staticmethod
	def buildUpdatedCache(element: object, request: object) -> ObjectRead:
		try:
			return ObjectRead("value", _call(element, "buildUpdatedCache", request))
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.CACHE_BUILD_FAILED")

	@classmethod
	def readCachedProperty(cls, element: object, propertyId: int) -> ObjectRead:
		try:
			return cls._normalizeRaw(_call(element, "getCachedPropertyValueEx", propertyId, True))
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.CACHED_READ_FAILED")

	@classmethod
	def readCurrentProperty(cls, element: object, propertyId: int) -> ObjectRead:
		try:
			return cls._normalizeRaw(_call(element, "getCurrentPropertyValueEx", propertyId, True))
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.CURRENT_READ_FAILED")

	@staticmethod
	def readElementReference(
		value: object,
		maximumRuntimeIds: int,
		scopedReference: str,
		providerProcessId: int,
	) -> ObjectRead:
		try:
			raw = _call(value, "getRuntimeId")
			if type(raw) not in (tuple, list):
				return ObjectRead("unsupported")
			items = cast(tuple[object, ...] | list[object], raw)
			if any(type(item) is not int for item in items):
				return ObjectRead("unsupported")
			return ObjectRead(
				"value",
				ElementReference(
					None,
					scopedReference,
					cast(tuple[int, ...], tuple(items[: maximumRuntimeIds + 1])),
					providerProcessId,
				),
			)
		except Exception:
			return ObjectRead("failed", errorCode="KS.CUSTOM_UIA.ELEMENT_REFERENCE_FAILED")

	@staticmethod
	def releaseResource(resource: object) -> None:
		_ = resource


def _result(read: ObjectRead) -> ProviderReadResult:
	return ProviderReadResult(read.status, errorCode=read.errorCode)


def _safeName(value: object) -> str | None:
	if not isinstance(value, str):
		return None
	normalized = unicodedata.normalize("NFC", value)
	if not normalized or len(normalized) > 128:
		return None
	if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
		return None
	return normalized


class CustomUiaProviderAdapter:
	def __init__(
		self,
		getter: CustomUiaGetterPort,
		knownProperties: tuple[tuple[CustomUiaProperty, RegistrationStatus], ...],
		*,
		corePropertyIds: frozenset[int] | None = None,
		clockMicroseconds: Callable[[], int] = lambda: monotonic_ns() // 1_000,
		maximumObservations: int = 1_024,
	) -> None:
		super().__init__()
		if type(maximumObservations) is not int or maximumObservations <= 0:
			raise ValueError("maximumObservations must be a positive integer")
		self._getter = getter
		self._known = tuple(
			sorted(
				knownProperties,
				key=lambda item: (item[0].identityBytes, item[0].stableKey),
			),
		)
		self._corePropertyIds = corePropertyIds or frozenset()
		self._clock = clockMicroseconds
		self._observations: deque[MeasurementObservation] = deque(maxlen=maximumObservations)

	@property
	def observations(self) -> tuple[MeasurementObservation, ...]:
		return tuple(self._observations)

	def _measured(
		self,
		section: ProviderSectionData,
		*,
		started: int,
		callCount: int,
		candidateCount: int,
		budget: CustomUiaBudget,
	) -> ProviderSectionData:
		elapsed = max(0, self._clock() - started)
		outcome = (
			"success"
			if section.status.status in ("value", "empty")
			else "unsupported"
			if section.status.status == "unsupported"
			else "failed"
		)
		self._observations.append(
			MeasurementObservation(
				"uia",
				"poll",
				outcome,
				elapsed,
				candidateCount,
				budget.maximumMilliseconds * 1_000,
				_MEASUREMENT_PROVENANCE,
				(("attempt", callCount), ("batchSize", candidateCount)),
			),
		)
		return section

	@staticmethod
	def _potential(
		read: ObjectRead,
		*,
		kind: str,
		sessionId: str,
		processId: int,
		maximumCandidates: int,
		suppressedIds: frozenset[int],
	) -> tuple[ProviderReadResult, tuple[str, ...]]:
		if read.status != "value":
			return _result(read), ()
		rawValue = cast(object, read.value)
		if type(rawValue) is not tuple or len(cast(tuple[object, ...], rawValue)) != 2:
			return ProviderReadResult("failed", errorCode="KS.CUSTOM_UIA.POLL_ARRAY_MALFORMED"), (
				"pollArrayMalformed",
			)
		rawIds, rawNames = cast(tuple[object, object], rawValue)
		if type(rawIds) not in (tuple, list) or type(rawNames) not in (tuple, list):
			return ProviderReadResult("failed", errorCode="KS.CUSTOM_UIA.POLL_ARRAY_MALFORMED"), (
				"pollArrayMalformed",
			)
		ids = cast(tuple[object, ...] | list[object], rawIds)
		names = cast(tuple[object, ...] | list[object], rawNames)
		diagnostics: list[str] = []
		if len(ids) != len(names):
			diagnostics.append("pollArrayLengthMismatch")
		seen: set[int] = set()
		candidates: list[tuple[str, int, str, str, str, int]] = []
		for rawId, rawName in zip(ids, names):
			if len(candidates) >= maximumCandidates:
				diagnostics.append("candidateLimitReached")
				break
			if type(rawId) is not int or rawId <= 0:
				diagnostics.append("malformedCandidateId")
				continue
			name = _safeName(rawName)
			if name is None:
				diagnostics.append("malformedCandidateName")
				continue
			if rawId in suppressedIds:
				diagnostics.append("corePropertySuppressed")
				continue
			if rawId in seen:
				diagnostics.append("duplicateCandidate")
				continue
			seen.add(rawId)
			candidates.append((kind, rawId, name, "runtimeSession", sessionId, processId))
		return ProviderReadResult("value" if candidates else "empty", tuple(candidates)), tuple(diagnostics)

	@staticmethod
	def _normalized(
		read: ObjectRead,
		property: CustomUiaProperty,
		*,
		protection: ProtectionEvidence,
		policy: PrivacyPolicy,
		limits: CustomValueLimits,
		sourceId: str,
	) -> ProviderReadResult:
		declared = cast(CustomDeclaredType, property.propertyType)
		if read.status != "value":
			nonvalueStatus = (
				read.status
				if read.status in ("empty", "unsupported", "unavailable", "failed")
				else "unavailable"
			)
			errorCode = read.errorCode
			if nonvalueStatus == "unavailable" and errorCode is None:
				errorCode = "KS.CUSTOM_UIA.VALUE_STALE"
			evidence = nonvalueCustomEvidence(
				declared,
				nonvalueStatus,
				property.privacy,
				protection,
				errorCode,
			)
		else:
			evidence = normalizeCustomValue(
				declared,
				read.value,
				configuredPrivacy=property.privacy,
				protection=protection,
				policy=policy,
				limits=limits,
				sourceId=sourceId,
			)
		return ProviderReadResult("value", evidence.asPlainValue())

	@staticmethod
	def _normalizedPotential(
		read: ObjectRead,
		*,
		protection: ProtectionEvidence,
		policy: PrivacyPolicy,
		limits: CustomValueLimits,
		sourceId: str,
	) -> ProviderReadResult:
		if read.status != "value":
			nonvalueStatus = (
				read.status
				if read.status in ("empty", "unsupported", "unavailable", "failed")
				else "unavailable"
			)
			errorCode = read.errorCode
			if nonvalueStatus == "unavailable" and errorCode is None:
				errorCode = "KS.CUSTOM_UIA.VALUE_STALE"
			evidence = nonvalueCustomEvidence(
				"unknown",
				nonvalueStatus,
				"unknown",
				protection,
				errorCode,
			)
		else:
			evidence = normalizeCustomValue(
				"unknown",
				read.value,
				configuredPrivacy="unknown",
				protection=protection,
				policy=policy,
				limits=limits,
				sourceId=sourceId,
			)
		return ProviderReadResult("value", evidence.asPlainValue())

	@staticmethod
	def _matchesTarget(property: CustomUiaProperty, target: object) -> bool:
		"""Apply the definition's application filters before attempting a provider read."""

		try:
			appModule = getattr(target, "appModule", None)
			appName = getattr(appModule, "appName", None)
		except Exception:
			return False
		if not isinstance(appName, str) or not appName:
			return False
		actualExecutable = appName if appName.lower().endswith(".exe") else f"{appName}.exe"
		if property.executableTarget.casefold() != actualExecutable.casefold():
			return False
		if property.frameworkFilter is not None:
			try:
				framework = getattr(target, "UIAFrameworkId", None)
			except Exception:
				return False
			if not isinstance(framework, str) or framework.casefold() != property.frameworkFilter.casefold():
				return False
		if property.windowClassFilter is not None:
			try:
				windowClass = getattr(target, "windowClassName", None)
			except Exception:
				return False
			if (
				not isinstance(windowClass, str)
				or windowClass.casefold() != property.windowClassFilter.casefold()
			):
				return False
		return True

	def collectNormal(
		self,
		target: object,
		*,
		captureSessionId: str,
		providerProcessId: int,
		budget: CustomUiaBudget,
		privacyPolicy: PrivacyPolicy,
		protection: ProtectionEvidence,
	) -> ProviderSectionData:
		"""Read configured, applicable definitions without probing discovery surfaces.

		The normal snapshot is evidence for a user's configured properties, not a native UIA
		inventory.  Potential-property polling, registration telemetry, cache measurements, and
		out-of-target definitions remain available only from the explicit diagnostic collector.
		"""

		applicable = tuple(
			(property, status)
			for property, status in self._known
			if property.enabled and self._matchesTarget(property, target)
		)
		if not applicable:
			return ProviderSectionData("customUia", ProviderReadResult("unsupported"))

		elementRead = self._getter.acquireElement(target)
		if elementRead.status != "value":
			return ProviderSectionData("customUia", _result(elementRead))
		assert elementRead.value is not None

		identity: list[ProviderDatum] = []
		properties: list[ProviderDatum] = []
		for index, (property, registration) in enumerate(applicable):
			identity.append(
				ProviderDatum(
					f"known.{property.stableKey}.definition",
					ProviderReadResult(
						"value",
						(
							property.stableKey,
							property.canonicalGuid,
							property.userVisibleName,
							property.enumValues,
						),
					),
				),
			)
			if registration.status != "registered" or registration.runtimeId is None:
				status = (
					registration.status if registration.status in ("failed", "unavailable") else "unavailable"
				)
				properties.append(
					ProviderDatum(
						f"known.{property.stableKey}.current",
						ProviderReadResult(
							status,
							errorCode=registration.errorCode or "KS.CUSTOM_UIA.REGISTRATION_UNAVAILABLE",
						),
					),
				)
				continue
			if index >= budget.maximumValueReads:
				read = ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.BUDGET_EXHAUSTED")
			else:
				read = self._getter.readCurrentProperty(elementRead.value, registration.runtimeId)
			if (
				property.propertyType == "element"
				and read.status == "value"
				and not isinstance(
					read.value,
					ElementReference,
				)
			):
				read = self._getter.readElementReference(
					read.value,
					budget.valueLimits.maximumElementRuntimeIds,
					f"{captureSessionId}-current-{index}",
					providerProcessId,
				)
			properties.append(
				ProviderDatum(
					f"known.{property.stableKey}.current",
					self._normalized(
						read,
						property,
						protection=protection,
						policy=privacyPolicy,
						limits=budget.valueLimits,
						sourceId=f"custom-{property.stableKey}-current",
					),
				),
			)
		return ProviderSectionData(
			"customUia",
			ProviderReadResult("value", "configured"),
			tuple(identity),
			tuple(properties),
		)

	def collect(
		self,
		target: object,
		*,
		captureSessionId: str,
		providerProcessId: int,
		budget: CustomUiaBudget,
		privacyPolicy: PrivacyPolicy,
		protection: ProtectionEvidence,
	) -> ProviderSectionData:
		started = self._clock()
		callCount = 0
		potentialValueReads = 0
		knownValueReads = 0

		def allowed() -> bool:
			return (
				callCount < budget.maximumCalls
				and self._clock() - started <= budget.maximumMilliseconds * 1_000
			)

		def unavailable() -> ObjectRead:
			return ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.BUDGET_EXHAUSTED")

		callCount += 1
		elementRead = self._getter.acquireElement(target)
		if elementRead.status != "value":
			return self._measured(
				ProviderSectionData("customUia", _result(elementRead)),
				started=started,
				callCount=callCount,
				candidateCount=0,
				budget=budget,
			)

		assert elementRead.value is not None
		element = elementRead.value
		properties: list[ProviderDatum] = []
		diagnostics: list[str] = []
		if allowed():
			callCount += 1
			propertyPoll = self._getter.pollPotentialProperties(element)
		else:
			propertyPoll = unavailable()
		potentialProperties, propertyDiagnostics = self._potential(
			propertyPoll,
			kind="potential",
			sessionId=captureSessionId,
			processId=providerProcessId,
			maximumCandidates=budget.maximumCandidates,
			suppressedIds=self._corePropertyIds,
		)
		properties.append(ProviderDatum("potentialProperties", potentialProperties))
		diagnostics.extend(propertyDiagnostics)
		if allowed():
			callCount += 1
			patternPoll = self._getter.pollPotentialPatterns(element)
		else:
			patternPoll = unavailable()
		potentialPatterns, patternDiagnostics = self._potential(
			patternPoll,
			kind="potential",
			sessionId=captureSessionId,
			processId=providerProcessId,
			maximumCandidates=budget.maximumCandidates,
			suppressedIds=frozenset(),
		)
		properties.append(ProviderDatum("potentialPatterns", potentialPatterns))
		diagnostics.extend(patternDiagnostics)
		if potentialProperties.status == "value" and type(potentialProperties.value) is tuple:
			for index, rawCandidate in enumerate(
				cast(tuple[object, ...], potentialProperties.value)[: budget.maximumValueReads],
				start=1,
			):
				if type(rawCandidate) is not tuple:
					continue
				candidate = cast(tuple[object, ...], rawCandidate)
				if len(candidate) < 2 or type(candidate[1]) is not int:
					continue
				if allowed():
					callCount += 1
					potentialValueReads += 1
					read = self._getter.readCurrentProperty(element, candidate[1])
				else:
					read = unavailable()
				properties.append(
					ProviderDatum(
						f"potentialProperty.{index}.current",
						self._normalizedPotential(
							read,
							protection=protection,
							policy=privacyPolicy,
							limits=budget.valueLimits,
							sourceId=f"custom-potential-{captureSessionId}-{index}",
						),
					),
				)
		applicableKnown: list[tuple[CustomUiaProperty, RegistrationStatus]] = []
		for property, status in self._known:
			applicable = self._matchesTarget(property, target)
			properties.append(
				ProviderDatum(
					f"known.{property.stableKey}.registration",
					ProviderReadResult(
						"value",
						(
							("status", status.status),
							("errorCode", status.errorCode) if status.errorCode is not None else ("noError",),
							("runtimeScopedIdAvailable", status.runtimeId is not None),
							("configuredExecutable", property.executableTarget),
							("displayName", property.userVisibleName),
							("enumValues", property.enumValues),
							("applicableToElement", applicable),
						),
					),
				),
			)
			if applicable:
				applicableKnown.append((property, status))

		registered = tuple(
			(property, status)
			for property, status in applicableKnown
			if property.enabled and status.status == "registered" and status.runtimeId is not None
		)[: (budget.maximumValueReads + 1) // 2]
		identity = tuple(
			ProviderDatum(
				f"known.{property.stableKey}.identity",
				ProviderReadResult("value", (property.stableKey, property.canonicalGuid)),
			)
			for property, _status in registered
		)
		if registered and allowed():
			callCount += 1
			cacheRead = self._getter.createCacheRequest()
		else:
			cacheRead = unavailable() if registered else ObjectRead("empty")
		cache: object | None = None
		request = cacheRead.value if cacheRead.status == "value" else None
		try:
			cacheable: list[tuple[CustomUiaProperty, RegistrationStatus]] = []
			if request is not None:
				for property, status in registered:
					assert status.runtimeId is not None
					if allowed():
						callCount += 1
						added = self._getter.addPropertyToCache(request, status.runtimeId)
					else:
						added = ProviderReadResult(
							"unavailable",
							errorCode="KS.CUSTOM_UIA.BUDGET_EXHAUSTED",
						)
					properties.append(ProviderDatum(f"known.{property.stableKey}.cacheAdd", added))
					if added.status == "value":
						cacheable.append((property, status))
				if cacheable:
					if allowed():
						callCount += 1
						built = self._getter.buildUpdatedCache(element, request)
					else:
						built = unavailable()
					if built.status == "value":
						cache = built.value
					else:
						properties.append(ProviderDatum("knownCacheBuild", _result(built)))
			elif registered:
				properties.append(ProviderDatum("knownCacheRequest", _result(cacheRead)))

			for index, (property, status) in enumerate(registered):
				assert status.runtimeId is not None
				if cache is not None and any(item[0] == property for item in cacheable):
					if knownValueReads < budget.maximumValueReads and allowed():
						callCount += 1
						knownValueReads += 1
						cachedRead = self._getter.readCachedProperty(cache, status.runtimeId)
					else:
						cachedRead = unavailable()
				else:
					cachedRead = ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.CACHE_VALUE_UNAVAILABLE")
				if knownValueReads < budget.maximumValueReads and allowed():
					callCount += 1
					knownValueReads += 1
					currentRead = self._getter.readCurrentProperty(element, status.runtimeId)
				else:
					currentRead = unavailable()
				if property.propertyType == "element":
					if cachedRead.status == "value" and not isinstance(cachedRead.value, ElementReference):
						cachedRead = self._getter.readElementReference(
							cachedRead.value,
							budget.valueLimits.maximumElementRuntimeIds,
							f"{captureSessionId}-cached-{index}",
							providerProcessId,
						)
					if currentRead.status == "value" and not isinstance(currentRead.value, ElementReference):
						currentRead = self._getter.readElementReference(
							currentRead.value,
							budget.valueLimits.maximumElementRuntimeIds,
							f"{captureSessionId}-current-{index}",
							providerProcessId,
						)
				properties.append(
					ProviderDatum(
						f"known.{property.stableKey}.cached",
						self._normalized(
							cachedRead,
							property,
							protection=protection,
							policy=privacyPolicy,
							limits=budget.valueLimits,
							sourceId=f"custom-{property.stableKey}-cached",
						),
					),
				)
				properties.append(
					ProviderDatum(
						f"known.{property.stableKey}.current",
						self._normalized(
							currentRead,
							property,
							protection=protection,
							policy=privacyPolicy,
							limits=budget.valueLimits,
							sourceId=f"custom-{property.stableKey}-current",
						),
					),
				)
		finally:
			if cache is not None:
				self._getter.releaseResource(cache)
			if request is not None:
				self._getter.releaseResource(request)
		diagnosticValues = tuple(dict.fromkeys(diagnostics))
		properties.append(
			ProviderDatum(
				"potentialDiagnostics",
				ProviderReadResult("value", diagnosticValues)
				if diagnosticValues
				else ProviderReadResult("empty"),
			),
		)
		candidateCount = sum(
			len(cast(tuple[object, ...], result.value))
			for result in (potentialProperties, potentialPatterns)
			if result.status == "value" and type(result.value) is tuple
		)
		properties.append(
			ProviderDatum(
				"collectionBudget",
				ProviderReadResult(
					"value",
					(
						("calls", callCount),
						("potentialValueReads", potentialValueReads),
						("knownValueReads", knownValueReads),
						("candidates", candidateCount),
						("maximumCalls", budget.maximumCalls),
						("maximumValueReads", budget.maximumValueReads),
					),
				),
			),
		)
		return self._measured(
			ProviderSectionData(
				"customUia",
				ProviderReadResult("value", "available"),
				identity,
				tuple(properties),
			),
			started=started,
			callCount=callCount,
			candidateCount=candidateCount,
			budget=budget,
		)

	def collectCustomUia(
		self,
		nodeRef: object,
		*,
		mode: CustomUiaCaptureMode,
		captureSessionId: str,
		providerProcessId: int,
		budget: CustomUiaBudget,
		privacyPolicy: PrivacyPolicy,
		protection: ProtectionEvidence,
	) -> ProviderSectionData:
		"""Collect only the evidence explicitly selected by the capture mode."""
		if mode is CustomUiaCaptureMode.NORMAL:
			return self.collectNormal(
				nodeRef,
				captureSessionId=captureSessionId,
				providerProcessId=providerProcessId,
				budget=budget,
				privacyPolicy=privacyPolicy,
				protection=protection,
			)
		if mode is not CustomUiaCaptureMode.DIAGNOSTIC_EXPORT:
			raise ValueError("custom UIA capture mode is not supported")
		return self.collect(
			nodeRef,
			captureSessionId=captureSessionId,
			providerProcessId=providerProcessId,
			budget=budget,
			privacyPolicy=privacyPolicy,
			protection=protection,
		)
