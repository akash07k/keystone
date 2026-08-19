from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda.custom_uia_registry import RegistrationStatus
from addon.globalPlugins.keystone.adapters.providers.common import (
	ObjectRead,
	ProviderDatum,
	ProviderSectionData,
	encodeProviderSections,
)
from addon.globalPlugins.keystone.adapters.providers.custom_uia import (
	CustomUiaBudget,
	CustomUiaCaptureMode,
	CustomUiaProviderAdapter,
	NvdaCustomUiaGetter,
)
from addon.globalPlugins.keystone.application.capture_service import (
	CaptureOutputPort,
	CaptureService,
	CustomUiaCaptureOptions,
)
from addon.globalPlugins.keystone.application.lifecycle import LifecycleService
from addon.globalPlugins.keystone.domain.correlation import CorrelationContext, CorrelationId
from addon.globalPlugins.keystone.domain.custom_uia import CustomUiaProperty
from addon.globalPlugins.keystone.domain.custom_uia_values import CustomValueLimits
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy, ProtectionEvidence
from addon.globalPlugins.keystone.domain.provider_measurement import aggregateMeasurements, proposeThreshold
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.ports.providers import (
	ProviderMetadataRequest,
	ProviderReadResult,
	IdentityComparisonPort,
	ReadOnlyNodePort,
	ReadBudget,
)
from addon.globalPlugins.keystone.ports.effects import ScreenshotPort


_PROPERTY = CustomUiaProperty(
	"sample.reading-mode",
	"{12345678-1234-4ABC-8DEF-1234567890AB}",
	"Sample.ReadingMode",
	"string",
	"unknown",
	True,
	None,
	"sample.exe",
	None,
	None,
	displayName="Reading mode",
)


class RecordingCustomGetter:
	def __init__(self) -> None:
		super().__init__()
		self.calls: list[tuple[str, object]] = []
		self.patternSurfaceAccessed = False

	def acquireElement(self, target: object) -> ObjectRead:
		self.calls.append(("acquireElement", target))
		return ObjectRead("value", "element")

	def pollPotentialProperties(self, element: object) -> ObjectRead:
		self.calls.append(("pollPotentialProperties", element))
		return ObjectRead(
			"value",
			(
				(30_001, 30_002, 30_002, 30_003, 30_004, 30_005),
				("First", "Duplicate first", "Duplicate ignored", "", object()),
			),
		)

	def pollPotentialPatterns(self, element: object) -> ObjectRead:
		self.calls.append(("pollPotentialPatterns", element))
		return ObjectRead("value", ((40_001, 40_002), ("Custom.Toggle", "Custom.Action")))

	def createCacheRequest(self) -> ObjectRead:
		self.calls.append(("createCacheRequest", None))
		return ObjectRead("value", "request")

	def addPropertyToCache(self, request: object, propertyId: int) -> ProviderReadResult:
		self.calls.append(("addPropertyToCache", (request, propertyId)))
		return ProviderReadResult("value", True)

	def buildUpdatedCache(self, element: object, request: object) -> ObjectRead:
		self.calls.append(("buildUpdatedCache", (element, request)))
		return ObjectRead("value", "cached-element")

	def readCachedProperty(self, element: object, propertyId: int) -> ObjectRead:
		self.calls.append(("readCachedProperty", (element, propertyId)))
		return ObjectRead("value", "cached")

	def readCurrentProperty(self, element: object, propertyId: int) -> ObjectRead:
		self.calls.append(("readCurrentProperty", (element, propertyId)))
		return ObjectRead("value", "current")

	def readElementReference(
		self,
		value: object,
		maximumRuntimeIds: int,
		scopedReference: str,
		providerProcessId: int,
	) -> ObjectRead:
		_ = value, maximumRuntimeIds, scopedReference, providerProcessId
		raise AssertionError("the string property must not request an element reference")

	def releaseResource(self, resource: object) -> None:
		self.calls.append(("releaseResource", resource))

	def __getattr__(self, name: str) -> object:
		if any(token in name.lower() for token in ("patternobject", "getpattern", "invokepattern")):
			self.patternSurfaceAccessed = True
		raise AssertionError(f"custom pattern interaction is forbidden: {name}")


class _EqualSentinel:
	@override
	def __eq__(self, other: object) -> bool:
		return isinstance(other, _EqualSentinel)


class CustomUiaHostValueTests(unittest.TestCase):
	def test_current_property_uses_com_dynamic_method_resolution(self) -> None:
		module = SimpleNamespace(
			handler=SimpleNamespace(reservedNotSupportedValue=object()),
		)

		class _Element:
			def __getattr__(self, name: str) -> object:
				if name == "getCurrentPropertyValueEx":

					def getCurrentPropertyValueEx(propertyId: int, ignoreDefault: bool) -> str:
						return f"{propertyId}:{ignoreDefault}"

					return getCurrentPropertyValueEx
				raise AttributeError(name)

		with patch.object(
			NvdaCustomUiaGetter,
			"_module",
			return_value=module,
		):
			result = NvdaCustomUiaGetter().readCurrentProperty(_Element(), 30_005)

		self.assertEqual("value", result.status)
		self.assertEqual("30005:True", result.value)

	def test_equivalent_not_supported_wrapper_is_not_exported_as_a_value(self) -> None:
		module = SimpleNamespace(
			handler=SimpleNamespace(reservedNotSupportedValue=_EqualSentinel()),
		)

		class _Element:
			def getCurrentPropertyValueEx(self, _propertyId: int, _ignoreDefault: bool) -> object:
				return _EqualSentinel()

		with patch.object(
			NvdaCustomUiaGetter,
			"_module",
			return_value=module,
		):
			result = NvdaCustomUiaGetter().readCurrentProperty(_Element(), 30_001)

		self.assertEqual("unsupported", result.status)


def _budget(**changes: object) -> CustomUiaBudget:
	base = CustomUiaBudget(
		maximumNodes=1,
		maximumCalls=12,
		maximumCandidates=8,
		maximumValueReads=2,
		maximumMilliseconds=100,
		valueLimits=CustomValueLimits(32, 64, 4),
	)
	return replace(base, **changes)


class CustomUiaProviderTracerTests(unittest.TestCase):
	def test_normal_capture_reads_only_applicable_registered_values_without_discovery(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		section = CustomUiaProviderAdapter(getter, ((_PROPERTY, registration),)).collectNormal(
			SimpleNamespace(appModule=SimpleNamespace(appName="sample.exe")),
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		self.assertEqual("value", section.status.status)
		self.assertEqual(
			("known.sample.reading-mode.definition",),
			tuple(item.fieldId for item in section.identity),
		)
		self.assertEqual(
			(
				_PROPERTY.stableKey,
				_PROPERTY.canonicalGuid,
				_PROPERTY.userVisibleName,
				_PROPERTY.enumValues,
			),
			section.identity[0].result.value,
		)
		self.assertEqual(
			("known.sample.reading-mode.current",),
			tuple(item.fieldId for item in section.properties),
		)
		current = cast(tuple[tuple[object, ...], ...], section.properties[0].result.value)
		currentFields = {item[0]: item[1] for item in current if len(item) == 2}
		self.assertEqual("value", currentFields["status"])
		self.assertEqual("current", currentFields["value"])
		self.assertEqual(
			["acquireElement", "readCurrentProperty"],
			[name for name, _value in getter.calls],
		)

	def test_normal_capture_omits_custom_uia_when_no_enabled_definition_applies(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		section = CustomUiaProviderAdapter(getter, ((_PROPERTY, registration),)).collectNormal(
			SimpleNamespace(appModule=SimpleNamespace(appName="other.exe")),
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		self.assertEqual("unsupported", section.status.status)
		self.assertEqual([], getter.calls)

	def test_missing_application_identity_excludes_all_registered_filters(self) -> None:
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		properties = (
			_PROPERTY,
			replace(_PROPERTY, frameworkFilter="WPF"),
			replace(_PROPERTY, windowClassFilter="SampleWindow"),
		)

		for property in properties:
			with self.subTest(property=property.stableKey):
				getter = RecordingCustomGetter()
				section = CustomUiaProviderAdapter(getter, ((property, registration),)).collectNormal(
					SimpleNamespace(),
					captureSessionId="capture-session",
					providerProcessId=77,
					budget=_budget(),
					privacyPolicy=PrivacyPolicy(1, 1, False),
					protection=ProtectionEvidence.allClear(),
				)

				self.assertEqual("unsupported", section.status.status)
				self.assertEqual([], getter.calls)

	def test_potential_polling_and_one_known_property_are_independent_and_bounded(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		adapter = CustomUiaProviderAdapter(
			getter,
			((_PROPERTY, registration),),
			corePropertyIds=frozenset((30_001,)),
		)

		section = adapter.collect(
			SimpleNamespace(appModule=SimpleNamespace(appName="sample.exe")),
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		self.assertEqual("customUia", section.sectionId)
		self.assertEqual("value", section.status.status)
		properties = {item.fieldId: item.result for item in section.properties}
		potential = properties["potentialProperties"].value
		self.assertEqual(
			(("potential", 30_002, "Duplicate first", "runtimeSession", "capture-session", 77),),
			potential,
		)
		self.assertEqual(
			(
				("potential", 40_001, "Custom.Toggle", "runtimeSession", "capture-session", 77),
				("potential", 40_002, "Custom.Action", "runtimeSession", "capture-session", 77),
			),
			properties["potentialPatterns"].value,
		)
		self.assertEqual("value", properties["known.sample.reading-mode.cached"].status)
		self.assertEqual("value", properties["known.sample.reading-mode.current"].status)
		registration = cast(
			tuple[tuple[str, object], ...],
			properties["known.sample.reading-mode.registration"].value,
		)
		self.assertIn(("displayName", "Reading mode"), registration)
		self.assertEqual("value", properties["potentialProperty.1.current"].status)
		diagnostics = cast(tuple[str, ...], properties["potentialDiagnostics"].value)
		self.assertIn("pollArrayLengthMismatch", diagnostics)
		self.assertIn("duplicateCandidate", diagnostics)
		self.assertIn("corePropertySuppressed", diagnostics)
		self.assertFalse(getter.patternSurfaceAccessed)
		self.assertEqual(
			[
				"acquireElement",
				"pollPotentialProperties",
				"pollPotentialPatterns",
				"readCurrentProperty",
				"createCacheRequest",
				"addPropertyToCache",
				"buildUpdatedCache",
				"readCachedProperty",
				"readCurrentProperty",
				"releaseResource",
				"releaseResource",
			],
			[name for name, _value in getter.calls],
		)

	def test_registered_property_is_not_read_for_a_different_application(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		target = SimpleNamespace(appModule=SimpleNamespace(appName="other.exe"))
		section = CustomUiaProviderAdapter(getter, ((_PROPERTY, registration),)).collect(
			target,
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		properties = {item.fieldId: item.result for item in section.properties}
		registrationValue = cast(
			tuple[tuple[str, object], ...],
			properties["known.sample.reading-mode.registration"].value,
		)
		self.assertIn(("configuredExecutable", "sample.exe"), registrationValue)
		self.assertIn(("applicableToElement", False), registrationValue)
		self.assertNotIn("known.sample.reading-mode.current", properties)


class CustomUiaProviderSafetyTests(unittest.TestCase):
	def test_custom_pattern_surface_is_metadata_only_by_structure(self) -> None:
		source = (
			Path(__file__).parents[2]
			/ "addon"
			/ "globalPlugins"
			/ "keystone"
			/ "adapters"
			/ "providers"
			/ "custom_uia.py"
		).read_text(encoding="utf-8")

		for forbidden in (
			"GetCurrentPattern",
			"getCurrentPattern",
			"getCachedPattern",
			"invokePattern",
			"patternInterface",
			"queryInterface",
		):
			self.assertNotIn(forbidden, source)

	def test_unknown_registration_degrades_known_values_without_disabling_polls(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"unavailable",
			errorCode="nativeRegistrationUnavailable",
		)
		section = CustomUiaProviderAdapter(getter, ((_PROPERTY, registration),)).collect(
			SimpleNamespace(appModule=SimpleNamespace(appName="sample.exe")),
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		properties = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("value", properties["potentialProperties"].status)
		self.assertNotIn("known.sample.reading-mode.current", properties)
		self.assertEqual("value", properties["known.sample.reading-mode.registration"].status)
		self.assertFalse(getter.patternSurfaceAccessed)

	def test_property_poll_failure_does_not_disable_patterns_or_known_reads(self) -> None:
		getter = RecordingCustomGetter()

		def failedPoll(_element: object) -> ObjectRead:
			return ObjectRead("unavailable", errorCode="KS.CUSTOM_UIA.PROPERTY_POLL_UNAVAILABLE")

		getter.pollPotentialProperties = failedPoll  # type: ignore[method-assign]
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"registered",
			runtimeId=50_001,
		)
		section = CustomUiaProviderAdapter(getter, ((_PROPERTY, registration),)).collect(
			SimpleNamespace(appModule=SimpleNamespace(appName="sample.exe")),
			captureSessionId="capture-session",
			providerProcessId=77,
			budget=_budget(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			protection=ProtectionEvidence.allClear(),
		)

		properties = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("unavailable", properties["potentialProperties"].status)
		self.assertEqual("value", properties["potentialPatterns"].status)
		self.assertEqual("value", properties["known.sample.reading-mode.current"].status)

	def test_call_budget_is_independent_and_measurements_can_propose_a_default(self) -> None:
		getter = RecordingCustomGetter()
		registration = RegistrationStatus(
			_PROPERTY.stableKey,
			_PROPERTY.canonicalGuid,
			1,
			"unavailable",
			errorCode="nativeRegistrationUnavailable",
		)
		ticks = iter((0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150))
		adapter = CustomUiaProviderAdapter(
			getter,
			((_PROPERTY, registration),),
			clockMicroseconds=lambda: next(ticks),
		)

		for _index in range(3):
			section = adapter.collect(
				"selected",
				captureSessionId="capture-session",
				providerProcessId=77,
				budget=_budget(maximumCalls=2),
				privacyPolicy=PrivacyPolicy(1, 1, False),
				protection=ProtectionEvidence.allClear(),
			)
			properties = {item.fieldId: item.result for item in section.properties}
			self.assertEqual("unavailable", properties["potentialPatterns"].status)

		self.assertEqual(3, len(adapter.observations))
		aggregate = aggregateMeasurements(adapter.observations)[0]
		candidate = proposeThreshold(aggregate)
		self.assertEqual("candidate", candidate.status)
		self.assertGreater(candidate.valueMicroseconds or 0, 0)

	def test_measurements_retain_only_the_configured_recent_window(self) -> None:
		adapter = CustomUiaProviderAdapter(
			RecordingCustomGetter(),
			(
				(
					_PROPERTY,
					RegistrationStatus(
						_PROPERTY.stableKey,
						_PROPERTY.canonicalGuid,
						1,
						"unavailable",
						errorCode="nativeRegistrationUnavailable",
					),
				),
			),
			maximumObservations=2,
		)

		for sessionNumber in range(3):
			_ = adapter.collect(
				"selected",
				captureSessionId=f"capture-session-{sessionNumber}",
				providerProcessId=77,
				budget=_budget(maximumCalls=2),
				privacyPolicy=PrivacyPolicy(1, 1, False),
				protection=ProtectionEvidence.allClear(),
			)

		self.assertEqual(2, len(adapter.observations))


class _UnavailableMetadataProvider:
	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		_ = request
		return ProviderReadResult("unsupported")


class _CoreUiaMetadataProvider:
	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		_ = request
		return ProviderReadResult(
			"value",
			encodeProviderSections(
				(ProviderSectionData("uia", ProviderReadResult("value", "available")),),
			),
		)


class _CaptureCustomPort:
	def __init__(self, section: ProviderSectionData | Exception) -> None:
		super().__init__()
		self.section = section
		self.calls: list[tuple[object, CustomUiaBudget]] = []

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
		_ = mode, captureSessionId, providerProcessId, privacyPolicy, protection
		self.calls.append((nodeRef, budget))
		if isinstance(self.section, Exception):
			raise self.section
		return self.section


class CustomUiaCaptureIntegrationTests(unittest.TestCase):
	def _service(
		self,
		port: _CaptureCustomPort,
		options: CustomUiaCaptureOptions,
		provider: object | None = None,
	) -> CaptureService:
		return CaptureService(
			cast(LifecycleService, None),
			cast(ReadOnlyNodePort, provider or _UnavailableMetadataProvider()),
			cast(IdentityComparisonPort, None),
			cast(CaptureOutputPort, None),
			cast(ScreenshotPort, None),
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			privacyPolicy=PrivacyPolicy(1, 1, False),
			documentIdFactory=lambda: "00000000-0000-4000-8000-000000000001",
			publicationIdFactory=lambda: "publication",
			screenshotAttemptIdFactory=lambda: "attempt",
			customUia=port,
			customUiaOptions=options,
		)

	@staticmethod
	def _context() -> CorrelationContext:
		return CorrelationContext(
			CorrelationId("00000000-0000-4000-8000-000000000001"),
			CorrelationId("00000000-0000-4000-8000-000000000002"),
			CorrelationId("00000000-0000-4000-8000-000000000003"),
			1,
		)

	def test_details_poll_by_default_while_hierarchy_requires_advanced_option(self) -> None:
		options = CustomUiaCaptureOptions.defaults()

		self.assertTrue(options.shouldCollect(detailCollection=True, depth=0, collectedNodes=0))
		self.assertFalse(options.shouldCollect(detailCollection=True, depth=1, collectedNodes=1))
		self.assertFalse(options.shouldCollect(detailCollection=False, depth=0, collectedNodes=0))
		advanced = replace(options, hierarchyPollingEnabled=True, maximumNodes=2)
		self.assertTrue(advanced.shouldCollect(detailCollection=False, depth=1, collectedNodes=1))
		self.assertFalse(advanced.shouldCollect(detailCollection=False, depth=2, collectedNodes=2))

	def test_custom_source_overrides_only_custom_section_and_failure_keeps_core_uia(self) -> None:
		customSection = ProviderSectionData(
			"customUia",
			ProviderReadResult("value", "available"),
			properties=(
				ProviderDatum("potentialPatterns", ProviderReadResult("value", (("potential", 40_001),))),
			),
		)
		port = _CaptureCustomPort(customSection)
		service = self._service(port, CustomUiaCaptureOptions.defaults())

		sections = service._providerSections(  # pyright: ignore[reportPrivateUsage]
			"node-1",
			self._context(),
			ReadBudget(10, 100, 100),
			ProtectionEvidence.allClear(),
			collectCustom=True,
			providerProcessId=77,
		)

		byName = dict(sections.items)
		self.assertEqual("value", byName["customUia"].status.status)
		self.assertEqual("notApplicable", byName["uia"].status.status)
		self.assertEqual(1, len(port.calls))

		failedPort = _CaptureCustomPort(RuntimeError("private provider detail"))
		failedService = self._service(
			failedPort,
			CustomUiaCaptureOptions.defaults(),
			_CoreUiaMetadataProvider(),
		)
		failed = failedService._providerSections(  # pyright: ignore[reportPrivateUsage]
			"node-1",
			self._context(),
			ReadBudget(10, 100, 100),
			ProtectionEvidence.allClear(),
			collectCustom=True,
			providerProcessId=77,
		)
		failedByName = dict(failed.items)
		self.assertEqual("unsupported", failedByName["customUia"].status.status)
		self.assertEqual("value", failedByName["uia"].status.status)


if __name__ == "__main__":
	_ = unittest.main()
