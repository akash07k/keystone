from __future__ import annotations

# pyright: reportPrivateUsage=false
import unittest
from collections.abc import Iterator
from enum import Enum
from types import SimpleNamespace
from typing import cast, override
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.providers.common import (
	CommonProviderAdapter,
	NvdaObjectGetter,
	ObjectBatch,
	ObjectRead,
	ProviderDatum,
	normalizeProviderValue,
)
from addon.globalPlugins.keystone.adapters.providers.ia2_msaa import (
	Ia2MsaaProviderAdapter,
	NvdaIa2MsaaGetter,
	OwnedProviderRead,
)
from addon.globalPlugins.keystone.adapters.providers.jab import (
	JabProviderAdapter,
	NvdaJabGetter,
	OwnedJabRead,
)
from addon.globalPlugins.keystone.adapters.providers.overlay import (
	NvdaOverlayGetter,
	OverlayProviderAdapter,
)
from addon.globalPlugins.keystone.adapters.providers.uia import (
	NvdaUiaGetter,
	UiaProviderAdapter,
	UiaScanPlan,
	_derivePatternInfo,
	_readTextRangeGroup,
)
from addon.globalPlugins.keystone.adapters.nvda.event_sources import targetIdentityFromObject
from addon.globalPlugins.keystone.ports.providers import (
	ProviderReadResult,
	ReadBudget,
)
from tests.contract.fakes import ExpectedCall, ResourceLedger, StrictCallFake


def _invoke(fake: StrictCallFake, member: str, *args: object) -> object:
	return fake.member(member)(*args)


class CommonProviderBoundaryTests(unittest.TestCase):
	def test_roles_and_states_use_nvda_display_labels(self) -> None:
		class _Semantic(Enum):
			LIST_ITEM = 15
			SELECTABLE = 8_388_608
			FOCUSABLE = 16_777_216

			@property
			def displayString(self) -> str:
				return self.name.replace("_", " ").lower()

		target = type(
			"_Target",
			(),
			{
				"role": _Semantic.LIST_ITEM,
				"states": {_Semantic.SELECTABLE, _Semantic.FOCUSABLE},
			},
		)()
		budget = ReadBudget(8, 80, 50)

		role = NvdaObjectGetter.readAttribute(target, "role", budget)
		states = NvdaObjectGetter.readAttribute(target, "states", budget)

		self.assertEqual("list item", role.value)
		self.assertEqual({"selectable", "focusable"}, set(cast(tuple[str, ...], states.value)))

	def test_top_level_none_is_empty_evidence_not_a_value(self) -> None:
		target = type("_Target", (), {"description": None})()

		result = NvdaObjectGetter.readAttribute(target, "description", ReadBudget(8, 80, 50))

		self.assertEqual("empty", result.status)
		self.assertIsNone(result.value)

	def test_non_finite_numbers_are_unsupported_at_any_depth(self) -> None:
		for value in (float("nan"), (1, float("inf"))):
			with self.subTest(value=value):
				target = type("_Target", (), {"description": value})()

				result = NvdaObjectGetter.readAttribute(target, "description", ReadBudget(8, 80, 50))

				self.assertEqual("unsupported", result.status)
				self.assertIsNone(result.value)

	def test_deep_and_cyclic_values_are_unsupported(self) -> None:
		deep: object = "leaf"
		for _ in range(65):
			deep = (deep,)
		cyclic: list[object] = []
		cyclic.append(cyclic)
		cyclicMapping: dict[str, object] = {}
		cyclicMapping["self"] = cyclicMapping

		for value in (deep, cyclic, cyclicMapping):
			with self.subTest(valueType=type(value).__name__):
				target = type("_Target", (), {"description": value})()

				result = NvdaObjectGetter.readAttribute(target, "description", ReadBudget(8, 80, 50))

				self.assertEqual("unsupported", result.status)
				self.assertIsNone(result.value)

	def test_lazy_value_iteration_failure_is_stably_failed(self) -> None:
		class _BrokenValues:
			def __iter__(self) -> Iterator[object]:
				yield "first"
				raise RuntimeError("provider value became unavailable")

		target = type("_Target", (), {"description": _BrokenValues()})()

		result = NvdaObjectGetter.readAttribute(target, "description", ReadBudget(8, 80, 50))

		self.assertEqual(("failed", "KS.PROVIDER.NVDA_GETTER_FAILED"), (result.status, result.errorCode))
		self.assertIsNone(result.value)

	def test_child_enumeration_stops_after_detecting_truncation(self) -> None:
		observed: list[int] = []

		def children() -> object:
			for index in range(100):
				observed.append(index)
				yield object()

		target = type("_Target", (), {"children": children()})()

		result = NvdaObjectGetter.readChildren(target, ReadBudget(2, 80, 50))

		self.assertEqual(2, len(result.values))
		self.assertEqual(3, result.observedCount)
		self.assertTrue(result.truncated)
		self.assertEqual([0, 1, 2], observed)

	def test_child_iteration_failure_retains_pre_error_children(self) -> None:
		first = object()

		class _BrokenChildren:
			def __iter__(self) -> Iterator[object]:
				yield first
				raise RuntimeError("children became unavailable")

		target = type("_Target", (), {"children": _BrokenChildren()})()

		result = NvdaObjectGetter.readChildren(target, ReadBudget(8, 80, 50))

		self.assertEqual(
			("failed", 1, True, "KS.PROVIDER.CHILDREN_FAILED"),
			(result.status, result.observedCount, result.truncated, result.errorCode),
		)
		self.assertEqual((first,), result.values)
		with self.assertRaises(ValueError):
			_ = ObjectBatch("failed", (first,), 1, False, "KS.PROVIDER.CHILDREN_FAILED")

	def test_children_access_failure_remains_total(self) -> None:
		class _Target:
			@property
			def children(self) -> object:
				raise RuntimeError("children are unavailable")

		result = NvdaObjectGetter.readChildren(_Target(), ReadBudget(8, 80, 50))

		self.assertEqual(
			("failed", (), 0, False, "KS.PROVIDER.CHILDREN_FAILED"),
			(result.status, result.values, result.observedCount, result.truncated, result.errorCode),
		)

	def test_mapping_key_truncation_is_explicit_and_collision_safe(self) -> None:
		value, truncated = normalizeProviderValue(
			{"abcdef": 1},
			maximumItems=8,
			maximumTextLength=3,
		)
		self.assertEqual((("abc", 1),), value)
		self.assertTrue(truncated)

		with self.assertRaisesRegex(ValueError, "collide"):
			_ = normalizeProviderValue(
				{"abcdef": 1, "abcxyz": 2},
				maximumItems=8,
				maximumTextLength=3,
			)

	def test_normalization_clamps_to_plain_value_boundary_limits(self) -> None:
		for value, expectedLength in (
			("x" * 20_000, 16_384),
			(tuple(range(5_000)), 4_096),
		):
			with self.subTest(expectedLength=expectedLength):
				target = type("_Target", (), {"description": value})()

				result = NvdaObjectGetter.readAttribute(target, "description", ReadBudget(5_000, 20_000, 50))

				self.assertEqual("value", result.status)
				self.assertEqual(expectedLength, len(cast(str | tuple[object, ...], result.value)))
				self.assertTrue(result.truncated)

	def test_synthesized_class_metadata_respects_read_budget(self) -> None:
		baseType = type(
			"BaseClassWithLongName",
			(),
			{"__module__": "module_name_that_is_long"},
		)
		target = type(
			"TargetClassWithLongName",
			(baseType,),
			{"__module__": "module_name_that_is_long"},
		)()
		budget = ReadBudget(1, 10, 50)

		className = CommonProviderAdapter(NvdaObjectGetter()).readField(target, "pythonClass", budget)
		hierarchy = CommonProviderAdapter(NvdaObjectGetter()).readField(
			target,
			"classHierarchy",
			budget,
		)
		overlay = NvdaOverlayGetter.read(target, "overlayClasses", budget)

		self.assertEqual("module_nam", className.value)
		self.assertTrue(className.truncated)
		for result in (hierarchy, overlay):
			self.assertEqual(("module_nam",), result.value)
			self.assertTrue(result.truncated)

	def test_absent_provider_values_are_empty_evidence(self) -> None:
		budget = ReadBudget(8, 80, 50)
		overlayTarget = type(
			"_OverlayTarget",
			(),
			{"appModule": type("_AppModule", (), {"appName": None})()},
		)()
		ia2Target = type("_Ia2Target", (), {"IA2UniqueID": None})()
		jabTarget = type(
			"_JabTarget",
			(),
			{"_JABAccContextInfo": type("_JabInfo", (), {"role_en_US": None})()},
		)()

		results = (
			NvdaOverlayGetter.read(overlayTarget, "logicalApplication", budget),
			NvdaIa2MsaaGetter.read(ia2Target, "IA2UniqueID", budget).result,
			NvdaJabGetter.read(jabTarget, "rawRole", budget).result,
		)

		for result in results:
			self.assertEqual("empty", result.status)
			self.assertIsNone(result.value)


class _UiaGetter:
	def __init__(self, fake: StrictCallFake) -> None:
		super().__init__()
		self._fake = fake

	def installedIdentifiers(self) -> tuple[tuple[str, int], ...]:
		return cast(tuple[tuple[str, int], ...], _invoke(self._fake, "installedIdentifiers"))

	def acquireElement(self, target: object) -> ObjectRead:
		return cast(ObjectRead, _invoke(self._fake, "acquireElement", target))

	def createCacheRequest(self, propertyIds: tuple[int, ...]) -> ObjectRead:
		return cast(ObjectRead, _invoke(self._fake, "createCacheRequest", propertyIds))

	def buildUpdatedCache(self, element: object, cacheRequest: object) -> ObjectRead:
		return cast(ObjectRead, _invoke(self._fake, "buildUpdatedCache", element, cacheRequest))

	def readCachedProperty(
		self,
		cachedElement: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult:
		return cast(
			ProviderReadResult,
			_invoke(self._fake, "readCachedProperty", cachedElement, propertyId, budget),
		)

	def readCurrentProperty(
		self,
		element: object,
		propertyId: int,
		budget: ReadBudget,
	) -> ProviderReadResult:
		return cast(
			ProviderReadResult,
			_invoke(self._fake, "readCurrentProperty", element, propertyId, budget),
		)

	def acquirePattern(self, element: object, patternId: int, interfaceName: str) -> ObjectRead:
		return cast(ObjectRead, _invoke(self._fake, "acquirePattern", element, patternId, interfaceName))

	def readTextPatternEvidence(
		self,
		patternObject: object,
		textAttributes: tuple[object, ...],
		budget: ReadBudget,
	) -> tuple[ProviderDatum, ...]:
		return cast(
			tuple[ProviderDatum, ...],
			_invoke(self._fake, "readTextPatternEvidence", patternObject, textAttributes, budget),
		)

	def releaseResource(self, resource: object) -> None:
		_ = _invoke(self._fake, "releaseResource", resource)


class _EqualSentinel:
	@override
	def __eq__(self, other: object) -> bool:
		return isinstance(other, _EqualSentinel)


_DEFAULT_CURRENT_PROPERTY = object()


class _CurrentProperty:
	def __init__(self, value: object = _DEFAULT_CURRENT_PROPERTY) -> None:
		super().__init__()
		self.value = _EqualSentinel() if value is _DEFAULT_CURRENT_PROPERTY else value

	def getCurrentPropertyValueEx(self, propertyId: int, ignoreDefault: bool) -> object:
		_ = propertyId, ignoreDefault
		return self.value


class _IndeterminateText(str):
	@override
	def __eq__(self, other: object) -> bool:
		_ = other
		return cast(bool, NotImplemented)


class _Ia2Getter:
	def __init__(self, fake: StrictCallFake) -> None:
		super().__init__()
		self._fake = fake

	def acquire(self, target: object) -> ProviderReadResult:
		return cast(ProviderReadResult, _invoke(self._fake, "acquire", target))

	def supportsIa2(self, target: object) -> bool:
		return cast(bool, _invoke(self._fake, "supportsIa2", target))

	def read(self, target: object, member: str, budget: ReadBudget) -> OwnedProviderRead:
		return cast(OwnedProviderRead, _invoke(self._fake, "read", target, member, budget))

	def releaseResource(self, resourceToken: object) -> None:
		_ = _invoke(self._fake, "releaseResource", resourceToken)


class _JabGetter:
	def __init__(self, fake: StrictCallFake) -> None:
		super().__init__()
		self._fake = fake

	def acquire(self, target: object) -> ProviderReadResult:
		return cast(ProviderReadResult, _invoke(self._fake, "acquire", target))

	def read(self, target: object, fieldId: str, budget: ReadBudget) -> OwnedJabRead:
		return cast(OwnedJabRead, _invoke(self._fake, "read", target, fieldId, budget))

	def releaseResource(self, resourceToken: object) -> None:
		_ = _invoke(self._fake, "releaseResource", resourceToken)


class _OverlayGetter:
	def __init__(self, fake: StrictCallFake) -> None:
		super().__init__()
		self._fake = fake

	def read(self, target: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		return cast(ProviderReadResult, _invoke(self._fake, "read", target, fieldId, budget))


class _RelatedElement:
	def __init__(self, **attrs: object) -> None:
		super().__init__()
		for key, value in attrs.items():
			setattr(self, key, value)


class _RelatedElementArray:
	def __init__(self, elements: tuple[object, ...]) -> None:
		super().__init__()
		self._elements = elements

	@property
	def length(self) -> int:
		return len(self._elements)

	def getElement(self, index: int) -> object:
		return self._elements[index]


def _fakeHandlerModule(**extraAttributes: object) -> object:
	handler = type(
		"_Handler",
		(),
		{
			"reservedNotSupportedValue": object(),
			"ReservedMixedAttributeValue": object(),
		},
	)()
	return SimpleNamespace(handler=handler, **extraAttributes)


class UiaPatternNamingTests(unittest.TestCase):
	def test_unversioned_pattern_derives_short_name_availability_and_interface(self) -> None:
		derived = _derivePatternInfo("UIA_TogglePatternId")

		self.assertEqual(("Toggle", "IsTogglePatternAvailable", "IUIAutomationTogglePattern"), derived)

	def test_versioned_pattern_derives_a_distinct_short_name(self) -> None:
		derived = _derivePatternInfo("UIA_TextPattern2Id")

		self.assertEqual(("Text2", "IsTextPattern2Available", "IUIAutomationTextPattern2"), derived)

	def test_unversioned_text_pattern_is_distinguishable_from_versioned(self) -> None:
		derived = _derivePatternInfo("UIA_TextPatternId")

		self.assertEqual(("Text", "IsTextPatternAvailable", "IUIAutomationTextPattern"), derived)

	def test_non_pattern_constants_are_rejected(self) -> None:
		for name in ("UIA_NamePropertyId", "UIA_ButtonControlTypeId", "UIA_FontNameAttributeId"):
			with self.subTest(name=name):
				self.assertIsNone(_derivePatternInfo(name))


class UiaProviderAdapterTests(unittest.TestCase):
	def test_cache_request_uses_dynamic_com_dispatch_and_skips_unsupported_identifiers(self) -> None:
		added: list[int] = []

		class _DynamicRequest:
			def __getattr__(self, name: str) -> object:
				if name != "addProperty":
					raise AttributeError(name)

				def addProperty(propertyId: int) -> None:
					added.append(propertyId)
					if propertyId == 2:
						raise ValueError("property is newer than this UIA client")

				return addProperty

		request = _DynamicRequest()

		class _DynamicClient:
			def __getattr__(self, name: str) -> object:
				if name == "createCacheRequest":
					return lambda: request
				raise AttributeError(name)

		module = SimpleNamespace(handler=SimpleNamespace(clientObject=_DynamicClient()))
		getter = NvdaUiaGetter()

		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.createCacheRequest((1, 2, 3))

		self.assertEqual("value", result.status)
		self.assertIs(request, result.value)
		self.assertEqual([1, 2, 3], added)

	def test_installed_scan_plan_respects_item_and_text_budgets(self) -> None:
		plan = UiaScanPlan.discover(
			(
				("UIA_NamePropertyId", 30005),
				("UIA_AutomationIdPropertyId", 30011),
				("UIA_IsGridPatternAvailablePropertyId", 30031),
				("UIA_ButtonControlTypeId", 50000),
				("UIA_FontNameAttributeId", 40005),
			),
		)

		result = plan.asReadResult(ReadBudget(2, 10, 50))

		categories = cast(tuple[tuple[str, tuple[tuple[str, int], ...]], ...], result.value)
		self.assertEqual(2, len(categories))
		for categoryName, entries in categories:
			self.assertLessEqual(len(categoryName), 10)
			self.assertLessEqual(len(entries), 2)
			for name, _identifier in entries:
				self.assertLessEqual(len(name), 10)
		self.assertTrue(result.truncated)

	def test_scan_plan_discovers_every_property_not_just_the_legacy_allowlist(self) -> None:
		plan = UiaScanPlan.discover(
			(
				("UIA_NamePropertyId", 30005),
				("UIA_HelpTextPropertyId", 30013),
				("UIA_ValueValuePropertyId", 30045),
				("UIA_LandmarkTypePropertyId", 30157),
			),
		)

		names = {item.name for item in plan.properties}

		self.assertEqual({"Name", "HelpText", "ValueValue", "LandmarkType"}, names)

	def test_scan_plan_derives_patterns_including_versioned_ones(self) -> None:
		plan = UiaScanPlan.discover(
			(
				("UIA_TogglePatternId", 10015),
				("UIA_IsTogglePatternAvailablePropertyId", 30086),
				("UIA_TextPatternId", 10014),
				("UIA_IsTextPatternAvailablePropertyId", 30040),
				("UIA_TextPattern2Id", 10024),
				("UIA_IsTextPattern2AvailablePropertyId", 30149),
			),
		)

		patternsByName = {pattern.shortName: pattern for pattern in plan.patterns}
		self.assertEqual({"Toggle", "Text", "Text2"}, set(patternsByName))
		self.assertEqual(10015, patternsByName["Toggle"].patternId)
		self.assertEqual("IsTogglePatternAvailable", patternsByName["Toggle"].availabilityName)
		self.assertEqual("IUIAutomationTogglePattern", patternsByName["Toggle"].interfaceName)
		self.assertEqual("IsTextPattern2Available", patternsByName["Text2"].availabilityName)
		self.assertEqual("IUIAutomationTextPattern2", patternsByName["Text2"].interfaceName)
		# Every "IsXPatternAvailable" property routes to patternAvailability, not
		# the general properties bucket, even when the pattern itself is versioned.
		self.assertEqual(set(), {item.name for item in plan.properties})
		self.assertEqual(
			{"IsTogglePatternAvailable", "IsTextPatternAvailable", "IsTextPattern2Available"},
			{item.name for item in plan.patternAvailability},
		)

	def test_equal_com_wrappers_are_recognized_as_unsupported(self) -> None:
		handler = type(
			"_Handler",
			(),
			{
				"reservedNotSupportedValue": _EqualSentinel(),
				"ReservedMixedAttributeValue": object(),
			},
		)()
		module = type("_Module", (), {"handler": handler})()
		getter = NvdaUiaGetter()
		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.readCurrentProperty(_CurrentProperty(), 30005, ReadBudget(8, 64, 250))
			indeterminate = getter.readCurrentProperty(
				_CurrentProperty(_IndeterminateText("ordinary")),
				30005,
				ReadBudget(8, 64, 250),
			)
			empty = getter.readCurrentProperty(
				_CurrentProperty(None),
				30005,
				ReadBudget(8, 64, 250),
			)

		self.assertEqual("unsupported", result.status)
		self.assertEqual("value", indeterminate.status)
		self.assertEqual("ordinary", indeterminate.value)
		self.assertEqual("empty", empty.status)

	def test_related_element_reference_converts_to_a_bounded_readable_summary(self) -> None:
		module = _fakeHandlerModule(UIA_ButtonControlTypeId=50000)
		relatedElement = _RelatedElement(
			currentName="OK",
			currentAutomationId="okButton",
			currentControlType=50000,
			currentClassName="Button",
			currentProcessId=4242,
		)
		getter = NvdaUiaGetter()
		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.readCurrentProperty(
				_CurrentProperty(relatedElement),
				30018,
				ReadBudget(8, 64, 250),
			)

		self.assertEqual("value", result.status)
		summary = dict(cast(tuple[tuple[str, object], ...], result.value))
		self.assertEqual("OK", summary["name"])
		self.assertEqual("okButton", summary["automationId"])
		self.assertEqual(50000, summary["controlType"])
		self.assertEqual("Button", summary["controlTypeName"])
		self.assertEqual("Button", summary["className"])
		self.assertEqual(4242, summary["process"])

	def test_related_element_array_is_bounded_with_truncation_evidence(self) -> None:
		module = _fakeHandlerModule()
		elements = tuple(
			_RelatedElement(currentName=f"item{index}", currentControlType=None) for index in range(3)
		)
		getter = NvdaUiaGetter()
		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.readCurrentProperty(
				_CurrentProperty(_RelatedElementArray(elements)),
				30104,
				ReadBudget(2, 64, 250),
			)

		self.assertEqual("value", result.status)
		payload = dict(cast(tuple[tuple[str, object], ...], result.value))
		self.assertTrue(payload["truncated"])
		self.assertEqual(2, len(cast(tuple[object, ...], payload["items"])))

	def test_related_recursion_stops_at_the_depth_bound(self) -> None:
		module = _fakeHandlerModule()
		leaf = _RelatedElementArray(())
		middle = _RelatedElementArray((leaf,))
		outer = _RelatedElementArray((middle,))
		getter = NvdaUiaGetter()
		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.readCurrentProperty(
				_CurrentProperty(outer),
				30105,
				ReadBudget(8, 64, 250),
			)

		self.assertEqual("value", result.status)
		outerItems = cast(tuple[object, ...], result.value)
		middleItems = cast(tuple[object, ...], outerItems[0])
		self.assertEqual("<unrecognizedReference>", middleItems[0])

	def test_unrecognized_reference_falls_back_to_a_stable_marker(self) -> None:
		module = _fakeHandlerModule()
		getter = NvdaUiaGetter()
		with patch.object(NvdaUiaGetter, "_handlerModule", return_value=module):
			result = getter.readCurrentProperty(
				_CurrentProperty(object()),
				30018,
				ReadBudget(8, 64, 250),
			)

		self.assertEqual("value", result.status)
		self.assertEqual("<unrecognizedReference>", result.value)

	def test_cache_failure_and_current_read_statuses_remain_distinct(self) -> None:
		target = object()
		budget = ReadBudget(8, 64, 250)
		calls = StrictCallFake(
			"uiaFallback",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_AutomationIdPropertyId", 30011),
						("UIA_ControlTypePropertyId", 30003),
						("UIA_DescribedByPropertyId", 30105),
						("UIA_LabeledByPropertyId", 30018),
						("UIA_NamePropertyId", 30005),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall(
					"createCacheRequest",
					((30011, 30003, 30105, 30018, 30005),),
					ObjectRead("failed", errorCode="KS.UIA.CACHE_FAILED"),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30011, budget),
					ProviderReadResult("empty"),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30003, budget),
					ProviderReadResult("unsupported"),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30105, budget),
					ProviderReadResult("failed", errorCode="KS.UIA.MALFORMED_REFERENCE"),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30018, budget),
					ProviderReadResult("value", ("mixed",)),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30005, budget),
					ProviderReadResult("failed", errorCode="KS.UIA.CURRENT_FAILED"),
				),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("failed", values["cache"].status)
		self.assertEqual("empty", values["AutomationId"].status)
		self.assertEqual("unsupported", values["ControlType"].status)
		self.assertEqual("KS.UIA.MALFORMED_REFERENCE", values["DescribedBy"].errorCode)
		self.assertEqual(("mixed",), values["LabeledBy"].value)
		self.assertEqual("failed", values["Name"].status)
		self.assertEqual("KS.UIA.CURRENT_FAILED", values["Name"].errorCode)
		self.assertEqual(5, values["propertyInventory"].value)
		self.assertFalse(values["propertyInventory"].truncated)
		self.assertEqual(0, values["patternInventory"].value)
		self.assertEqual(
			("AutomationId",),
			tuple(item.fieldId for item in section.identity),
		)
		calls.assertComplete()

	def test_property_read_budget_truncates_and_reports_inventory(self) -> None:
		target = object()
		budget = ReadBudget(1, 64, 250)
		calls = StrictCallFake(
			"uiaBudget",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_AutomationIdPropertyId", 30011),
						("UIA_NamePropertyId", 30005),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall(
					"createCacheRequest",
					((30011,),),
					ObjectRead("failed", errorCode="KS.UIA.NO_CACHE"),
				),
				ExpectedCall(
					"readCurrentProperty",
					("element", 30011, budget),
					ProviderReadResult("value", "okButton"),
				),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertEqual(2, values["propertyInventory"].value)
		self.assertTrue(values["propertyInventory"].truncated)
		calls.assertComplete()

	def test_pattern_availability_requires_strict_boolean_true(self) -> None:
		target = object()
		budget = ReadBudget(8, 64, 250)
		calls = StrictCallFake(
			"uiaPatternStrict",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_IsTogglePatternAvailablePropertyId", 30086),
						("UIA_TogglePatternId", 10015),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall("createCacheRequest", ((30086,),), ObjectRead("value", "cacheRequest")),
				ExpectedCall("buildUpdatedCache", ("element", "cacheRequest"), ObjectRead("value", "cache")),
				ExpectedCall(
					"readCachedProperty",
					("cache", 30086, budget),
					ProviderReadResult("value", ("mixed",)),
				),
				ExpectedCall("releaseResource", ("cache",), None),
				ExpectedCall("releaseResource", ("cacheRequest",), None),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("unsupported", values["Toggle"].status)
		calls.assertComplete()

	def test_identity_is_prioritized_and_unread_pattern_availability_is_explicit(self) -> None:
		target = object()
		budget = ReadBudget(1, 64, 250)
		calls = StrictCallFake(
			"uiaPatternBudget",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_AutomationIdPropertyId", 30011),
						("UIA_IsTogglePatternAvailablePropertyId", 30086),
						("UIA_NamePropertyId", 30005),
						("UIA_TogglePatternId", 10015),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall("createCacheRequest", ((30011,),), ObjectRead("value", "cacheRequest")),
				ExpectedCall("buildUpdatedCache", ("element", "cacheRequest"), ObjectRead("value", "cache")),
				ExpectedCall(
					"readCachedProperty",
					("cache", 30011, budget),
					ProviderReadResult("value", "submit"),
				),
				ExpectedCall("releaseResource", ("cache",), None),
				ExpectedCall("releaseResource", ("cacheRequest",), None),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("submit", values["AutomationId"].value)
		self.assertEqual("unavailable", values["Toggle"].status)
		self.assertEqual(
			"KS.PROVIDER.UIA_PROPERTY_BUDGET_EXHAUSTED",
			values["Toggle"].errorCode,
		)
		self.assertNotIn("Name", values)
		self.assertTrue(values["propertyInventory"].truncated)
		calls.assertComplete()

	def test_all_identity_properties_precede_pattern_and_general_inventory(self) -> None:
		plan = UiaScanPlan.discover(
			(
				("UIA_NamePropertyId", 30005),
				("UIA_AutomationIdPropertyId", 30011),
				("UIA_ProcessIdPropertyId", 30002),
				("UIA_NativeWindowHandlePropertyId", 30020),
				("UIA_IsTogglePatternAvailablePropertyId", 30086),
				("UIA_TogglePatternId", 10015),
			),
		)
		target = object()
		budget = ReadBudget(3, 64, 250)
		identityIds = tuple(item.value for item in plan.properties if item.name != "Name")
		calls = StrictCallFake(
			"uiaIdentityBudget",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_NamePropertyId", 30005),
						("UIA_AutomationIdPropertyId", 30011),
						("UIA_ProcessIdPropertyId", 30002),
						("UIA_NativeWindowHandlePropertyId", 30020),
						("UIA_IsTogglePatternAvailablePropertyId", 30086),
						("UIA_TogglePatternId", 10015),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall(
					"createCacheRequest",
					(identityIds,),
					ObjectRead("failed", errorCode="KS.UIA.NO_CACHE"),
				),
				*(
					ExpectedCall(
						"readCurrentProperty",
						("element", identifier, budget),
						ProviderReadResult("value", identifier),
					)
					for identifier in identityIds
				),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		self.assertEqual(
			{"AutomationId", "NativeWindowHandle", "ProcessId"},
			{item.fieldId for item in section.identity},
		)
		calls.assertComplete()

	def test_text_range_length_at_the_character_limit_is_marked_truncated(self) -> None:
		def getText(_maximum: int) -> str:
			return "abcd"

		textRange = SimpleNamespace(GetText=getText)

		def getElement(_index: int) -> object:
			return textRange

		ranges = SimpleNamespace(length=1, GetElement=getElement)
		pattern = SimpleNamespace(GetVisibleRanges=lambda: ranges)

		result = _readTextRangeGroup(pattern, "GetVisibleRanges", "VisibleRanges", 4, 2).result

		self.assertEqual(("abcd",), result.value)
		self.assertTrue(result.truncated)

	def test_unavailable_text_pattern_never_acquires_the_pattern_object(self) -> None:
		target = object()
		budget = ReadBudget(8, 64, 250)
		calls = StrictCallFake(
			"uiaTextUnavailable",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_IsTextPatternAvailablePropertyId", 30040),
						("UIA_TextPatternId", 10014),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall("createCacheRequest", ((30040,),), ObjectRead("value", "cacheRequest")),
				ExpectedCall("buildUpdatedCache", ("element", "cacheRequest"), ObjectRead("value", "cache")),
				ExpectedCall(
					"readCachedProperty",
					("cache", 30040, budget),
					ProviderReadResult("value", False),
				),
				ExpectedCall("releaseResource", ("cache",), None),
				ExpectedCall("releaseResource", ("cacheRequest",), None),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertIs(False, values["Text"].value)
		self.assertNotIn("TextDocumentText", values)
		calls.assertComplete()

	def test_available_text_pattern_extracts_evidence_with_isolated_failures(self) -> None:
		target = object()
		budget = ReadBudget(8, 64, 250)
		textDatums = (
			ProviderDatum("DocumentText", ProviderReadResult("value", "hello world")),
			ProviderDatum(
				"VisibleRanges",
				ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_TEXT_RANGE_FAILED"),
			),
			ProviderDatum("SelectionRanges", ProviderReadResult("empty")),
			ProviderDatum("AggregateAttributes", ProviderReadResult("empty")),
		)
		calls = StrictCallFake(
			"uiaTextAvailable",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_IsTextPatternAvailablePropertyId", 30040),
						("UIA_TextPatternId", 10014),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall("createCacheRequest", ((30040,),), ObjectRead("value", "cacheRequest")),
				ExpectedCall("buildUpdatedCache", ("element", "cacheRequest"), ObjectRead("value", "cache")),
				ExpectedCall(
					"readCachedProperty",
					("cache", 30040, budget),
					ProviderReadResult("value", True),
				),
				ExpectedCall(
					"acquirePattern",
					("element", 10014, "IUIAutomationTextPattern"),
					ObjectRead("value", "textPatternObject"),
				),
				ExpectedCall(
					"readTextPatternEvidence",
					("textPatternObject", (), budget),
					textDatums,
				),
				ExpectedCall("releaseResource", ("textPatternObject",), None),
				ExpectedCall("releaseResource", ("cache",), None),
				ExpectedCall("releaseResource", ("cacheRequest",), None),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertIs(True, values["Text"].value)
		self.assertEqual("hello world", values["TextDocumentText"].value)
		self.assertEqual("failed", values["TextVisibleRanges"].status)
		self.assertEqual("KS.PROVIDER.UIA_TEXT_RANGE_FAILED", values["TextVisibleRanges"].errorCode)
		self.assertEqual("empty", values["TextSelectionRanges"].status)
		self.assertEqual("empty", values["TextAggregateAttributes"].status)
		calls.assertComplete()

	def test_text_pattern_object_acquisition_failure_is_reported_without_aborting(self) -> None:
		target = object()
		budget = ReadBudget(8, 64, 250)
		calls = StrictCallFake(
			"uiaTextAcquireFailure",
			(
				ExpectedCall(
					"installedIdentifiers",
					(),
					(
						("UIA_IsTextPatternAvailablePropertyId", 30040),
						("UIA_TextPatternId", 10014),
					),
				),
				ExpectedCall("acquireElement", (target,), ObjectRead("value", "element")),
				ExpectedCall("createCacheRequest", ((30040,),), ObjectRead("value", "cacheRequest")),
				ExpectedCall("buildUpdatedCache", ("element", "cacheRequest"), ObjectRead("value", "cache")),
				ExpectedCall(
					"readCachedProperty",
					("cache", 30040, budget),
					ProviderReadResult("value", True),
				),
				ExpectedCall(
					"acquirePattern",
					("element", 10014, "IUIAutomationTextPattern"),
					ObjectRead("failed", errorCode="KS.PROVIDER.UIA_PATTERN_ACQUIRE_FAILED"),
				),
				ExpectedCall("releaseResource", ("cache",), None),
				ExpectedCall("releaseResource", ("cacheRequest",), None),
			),
		)

		section = UiaProviderAdapter(_UiaGetter(calls)).collect(target, budget)

		values = {item.fieldId: item.result for item in section.properties}
		self.assertIs(True, values["Text"].value)
		self.assertEqual("failed", values["TextPatternObject"].status)
		self.assertEqual("KS.PROVIDER.UIA_PATTERN_ACQUIRE_FAILED", values["TextPatternObject"].errorCode)
		calls.assertComplete()


class ProviderExpansionTests(unittest.TestCase):
	def test_jab_com_errors_map_to_stable_acquire_and_field_statuses(self) -> None:
		class _ComError(Exception):
			pass

		class JAB:
			@override
			def __getattribute__(self, name: str) -> object:
				if name in ("jabContext", "_JABAccContextInfo"):
					raise _ComError("JAB context is unavailable")
				return object.__getattribute__(self, name)

		target = JAB()
		budget = ReadBudget(8, 128, 250)

		acquired = NvdaJabGetter.acquire(target)
		read = NvdaJabGetter.read(target, "rawRole", budget).result

		self.assertEqual(("failed", "KS.PROVIDER.JAB_ACQUIRE_FAILED"), (acquired.status, acquired.errorCode))
		self.assertEqual(("failed", "KS.PROVIDER.JAB_FIELD_FAILED"), (read.status, read.errorCode))

	def test_overlay_com_errors_map_to_stable_application_and_field_statuses(self) -> None:
		class _ComError(Exception):
			pass

		class _Overlay:
			@override
			def __getattribute__(self, name: str) -> object:
				if name in ("appModule", "windowClassName"):
					raise _ComError("overlay data is unavailable")
				return object.__getattribute__(self, name)

		target = _Overlay()
		budget = ReadBudget(8, 128, 250)

		application = NvdaOverlayGetter.read(target, "logicalApplication", budget)
		windowClass = NvdaOverlayGetter.read(target, "windowClass", budget)

		self.assertEqual(
			("failed", "KS.PROVIDER.OVERLAY_APP_FAILED"),
			(application.status, application.errorCode),
		)
		self.assertEqual(
			("failed", "KS.PROVIDER.OVERLAY_FIELD_FAILED"),
			(windowClass.status, windowClass.errorCode),
		)

	def test_ia2_com_errors_map_to_stable_capability_and_field_statuses(self) -> None:
		class _ComError(Exception):
			pass

		class IAccessible:
			@override
			def __getattribute__(self, name: str) -> object:
				if name == "IA2UniqueID":
					raise _ComError("IA2 object is unavailable")
				return object.__getattribute__(self, name)

		target = IAccessible()
		read = NvdaIa2MsaaGetter.read(target, "IA2UniqueID", ReadBudget(8, 128, 250)).result

		self.assertFalse(NvdaIa2MsaaGetter.supportsIa2(target))
		self.assertEqual(("failed", "KS.PROVIDER.IA2_FIELD_FAILED"), (read.status, read.errorCode))

	def test_jab_windows_bool_capabilities_are_normalized(self) -> None:
		class JAB:
			def __init__(self) -> None:
				super().__init__()
				self.jabContext: object = type("_Context", (), {"vmID": 2})()
				self._JABAccContextInfo: object = type(
					"_Info",
					(),
					{
						"accessibleComponent": 1,
						"accessibleAction": 0,
						"accessibleSelection": 0,
						"accessibleText": 1,
						"accessibleValue": 0,
					},
				)()

		target = JAB()
		result = NvdaJabGetter.read(target, "textCapable", ReadBudget(8, 128, 250)).result

		self.assertIs(True, result.value)

	def test_plain_msaa_is_ordinary_and_does_not_probe_ia2_optionals(self) -> None:
		target = object()
		budget = ReadBudget(16, 128, 250)
		calls = StrictCallFake(
			"msaa",
			(
				ExpectedCall("acquire", (target,), ProviderReadResult("value", "selected")),
				ExpectedCall("supportsIa2", (target,), False),
				ExpectedCall(
					"read",
					(target, "event_windowHandle", budget),
					OwnedProviderRead(ProviderReadResult("value", 42)),
				),
				ExpectedCall(
					"read",
					(target, "event_objectID", budget),
					OwnedProviderRead(ProviderReadResult("value", -4)),
				),
				ExpectedCall(
					"read",
					(target, "event_childID", budget),
					OwnedProviderRead(ProviderReadResult("value", 7)),
				),
			),
		)

		section = Ia2MsaaProviderAdapter(_Ia2Getter(calls)).collect(target, budget)

		self.assertEqual("msaaOnly", section.status.value)
		self.assertFalse(
			dict((item.fieldId, item.result.value) for item in section.properties)["ia2Available"],
		)
		calls.assertComplete()

	def test_ia2_reads_only_members_materialized_by_current_nvda_objects(self) -> None:
		target = object()
		budget = ReadBudget(16, 128, 250)
		expected: list[ExpectedCall] = [
			ExpectedCall("acquire", (target,), ProviderReadResult("value", "selected")),
			ExpectedCall("supportsIa2", (target,), True),
			ExpectedCall(
				"read",
				(target, "windowHandle", budget),
				OwnedProviderRead(ProviderReadResult("value", 42)),
			),
			ExpectedCall(
				"read",
				(target, "IA2UniqueID", budget),
				OwnedProviderRead(ProviderReadResult("value", 99)),
			),
		]
		for fieldId, member in (
			("attributes", "IA2Attributes"),
			("rawRole", "IAccessibleRole"),
			("rawStates", "IAccessibleStates"),
		):
			result = (
				OwnedProviderRead(
					ProviderReadResult("failed", errorCode="KS.IA2.ROLE_FAILED"),
				)
				if fieldId == "rawRole"
				else OwnedProviderRead(ProviderReadResult("value", (("id", "node-2"),)))
				if fieldId == "attributes"
				else OwnedProviderRead(ProviderReadResult("value", 0))
			)
			expected.append(ExpectedCall("read", (target, member, budget), result))
		for member in (
			"IAccessibleActionObject",
			"IAccessibleTable2Object",
			"IAccessibleTableObject",
			"IAccessibleTextObject",
		):
			expected.append(
				ExpectedCall(
					"read",
					(target, member, budget),
					OwnedProviderRead(ProviderReadResult("unsupported")),
				),
			)
		calls = StrictCallFake("ia2", tuple(expected))

		section = Ia2MsaaProviderAdapter(_Ia2Getter(calls)).collect(target, budget)

		properties = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("value", properties["attributes"].status)
		self.assertEqual("failed", properties["rawRole"].status)
		self.assertEqual(
			{
				"ia2Available",
				"attributes",
				"rawRole",
				"rawStates",
				"actionInterface",
				"table2Interface",
				"tableInterface",
				"textInterface",
			},
			set(properties),
		)
		calls.assertComplete()

	def test_jab_event_identity_uses_the_materialized_context_handle(self) -> None:
		target = SimpleNamespace(
			processID=41,
			windowHandle=101,
			jabContext=SimpleNamespace(
				vmID=7,
				accContext=SimpleNamespace(value=9001),
			),
		)

		identity = targetIdentityFromObject(target)

		self.assertIsNotNone(identity)
		assert identity is not None
		self.assertEqual((("jabObject", "7:9001"),), identity.providerEvidence)

	def test_uia_event_identity_uses_the_runtime_id_without_an_automation_id(self) -> None:
		target = SimpleNamespace(
			processID=41,
			windowHandle=101,
			UIAAutomationId="",
			UIAElement=SimpleNamespace(GetRuntimeId=lambda: [42, 1_234, 5_678]),
		)

		identity = targetIdentityFromObject(target)

		self.assertIsNotNone(identity)
		assert identity is not None
		self.assertEqual((("uiaRuntimeId", "42.1234.5678"),), identity.providerEvidence)
		self.assertEqual(41, identity.processId)
		self.assertEqual(101, identity.windowHandle)

	def test_uia_runtime_identity_never_correlates_across_process_or_window(self) -> None:
		element = SimpleNamespace(GetRuntimeId=lambda: [42, 7])
		target = SimpleNamespace(processID=41, windowHandle=101, UIAElement=element)
		otherProcess = SimpleNamespace(processID=42, windowHandle=101, UIAElement=element)
		otherWindow = SimpleNamespace(processID=41, windowHandle=102, UIAElement=element)

		identity = targetIdentityFromObject(target)
		acrossProcess = targetIdentityFromObject(otherProcess)
		acrossWindow = targetIdentityFromObject(otherWindow)

		assert identity is not None
		assert acrossProcess is not None
		assert acrossWindow is not None
		self.assertTrue(identity.correlates(identity))
		self.assertFalse(identity.correlates(acrossProcess))
		self.assertFalse(identity.correlates(acrossWindow))

	def test_uia_runtime_identity_reports_com_failure_and_yields_no_evidence(self) -> None:
		class _ComError(Exception):
			def __init__(self) -> None:
				super().__init__("element unavailable")
				self.hresult = -2147220991

		failures: list[bool] = []

		def raiseComError() -> list[int]:
			raise _ComError()

		target = SimpleNamespace(
			processID=41,
			windowHandle=101,
			UIAElement=SimpleNamespace(GetRuntimeId=raiseComError),
		)

		identity = targetIdentityFromObject(target, onComFailure=lambda: failures.append(True))

		self.assertIsNone(identity)
		self.assertEqual([True], failures)

	def test_uia_runtime_identity_ignores_an_unreadable_runtime_id(self) -> None:
		for runtimeId in ("not-a-runtime-id", (), None):
			with self.subTest(runtimeId=runtimeId):
				target = SimpleNamespace(
					processID=41,
					windowHandle=101,
					UIAElement=SimpleNamespace(GetRuntimeId=lambda value=runtimeId: value),
				)

				self.assertIsNone(targetIdentityFromObject(target))

	def test_jab_capability_flags_gate_metadata_and_release_short_lived_context(self) -> None:
		target = object()
		budget = ReadBudget(16, 128, 250)
		ledger = ResourceLedger("jab")
		ledger.acquire("states-context")
		values: dict[str, object] = {
			"vmId": 2,
			"rawRole": "text",
			"rawStates": "enabled,visible",
			"componentCapable": True,
			"actionCapable": False,
			"selectionCapable": False,
			"textCapable": True,
			"valueCapable": False,
		}
		expected = [ExpectedCall("acquire", (target,), ProviderReadResult("value", "selected"))]
		for fieldId in values:
			owned = OwnedJabRead(
				ProviderReadResult("value", values[fieldId]),  # pyright: ignore[reportArgumentType]
				"states-context" if fieldId == "rawStates" else None,
			)
			expected.append(ExpectedCall("read", (target, fieldId, budget), owned))
			if fieldId == "rawStates":
				expected.append(
					ExpectedCall(
						"releaseResource",
						("states-context",),
						None,
						releaseTokenArgument=0,
					),
				)
		calls = StrictCallFake("jab", tuple(expected), ledger=ledger)

		section = JabProviderAdapter(_JabGetter(calls)).collect(target, budget)

		properties = {item.fieldId: item.result for item in section.properties}
		self.assertEqual("value", properties["text"].status)
		self.assertEqual("unsupported", properties["actions"].status)
		self.assertEqual("unsupported", properties["value"].status)
		calls.assertComplete()

	def test_overlay_uses_only_already_materialized_selected_metadata(self) -> None:
		target = object()
		budget = ReadBudget(8, 128, 250)
		calls = StrictCallFake(
			"overlay",
			(
				ExpectedCall(
					"read",
					(target, "overlayClasses", budget),
					ProviderReadResult("value", ("PowerPointDocumentWindow", "IAccessible")),
				),
				ExpectedCall(
					"read",
					(target, "logicalApplication", budget),
					ProviderReadResult("value", "powerpnt"),
				),
				ExpectedCall(
					"read",
					(target, "windowClass", budget),
					ProviderReadResult("value", "PPTFrameClass"),
				),
				ExpectedCall(
					"read",
					(target, "presentationType", budget),
					ProviderReadResult("unsupported"),
				),
				ExpectedCall(
					"read",
					(target, "shapeType", budget),
					ProviderReadResult("unsupported"),
				),
			),
		)

		section = OverlayProviderAdapter(_OverlayGetter(calls)).collect(target, budget)

		self.assertEqual("selectedObject", section.status.value)
		self.assertEqual(("PowerPointDocumentWindow", "IAccessible"), section.identity[0].result.value)
		calls.assertComplete()
