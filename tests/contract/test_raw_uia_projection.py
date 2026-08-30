from __future__ import annotations

import inspect
from types import SimpleNamespace
import unittest

# pyright: reportPrivateUsage=false
from collections.abc import Callable
from typing import cast, override
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.providers.common import ObjectBatch
from addon.globalPlugins.keystone.adapters.providers.raw_uia import (
	NvdaRawUiaGetter,
	RawEvidenceQuality,
	RawProjectionOutcome,
	RawUiaAdapter,
)
from addon.globalPlugins.keystone.adapters.nvda.selected_objects import _fallbackProjectionPlain
from addon.globalPlugins.keystone.domain.correlation import CorrelationContext, CorrelationId
from addon.globalPlugins.keystone.domain.projection import (
	IdentityProbe,
	ProjectionBudget,
	ProjectionCandidate,
	ProjectionEvidence,
	ProjectionMethod,
	ProjectionRequest,
	ProjectionStatus,
	SelectedIdentity,
	decideProjection,
)
from addon.globalPlugins.keystone.ports.providers import (
	IdentityComparisonRequest,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ReadBudget,
)


def _context() -> CorrelationContext:
	return CorrelationContext(
		CorrelationId("00000000-0000-4000-8000-000000000001"),
		CorrelationId("00000000-0000-4000-8000-000000000002"),
		CorrelationId("00000000-0000-4000-8000-000000000003"),
		1,
	)


class _Getter:
	def __init__(
		self,
		*,
		candidates: tuple[object, ...] = ("raw-root",),
		processes: dict[object, int] | None = None,
		children: dict[object, tuple[object, ...]] | None = None,
		emptyRoot: bool = False,
		processResult: ProviderReadResult | None = None,
		qualities: dict[object, RawEvidenceQuality] | None = None,
	) -> None:
		super().__init__()
		self.candidates = candidates
		self.processes = processes or {candidate: 41 for candidate in candidates}
		self.children = children or {"raw-root": ("raw-child",), "raw-child": ()}
		self.emptyRoot = emptyRoot
		self.processResult = processResult
		self.qualities = qualities or {candidate: "native" for candidate in candidates}
		self.calls: list[tuple[str, object]] = []
		self.windowContexts: list[tuple[object, int | None]] = []

	def nvdaProcessId(self) -> int:
		return 999

	def selectedIdentity(self, target: object, budget: ReadBudget) -> SelectedIdentity:
		self.calls.append(("selectedIdentity", target))
		return SelectedIdentity(41, "uia", "window", (("runtime", (1,)),), 101, True)

	def candidateElements(
		self,
		target: object,
		targetKind: str,
		maximumCandidates: int,
		*,
		preferPoint: bool = False,
	) -> ObjectBatch:
		self.calls.append(("candidateElements", (targetKind, preferPoint)))
		values = self.candidates[:maximumCandidates]
		return ObjectBatch(
			"value" if values else "empty",
			values,
			len(self.candidates),
			len(values) < len(self.candidates),
		)

	def processId(self, element: object) -> ProviderReadResult:
		self.calls.append(("processId", element))
		if self.processResult is not None:
			return self.processResult
		process = self.processes.get(element)
		return (
			ProviderReadResult("value", process)
			if process is not None
			else ProviderReadResult("failed", errorCode="KS.TEST.PID")
		)

	def evidenceQuality(
		self,
		element: object,
		*,
		windowHandle: int | None = None,
	) -> RawEvidenceQuality:
		self.calls.append(("evidenceQuality", element))
		self.windowContexts.append((element, windowHandle))
		return self.qualities.get(element, "incomplete")

	def candidateIdentity(
		self,
		element: object,
		processId: int,
		budget: ReadBudget,
	) -> ProjectionCandidate:
		self.calls.append(("candidateIdentity", element))
		if processId != self.processes[element]:
			raise AssertionError("candidate process ID was not reused")
		return ProjectionCandidate(
			str(element),
			processId,
			"uia",
			"window",
			(("runtime", (1,)),),
			101,
			True,
			IdentityProbe(providerComparison="same"),
		)

	def readProperty(self, element: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		self.calls.append(("readProperty", fieldId))
		if fieldId == "process":
			return self.processId(element)
		if fieldId == "name":
			return ProviderReadResult("value", "raw")
		return ProviderReadResult("unsupported")

	def rawChildren(self, element: object, budget: ReadBudget) -> ObjectBatch:
		self.calls.append(("rawChildren", element))
		values = self.children.get(element, ())
		if self.emptyRoot and element == "raw-root":
			return ObjectBatch("empty", (), 0, False)
		return ObjectBatch("value" if values else "empty", values, len(values), False)

	def releaseElement(self, element: object) -> None:
		self.calls.append(("releaseElement", element))


class _ErrorChildrenGetter(_Getter):
	@override
	def rawChildren(self, element: object, budget: ReadBudget) -> ObjectBatch:
		if not any(call[0] == "rawChildren" for call in self.calls):
			return super().rawChildren(element, budget)
		self.calls.append(("rawChildren", element))
		return ObjectBatch("failed", ("partial-child",), 1, True, "KS.TEST.CHILDREN")


class _ProviderLookupErrorGetter(_Getter):
	def __init__(self) -> None:
		super().__init__()
		self.failReads = False

	@override
	def readProperty(self, element: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		_ = element, fieldId, budget
		raise KeyError("provider-secret")

	@override
	def rawChildren(self, element: object, budget: ReadBudget) -> ObjectBatch:
		if self.failReads:
			raise IndexError("provider-secret")
		return super().rawChildren(element, budget)


class _Walker:
	def __init__(self, children: tuple[object, ...]) -> None:
		super().__init__()
		self.children = children

	def GetFirstChildElement(self, element: object) -> object | None:
		_ = element
		return self.children[0] if self.children else None

	def GetNextSiblingElement(self, child: object) -> object | None:
		index = self.children.index(child) + 1
		return self.children[index] if index < len(self.children) else None


class _ComFailingLeafWalker(_Walker):
	@override
	def GetFirstChildElement(self, element: object) -> object | None:
		_ = element
		raise _ComFailure()

	def GetFirstChildElementBuildCache(self, element: object, cacheRequest: object) -> object | None:
		_ = element, cacheRequest
		raise _ComFailure()


class _CachedTreeElement:
	def __init__(
		self,
		name: str,
		*,
		process: int = 41,
		windowHandle: int = 707,
		role: str = "document",
	) -> None:
		super().__init__()
		self.name = name
		self.CachedProcessId = process
		self.CachedNativeWindowHandle = windowHandle
		self.CachedLocalizedControlType = role

	def getCurrentPropertyValueEx(self, identifier: int, ignoreDefault: bool) -> object:
		_ = identifier, ignoreDefault
		raise AssertionError("cached identity should avoid a current-property read")

	def getRuntimeId(self) -> tuple[int, ...]:
		return (len(self.name),)


class _CachedSiblingWalker(_Walker):
	def __init__(
		self,
		children: tuple[object, ...],
		*,
		failAfterChild: int | None = None,
		failureType: type[Exception] | None = None,
	) -> None:
		super().__init__(children)
		self.failAfterChild = failAfterChild
		self.failureType = failureType or _ComFailure
		self.calls: list[str] = []

	def GetFirstChildElementBuildCache(self, element: object, cacheRequest: object) -> object | None:
		_ = element, cacheRequest
		self.calls.append("GetFirstChildElementBuildCache")
		return self.children[0] if self.children else None

	@override
	def GetFirstChildElement(self, element: object) -> object | None:
		self.calls.append("GetFirstChildElement")
		return super().GetFirstChildElement(element)

	def _next(self, child: object) -> object | None:
		current = self.children.index(child) + 1
		if self.failAfterChild == current:
			raise self.failureType()
		return self.children[current] if current < len(self.children) else None

	def GetNextSiblingElementBuildCache(self, child: object, cacheRequest: object) -> object | None:
		_ = cacheRequest
		self.calls.append("GetNextSiblingElementBuildCache")
		return self._next(child)

	@override
	def GetNextSiblingElement(self, child: object) -> object | None:
		self.calls.append("GetNextSiblingElement")
		return self._next(child)


class _Handler:
	def __init__(
		self,
		walker: _Walker,
		*,
		unsupportedValue: object | None = None,
		clientObject: object | None = None,
		baseCacheRequest: object | None = None,
		native: bool = True,
	) -> None:
		super().__init__()
		self.baseTreeWalker = walker
		self.reservedNotSupportedValue = unsupportedValue
		self.clientObject = clientObject
		self.baseCacheRequest = baseCacheRequest
		self.native = native
		self.nativeCalls: list[object] = []

	def isNativeUIAElement(self, element: object) -> bool:
		self.nativeCalls.append(element)
		return self.native


class _EqualSentinel:
	@override
	def __eq__(self, other: object) -> bool:
		return isinstance(other, _EqualSentinel)


class _IndeterminateText(str):
	@override
	def __eq__(self, other: object) -> bool:
		_ = other
		return cast(bool, NotImplemented)


class _PropertyElement:
	def __init__(self, value: object) -> None:
		super().__init__()
		self.value = value

	def getCurrentPropertyValueEx(self, identifier: int, ignoreDefault: bool) -> object:
		_ = identifier, ignoreDefault
		return self.value


class _NamedPropertyElement(_PropertyElement):
	CachedLocalizedControlType: str
	CachedNativeWindowHandle: int

	def __init__(self, name: str, role: str, windowHandle: int) -> None:
		super().__init__(name)
		self.CachedLocalizedControlType = role
		self.CachedNativeWindowHandle = windowHandle


class _RuntimeElement:
	def __init__(self, runtimeId: tuple[int, ...]) -> None:
		super().__init__()
		self.runtimeId = runtimeId

	def getRuntimeId(self) -> tuple[int, ...]:
		return self.runtimeId


class _CandidateElement(_RuntimeElement):
	def getCurrentPropertyValueEx(self, identifier: int, ignoreDefault: bool) -> object:
		_ = ignoreDefault
		return {
			30003: 50000,
			30020: 101,
		}[identifier]


class _FailingPropertyElement:
	def getCurrentPropertyValueEx(self, identifier: int, ignoreDefault: bool) -> object:
		_ = identifier, ignoreDefault
		raise OSError("injected property failure")


# Fixed identifier used for every acquisition test below; the real numeric value
# is irrelevant because `_identifier` is always patched to this mapping.
_PROCESS_IDENTIFIER = 30002
_PROCESS_IDENTIFIERS: dict[str, int] = {"UIA_ProcessIdPropertyId": _PROCESS_IDENTIFIER}


class _ProcessElement:
	"""A raw candidate element that only answers UIA_ProcessIdPropertyId reads."""

	def __init__(self, process: int, *, runtimeId: tuple[int, ...] | None = None) -> None:
		super().__init__()
		self.process = process
		self.runtimeId = runtimeId

	def getCurrentPropertyValueEx(self, identifier: int, ignoreDefault: bool) -> object:
		_ = ignoreDefault
		return self.process if identifier == _PROCESS_IDENTIFIER else None

	def getRuntimeId(self) -> tuple[int, ...]:
		if self.runtimeId is None:
			raise OSError("no runtime id for this element")
		return self.runtimeId


class _AcquisitionClient:
	"""A fake IUIAutomation client covering element acquisition and comparison only."""

	def __init__(
		self,
		*,
		byHandle: dict[int, object] | None = None,
		byAccessible: dict[tuple[object, int], object] | None = None,
		handleError: bool = False,
		byPoint: object | None = None,
		pointError: bool = False,
		focused: object | None = None,
		focusedError: bool = False,
		compare: Callable[[object, object], bool] | None = None,
		compareAvailable: bool = True,
	) -> None:
		super().__init__()
		self._byHandle = byHandle or {}
		self._byAccessible = byAccessible or {}
		self._handleError = handleError
		self._byPoint = byPoint
		self._pointError = pointError
		self._focused = focused
		self._focusedError = focusedError
		self.calls: list[str] = []
		self.cacheRequests: list[object] = []
		self.CompareElements: Callable[[object, object], bool] | None = (
			(compare if compare is not None else (lambda first, second: first is second))
			if compareAvailable
			else None
		)

	def ElementFromHandle(self, hwnd: int) -> object:
		self.calls.append("ElementFromHandle")
		if self._handleError:
			raise OSError("injected ElementFromHandle failure")
		if hwnd in self._byHandle:
			return self._byHandle[hwnd]
		raise OSError("no element registered for this handle")

	def ElementFromHandleBuildCache(self, hwnd: int, cacheRequest: object) -> object:
		self.calls.append("ElementFromHandleBuildCache")
		self.cacheRequests.append(cacheRequest)
		if self._handleError:
			raise OSError("injected ElementFromHandle failure")
		if hwnd in self._byHandle:
			return self._byHandle[hwnd]
		raise OSError("no element registered for this handle")

	def ElementFromIAccessible(self, accessible: object, childId: int) -> object:
		self.calls.append("ElementFromIAccessible")
		try:
			return self._byAccessible[(accessible, childId)]
		except KeyError as error:
			raise OSError("no element registered for this IAccessible input") from error

	def ElementFromIAccessibleBuildCache(
		self,
		accessible: object,
		childId: int,
		cacheRequest: object,
	) -> object:
		self.calls.append("ElementFromIAccessibleBuildCache")
		self.cacheRequests.append(cacheRequest)
		_ = cacheRequest
		try:
			return self._byAccessible[(accessible, childId)]
		except KeyError as error:
			raise OSError("no element registered for this IAccessible input") from error

	def ElementFromPoint(self, point: object) -> object:
		self.calls.append("ElementFromPoint")
		_ = point
		if self._pointError or self._byPoint is None:
			raise OSError("no element registered for this point")
		return self._byPoint

	def ElementFromPointBuildCache(self, point: object, cacheRequest: object) -> object:
		self.calls.append("ElementFromPointBuildCache")
		self.cacheRequests.append(cacheRequest)
		_ = point
		if self._pointError or self._byPoint is None:
			raise OSError("no element registered for this point")
		return self._byPoint

	def GetFocusedElement(self) -> object:
		self.calls.append("GetFocusedElement")
		if self._focusedError or self._focused is None:
			raise OSError("no focused element registered")
		return self._focused

	def GetFocusedElementBuildCache(self, cacheRequest: object) -> object:
		self.calls.append("GetFocusedElementBuildCache")
		self.cacheRequests.append(cacheRequest)
		if self._focusedError or self._focused is None:
			raise OSError("no focused element registered")
		return self._focused


class _RecordingWatchdog:
	def __init__(self, error: Exception | None = None) -> None:
		super().__init__()
		self.error = error
		self.calls: list[str] = []

	def cancellableExecute(
		self,
		func: Callable[..., object],
		*args: object,
		**kwargs: object,
	) -> object:
		_ = kwargs
		self.calls.append(getattr(func, "__name__", type(func).__name__))
		if self.error is not None:
			raise self.error
		return func(*args)


class _CurrentPropertyComFailureWatchdog(_RecordingWatchdog):
	@override
	def cancellableExecute(
		self,
		func: Callable[..., object],
		*args: object,
		**kwargs: object,
	) -> object:
		name = getattr(func, "__name__", type(func).__name__)
		self.calls.append(name)
		if name in {
			"getCurrentPropertyValueEx",
			"getRuntimeId",
			"isNativeUIAElement",
			"GetFirstChildElement",
			"GetFirstChildElementBuildCache",
			"GetNextSiblingElement",
			"GetNextSiblingElementBuildCache",
		}:
			raise _ComFailure()
		return func(*args, **kwargs)


class _CancelledCall(Exception):
	pass


class _ComFailure(Exception):
	hresult = -2147220991


class _AbsentRead:
	def read(self) -> None:
		return None


def _acquisitionHandler(client: _AcquisitionClient) -> _Handler:
	return _Handler(_Walker(()), clientObject=client)


class RawUiaTracerTests(unittest.TestCase):
	def test_selected_runtime_identity_is_bounded_and_complete(self) -> None:
		target = type(
			"_Target",
			(),
			{
				"processID": 41,
				"role": "window",
				"windowHandle": 101,
				"UIAElement": _RuntimeElement((1, 2, 3)),
			},
		)()
		getter = NvdaRawUiaGetter()

		complete = getter.selectedIdentity(target, ReadBudget(3, 80, 50))
		truncated = getter.selectedIdentity(target, ReadBudget(2, 80, 50))

		self.assertEqual((("runtime", (1, 2, 3)),), complete.stableKeys)
		self.assertEqual((), truncated.stableKeys)

	def test_numeric_control_type_is_not_coerced_into_a_semantic_role(self) -> None:
		getter = NvdaRawUiaGetter()
		element = _CandidateElement((1, 2, 3))
		handler = _Handler(_Walker(()), unsupportedValue=object())
		identifiers = {
			"UIA_ControlTypePropertyId": 30003,
			"UIA_NativeWindowHandlePropertyId": 30020,
		}
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=identifiers.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			candidate = getter.candidateIdentity(element, 41, ReadBudget(8, 80, 50))

		self.assertIsNone(candidate.role)
		self.assertEqual(101, candidate.windowHandle)
		self.assertEqual((("runtime", (1, 2, 3)),), candidate.stableKeys)

	def test_control_type_role_uses_a_readable_name_and_keeps_its_identifier(self) -> None:
		getter = NvdaRawUiaGetter()
		handler = _Handler(_Walker(()), unsupportedValue=object())
		module = type(
			"_Module",
			(),
			{
				"UIA_ControlTypePropertyId": 30003,
				"UIA_PaneControlTypeId": 50033,
			},
		)()
		with (
			patch.object(NvdaRawUiaGetter, "_module", return_value=module),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			result = getter.readProperty(
				_PropertyElement(50033),
				"role",
				ReadBudget(2, 80, 50),
			)

		self.assertEqual("value", result.status)
		self.assertEqual("Pane (50033)", result.value)

	def test_position_resolved_candidate_requires_the_selected_name(self) -> None:
		getter = NvdaRawUiaGetter()
		element = _NamedPropertyElement("Subtitle placeholder", "pane", 555)
		target = type(
			"_SelectedShape",
			(),
			{"processID": 41, "windowHandle": 555, "role": "shape", "name": "Subtitle placeholder"},
		)()
		handler = _Handler(_Walker(()), unsupportedValue=object())
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", return_value=30005),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			_ = getter.selectedIdentity(target, ReadBudget(2, 80, 50))
			getter._spatialElement = element
			getter._pointResolvedElement = element
			candidate = getter.candidateIdentity(element, 41, ReadBudget(2, 80, 50))

		self.assertTrue(candidate.probe.geometryGuidance)
		self.assertTrue(candidate.probe.positionAndNameMatch)

	def test_getter_release_clears_selected_com_reference(self) -> None:
		element = object()
		target = type("_Target", (), {"UIAElement": element, "processID": 41})()
		getter = NvdaRawUiaGetter()
		_ = getter.selectedIdentity(target, ReadBudget(1, 32, 100))
		batch = getter.candidateElements(target, "foreground", 1)
		self.assertEqual((element,), batch.values)
		self.assertIs(element, getter._selectedElement)

		getter.releaseElement(element)

		self.assertIsNone(getter._selectedElement)

	def test_equal_com_wrappers_are_recognized_as_the_unsupported_sentinel(self) -> None:
		getter = NvdaRawUiaGetter()
		handler = _Handler(_Walker(()), unsupportedValue=_EqualSentinel())
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", return_value=30005),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			result = getter.readProperty(
				_PropertyElement(_EqualSentinel()),
				"name",
				ReadBudget(2, 80, 50),
			)
			indeterminate = getter.readProperty(
				_PropertyElement(_IndeterminateText("ordinary")),
				"name",
				ReadBudget(2, 80, 50),
			)
			empty = getter.readProperty(
				_PropertyElement(None),
				"name",
				ReadBudget(2, 80, 50),
			)

		self.assertEqual("unsupported", result.status)
		self.assertEqual("value", indeterminate.status)
		self.assertEqual("ordinary", indeterminate.value)
		self.assertEqual("empty", empty.status)

	def test_property_value_shape_failures_remain_distinct_from_provider_failures(self) -> None:
		getter = NvdaRawUiaGetter()
		handler = _Handler(_Walker(()), unsupportedValue=object())
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", return_value=30005),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			unsupported = getter.readProperty(
				_PropertyElement(float("inf")),
				"name",
				ReadBudget(2, 80, 50),
			)
			failed = getter.readProperty(
				_FailingPropertyElement(),
				"name",
				ReadBudget(2, 80, 50),
			)

		self.assertEqual("unsupported", unsupported.status)
		self.assertEqual("failed", failed.status)
		self.assertEqual("KS.RAW_UIA.PROPERTY_FAILED", failed.errorCode)

	def test_child_count_is_unsupported_without_bounded_enumeration(self) -> None:
		result = NvdaRawUiaGetter().readProperty(
			_PropertyElement(3),
			"childCount",
			ReadBudget(2, 80, 50),
		)

		self.assertEqual("unsupported", result.status)

	def test_raw_child_budget_probes_once_without_false_truncation(self) -> None:
		getter = NvdaRawUiaGetter()
		for children, expectedTruncated, expectedObserved in (
			(("first", "second"), False, 2),
			(("first", "second", "third"), True, 3),
		):
			with self.subTest(children=children):
				with patch.object(NvdaRawUiaGetter, "_handler", return_value=_Handler(_Walker(children))):
					result = getter.rawChildren("root", ReadBudget(2, 80, 50))

				self.assertEqual("value", result.status)
				self.assertEqual(("first", "second"), result.values)
				self.assertEqual(expectedObserved, result.observedCount)
				self.assertEqual(expectedTruncated, result.truncated)

	def test_cached_empty_first_child_does_not_try_plain_fallback(self) -> None:
		root = _CachedTreeElement("root")
		walker = _CachedSiblingWalker(())
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)

		with (
			patch.object(
				NvdaRawUiaGetter,
				"_handler",
				return_value=_Handler(walker, baseCacheRequest=object()),
			),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
		):
			result = getter.rawChildren(root, ReadBudget(8, 80, 50))

		self.assertEqual("empty", result.status)
		self.assertEqual(["GetFirstChildElementBuildCache"], walker.calls)
		self.assertEqual(["GetFirstChildElementBuildCache"], watchdog.calls)
		self.assertEqual(
			1,
			sum("raw.children.final" in message for message in diagnostics),
		)

	def test_cached_empty_sibling_stays_on_watchdog_and_skips_plain_fallback(self) -> None:
		root = _CachedTreeElement("root", windowHandle=808)
		child = _CachedTreeElement("child", windowHandle=808)
		walker = _CachedSiblingWalker((child,))
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		windowChecks: list[int | None] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)

		def recordWindowCheck(hwnd: int | None) -> None:
			windowChecks.append(hwnd)

		with (
			patch.object(
				NvdaRawUiaGetter,
				"_handler",
				return_value=_Handler(walker, baseCacheRequest=object()),
			),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(
				NvdaRawUiaGetter,
				"_windowBlockReason",
				side_effect=recordWindowCheck,
			),
		):
			result = getter.rawChildren(root, ReadBudget(8, 80, 50))

		self.assertEqual("value", result.status)
		self.assertEqual((child,), result.values)
		self.assertFalse(result.truncated)
		self.assertEqual(
			["GetFirstChildElementBuildCache", "GetNextSiblingElementBuildCache"],
			walker.calls,
		)
		self.assertEqual(walker.calls, watchdog.calls)
		self.assertEqual({808}, set(windowChecks))
		self.assertTrue(
			any(
				"raw.children.sibling" in message
				and "execution=watchdog" in message
				and "index=1" in message
				and "method=GetNextSiblingElementBuildCache" in message
				and "status=empty" in message
				for message in diagnostics
			),
		)

	def test_sibling_com_failure_retains_owner_thread_partial_batch(self) -> None:
		root = _CachedTreeElement("root")
		first = _CachedTreeElement("first")
		second = _CachedTreeElement("second")
		walker = _CachedSiblingWalker((first, second), failAfterChild=2)
		handler = _Handler(walker, baseCacheRequest=object())
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		released: list[object] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		getter._selectedElement = root
		getter._selectedIdentity = SelectedIdentity(41, "uia", "document", (), 707, False)

		with (
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "_isComFailure", return_value=True),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			result = getter.rawChildren(root, ReadBudget(8, 80, 50))

		self.assertEqual("value", result.status)
		self.assertEqual((first, second), result.values)
		self.assertEqual(2, result.observedCount)
		self.assertTrue(result.truncated)
		self.assertEqual([], released)
		self.assertEqual([], watchdog.calls)
		self.assertEqual(
			[
				"GetFirstChildElementBuildCache",
				"GetNextSiblingElementBuildCache",
				"GetNextSiblingElementBuildCache",
				"GetNextSiblingElement",
			],
			walker.calls,
		)
		self.assertTrue(
			any(
				"raw.children.sibling" in message
				and "execution=owner" in message
				and "hresult=0x80040201" in message
				and "index=2" in message
				and "method=GetNextSiblingElementBuildCache" in message
				and "status=failed" in message
				for message in diagnostics
			),
		)
		finalTraces = [message for message in diagnostics if "raw.children.final" in message]
		self.assertEqual(1, len(finalTraces))
		self.assertIn("error=KS.RAW_UIA.COM_FAILED", finalTraces[0])
		self.assertIn("observed=2", finalTraces[0])
		self.assertIn("outcome=partial", finalTraces[0])
		self.assertIn("retained=2", finalTraces[0])
		self.assertIn("status=value", finalTraces[0])
		self.assertIn("truncated=true", finalTraces[0])

	def test_non_com_sibling_failure_releases_retained_children(self) -> None:
		root = _CachedTreeElement("root")
		first = _CachedTreeElement("first")
		second = _CachedTreeElement("second")
		walker = _CachedSiblingWalker(
			(first, second),
			failAfterChild=2,
			failureType=OSError,
		)
		diagnostics: list[str] = []
		released: list[object] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		getter._selectedElement = root
		getter._selectedIdentity = SelectedIdentity(41, "uia", "document", (), 707, False)

		with (
			patch.object(
				NvdaRawUiaGetter,
				"_handler",
				return_value=_Handler(walker, baseCacheRequest=object()),
			),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			result = getter.rawChildren(root, ReadBudget(8, 80, 50))

		self.assertEqual("failed", result.status)
		self.assertEqual((), result.values)
		self.assertEqual([second, first], released)
		self.assertTrue(
			any(
				"raw.children.final" in message
				and "error=KS.RAW_UIA.CALL_FAILED" in message
				and "outcome=reject" in message
				for message in diagnostics
			),
		)

	def test_cached_identity_fields_avoid_current_property_reads(self) -> None:
		element = _CachedTreeElement("cached", process=99, windowHandle=909, role="pane")
		getter = NvdaRawUiaGetter()

		process = getter.processId(element)
		candidate = getter.candidateIdentity(element, 99, ReadBudget(8, 80, 50))

		self.assertEqual("value", process.status)
		self.assertEqual(99, process.value)
		self.assertEqual("pane", candidate.role)
		self.assertEqual(909, candidate.windowHandle)

	def test_explicit_request_projects_and_walks_direct_raw_children(self) -> None:
		getter = _Getter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(4, 16, 250)),
		)
		self.assertEqual(ProjectionStatus.APPLIED, outcome.evidence.status)
		self.assertTrue(outcome.evidence.requested)
		self.assertTrue(outcome.evidence.applied)
		self.assertEqual("providerNative", outcome.evidence.method.value)
		assert outcome.rootRef is not None

		children = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(8, 128, 250), _context()),
		)
		self.assertEqual("value", children.status)
		self.assertEqual(1, len(children.nodeRefs))
		self.assertEqual(1, getter.calls.count(("processId", "raw-root")))
		self.assertIn(("rawChildren", "raw-root"), getter.calls)
		self.assertNotIn(("rawChildren", "selected-root"), getter.calls)

		metadata = adapter.readMetadata(
			ProviderMetadataRequest(outcome.rootRef, "rawProjection", ReadBudget(8, 128, 250), _context()),
		)
		self.assertEqual("value", metadata.status)
		self.assertIn(("status", "applied"), cast(tuple[object, ...], metadata.value))
		self.assertIn(("requestId", "raw-request"), cast(tuple[object, ...], metadata.value))

		sectionsResult = adapter.readMetadata(
			ProviderMetadataRequest(
				outcome.rootRef,
				"providerSections",
				ReadBudget(8, 128, 250),
				_context(),
			),
		)
		sections = cast(tuple[tuple[object, object, object, object], ...], sectionsResult.value)
		byName = {cast(str, section[0]): section for section in sections}
		statuses = {name: cast(tuple[object, ...], section[1])[0] for name, section in byName.items()}
		self.assertEqual("value", statuses["rawUia"])
		self.assertEqual("value", statuses["uia"])
		self.assertEqual("unsupported", statuses["generic"])
		self.assertEqual("empty", cast(tuple[object, ...], byName["rawUia"][2])[0])
		self.assertEqual("value", cast(tuple[object, ...], byName["rawUia"][3])[0])

	def test_provider_lookup_errors_use_fixed_safe_codes(self) -> None:
		getter = _ProviderLookupErrorGetter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(4, 16, 250)),
		)
		assert outcome.rootRef is not None
		getter.failReads = True
		context = _context()

		field = adapter.readField(
			ProviderFieldRequest(outcome.rootRef, "name", ReadBudget(8, 128, 250), context),
		)
		rootChildren = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(8, 128, 250), context),
		)
		children = adapter.readChildren(
			ProviderChildrenRequest(rootChildren.nodeRefs[0], ReadBudget(8, 128, 250), context),
		)

		self.assertEqual(("failed", "KS.RAW_UIA.PROPERTY_FAILED"), (field.status, field.errorCode))
		self.assertEqual(("failed", "KS.RAW_UIA.CHILDREN_FAILED"), (children.status, children.errorCode))
		self.assertNotIn("provider-secret", str((field.errorCode, children.errorCode)))

	def test_unknown_node_references_use_fixed_stale_codes(self) -> None:
		adapter = RawUiaAdapter(_Getter(), generation=1)
		context = _context()

		field = adapter.readField(
			ProviderFieldRequest("secret-node", "name", ReadBudget(8, 128, 250), context),
		)
		children = adapter.readChildren(
			ProviderChildrenRequest("secret-node", ReadBudget(8, 128, 250), context),
		)
		metadata = adapter.readMetadata(
			ProviderMetadataRequest("secret-node", "rawProjection", ReadBudget(8, 128, 250), context),
		)
		comparison = adapter.compareIdentity(
			IdentityComparisonRequest(
				"secret-node",
				"other-secret-node",
				"rawUia",
				"process-41",
				ReadBudget(8, 128, 250),
				context,
			),
		)

		self.assertEqual(("stale", "KS.RAW_UIA.UNKNOWN_NODE_REF"), (field.status, field.errorCode))
		self.assertEqual(("stale", "KS.RAW_UIA.UNKNOWN_NODE_REF"), (children.status, children.errorCode))
		self.assertEqual(("stale", "KS.RAW_UIA.UNKNOWN_NODE_REF"), (metadata.status, metadata.errorCode))
		self.assertEqual(("stale", "KS.RAW_UIA.UNKNOWN_NODE_REF"), (comparison.status, comparison.errorCode))

	def test_error_child_batches_discard_observations_and_release_attached_children(self) -> None:
		getter = _ErrorChildrenGetter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(4, 16, 250)),
		)
		assert outcome.rootRef is not None

		rootChildren = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(8, 128, 250), _context()),
		)
		self.assertEqual(1, len(rootChildren.nodeRefs))
		children = adapter.readChildren(
			ProviderChildrenRequest(rootChildren.nodeRefs[0], ReadBudget(8, 128, 250), _context()),
		)

		self.assertEqual("failed", children.status)
		self.assertEqual((), children.nodeRefs)
		self.assertEqual(0, children.observedCount)
		self.assertFalse(children.truncated)
		self.assertEqual("KS.TEST.CHILDREN", children.errorCode)
		self.assertIn(("releaseElement", "partial-child"), getter.calls)

	def test_close_releases_preloaded_children_before_the_projected_root(self) -> None:
		getter = _Getter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(4, 16, 250)),
		)
		self.assertIsNotNone(outcome.rootRef)

		adapter.close()

		releases = [call for call in getter.calls if call[0] == "releaseElement"]
		self.assertEqual(
			[("releaseElement", "raw-child"), ("releaseElement", "raw-root")],
			releases,
		)

	def test_preloaded_children_are_trimmed_to_the_read_budget(self) -> None:
		getter = _Getter(
			children={
				"raw-root": ("first", "second", "third", "fourth"),
				"first": (),
				"second": (),
				"third": (),
				"fourth": (),
			},
		)
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(4, 16, 250)),
		)
		assert outcome.rootRef is not None

		children = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(1, 80, 50), _context()),
		)

		self.assertEqual(1, len(children.nodeRefs))
		self.assertEqual(4, children.observedCount)
		self.assertTrue(children.truncated)
		self.assertEqual(
			[
				("releaseElement", "fourth"),
				("releaseElement", "third"),
				("releaseElement", "second"),
			],
			[call for call in getter.calls if call[0] == "releaseElement"],
		)

	def test_child_quality_is_classified_independently_of_the_projected_root(self) -> None:
		getter = _Getter(qualities={"raw-root": "native", "raw-child": "synthesizedProxy"})
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(1, 16, 250)),
		)
		assert outcome.rootRef is not None

		children = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(8, 80, 50), _context()),
		)
		metadata = adapter.readMetadata(
			ProviderMetadataRequest(children.nodeRefs[0], "rawProjection", ReadBudget(8, 80, 50), _context()),
		)

		self.assertIn(("evidenceQuality", "synthesizedProxy"), cast(tuple[object, ...], metadata.value))
		self.assertIn(("evidenceQuality", "raw-child"), getter.calls)
		self.assertIn(("raw-child", 101), getter.windowContexts)

	def test_child_quality_falls_back_to_incomplete_after_its_read_budget(self) -> None:
		getter = _Getter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected-root",
			"foreground",
			ProjectionRequest.explicit("raw-request", ProjectionBudget(1, 16, 250)),
		)
		assert outcome.rootRef is not None

		with patch(
			"addon.globalPlugins.keystone.adapters.providers.raw_uia.monotonic_ns",
			side_effect=(0, 2_000_000),
		):
			children = adapter.readChildren(
				ProviderChildrenRequest(outcome.rootRef, ReadBudget(8, 80, 1), _context()),
			)
		metadata = adapter.readMetadata(
			ProviderMetadataRequest(children.nodeRefs[0], "rawProjection", ReadBudget(8, 80, 50), _context()),
		)

		self.assertIn(("evidenceQuality", "incomplete"), cast(tuple[object, ...], metadata.value))
		self.assertNotIn(("evidenceQuality", "raw-child"), getter.calls)

	def test_projection_read_budget_has_an_independent_item_limit(self) -> None:
		self.assertEqual(64, ProjectionBudget(1, 16, 250).maximumItems)
		with self.assertRaises(ValueError):
			_ = ProjectionBudget(1, 16, 250, maximumItems=0)

		budget = RawUiaAdapter._readBudget(
			ProjectionRequest.explicit(
				"raw-request",
				ProjectionBudget(1, 16, 250, maximumItems=8),
			),
		)

		self.assertEqual(
			(8, 4096, 250),
			(budget.maximumItems, budget.maximumTextLength, budget.maximumMilliseconds),
		)


class RawUiaFallbackTests(unittest.TestCase):
	def test_selected_fallback_preserves_degraded_quality_and_defaults_rejections(self) -> None:
		request = ProjectionRequest.explicit("fallback", ProjectionBudget(3, 16, 250))
		degraded = RawUiaAdapter._degraded(
			request,
			"KS.RAW_UIA.SYNTHESIZED_PROXY",
			"synthesizedProxy",
			decideProjection(
				request,
				SelectedIdentity(41, "uia", "window", (), 101, True),
				(
					ProjectionCandidate(
						"candidate",
						41,
						"uia",
						"window",
						(),
						101,
						True,
						IdentityProbe(trustedAcquisition=True),
					),
				),
			).evidence,
		)
		rejected = RawProjectionOutcome(
			None,
			RawUiaAdapter._rejected(
				request,
				"KS.RAW_UIA.NO_CANDIDATE",
			).evidence,
		)

		self.assertIn(
			("evidenceQuality", "synthesizedProxy"),
			cast(tuple[object, ...], _fallbackProjectionPlain(degraded)),
		)
		self.assertIn(
			("evidenceQuality", "incomplete"),
			cast(tuple[object, ...], _fallbackProjectionPlain(rejected)),
		)

	def test_cross_process_and_nvda_process_reject_before_identity_or_tree_reads(self) -> None:
		for process in (77, 999):
			with self.subTest(process=process):
				getter = _Getter(processes={"raw-root": process})
				adapter = RawUiaAdapter(getter, generation=1)
				outcome = adapter.project(
					"selected",
					"foreground",
					ProjectionRequest.explicit("unsafe", ProjectionBudget(2, 8, 250)),
				)
				self.assertEqual(ProjectionStatus.REJECTED, outcome.evidence.status)
				self.assertIsNone(outcome.rootRef)
				self.assertFalse(
					any(call[0] in ("candidateIdentity", "rawChildren") for call in getter.calls),
				)

	def test_invalid_null_ambiguous_and_stale_roots_fall_back(self) -> None:
		cases = (
			("null", _Getter(candidates=()), "KS.RAW_UIA.NO_CANDIDATE"),
			("ambiguous", _Getter(candidates=("one", "two")), "KS.RAW_UIA.AMBIGUOUS"),
			(
				"stale",
				_Getter(processResult=ProviderReadResult("stale", errorCode="KS.TEST.STALE")),
				"KS.RAW_UIA.STALE_ROOT",
			),
		)
		for name, getter, reason in cases:
			with self.subTest(name=name):
				adapter = RawUiaAdapter(getter, generation=1)
				outcome = adapter.project(
					"selected",
					"navigator",
					ProjectionRequest.explicit(name, ProjectionBudget(3, 16, 250)),
				)
				self.assertEqual(ProjectionStatus.REJECTED, outcome.evidence.status)
				self.assertEqual(reason, outcome.evidence.reasonCode)
				self.assertIsNone(outcome.rootRef)
				self.assertFalse(outcome.evidence.completenessClaimed)

	def test_identified_leaf_is_a_valid_raw_root(self) -> None:
		getter = _Getter(emptyRoot=True)
		adapter = RawUiaAdapter(getter, generation=1)

		outcome = adapter.project(
			"selected",
			"focus",
			ProjectionRequest.explicit("leaf", ProjectionBudget(3, 16, 250)),
		)

		assert outcome.rootRef is not None
		children = adapter.readChildren(
			ProviderChildrenRequest(outcome.rootRef, ReadBudget(3, 80, 50), _context()),
		)
		self.assertEqual("empty", children.status)
		self.assertEqual((), children.nodeRefs)

	def test_disabled_mode_does_not_touch_raw_or_nvda_policy(self) -> None:
		getter = _Getter()
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project("selected", "foreground", ProjectionRequest.disabled("normal"))
		self.assertEqual(ProjectionStatus.NOT_REQUESTED, outcome.evidence.status)
		self.assertEqual([], getter.calls)

	def test_proxy_only_projection_degrades_without_replacing_selected_evidence(self) -> None:
		getter = _Getter(qualities={"raw-root": "synthesizedProxy"})
		adapter = RawUiaAdapter(getter, generation=1)

		outcome = adapter.project(
			"selected",
			"foreground",
			ProjectionRequest.explicit("proxy", ProjectionBudget(3, 16, 250)),
		)

		self.assertIsNone(outcome.rootRef)
		self.assertEqual(ProjectionStatus.DEGRADED, outcome.evidence.status)
		self.assertEqual("KS.RAW_UIA.SYNTHESIZED_PROXY", outcome.evidence.reasonCode)
		self.assertEqual("synthesizedProxy", outcome.evidenceQuality)
		self.assertNotIn(("rawChildren", "raw-root"), getter.calls)

	def test_incomplete_classification_is_distinct_from_proxy_evidence(self) -> None:
		getter = _Getter(qualities={"raw-root": "incomplete"})
		adapter = RawUiaAdapter(getter, generation=1)

		outcome = adapter.project(
			"selected",
			"foreground",
			ProjectionRequest.explicit("incomplete", ProjectionBudget(3, 16, 250)),
		)

		self.assertIsNone(outcome.rootRef)
		self.assertEqual(ProjectionStatus.DEGRADED, outcome.evidence.status)
		self.assertEqual("KS.RAW_UIA.INCOMPLETE_EVIDENCE", outcome.evidence.reasonCode)
		self.assertEqual("incomplete", outcome.evidenceQuality)

	def test_desktop_proxy_without_a_native_provider_falls_back_before_identity(self) -> None:
		"""No desktop-specific exception may promote a proxy-only MSAA target."""

		getter = _Getter(qualities={"raw-root": "noNativeProvider"})
		adapter = RawUiaAdapter(getter, generation=1)

		outcome = adapter.project(
			"Dynamic_SysListView32",
			"focus",
			ProjectionRequest.explicit("desktop-msaa", ProjectionBudget(3, 16, 250)),
		)

		self.assertIsNone(outcome.rootRef)
		self.assertEqual(ProjectionStatus.DEGRADED, outcome.evidence.status)
		self.assertEqual("KS.RAW_UIA.NO_NATIVE_PROVIDER", outcome.evidence.reasonCode)
		self.assertEqual("noNativeProvider", outcome.evidenceQuality)
		self.assertNotIn(("candidateIdentity", "raw-root"), getter.calls)
		self.assertNotIn(("rawChildren", "raw-root"), getter.calls)

	def test_desktop_window_without_server_provider_falls_back_without_ambiguity(self) -> None:
		element = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: element})
		handler = _acquisitionHandler(client)
		target = type("_DesktopMsaaTarget", (), {"processID": 41, "windowHandle": 555})()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		adapter = RawUiaAdapter(getter, generation=1, diagnostic=diagnostics.append)
		probeCalls: list[int] = []
		watchdog = _RecordingWatchdog()

		def absentProvider(hwnd: int) -> bool:
			probeCalls.append(hwnd)
			return False

		def importModule(name: str) -> object:
			if name == "winBindings.uiAutomationCore":
				return SimpleNamespace(UiaHasServerSideProvider=absentProvider)
			if name == "watchdog":
				return watchdog
			raise ImportError(name)

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch(
				"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
				side_effect=importModule,
			),
		):
			outcome = adapter.project(
				target,
				"focus",
				ProjectionRequest.explicit("desktop-shell", ProjectionBudget(3, 16, 250)),
			)

		self.assertEqual("KS.RAW_UIA.NO_NATIVE_PROVIDER", outcome.evidence.reasonCode)
		self.assertEqual("noNativeProvider", outcome.evidenceQuality)
		self.assertEqual([555], probeCalls)
		self.assertIn("absentProvider", watchdog.calls)
		self.assertEqual([], handler.nativeCalls)
		self.assertTrue(
			any(
				"raw.classification" in message
				and "providerAvailability=absent" in message
				and "windowClass=" in message
				for message in diagnostics
			),
		)
		self.assertTrue(
			any(
				"raw.final" in message
				and "gates=process,provider,identity" in message
				and "terminalReason=KS.RAW_UIA.NO_NATIVE_PROVIDER" in message
				for message in diagnostics
			),
		)

	def test_provider_probe_failure_is_traced_before_nvda_fallback(self) -> None:
		element = _ProcessElement(41)
		handler = _Handler(_Walker(()), native=True)
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)

		def failingProbe(hwnd: int) -> bool:
			_ = hwnd
			raise OSError("probe failure")

		def importModule(name: str) -> object:
			if name == "winBindings.uiAutomationCore":
				return SimpleNamespace(UiaHasServerSideProvider=failingProbe)
			if name == "watchdog":
				return watchdog
			raise ImportError(name)

		with (
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch(
				"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
				side_effect=importModule,
			),
		):
			quality = getter._classifyEvidence(element, 555)

		self.assertEqual("native", quality)
		self.assertIn("failingProbe", watchdog.calls)
		self.assertTrue(
			any(
				"raw.classification" in message
				and "providerError=KS.RAW_UIA.CALL_FAILED" in message
				and "providerStatus=failed" in message
				for message in diagnostics
			),
		)

	def test_child_classification_probes_server_provider_with_parent_window(self) -> None:
		child = object()
		getter = NvdaRawUiaGetter()
		adapter = RawUiaAdapter(getter, generation=1)
		rootRef = adapter._register(object())
		adapter._projectionByRef[rootRef] = ProjectionEvidence(
			True,
			"child-provider",
			True,
			ProjectionStatus.APPLIED,
			ProjectionMethod.PROVIDER_NATIVE,
			"uia",
			"direct",
			"KS.TEST.APPLIED",
			1,
			5,
		)
		adapter._qualityByRef[rootRef] = "native"
		adapter._windowHandleByRef[rootRef] = 555
		adapter._preloadedChildren[rootRef] = ObjectBatch("value", (child,), 1, False)
		probeCalls: list[int] = []
		watchdog = _RecordingWatchdog()

		def absentProvider(hwnd: int) -> bool:
			probeCalls.append(hwnd)
			return False

		def importModule(name: str) -> object:
			if name == "winBindings.uiAutomationCore":
				return SimpleNamespace(UiaHasServerSideProvider=absentProvider)
			if name == "watchdog":
				return watchdog
			raise ImportError(name)

		with patch(
			"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
			side_effect=importModule,
		):
			children = adapter.readChildren(
				ProviderChildrenRequest(rootRef, ReadBudget(8, 80, 50), _context()),
			)
		metadata = adapter.readMetadata(
			ProviderMetadataRequest(children.nodeRefs[0], "rawProjection", ReadBudget(8, 80, 50), _context()),
		)

		self.assertEqual([555], probeCalls)
		self.assertEqual(["absentProvider"], watchdog.calls)
		self.assertIn(("evidenceQuality", "noNativeProvider"), cast(tuple[object, ...], metadata.value))

	def test_child_classification_falls_back_when_parent_window_is_hung(self) -> None:
		child = object()
		getter = NvdaRawUiaGetter()
		adapter = RawUiaAdapter(getter, generation=1)
		rootRef = adapter._register(object())
		adapter._projectionByRef[rootRef] = ProjectionEvidence(
			True,
			"hung-child",
			True,
			ProjectionStatus.APPLIED,
			ProjectionMethod.PROVIDER_NATIVE,
			"uia",
			"direct",
			"KS.TEST.APPLIED",
			1,
			5,
		)
		adapter._qualityByRef[rootRef] = "native"
		adapter._windowHandleByRef[rootRef] = 555
		adapter._preloadedChildren[rootRef] = ObjectBatch("value", (child,), 1, False)
		probeCalls: list[int] = []
		windowChecks: list[int | None] = []

		def provider(hwnd: int) -> bool:
			probeCalls.append(hwnd)
			return True

		def blockHungWindow(hwnd: int | None) -> str:
			windowChecks.append(hwnd)
			return "KS.RAW_UIA.HUNG_TARGET"

		with (
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", side_effect=blockHungWindow),
			patch(
				"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
				return_value=SimpleNamespace(UiaHasServerSideProvider=provider),
			),
		):
			children = adapter.readChildren(
				ProviderChildrenRequest(rootRef, ReadBudget(8, 80, 50), _context()),
			)
		metadata = adapter.readMetadata(
			ProviderMetadataRequest(children.nodeRefs[0], "rawProjection", ReadBudget(8, 80, 50), _context()),
		)

		self.assertEqual([555], windowChecks)
		self.assertEqual([], probeCalls)
		self.assertIn(("evidenceQuality", "incomplete"), cast(tuple[object, ...], metadata.value))

	def test_native_quality_is_reported_separately_from_projection_status(self) -> None:
		getter = _Getter(qualities={"raw-root": "native"})
		adapter = RawUiaAdapter(getter, generation=1)
		outcome = adapter.project(
			"selected",
			"foreground",
			ProjectionRequest.explicit("native", ProjectionBudget(3, 16, 250)),
		)
		assert outcome.rootRef is not None

		metadata = adapter.readMetadata(
			ProviderMetadataRequest(outcome.rootRef, "rawProjection", ReadBudget(8, 128, 250), _context()),
		)

		self.assertEqual(ProjectionStatus.APPLIED, outcome.evidence.status)
		self.assertEqual("native", outcome.evidenceQuality)
		self.assertIn(("evidenceQuality", "native"), cast(tuple[object, ...], metadata.value))
		self.assertEqual(1, getter.calls.count(("evidenceQuality", "raw-root")))

	def test_live_adapter_has_no_nvda_policy_setter_or_patch_surface(self) -> None:
		from addon.globalPlugins.keystone.adapters.providers.raw_uia import NvdaRawUiaGetter

		source = inspect.getsource(NvdaRawUiaGetter)
		for forbidden in (
			"setFocusObject",
			"setNavigatorObject",
			"setShouldUseUIA",
			"config.conf",
			"monkeypatch",
		):
			with self.subTest(forbidden=forbidden):
				self.assertNotIn(forbidden, source)


class RawUiaCandidateAcquisitionTests(unittest.TestCase):
	"""Contract tests for NvdaRawUiaGetter.candidateElements' bounded acquisition sequence."""

	def test_all_raw_acquisition_entry_points_use_watchdog_execution(self) -> None:
		element = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: element}, byPoint=element, focused=element)
		watchdog = _RecordingWatchdog()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
		):
			byHandle = getter._acquireByHandle(client, 555)
			byPoint = getter._acquireByPoint(client, (10, 20), 555)
			focused = getter._acquireFocused(client, 555)
			propertyRead = getter._invoke(
				element,
				("getCurrentPropertyValueEx",),
				(_PROCESS_IDENTIFIER, True),
				hwnd=555,
			)

		self.assertEqual("value", byHandle.status)
		self.assertEqual("value", byPoint.status)
		self.assertEqual("value", focused.status)
		self.assertEqual("value", propertyRead.status)
		self.assertEqual(
			[
				"ElementFromHandle",
				"ElementFromPoint",
				"GetFocusedElement",
				"getCurrentPropertyValueEx",
			],
			watchdog.calls,
		)

	def test_each_acquired_candidate_is_classified_once_even_when_sources_repeat_it(self) -> None:
		element = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: element}, focused=element)
		handler = _acquisitionHandler(client)
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		target = type("_Target", (), {"processID": 41, "windowHandle": 555})()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
		):
			batch = getter.candidateElements(target, "foreground", 4)

		self.assertEqual((element,), batch.values)
		self.assertEqual([element], handler.nativeCalls)
		self.assertEqual("native", getter.evidenceQuality(element))
		self.assertEqual([element], handler.nativeCalls)
		self.assertEqual(0, watchdog.calls.count("isNativeUIAElement"))
		self.assertTrue(
			any(
				"raw.classification" in message
				and "classification=native" in message
				and "execution=owner" in message
				for message in diagnostics
			),
		)

	def test_non_retained_acquisition_prefers_nvda_base_cache(self) -> None:
		cacheRequest = object()
		handleElement = _ProcessElement(41)
		pointElement = _ProcessElement(41)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(
			byHandle={555: handleElement},
			byPoint=pointElement,
			focused=focusedElement,
		)
		handler = _Handler(_Walker(()), clientObject=client, baseCacheRequest=cacheRequest)
		watchdog = _RecordingWatchdog()
		getter = NvdaRawUiaGetter()

		with (
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
		):
			byHandle = getter._acquireByHandle(client, 555)
			byPoint = getter._acquireByPoint(client, (10, 20), 555)
			focused = getter._acquireFocused(client, 555)

		self.assertIs(handleElement, byHandle.value)
		self.assertIs(pointElement, byPoint.value)
		self.assertIs(focusedElement, focused.value)
		self.assertEqual(
			[
				"ElementFromHandleBuildCache",
				"ElementFromPointBuildCache",
				"GetFocusedElementBuildCache",
			],
			client.calls,
		)
		self.assertEqual([cacheRequest, cacheRequest, cacheRequest], client.cacheRequests)
		self.assertEqual(client.calls, watchdog.calls)

	def test_hung_target_is_rejected_before_watchdog_or_provider_call(self) -> None:
		element = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: element})
		watchdog = _RecordingWatchdog()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(
				NvdaRawUiaGetter,
				"_windowBlockReason",
				return_value="KS.RAW_UIA.HUNG_TARGET",
			),
		):
			result = getter._acquireByHandle(client, 555)

		self.assertEqual("unavailable", result.status)
		self.assertEqual("KS.RAW_UIA.HUNG_TARGET", result.errorCode)
		self.assertEqual([], watchdog.calls)

	def test_raw_call_outcomes_keep_cancellation_failure_absence_and_no_client_distinct(self) -> None:
		getter = NvdaRawUiaGetter()
		client = _AcquisitionClient()
		cancelled = _CancelledCall()
		failed = _ComFailure()

		with (
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=_RecordingWatchdog(cancelled)),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "_isWatchdogCancellation", return_value=True),
		):
			cancelledResult = getter._acquireFocused(client)
		with (
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=_RecordingWatchdog(failed)),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "_isWatchdogCancellation", return_value=False),
			patch.object(NvdaRawUiaGetter, "_isComFailure", return_value=True),
		):
			failedResult = getter._acquireFocused(client)
		absentResult = getter._invoke(
			_AbsentRead(),
			("read",),
			(),
		)
		noClientResult = getter._acquireByHandle(None, 555)

		self.assertEqual(
			("unavailable", "KS.RAW_UIA.WATCHDOG_CANCELLED"),
			(cancelledResult.status, cancelledResult.errorCode),
		)
		self.assertEqual(
			("failed", "KS.RAW_UIA.COM_FAILED"),
			(failedResult.status, failedResult.errorCode),
		)
		self.assertEqual("empty", absentResult.status)
		self.assertEqual(
			("unavailable", "KS.RAW_UIA.NO_CLIENT"),
			(noClientResult.status, noClientResult.errorCode),
		)

	def test_watchdog_cancellation_uses_nvdas_exceptions_module(self) -> None:
		class HostCallCancelled(Exception):
			pass

		error = HostCallCancelled()
		imports: list[str] = []

		def importModule(name: str) -> object:
			imports.append(name)
			if name == "exceptions":
				return SimpleNamespace(CallCancelled=HostCallCancelled)
			raise ImportError(name)

		with patch(
			"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
			side_effect=importModule,
		):
			self.assertTrue(NvdaRawUiaGetter._isWatchdogCancellation(error))

		self.assertEqual(["exceptions"], imports)

	def test_ia2_target_without_uia_element_projects_via_window_handle(self) -> None:
		hwndElement = _CachedTreeElement("window", process=41, windowHandle=555, role="window")
		client = _AcquisitionClient(byHandle={555: hwndElement})
		handler = _acquisitionHandler(client)
		target = type("_Ia2Target", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual("value", batch.status)
		self.assertEqual((hwndElement,), batch.values)
		self.assertIsNone(getter._selectedElement)
		selected = getter.selectedIdentity(target, ReadBudget(4, 80, 50))
		candidate = getter.candidateIdentity(hwndElement, 41, ReadBudget(4, 80, 50))
		decision = decideProjection(
			ProjectionRequest.explicit("ia2-window", ProjectionBudget(4, 20, 100)),
			selected,
			(candidate,),
		)
		self.assertEqual(ProjectionStatus.APPLIED, decision.evidence.status)
		self.assertEqual(ProjectionMethod.WINDOW_SCOPED_ACQUISITION, decision.evidence.method)

	def test_msaa_bridge_without_uia_element_is_trusted_by_construction(self) -> None:
		accessible = object()
		bridgeElement = _ProcessElement(41)
		client = _AcquisitionClient(byAccessible={(accessible, 7): bridgeElement})
		handler = _acquisitionHandler(client)
		target = type(
			"_ChromiumIa2Target",
			(),
			{
				"processID": 41,
				"windowHandle": 555,
				"IAccessibleObject": accessible,
				"IAccessibleChildID": 7,
			},
		)()
		getter = NvdaRawUiaGetter()
		adapter = RawUiaAdapter(getter, generation=1)

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			outcome = adapter.project(
				target,
				"focus",
				ProjectionRequest.explicit("chromium-ia2", ProjectionBudget(4, 32, 250)),
			)

		self.assertIsNotNone(outcome.rootRef)
		self.assertEqual(ProjectionStatus.APPLIED, outcome.evidence.status)
		self.assertEqual(ProjectionMethod.PROCESS_SCOPED_ACQUISITION, outcome.evidence.method)
		self.assertEqual("native", outcome.evidenceQuality)
		self.assertIn("ElementFromIAccessible", client.calls)

	def test_bridge_candidate_skips_lower_ranked_window_root(self) -> None:
		accessible = object()
		bridgeElement = _ProcessElement(41)
		windowElement = _ProcessElement(41)
		client = _AcquisitionClient(
			byAccessible={(accessible, 7): bridgeElement},
			byHandle={555: windowElement},
		)
		handler = _acquisitionHandler(client)
		target = type(
			"_Ia2Target",
			(),
			{
				"processID": 41,
				"windowHandle": 555,
				"IAccessibleObject": accessible,
				"IAccessibleChildID": 7,
			},
		)()
		getter = NvdaRawUiaGetter()

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "focus", 4)

		self.assertEqual((bridgeElement,), batch.values)
		self.assertNotIn("ElementFromHandle", client.calls)

	def test_window_candidate_skips_lower_ranked_focused_element(self) -> None:
		windowElement = _ProcessElement(41)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: windowElement}, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type("_WindowTarget", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "focus", 4)

		self.assertEqual((windowElement,), batch.values)
		self.assertNotIn("GetFocusedElement", client.calls)

	def test_release_clears_window_scoped_candidate_bookkeeping(self) -> None:
		windowElement = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: windowElement})
		handler = _acquisitionHandler(client)
		target = type("_WindowTarget", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			_ = getter.candidateElements(target, "foreground", 4)

		self.assertIsNotNone(getter._windowScopedElement)
		getter.releaseElement(windowElement)
		self.assertIsNone(getter._windowScopedElement)

	def test_nvda_owned_global_focus_skips_point_and_focus_acquisition(self) -> None:
		pointElement = _ProcessElement(41)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(byPoint=pointElement, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_ExternalTarget",
			(),
			{
				"processID": 41,
				"location": {"left": 0, "top": 0, "width": 10, "height": 10},
			},
		)()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "nvdaProcessId", return_value=999),
			patch(
				"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
				return_value=SimpleNamespace(getFocusObject=lambda: SimpleNamespace(processID=999)),
			),
		):
			batch = getter.candidateElements(target, "focus", 4)

		self.assertEqual((), batch.values)
		self.assertNotIn("ElementFromPoint", client.calls)
		self.assertNotIn("GetFocusedElement", client.calls)
		self.assertTrue(
			any(
				"gate=globalFocusProcess" in message and "error=nvdaProcess" in message
				for message in diagnostics
			),
		)

	def test_strict_focus_resolves_the_selected_object_position_while_nvda_owns_focus(self) -> None:
		pointElement = _ProcessElement(41)
		windowElement = _ProcessElement(41)
		client = _AcquisitionClient(byPoint=pointElement, byHandle={555: windowElement})
		handler = _acquisitionHandler(client)
		target = type(
			"_PointResolvedTarget",
			(),
			{
				"processID": 41,
				"windowHandle": 555,
				"location": {"left": 10, "top": 20, "width": 100, "height": 50},
			},
		)()
		getter = NvdaRawUiaGetter()

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "nvdaProcessId", return_value=999),
			patch(
				"addon.globalPlugins.keystone.adapters.providers.raw_uia.importlib.import_module",
				return_value=SimpleNamespace(getFocusObject=lambda: SimpleNamespace(processID=999)),
			),
		):
			batch = getter.candidateElements(target, "focus", 4, preferPoint=True)

		self.assertEqual((pointElement,), batch.values)
		self.assertIn("ElementFromPoint", client.calls)
		self.assertNotIn("ElementFromHandle", client.calls)

	def test_target_without_window_handle_falls_back_to_screen_point(self) -> None:
		pointElement = _ProcessElement(41)
		client = _AcquisitionClient(byPoint=pointElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_PointTarget",
			(),
			{
				"processID": 41,
				"windowHandle": 0,
				"location": {"left": 10, "top": 20, "width": 100, "height": 50},
			},
		)()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual("value", batch.status)
		self.assertEqual((pointElement,), batch.values)

	def test_target_without_handle_or_geometry_falls_back_to_focused_element(self) -> None:
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type("_FocusTarget", (), {"processID": 41})()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "focus", 4)
		self.assertEqual("value", batch.status)
		self.assertEqual((focusedElement,), batch.values)

	def test_existing_uia_element_is_prioritized_over_other_sources(self) -> None:
		primaryElement = _ProcessElement(41, runtimeId=(1,))
		hwndElement = _ProcessElement(41, runtimeId=(2,))
		client = _AcquisitionClient(byHandle={555: hwndElement})
		handler = _acquisitionHandler(client)
		target = type(
			"_UiaPriorityTarget",
			(),
			{"processID": 41, "windowHandle": 555, "UIAElement": primaryElement},
		)()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((primaryElement,), batch.values)
		self.assertIs(primaryElement, getter._selectedElement)

	def test_retained_uia_focus_projects_without_cross_thread_current_property_reads(self) -> None:
		element = _ProcessElement(9308, runtimeId=(42, 656034))
		unreadableProxy = _ProcessElement(9308, runtimeId=(42, 999999))
		client = _AcquisitionClient(byHandle={656034: unreadableProxy}, focused=element)
		handler = _Handler(
			_ComFailingLeafWalker(()),
			clientObject=client,
			baseCacheRequest=object(),
			native=True,
		)
		target = type(
			"_RetainedNotepadUiaTarget",
			(),
			{
				"processID": 9308,
				"role": "document",
				"windowHandle": 656034,
				"UIAElement": element,
			},
		)()
		watchdog = _CurrentPropertyComFailureWatchdog()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		adapter = RawUiaAdapter(getter, generation=1, diagnostic=diagnostics.append)

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "_isComFailure", return_value=True),
		):
			outcome = adapter.project(
				target,
				"focus",
				ProjectionRequest.explicit("notepad-focus", ProjectionBudget(8, 64, 500)),
			)

		self.assertIsNotNone(outcome.rootRef)
		self.assertTrue(outcome.evidence.applied)
		self.assertEqual(ProjectionStatus.APPLIED, outcome.evidence.status)
		self.assertEqual("native", outcome.evidenceQuality)
		# Process rejection happens before the costly NVDA classification, so
		# the unreadable window candidate never reaches isNativeUIAElement.
		self.assertEqual([element], handler.nativeCalls)
		self.assertNotIn("__getattribute__", watchdog.calls)
		self.assertEqual(0, watchdog.calls.count("isNativeUIAElement"))
		self.assertEqual(0, watchdog.calls.count("getCurrentPropertyValueEx"))
		self.assertNotIn("GetFirstChildElement", watchdog.calls)
		self.assertTrue(
			any(
				"raw.children.attempt" in message
				and "method=GetFirstChildElementBuildCache" in message
				and "trusted=true" in message
				and "execution=owner" in message
				and "status=failed" in message
				and "error=KS.RAW_UIA.COM_FAILED" in message
				for message in diagnostics
			),
		)
		self.assertTrue(
			any(
				"raw.children.final" in message and "outcome=leaf" in message and "trusted=true" in message
				for message in diagnostics
			),
		)
		self.assertTrue(
			any(
				"raw.candidate" in message
				and "order=1" in message
				and "source=retainedElement" in message
				and "classification=native" in message
				and "outcome=accepted" in message
				for message in diagnostics
			),
		)
		joinedDiagnostics = "\n".join(diagnostics)
		self.assertNotIn("9308", joinedDiagnostics)
		self.assertNotIn("656034", joinedDiagnostics)
		self.assertTrue(
			any(
				"raw.candidate" in message
				and "order=3" in message
				and "source=windowHandle" in message
				and "outcome=rejected" in message
				for message in diagnostics
			),
		)
		self.assertTrue(
			any(
				"raw.final" in message
				and "applied=true" in message
				and "status=applied" in message
				and "method=pythonIdentity" in message
				and "quality=native" in message
				for message in diagnostics
			),
		)

	def test_untrusted_first_child_com_failure_stays_watchdog_contained_and_rejected(self) -> None:
		element = _CachedTreeElement("window", process=41, windowHandle=555, role="window")
		client = _AcquisitionClient(byHandle={555: element}, focused=element)
		handler = _Handler(
			_ComFailingLeafWalker(()),
			clientObject=client,
			baseCacheRequest=object(),
			native=True,
		)
		target = type("_UntrustedTarget", (), {"processID": 41, "windowHandle": 555})()
		watchdog = _RecordingWatchdog()
		diagnostics: list[str] = []
		getter = NvdaRawUiaGetter(diagnostic=diagnostics.append)
		adapter = RawUiaAdapter(getter, generation=1, diagnostic=diagnostics.append)

		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "_watchdog", return_value=watchdog),
			patch.object(NvdaRawUiaGetter, "_windowBlockReason", return_value=None),
			patch.object(NvdaRawUiaGetter, "_isComFailure", return_value=True),
		):
			outcome = adapter.project(
				target,
				"focus",
				ProjectionRequest.explicit("untrusted-focus", ProjectionBudget(8, 64, 500)),
			)

		self.assertIsNone(outcome.rootRef)
		self.assertEqual("KS.RAW_UIA.COM_FAILED", outcome.evidence.reasonCode)
		self.assertIn("GetFirstChildElementBuildCache", watchdog.calls)
		self.assertIn("GetFirstChildElement", watchdog.calls)
		self.assertTrue(
			any(
				"raw.children.attempt" in message
				and "method=GetFirstChildElementBuildCache" in message
				and "trusted=false" in message
				and "execution=watchdog" in message
				and "status=failed" in message
				for message in diagnostics
			),
		)
		self.assertTrue(
			any(
				"raw.children.final" in message
				and "outcome=reject" in message
				and "selectedMethod=none" in message
				and "fallbackMethod=GetFirstChildElement" in message
				for message in diagnostics
			),
		)

	def test_one_failed_acquisition_does_not_prevent_later_candidates(self) -> None:
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(handleError=True, pointError=True, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_FailureIsolationTarget",
			(),
			{
				"processID": 41,
				"windowHandle": 555,
				"location": {"left": 0, "top": 0, "width": 10, "height": 10},
			},
		)()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual("value", batch.status)
		self.assertEqual((focusedElement,), batch.values)

	def test_candidate_with_mismatched_process_is_excluded_not_fatal(self) -> None:
		wrongProcessElement = _ProcessElement(99)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(byPoint=wrongProcessElement, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_ProcessRejectTarget",
			(),
			{"processID": 41, "location": {"left": 0, "top": 0, "width": 10, "height": 10}},
		)()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((focusedElement,), batch.values)
		self.assertIn(wrongProcessElement, released)

	def test_candidate_matching_nvda_process_is_always_rejected(self) -> None:
		nvdaElement = _ProcessElement(999)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(byPoint=nvdaElement, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_NvdaProcessTarget",
			(),
			{"processID": 41, "location": {"left": 0, "top": 0, "width": 10, "height": 10}},
		)()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "nvdaProcessId", return_value=999),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((focusedElement,), batch.values)
		self.assertIn(nvdaElement, released)

	def test_python_identity_duplicate_is_skipped_without_release(self) -> None:
		sharedElement = _ProcessElement(41)
		client = _AcquisitionClient(byHandle={555: sharedElement}, focused=sharedElement)
		handler = _acquisitionHandler(client)
		target = type("_DedupIdentityTarget", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((sharedElement,), batch.values)
		self.assertEqual(1, batch.observedCount)
		self.assertEqual([], released)

	def test_provider_compare_elements_duplicate_is_released(self) -> None:
		hwndElement = _ProcessElement(41)
		focusedElement = _ProcessElement(41)
		client = _AcquisitionClient(
			byHandle={555: hwndElement},
			focused=focusedElement,
			compare=lambda first, second: True,
		)
		handler = _acquisitionHandler(client)
		target = type("_DedupCompareTarget", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((hwndElement,), batch.values)
		self.assertEqual(1, batch.observedCount)
		self.assertEqual([], released)

	def test_runtime_id_duplicate_is_released_without_compare_elements(self) -> None:
		hwndElement = _ProcessElement(41, runtimeId=(7, 8))
		focusedElement = _ProcessElement(41, runtimeId=(7, 8))
		client = _AcquisitionClient(
			byHandle={555: hwndElement},
			focused=focusedElement,
			compareAvailable=False,
		)
		handler = _acquisitionHandler(client)
		target = type("_DedupRuntimeTarget", (), {"processID": 41, "windowHandle": 555})()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual((hwndElement,), batch.values)
		self.assertEqual(1, batch.observedCount)
		self.assertEqual([], released)

	def test_maximum_candidates_bound_is_enforced_and_overflow_is_released(self) -> None:
		primaryElement = _ProcessElement(41, runtimeId=(1,))
		hwndElement = _ProcessElement(41, runtimeId=(2,))
		pointElement = _ProcessElement(41, runtimeId=(3,))
		focusedElement = _ProcessElement(41, runtimeId=(4,))
		client = _AcquisitionClient(byHandle={555: hwndElement}, byPoint=pointElement, focused=focusedElement)
		handler = _acquisitionHandler(client)
		target = type(
			"_BoundTarget",
			(),
			{
				"processID": 41,
				"windowHandle": 555,
				"location": {"left": 0, "top": 0, "width": 10, "height": 10},
				"UIAElement": primaryElement,
			},
		)()
		getter = NvdaRawUiaGetter()
		released: list[object] = []
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
			patch.object(NvdaRawUiaGetter, "releaseElement", side_effect=released.append),
		):
			batch = getter.candidateElements(target, "foreground", 2)
		self.assertEqual((primaryElement,), batch.values)
		self.assertEqual(1, batch.observedCount)
		self.assertFalse(batch.truncated)
		self.assertEqual([], released)

	def test_no_source_yields_a_candidate_returns_empty_batch(self) -> None:
		client = _AcquisitionClient()
		handler = _acquisitionHandler(client)
		target = type("_NoCandidateTarget", (), {"processID": 41})()
		getter = NvdaRawUiaGetter()
		with (
			patch.object(NvdaRawUiaGetter, "_identifier", side_effect=_PROCESS_IDENTIFIERS.__getitem__),
			patch.object(NvdaRawUiaGetter, "_handler", return_value=handler),
		):
			batch = getter.candidateElements(target, "foreground", 4)
		self.assertEqual("empty", batch.status)
		self.assertEqual((), batch.values)
		self.assertEqual(0, batch.observedCount)
		self.assertFalse(batch.truncated)


if __name__ == "__main__":
	_ = unittest.main()
