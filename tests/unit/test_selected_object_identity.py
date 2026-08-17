from __future__ import annotations

import gc
import unittest
import weakref
from typing import cast, override

from addon.globalPlugins.keystone.adapters.nvda.selected_objects import (
	SelectedObjectSession,
	SelectedTargetKind,
	accessibleIdentity,
)
from addon.globalPlugins.keystone.adapters.providers.common import ObjectBatch
from addon.globalPlugins.keystone.adapters.providers.raw_uia import RawUiaAdapter
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildrenRequest,
	ProviderReadResult,
	ReadBudget,
)


class _AccessibleNode:
	def __init__(
		self,
		*,
		childId: int,
		windowHandle: int,
		uniqueId: int,
		accessible: object,
	) -> None:
		super().__init__()
		self.IAccessibleChildID = childId
		self.windowHandle = windowHandle
		self.IA2WindowHandle = windowHandle
		self.IA2UniqueID = uniqueId
		self.IAccessibleObject = accessible

	@override
	def __eq__(self, other: object) -> bool:
		return self is other


class _UiaNode:
	def __init__(
		self,
		*,
		name: str,
		role: str,
		processId: int,
		location: tuple[int, int, int, int],
		runtimeId: tuple[int, ...] = (),
	) -> None:
		super().__init__()
		self.UIAElement = _UiaElement(runtimeId)
		self.name = name
		self.role = role
		self.processID = processId
		self.location = location

	@override
	def __eq__(self, other: object) -> bool:
		return self is other


class _UiaElement:
	def __init__(self, runtimeId: tuple[int, ...]) -> None:
		super().__init__()
		self._runtimeId = runtimeId

	def getRuntimeId(self) -> tuple[int, ...]:
		return self._runtimeId


class COMError(Exception):
	pass


class _StaleUiaElement:
	def getRuntimeId(self) -> tuple[int, ...]:
		raise COMError()


class _OverEqualUiaNode(_UiaNode):
	@override
	def __eq__(self, other: object) -> bool:
		return isinstance(other, _UiaNode)


class _CrossBackendAccessibleNode(_AccessibleNode):
	def __init__(
		self,
		*,
		name: str,
		role: str,
		processId: int,
		location: tuple[int, int, int, int],
	) -> None:
		super().__init__(childId=3, windowHandle=42, uniqueId=27, accessible=object())
		self.name = name
		self.role = role
		self.processID = processId
		self.location = location


class _UiaBackedAccessibleNode(_AccessibleNode):
	def __init__(self, *, childId: int, windowHandle: int) -> None:
		super().__init__(
			childId=childId,
			windowHandle=windowHandle,
			uniqueId=27,
			accessible=object(),
		)
		self.UIAElement = object()


class _SelectedSource:
	def __init__(self, target: object) -> None:
		super().__init__()
		self.target = target

	def selectedObject(self, targetKind: SelectedTargetKind) -> object:
		return self.target


class _TrackedChild:
	pass


class _OverfullChildrenGetter:
	def __init__(self, width: int) -> None:
		super().__init__()
		self.children = tuple(_TrackedChild() for _ in range(width))
		self.childBudgets: list[int] = []

	def readAttribute(self, target: object, member: str, budget: ReadBudget) -> ProviderReadResult:
		return ProviderReadResult("empty")

	def readChildren(self, target: object, budget: ReadBudget) -> ObjectBatch:
		self.childBudgets.append(budget.maximumItems)
		return ObjectBatch("value", self.children, len(self.children), False)

	def readLogicalFirstChild(self, target: object, budget: ReadBudget) -> ObjectBatch:
		return ObjectBatch("empty", (), 0, False)

	def discardChildren(self) -> None:
		self.children = ()


class _RawUia:
	def __init__(self) -> None:
		super().__init__()
		self.ownsCalls = 0
		self.comparisons: list[IdentityComparisonRequest] = []

	def owns(self, nodeRef: str) -> bool:
		self.ownsCalls += 1
		return nodeRef.startswith("raw-")

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		self.comparisons.append(request)
		return IdentityComparisonResult("value", "same", (("pythonIdentity", True),))

	def close(self) -> None:
		pass


class SelectedObjectIdentityTests(unittest.TestCase):
	def test_child_retention_is_limited_to_the_requested_capacity(self) -> None:
		root = object()
		getter = _OverfullChildrenGetter(1_000)
		session = SelectedObjectSession(_SelectedSource(root), generation=1, objectGetter=getter)
		context = CorrelationFactory().admit(generation=1)
		rootRef = session.retain(root)
		childReferences = tuple(weakref.ref(child) for child in getter.children)

		children = session.readChildren(
			ProviderChildrenRequest(rootRef, ReadBudget(3, 100, 100), context),
		)
		getter.discardChildren()
		_ = gc.collect()

		self.assertEqual([3], getter.childBudgets)
		self.assertEqual(3, len(children.nodeRefs))
		self.assertTrue(children.truncated)
		self.assertEqual(3, sum(child() is not None for child in childReferences))
		session.close()

	def test_distinct_ia2_wrappers_with_the_same_node_identity_match(self) -> None:
		first = _AccessibleNode(
			childId=3,
			windowHandle=42,
			uniqueId=27,
			accessible=object(),
		)
		second = _AccessibleNode(
			childId=3,
			windowHandle=42,
			uniqueId=27,
			accessible=object(),
		)

		self.assertEqual("ia2Object", accessibleIdentity(first, second))

	def test_distinct_ia2_nodes_with_different_unique_ids_do_not_match(self) -> None:
		first = _AccessibleNode(
			childId=3,
			windowHandle=42,
			uniqueId=27,
			accessible=object(),
		)
		second = _AccessibleNode(
			childId=3,
			windowHandle=42,
			uniqueId=28,
			accessible=object(),
		)

		self.assertIsNone(accessibleIdentity(first, second))

	def test_distinct_ia2_childid_self_nodes_in_one_window_do_not_match(self) -> None:
		first = _AccessibleNode(
			childId=0,
			windowHandle=42,
			uniqueId=27,
			accessible=object(),
		)
		second = _AccessibleNode(
			childId=0,
			windowHandle=42,
			uniqueId=28,
			accessible=object(),
		)

		self.assertIsNone(accessibleIdentity(first, second))

	def test_uia_backed_wrapper_never_matches_an_ia2_window_by_legacy_members(self) -> None:
		uia = _UiaBackedAccessibleNode(childId=0, windowHandle=42)
		window = _AccessibleNode(
			childId=0,
			windowHandle=42,
			uniqueId=27,
			accessible=object(),
		)

		self.assertIsNone(accessibleIdentity(uia, window))

	def test_cross_backend_wrappers_for_the_same_control_match(self) -> None:
		uia = _UiaNode(
			name="data",
			role="listItem",
			processId=2552,
			location=(563, 232, 598, 24),
		)
		accessible = _CrossBackendAccessibleNode(
			name="data",
			role="listItem",
			processId=2552,
			location=(563, 232, 598, 24),
		)

		self.assertEqual("crossBackendSpatial", accessibleIdentity(uia, accessible))

	def test_cross_backend_nodes_with_different_geometry_do_not_match(self) -> None:
		uia = _UiaNode(
			name="data",
			role="listItem",
			processId=2552,
			location=(563, 232, 598, 24),
		)
		accessible = _CrossBackendAccessibleNode(
			name="data",
			role="listItem",
			processId=2552,
			location=(563, 256, 598, 24),
		)

		self.assertIsNone(accessibleIdentity(uia, accessible))

	def test_distinct_uia_wrappers_with_the_same_runtime_id_match(self) -> None:
		first = _UiaNode(
			name="PerfLogs",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365912000, 0),
		)
		second = _UiaNode(
			name="PerfLogs",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365912000, 0),
		)

		self.assertEqual("uiaRuntimeId", accessibleIdentity(first, second))

	def test_distinct_uia_wrappers_with_different_runtime_ids_do_not_match(self) -> None:
		first = _UiaNode(
			name="PerfLogs",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365912000, 0),
		)
		second = _UiaNode(
			name="PerfLogs",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365913000, 0),
		)

		self.assertIsNone(accessibleIdentity(first, second))

	def test_uia_wrappers_with_different_runtime_ids_ignore_broad_nvda_equality(self) -> None:
		first = _OverEqualUiaNode(
			name="first",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365912000, 0),
		)
		second = _OverEqualUiaNode(
			name="second",
			role="listItem",
			processId=11120,
			location=(563, 312, 598, 24),
			runtimeId=(11120, 365913000, 0),
		)

		self.assertIsNone(accessibleIdentity(first, second))

	def test_uia_runtime_id_contains_stale_com_errors(self) -> None:
		target = type("StaleUiaNode", (), {"UIAElement": _StaleUiaElement()})()
		other = _UiaNode(
			name="other",
			role="listItem",
			processId=11120,
			location=(563, 312, 598, 24),
		)

		self.assertIsNone(accessibleIdentity(target, other))

	def test_comparison_reports_the_failing_uia_identity_criterion(self) -> None:
		first = _UiaNode(
			name="first",
			role="listItem",
			processId=11120,
			location=(563, 288, 598, 24),
			runtimeId=(11120, 365912000, 0),
		)
		second = _UiaNode(
			name="second",
			role="listItem",
			processId=11120,
			location=(563, 312, 598, 24),
			runtimeId=(11120, 365913000, 0),
		)
		rawUia = _RawUia()
		session = SelectedObjectSession(
			_SelectedSource(first),
			generation=1,
			rawUia=cast(RawUiaAdapter, rawUia),
		)
		context = CorrelationFactory().admit(generation=1)

		result = session.compareIdentity(
			IdentityComparisonRequest(
				session.retain(first),
				session.retain(second),
				"nvda-selected",
				"selected-process",
				ReadBudget(1, 100, 100),
				context,
			),
		)

		self.assertEqual(
			("value", "different", (("uiaElement", False),)),
			(result.status, result.decision, result.evidence),
		)
		session.close()

	def test_stale_context_is_rejected_before_mixed_raw_identity_branching(self) -> None:
		target = object()
		rawUia = _RawUia()
		session = SelectedObjectSession(
			_SelectedSource(target),
			generation=1,
			rawUia=cast(RawUiaAdapter, rawUia),
		)
		staleContext = CorrelationFactory().admit(generation=2)

		result = session.compareIdentity(
			IdentityComparisonRequest(
				"raw-1",
				session.retain(target),
				"mixed",
				"selected-process",
				ReadBudget(1, 100, 100),
				staleContext,
			),
		)

		self.assertEqual(
			("stale", "failed", "KS.PROVIDER.STALE_GENERATION"),
			(result.status, result.decision, result.errorCode),
		)
		self.assertEqual(0, rawUia.ownsCalls)
		session.close()

	def test_raw_uia_identity_comparison_still_delegates(self) -> None:
		rawUia = _RawUia()
		session = SelectedObjectSession(
			_SelectedSource(object()),
			generation=1,
			rawUia=cast(RawUiaAdapter, rawUia),
		)
		context = CorrelationFactory().admit(generation=1)
		request = IdentityComparisonRequest(
			"raw-1",
			"raw-2",
			"raw-uia",
			"selected-process",
			ReadBudget(1, 100, 100),
			context,
		)

		result = session.compareIdentity(request)

		self.assertEqual(
			("value", "same", (("pythonIdentity", True),)), (result.status, result.decision, result.evidence)
		)
		self.assertEqual([request], rawUia.comparisons)
		session.close()
