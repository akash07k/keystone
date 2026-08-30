from __future__ import annotations

import sys
from collections.abc import Callable
import unittest
from typing import override

from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.domain.traversal import (
	IterativeTraversal,
	TraversalLimits,
	TraversalProgress,
)
from addon.globalPlugins.keystone.ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ProviderRelationRequest,
	ProviderTextRequest,
)


class _TreeProvider:
	def __init__(
		self,
		children: dict[str, tuple[str, ...]] | None = None,
		*,
		logical: dict[str, tuple[str, ...]] | None = None,
		failedChildren: set[str] | None = None,
		fields: dict[tuple[str, str], ProviderReadResult] | None = None,
		onRead: Callable[[], None] | None = None,
	) -> None:
		super().__init__()
		self.children = children or {}
		self.logical = logical or {}
		self.failedChildren = failedChildren or set()
		self.fields = fields or {}
		self.onRead = onRead
		self.calls: list[str] = []
		self.childBudgets: list[int] = []
		self.logicalBudgets: list[int] = []

	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult:
		self.calls.append(f"field:{request.nodeRef}:{request.fieldId}")
		if self.onRead is not None:
			self.onRead()
		return self.fields.get((request.nodeRef, request.fieldId), ProviderReadResult("empty"))

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult:
		return ProviderReadResult("unsupported")

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult:
		return ProviderReadResult("unsupported")

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		return ProviderReadResult("unsupported")

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		self.calls.append(f"children:{request.nodeRef}")
		self.childBudgets.append(request.budget.maximumItems)
		if request.nodeRef in self.failedChildren:
			return ProviderChildBatch("failed", (), 0, False, "KS.PROVIDER.CHILDREN_FAILED")
		items = self.children.get(request.nodeRef, ())
		retained = items[: request.budget.maximumItems]
		return ProviderChildBatch(
			"value" if retained else "empty",
			retained,
			len(items),
			len(retained) < len(items),
		)

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		self.calls.append(f"logical:{request.nodeRef}")
		self.logicalBudgets.append(request.budget.maximumItems)
		items = self.logical.get(request.nodeRef, ())
		retained = items[: request.budget.maximumItems]
		return ProviderChildBatch(
			"value" if retained else "empty",
			retained,
			len(items),
			len(retained) < len(items),
		)


class _Identity:
	def __init__(self, aliases: tuple[tuple[str, str], ...] = ()) -> None:
		super().__init__()
		self.aliases = {frozenset(pair) for pair in aliases}
		self.calls = 0

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		self.calls += 1
		same = (
			request.firstNodeRef == request.secondNodeRef
			or frozenset((request.firstNodeRef, request.secondNodeRef)) in self.aliases
		)
		return IdentityComparisonResult("value", "same" if same else "different", ())


class _VeryWideTreeProvider(_TreeProvider):
	def __init__(self, width: int) -> None:
		super().__init__()
		self.width = width
		self.maximumReturned = 0

	@override
	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		self.calls.append(f"children:{request.nodeRef}")
		self.childBudgets.append(request.budget.maximumItems)
		if request.nodeRef != "root":
			return ProviderChildBatch("empty", (), 0, False)
		children = tuple(f"child-{index}" for index in range(request.budget.maximumItems))
		self.maximumReturned = max(self.maximumReturned, len(children))
		return ProviderChildBatch("value", children, self.width, True)


class _Clock:
	def __init__(self, step: int = 0) -> None:
		super().__init__()
		self.value = 0
		self.step = step

	def __call__(self) -> int:
		current = self.value
		self.value += self.step
		return current


def _limits(**changes: int | str) -> TraversalLimits:
	values: dict[str, int | str] = {
		"maximumNodes": 100,
		"maximumDepth": 100,
		"maximumMilliseconds": 100_000,
		"maximumTextScalars": 10_000,
		"maximumRanges": 50,
		"maximumRelations": 50,
		"maximumAncestry": 100,
		"maximumHyperlinks": 50,
		"workSliceMilliseconds": 100,
		"yieldMilliseconds": 0,
		"mode": "bounded",
	}
	values.update(changes)
	return TraversalLimits(**values)  # type: ignore[arg-type]


def _walk(
	provider: _TreeProvider,
	*,
	identity: _Identity | None = None,
	limits: TraversalLimits | None = None,
	clock: _Clock | None = None,
	cancel: Callable[[], bool] | None = None,
	yieldControl: Callable[[int], None] | None = None,
	progress: Callable[[TraversalProgress], None] | None = None,
):
	context = CorrelationFactory().admit(generation=1)
	return IterativeTraversal(
		provider,
		identity or _Identity(),
		clock=clock or _Clock(),
		cancelRequested=cancel,
		yieldControl=yieldControl,
	).walk(
		"root",
		providerScope="provider-scope",
		processScope="process-scope",
		backend="nvdaSelected",
		context=context,
		limits=limits or _limits(),
		progress=progress,
	)


class IterativeTraversalTests(unittest.TestCase):
	def test_deep_tree_does_not_change_or_depend_on_python_recursion_limit(self) -> None:
		depth = 1_200
		children = {
			("root" if index == 0 else f"node-{index}"): (f"node-{index + 1}",) for index in range(depth)
		}
		before = sys.getrecursionlimit()

		result = _walk(
			_TreeProvider(children),
			limits=_limits(
				maximumNodes=depth + 1,
				maximumDepth=depth + 1,
				maximumAncestry=depth + 1,
				maximumIdentityComparisons=depth * (depth + 1) // 2,
			),
		)

		self.assertEqual(depth + 1, len(result.nodes))
		self.assertEqual(depth, result.nodes[-1].depth)
		self.assertEqual(before, sys.getrecursionlimit())

	def test_unlimited_mode_keeps_nearby_identity_cycle_checks_available_deep_in_a_branch(self) -> None:
		depth = 1_500
		children: dict[str, tuple[str, ...]] = {
			("root" if index == 0 else f"node-{index}"): (f"node-{index + 1}",) for index in range(depth)
		}
		children[f"node-{depth}"] = ("identity-cycle", "root")
		identity = _Identity((("identity-cycle", f"node-{depth - 10}"),))

		result = _walk(
			_TreeProvider(children),
			identity=identity,
			limits=TraversalLimits.fromSettings(
				SettingsSnapshot.defaults(settingsRevision=1),
				"unlimited",
			),
		)

		identityCycle = next(node for node in result.nodes if node.nodeRef == "identity-cycle")
		rootCycle = result.nodes[-1]
		self.assertTrue(identityCycle.cycleDetected)
		self.assertEqual(f"n{depth - 10 + 1}", identityCycle.referenceKey)
		self.assertTrue(rootCycle.cycleDetected)
		self.assertEqual("n1", rootCycle.referenceKey)
		self.assertLessEqual(identity.calls, (depth + 1) * 40)
		self.assertFalse(
			next(item for item in result.limits if item.limitType == "identityComparisons").reached,
		)

	def test_cycle_emits_minimal_reference_and_stops_descent(self) -> None:
		result = _walk(_TreeProvider({"root": ("child",), "child": ("root",)}))

		self.assertEqual(3, len(result.nodes))
		reference = result.nodes[-1]
		self.assertTrue(reference.cycleDetected)
		self.assertEqual("n1", reference.referenceKey)
		self.assertEqual((), reference.childKeys)
		self.assertEqual(("reference", "n1"), reference.field("stableIds").value)

	def test_logical_first_child_merges_before_ordinary_children_and_deduplicates_by_identity(self) -> None:
		result = _walk(
			_TreeProvider(
				{"root": ("ordinary-a", "ordinary-b")},
				logical={"root": ("logical-a",)},
			),
			identity=_Identity((("logical-a", "ordinary-a"),)),
		)
		self.assertEqual(("n2", "n3"), result.nodes[0].childKeys)
		self.assertEqual(("ordinary-a", "ordinary-b"), tuple(node.nodeRef for node in result.nodes[1:]))

		distinct = _walk(
			_TreeProvider(
				{"root": ("ordinary-a", "ordinary-b")},
				logical={"root": ("logical-c",)},
			),
		)
		self.assertEqual(
			("logical-c", "ordinary-a", "ordinary-b"),
			tuple(node.nodeRef for node in distinct.nodes[1:]),
		)

	def test_node_depth_and_text_limits_record_configured_and_observed_counts(self) -> None:
		provider = _TreeProvider(
			{"root": ("a", "b"), "a": ("grandchild",)},
			fields={("root", "name"): ProviderReadResult("value", "abcdef")},
		)
		result = _walk(
			provider,
			limits=_limits(maximumNodes=2, maximumDepth=1, maximumTextScalars=4),
		)

		limits = {item.limitType: item for item in result.limits}
		self.assertTrue(result.truncated)
		self.assertEqual((2, 2), (limits["nodes"].configuredLimit, limits["nodes"].observedCount))
		self.assertEqual((1, 1), (limits["depth"].configuredLimit, limits["depth"].observedCount))
		self.assertEqual((4, 6), (limits["textScalars"].configuredLimit, limits["textScalars"].observedCount))
		self.assertTrue(result.nodes[0].truncated)
		self.assertEqual("abcd", result.nodes[0].field("name").value)
		self.assertTrue(result.nodes[0].field("name").truncated)
		self.assertEqual(
			{
				"nodes",
				"identityComparisons",
				"depth",
				"timeMilliseconds",
				"textScalars",
				"ancestry",
			},
			set(limits),
		)

	def test_node_limit_evidence_requires_known_pending_work(self) -> None:
		leaf = _walk(_TreeProvider(), limits=_limits(maximumNodes=1))
		leafNodeLimit = next(item for item in leaf.limits if item.limitType == "nodes")

		self.assertFalse(leafNodeLimit.reached)
		self.assertFalse(leaf.truncated)
		self.assertFalse(leaf.nodes[0].truncated)

		branch = _walk(
			_TreeProvider({"root": ("first", "omitted")}),
			limits=_limits(maximumNodes=2),
		)
		branchNodeLimit = next(item for item in branch.limits if item.limitType == "nodes")

		self.assertTrue(branchNodeLimit.reached)
		self.assertTrue(branch.truncated)
		self.assertTrue(branch.nodes[0].truncated)

	def test_node_limit_probes_the_final_frame_for_skipped_children(self) -> None:
		provider = _TreeProvider({"root": ("a",), "a": ("grandchild",)})

		result = _walk(provider, limits=_limits(maximumNodes=2))
		nodeLimit = next(item for item in result.limits if item.limitType == "nodes")

		self.assertEqual(("root", "a"), tuple(node.nodeRef for node in result.nodes))
		self.assertTrue(nodeLimit.reached)
		self.assertTrue(result.truncated)
		self.assertTrue(result.nodes[-1].truncated)
		self.assertIn("children:a", provider.calls)
		self.assertNotIn("children:grandchild", provider.calls)

	def test_node_limit_does_not_truncate_an_exact_capacity_leaf(self) -> None:
		result = _walk(_TreeProvider({"root": ("leaf",)}), limits=_limits(maximumNodes=2))
		nodeLimit = next(item for item in result.limits if item.limitType == "nodes")

		self.assertFalse(nodeLimit.reached)
		self.assertFalse(result.truncated)
		self.assertFalse(result.nodes[-1].truncated)

	def test_very_wide_tree_bounds_child_reads_and_identity_work(self) -> None:
		provider = _VeryWideTreeProvider(1_000_000)
		identity = _Identity()

		result = _walk(
			provider,
			identity=identity,
			limits=_limits(maximumNodes=8, maximumIdentityComparisons=3),
		)

		limits = {item.limitType: item for item in result.limits}
		self.assertEqual(7, provider.childBudgets[0])
		self.assertLessEqual(provider.maximumReturned, provider.childBudgets[0])
		self.assertEqual(3, identity.calls)
		self.assertTrue(limits["identityComparisons"].reached)
		self.assertTrue(result.nodes[0].truncated)
		self.assertTrue(result.truncated)

	def test_wide_sibling_identity_exhaustion_does_not_drop_narrow_branch(self) -> None:
		identity = _Identity()
		result = _walk(
			_TreeProvider(
				{
					"root": ("wide", "narrow"),
					"wide": ("wide-0", "wide-1", "wide-2", "wide-3"),
					"narrow": ("narrow-child",),
				},
				logical={"wide": ("wide-logical",)},
			),
			identity=identity,
			limits=_limits(maximumNodes=15, maximumIdentityComparisons=3),
		)

		limits = {item.limitType: item for item in result.limits}
		wide = next(node for node in result.nodes if node.nodeRef == "wide")
		self.assertEqual(3, identity.calls)
		self.assertTrue(limits["identityComparisons"].reached)
		self.assertTrue(wide.truncated)
		self.assertIn("narrow", tuple(node.nodeRef for node in result.nodes))
		self.assertIn("narrow-child", tuple(node.nodeRef for node in result.nodes))

	def test_default_settings_complete_a_moderately_deep_branching_tree(self) -> None:
		branching = 3
		depth = 7
		children: dict[str, tuple[str, ...]] = {}
		current = ("root",)
		for _ in range(depth):
			nextLevel: list[str] = []
			for node in current:
				nodeChildren = tuple(f"{node}-{index}" for index in range(branching))
				children[node] = nodeChildren
				nextLevel.extend(nodeChildren)
			current = tuple(nextLevel)
		limits = TraversalLimits.fromSettings(
			SettingsSnapshot.defaults(settingsRevision=1),
			"bounded",
		)

		result = _walk(_TreeProvider(children), limits=limits)

		self.assertEqual(sum(branching**level for level in range(depth + 1)), len(result.nodes))
		self.assertFalse(result.truncated)
		self.assertFalse(
			next(item for item in result.limits if item.limitType == "identityComparisons").reached,
		)

	def test_text_truncation_marks_a_leaf_without_child_truncation(self) -> None:
		result = _walk(
			_TreeProvider(fields={("root", "name"): ProviderReadResult("value", "abcdef")}),
			limits=_limits(maximumTextScalars=4),
		)

		self.assertTrue(result.truncated)
		self.assertTrue(result.nodes[0].truncated)
		self.assertTrue(result.nodes[0].field("name").truncated)

	def test_child_fetch_failure_is_not_reported_as_an_empty_leaf(self) -> None:
		result = _walk(_TreeProvider(failedChildren={"root"}))

		self.assertTrue(result.nodes[0].childFetchFailed)
		self.assertEqual((), result.nodes[0].childKeys)
		self.assertFalse(result.cancelled)

	def test_cancellation_is_checked_after_provider_return_and_yields_are_cooperative(self) -> None:
		cancelled = False
		yields: list[int] = []

		def cancelDuringRead() -> None:
			nonlocal cancelled
			cancelled = True

		result = _walk(
			_TreeProvider(onRead=cancelDuringRead),
			clock=_Clock(step=1),
			cancel=lambda: cancelled,
			yieldControl=yields.append,
			limits=_limits(workSliceMilliseconds=1),
		)

		self.assertTrue(result.cancelled)
		self.assertEqual((), result.nodes)
		self.assertTrue(yields)

	def test_progress_reports_safe_traversal_counts_without_provider_values(self) -> None:
		progress: list[TraversalProgress] = []

		_ = _walk(
			_TreeProvider({"root": ("child",)}),
			clock=_Clock(step=100),
			progress=progress.append,
		)

		self.assertTrue(progress)
		first = progress[0]
		self.assertEqual(0, first.processedNodes)
		self.assertGreater(first.pendingWorkCount, 0)
		self.assertGreaterEqual(first.elapsedMilliseconds, 0)

	def test_provider_stalls_create_value_free_timing_and_later_read_circuit_behavior(self) -> None:
		provider = _TreeProvider(fields={("root", "name"): ProviderReadResult("value", "private-value")})
		context = CorrelationFactory().admit(generation=1)
		result = IterativeTraversal(
			provider,
			_Identity(),
			clock=_Clock(step=1_001),
			stallThresholdMilliseconds=1_000,
			stallsBeforeOpen=2,
			resetAfterSkippedReads=3,
		).walk(
			"root",
			providerScope="provider-scope",
			processScope="process-scope",
			backend="nvdaSelected",
			context=context,
			limits=_limits(maximumMilliseconds=1_000_000, workSliceMilliseconds=100_000),
		)

		self.assertTrue(result.timings)
		self.assertTrue(result.timingAggregates)
		self.assertTrue(all(item.backend == "nvdaSelected" for item in result.timings))
		self.assertFalse(any("private-value" in repr(item) for item in result.timings))
		self.assertLess(len(provider.calls), 37)
		self.assertTrue(
			any(
				field.result.errorCode == "KS.PROVIDER.CIRCUIT_OPEN"
				for node in result.nodes
				for field in node.fields
			),
		)
		self.assertEqual(3, result.degradation.resetAfterSkippedReads)


if __name__ == "__main__":
	_ = unittest.main()
