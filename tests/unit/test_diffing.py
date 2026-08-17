from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from addon.globalPlugins.keystone.domain.diffing import (
	AmbiguousMatchError,
	diffSnapshots,
	diffSnapshotViews,
)
from addon.globalPlugins.keystone.domain.document_records import (
	COMMON_NODE_FIELDS,
	PROVIDER_SECTIONS,
	CaptureCounts,
	CaptureDetails,
	CaptureDuration,
	CaptureLimits,
	CaptureMetadata,
	DiagnosticMetadata,
	EnvironmentMetadata,
	JsonArray,
	JsonObject,
	NodeRecord,
	NodeStructure,
	ProjectionMetadata,
	ProviderSectionRecord,
	ProviderSections,
	RedactionMetadata,
	ScreenshotMetadata,
	StandaloneConventions,
)
from addon.globalPlugins.keystone.domain.documents import Snapshot
from addon.globalPlugins.keystone.domain.evidence import (
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Source,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy, UNREDACTED_SCREENSHOT_WARNING
from addon.globalPlugins.keystone.domain.snapshot_bundle import (
	BundleSnapshotView,
	InMemorySnapshotView,
	prepareBundle,
	projectSnapshotTopics,
)
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState


def makeEvidence(
	value: object = None,
	*,
	field: str = "field",
	classification: str = "public",
	status: EvidenceState | None = None,
) -> EvidenceEnvelope:
	actualStatus = status or (EvidenceState.EMPTY if value is None else EvidenceState.VALUE)
	return EvidenceEnvelope(
		actualStatus,
		Source("test", "DiffTests", field),
		Projection("normalNvda"),
		Confidence.DIRECT,
		PrivacyReference("node", classification, "retain", 1),  # type: ignore[arg-type]
		value if actualStatus is EvidenceState.VALUE else None,  # type: ignore[arg-type]
	)


def _providers(
	*,
	identity: str = "provider",
	properties: object = (),
) -> ProviderSections:
	unavailable = makeEvidence(field="provider", status=EvidenceState.NOT_APPLICABLE)
	return ProviderSections(
		tuple(
			(
				name,
				ProviderSectionRecord(
					makeEvidence("available", field=f"{name}.status"),
					makeEvidence(identity if name == "generic" else name, field=f"{name}.identity"),
					makeEvidence(properties if name == "generic" else (), field=f"{name}.properties")
					if name == "generic"
					else unavailable,
				),
			)
			for name in PROVIDER_SECTIONS
		),
	)


def makeNode(
	key: str,
	*,
	parent: str | None = None,
	children: tuple[str, ...] = (),
	name: str = "Item",
	role: object = "button",
	automationId: str | None = None,
	controlId: int = 0,
	windowClass: str = "Widget",
	index: int = 0,
	geometry: tuple[int, ...] = (0, 0, 10, 10),
	providerIdentity: str = "provider",
	providerProperties: object = (),
	protectedName: bool = False,
) -> NodeRecord:
	values: dict[str, object] = {
		"name": name,
		"role": role,
		"states": ("focusable",),
		"geometry": geometry,
		"windowHandle": 42,
		"windowClass": windowClass,
		"windowControlId": controlId,
		"childCount": len(children),
		"indexInParent": index,
		"backend": "uia",
		"process": 42,
		"stableIds": ((("uiaAutomationId", "window-42", automationId),) if automationId else ()),
		"children": children,
	}
	fields = tuple(
		(
			field,
			makeEvidence(
				values[field],
				field=field,
				classification="protected" if field == "name" and protectedName else "public",
			)
			if field in values
			else makeEvidence(field=field, status=EvidenceState.NOT_APPLICABLE),
		)
		for field in COMMON_NODE_FIELDS
	)
	depth = 0 if parent is None else 1
	return NodeRecord(
		key,
		NodeStructure(parent, depth, children, False, False, False),
		fields,
		_providers(identity=providerIdentity, properties=providerProperties),
	)


def makeSnapshot(
	nodes: tuple[NodeRecord, ...],
	*,
	identifier: int = 1,
	redaction: RedactionMetadata | None = None,
) -> Snapshot:
	rootKeys = tuple(node.key for node in nodes if node.structure.parentKey is None)
	nonvalue = makeEvidence(field="metadata", status=EvidenceState.NOT_APPLICABLE)
	metadata = CaptureMetadata(
		CaptureDetails(
			"2026-07-26T06:00:00+00:00",
			nonvalue,
			makeEvidence("capture", field="outputPath"),
			"snapshot",
			False,
			makeEvidence("window-42", field="containingForeground"),
			ScreenshotMetadata(
				True,
				makeEvidence("value", field="screenshot"),
				UNREDACTED_SCREENSHOT_WARNING,
			),
			DiagnosticMetadata(0, 0, False),
			StandaloneConventions(
				"keystone.capture",
				"2.0",
				"required fields are never omitted",
				"status is independent from value",
				"signed half-open virtual-screen pixels",
				"capture traversal order",
				"provider child order",
			),
		),
		EnvironmentMetadata(
			nonvalue,
			nonvalue,
			nonvalue,
			nonvalue,
			nonvalue,
			nonvalue,
			makeEvidence(("uia",)),
		),
		CaptureLimits(10_000, 10_000, 10_000, 10_000),
		CaptureCounts(len(nodes), len(nodes), 0, 0),
		CaptureDuration(0),
		ProjectionMetadata("normalNvda", 1),
		redaction or RedactionMetadata(False, "default", 1),
	)
	return Snapshot(
		"snapshot",
		f"00000000-0000-4000-8000-{identifier:012d}",
		metadata,
		JsonObject(
			(
				("roots", JsonArray(rootKeys)),
				("nodes", JsonArray(tuple(node.asObject() for node in nodes))),
			),
		),
		rootKeys,
		nodes,
	)


class DiffTransformTests(unittest.TestCase):
	def test_stable_automation_id_keeps_dynamic_label_as_one_modification(self) -> None:
		before = makeSnapshot((makeNode("old", name="Before", automationId="save"),))
		after = makeSnapshot((makeNode("new", name="After", automationId="save"),), identifier=2)

		changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

		self.assertEqual(1, len(changes))
		self.assertEqual("modified", changes[0].changeKind)
		self.assertEqual(("save", "name"), changes[0].ancestorPath)
		self.assertEqual("Before", changes[0].before.value if changes[0].before else None)
		self.assertEqual("After", changes[0].after.value if changes[0].after else None)

	def test_untrimmed_name_uses_generated_key_for_diff_path(self) -> None:
		for index, name in enumerate((" UTF-8", "UTF-8 ", " ")):
			with self.subTest(name=name):
				key = f"node-{index}"
				before = makeSnapshot((makeNode(key, name=name, role=7),), identifier=index + 10)
				after = makeSnapshot(
					(makeNode(key, name=name, role=7, geometry=(1, 0, 10, 10)),),
					identifier=index + 20,
				)

				changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

				self.assertEqual(1, len(changes))
				self.assertEqual((key, "geometry"), changes[0].ancestorPath)

	def test_untrimmed_automation_id_is_not_used_for_diff_path(self) -> None:
		for index, automationId in enumerate((" save", "save ", "save\n")):
			with self.subTest(automationId=automationId):
				key = f"node-{index}"
				before = makeSnapshot(
					(makeNode(key, name=" invalid", role=7, automationId=automationId),),
					identifier=index + 30,
				)
				after = makeSnapshot(
					(
						makeNode(
							key,
							name=" invalid",
							role=7,
							automationId=automationId,
							geometry=(1, 0, 10, 10),
						),
					),
					identifier=index + 40,
				)

				changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

				self.assertEqual(1, len(changes))
				self.assertEqual((key, "geometry"), changes[0].ancestorPath)

	def test_reorder_and_geometry_do_not_break_identity(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), automationId="root"),
				makeNode("a", parent="root", automationId="a", index=0),
				makeNode("b", parent="root", automationId="b", index=1),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("b2", "a2"), automationId="root"),
				makeNode("b2", parent="root2", automationId="b", index=0, geometry=(50, 50, 10, 10)),
				makeNode("a2", parent="root2", automationId="a", index=1),
			),
			identifier=2,
		)

		changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

		self.assertFalse(any(change.changeKind in {"added", "removed"} for change in changes))
		self.assertTrue(any(change.ancestorPath[-1] == "indexInParent" for change in changes))
		self.assertTrue(any(change.ancestorPath[-1] == "geometry" for change in changes))

	def test_nested_provider_mapping_reports_only_changed_leaf(self) -> None:
		before = makeSnapshot(
			(
				makeNode(
					"root",
					automationId="root",
					providerProperties=(("Range", (("Minimum", 0), ("Value", 2))),),
				),
			),
		)
		after = makeSnapshot(
			(
				makeNode(
					"root2",
					automationId="root",
					providerProperties=(("Range", (("Minimum", 0), ("Value", 3))),),
				),
			),
			identifier=2,
		)

		changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

		self.assertEqual(1, len(changes))
		self.assertEqual(
			("root", "providers", "generic", "properties", "Range", "Value"),
			changes[0].ancestorPath,
		)
		self.assertEqual(2, changes[0].before.value if changes[0].before else None)
		self.assertEqual(3, changes[0].after.value if changes[0].after else None)

	def test_duplicate_fallback_group_without_discriminator_is_rejected(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), automationId="root"),
				makeNode("a", parent="root"),
				makeNode("b", parent="root"),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("c", "d"), automationId="root"),
				makeNode("c", parent="root2"),
				makeNode("d", parent="root2"),
			),
			identifier=2,
		)

		with self.assertRaisesRegex(AmbiguousMatchError, "ambiguous"):
			_ = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

	def test_duplicate_fallback_group_uses_provider_discriminator_deterministically(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), automationId="root"),
				makeNode("a", parent="root", providerIdentity="left"),
				makeNode("b", parent="root", providerIdentity="right"),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("d", "c"), automationId="root"),
				makeNode("d", parent="root2", providerIdentity="right"),
				makeNode("c", parent="root2", providerIdentity="left"),
			),
			identifier=2,
		)

		self.assertEqual((), diffSnapshots(before, after, PrivacyPolicy(2, 2, True)))

	def test_added_and_removed_subtrees_emit_each_descendant_once(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("old",), automationId="root"),
				makeNode("old", parent="root", children=("old-child",), automationId="old"),
				makeNode("old-child", parent="old", automationId="old-child"),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("new",), automationId="root"),
				makeNode("new", parent="root2", children=("new-child",), automationId="new"),
				makeNode("new-child", parent="new", automationId="new-child"),
			),
			identifier=2,
		)

		changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

		self.assertEqual(
			{
				("added", ("root", "new")),
				("added", ("root", "new", "new-child")),
				("removed", ("root", "old")),
				("removed", ("root", "old", "old-child")),
			},
			{(change.changeKind, change.ancestorPath) for change in changes},
		)

	def test_stable_id_role_conflict_is_rejected(self) -> None:
		before = makeSnapshot((makeNode("old", automationId="root", role="button"),))
		after = makeSnapshot((makeNode("new", automationId="root", role="document"),), identifier=2)

		with self.assertRaisesRegex(AmbiguousMatchError, "conflicting role"):
			_ = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

	def test_current_policy_redacts_historical_protected_values_in_both_views(self) -> None:
		before = makeSnapshot((makeNode("root", name="old secret", automationId="root", protectedName=True),))
		after = makeSnapshot(
			(makeNode("root2", name="new secret", automationId="root", protectedName=True),),
			identifier=2,
		)

		changes = diffSnapshots(before, after, PrivacyPolicy(2, 2, True))

		self.assertEqual((), changes)

	def test_deep_tree_is_iterative_and_no_change_is_empty(self) -> None:
		count = 1_200
		nodes = tuple(
			makeNode(
				f"n{index}",
				parent=None if index == 0 else f"n{index - 1}",
				children=() if index == count - 1 else (f"n{index + 1}",),
				automationId=f"id-{index}",
			)
			for index in range(count)
		)
		before = makeSnapshot(nodes)
		afterNodes = tuple(
			makeNode(
				f"x{index}",
				parent=None if index == 0 else f"x{index - 1}",
				children=() if index == count - 1 else (f"x{index + 1}",),
				automationId=f"id-{index}",
			)
			for index in range(count)
		)
		after = makeSnapshot(afterNodes, identifier=2)

		self.assertEqual((), diffSnapshots(before, after, PrivacyPolicy(2, 2, True)))


def _bundleView(directory: Path, snapshot: Snapshot) -> BundleSnapshotView:
	source = projectSnapshotTopics(
		snapshot,
		generatedAt="2026-07-24T09:08:07Z",
		executable="reader.exe",
		processId=42,
		redactionEnabled=True,
		policyRevision=1,
		settingsRevision=1,
		snapshotKind="snapshot",
	)
	package = prepareBundle(source)
	for name, payload in package.artifacts():
		_ = (directory / name).write_bytes(payload)
	return BundleSnapshotView(directory)


class DiffSnapshotViewsTests(unittest.TestCase):
	def test_bundle_backed_views_reproduce_the_in_memory_diff(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), name="Main", role="window", automationId="root"),
				makeNode("a", parent="root", name="Alpha", automationId="a"),
				makeNode("b", parent="root", name="Beta", automationId="b"),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("a", "c"), name="Main", role="window", automationId="root"),
				makeNode("a", parent="root2", name="Alpha Renamed", automationId="a"),
				makeNode("c", parent="root2", name="Gamma", automationId="c"),
			),
			identifier=2,
		)
		policy = PrivacyPolicy(2, 2, True)
		inMemory = diffSnapshotViews(InMemorySnapshotView(before), InMemorySnapshotView(after), policy)
		with TemporaryDirectory() as beforeDir, TemporaryDirectory() as afterDir:
			fromBundles = diffSnapshotViews(
				_bundleView(Path(beforeDir), before),
				_bundleView(Path(afterDir), after),
				policy,
			)
			self.assertNotEqual((), fromBundles)
			self.assertEqual(inMemory, fromBundles)

	def test_disjoint_roots_compare_core_only_without_opening_deep_topics(self) -> None:
		before = makeSnapshot((makeNode("old", name="Old Root", role="window", automationId="old"),))
		after = makeSnapshot(
			(makeNode("new", name="New Root", role="window", automationId="new"),),
			identifier=2,
		)
		policy = PrivacyPolicy(2, 2, True)
		with TemporaryDirectory() as beforeDir, TemporaryDirectory() as afterDir:
			left = _bundleView(Path(beforeDir), before)
			right = _bundleView(Path(afterDir), after)
			changes = diffSnapshotViews(left, right, policy)
			self.assertNotEqual((), changes)
			self.assertEqual(0, left.deepOpens)
			self.assertEqual(0, right.deepOpens)
			self.assertEqual(0, left.openHandles)
			self.assertEqual(0, right.openHandles)

	def test_ambiguous_siblings_reject_and_release_every_deep_handle(self) -> None:
		before = makeSnapshot(
			(
				makeNode("root", children=("a", "b"), automationId="root"),
				makeNode("a", parent="root"),
				makeNode("b", parent="root"),
			),
		)
		after = makeSnapshot(
			(
				makeNode("root2", children=("c", "d"), automationId="root"),
				makeNode("c", parent="root2"),
				makeNode("d", parent="root2"),
			),
			identifier=2,
		)
		policy = PrivacyPolicy(2, 2, True)
		with TemporaryDirectory() as beforeDir, TemporaryDirectory() as afterDir:
			left = _bundleView(Path(beforeDir), before)
			right = _bundleView(Path(afterDir), after)
			with self.assertRaisesRegex(AmbiguousMatchError, "ambiguous"):
				_ = diffSnapshotViews(left, right, policy)
			self.assertEqual(0, left.openHandles)
			self.assertEqual(0, right.openHandles)


if __name__ == "__main__":
	_ = unittest.main()
