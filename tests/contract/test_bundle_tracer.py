from __future__ import annotations

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.windows.publication import (
	LocalPublicationBackend,
	PublicationManager,
	PublicationPolicy,
)
from addon.globalPlugins.keystone.adapters.wx.inspector_frame import (
	InspectorFrameController,
	InspectorTargetEvidence,
)
from addon.globalPlugins.keystone.application.bundle_service import (
	BundleService,
	portableSubtreeDestination,
	writePortableBundle,
)
from addon.globalPlugins.keystone.domain import snapshot_bundle as sb
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from tests.fixtures.representative_capture import (
	EXPECTED_RECORD_COUNTS,
	PROTECTED_SAMPLE_SECRET,
	RepresentativeCapture,
	fieldValue,
	representativeCapture,
)
from tests.fixtures.compact_snapshot_shapes import (
	writeLocalRetryLimitFixture,
)
from tests.unit.test_diffing import makeNode, makeSnapshot

_EVIDENCE = InspectorTargetEvidence("focus", "reader.exe", 42, 1, "uia", False, False, None)


def _source(capture: RepresentativeCapture) -> sb.BundleSource:
	return sb.BundleSource(
		snapshotKind="snapshot",
		generatedAt="2026-07-24T09:08:07Z",
		redactionEnabled=True,
		policyRevision=1,
		settingsRevision=1,
		executable="reader.exe",
		processId=42,
		rootIds=("n0",),
		topics=tuple(sb.BundleTopicRecords(topic.name, topic.records) for topic in capture.topics),
	)


class BundleTracerTests(unittest.TestCase):
	def test_portable_subtree_destination_uses_sanitized_application_element_and_timestamp(self) -> None:
		destination = portableSubtreeDestination(
			Path("C:/exports"),
			applicationName="reader.exe",
			elementName='Save: "draft"',
			automationId=None,
			role="button",
			now=datetime(2026, 8, 28, 12, 49, 45, 279123),
		)

		self.assertEqual(
			Path("C:/exports/reader/Save_ _draft_/20260828-124945.279123"),
			destination,
		)

	def test_portable_subtree_destination_falls_back_to_automation_id_then_role(self) -> None:
		now = datetime(2026, 8, 28, 12, 49, 45, 279123)
		automation = portableSubtreeDestination(
			Path("C:/exports"),
			applicationName="CON.EXE",
			elementName="...",
			automationId="save/button",
			role="button",
			now=now,
		)
		role = portableSubtreeDestination(
			Path("C:/exports"),
			applicationName="...",
			elementName=None,
			automationId=" ",
			role="list:item",
			now=now,
		)

		self.assertEqual(
			Path("C:/exports/application/save_button/20260828-124945.279123"),
			automation,
		)
		self.assertEqual(
			Path("C:/exports/application/list_item/20260828-124945.279123"),
			role,
		)

	def test_portable_subtree_destination_rejects_reserved_and_overlong_components(self) -> None:
		destination = portableSubtreeDestination(
			Path("C:/exports"),
			applicationName="NUL.txt",
			elementName="x" * 200,
			automationId=None,
			role="button",
			now=datetime(2026, 8, 28, 12, 49, 45, 279123),
		)

		self.assertEqual("application", destination.parts[-3])
		self.assertEqual(120, len(destination.parts[-2]))
		self.assertFalse(
			portableSubtreeDestination(
				Path("C:/exports"),
				applicationName="reader.exe",
				elementName=("x" * 119) + "." + ("suffix" * 20),
				automationId=None,
				role="button",
				now=datetime(2026, 8, 28, 12, 49, 45, 279123),
			)
			.parts[-2]
			.endswith((".", " ")),
		)

	def test_portable_export_removes_the_destination_when_final_admission_fails(self) -> None:
		package = sb.prepareBundle(_source(representativeCapture()))
		with TemporaryDirectory() as temporary:
			destination = Path(temporary) / "selected-subtree"

			def failFinalAdmission(
				directory: Path,
				*,
				sourceGeneration: int,
				limits: sb.BundleAdmissionLimits = sb.DEFAULT_BUNDLE_LIMITS,
			) -> sb.BundleAdmission:
				if directory == destination:
					raise ValueError("injected final admission failure")
				return sb.admitBundle(
					directory,
					sourceGeneration=sourceGeneration,
					limits=limits,
				)

			with (
				patch(
					"addon.globalPlugins.keystone.application.bundle_service.admitBundle",
					side_effect=failFinalAdmission,
				),
				self.assertRaisesRegex(ValueError, "injected final admission failure"),
			):
				_ = writePortableBundle(package, destination)

			self.assertFalse(destination.exists())

	def test_production_bundle_projection_maps_snapshot_to_local_identifiers(self) -> None:
		snapshot = makeSnapshot(
			(
				makeNode("root-key", children=("child-key",), name="Document", role="pane"),
				makeNode("child-key", parent="root-key", name="Save", role="button", index=0),
			),
		)
		source = sb.projectSnapshotTopics(
			snapshot,
			generatedAt="2026-07-24T09:08:07Z",
			executable="reader.exe",
			processId=42,
			redactionEnabled=True,
			policyRevision=1,
			settingsRevision=1,
			snapshotKind="snapshot",
		)
		core = source.topics[0].records
		self.assertEqual(fieldValue(core[0], "id"), "n0")
		self.assertEqual(fieldValue(core[0], "parent"), None)
		self.assertEqual(fieldValue(core[0], "name"), "Document")
		self.assertEqual(fieldValue(core[0], "children"), sb.JsonArray(("n1",)))
		self.assertEqual(fieldValue(core[1], "id"), "n1")
		self.assertEqual(fieldValue(core[1], "parent"), "n0")
		self.assertEqual(fieldValue(core[1], "name"), "Save")
		self.assertEqual(fieldValue(core[1], "children"), sb.JsonArray(()))
		self.assertEqual(source.rootIds, ("n0",))

		package = sb.prepareBundle(source)
		self.assertEqual(package.index.nodeCount, 2)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in package.artifacts():
				_ = (directory / name).write_bytes(payload)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			projection = sb.projectSelectedNode(admission, directory, "n1")
			self.assertEqual(
				[topic for topic, _record in projection.records],
				["nodes", "uia", "ia2Msaa", "jab", "overlay", "rawUia", "customUia"],
			)

	def test_bundle_flows_from_capture_through_publication_to_selected_export(self) -> None:
		service = BundleService()
		package = service.prepare(_source(representativeCapture()))
		publication = service.toPublicationPackage(
			package,
			publicationId="publication-a",
			completedAt=datetime(2026, 7, 24, 9, 8, 7),
		)
		context = CorrelationFactory().admit(generation=3)
		with TemporaryDirectory() as temporary:
			manager = PublicationManager(
				LocalPublicationBackend(Path(temporary)),
				nonceFactory=lambda: "nonce-a",
			)
			result = manager.publish(publication, lambda: PublicationPolicy(), context)
			self.assertTrue(result.committed)
			receipt = result.receipt
			self.assertIsNotNone(receipt)
			assert receipt is not None

			admission = service.openDirectory(receipt.path)
			catalog = {entry.topic: entry.recordCount for entry in admission.index.catalog}
			self.assertEqual(catalog, EXPECTED_RECORD_COUNTS)

			projection = service.selectNode("n13")
			exported = projection.toJsonBytes()
			self.assertNotIn(PROTECTED_SAMPLE_SECRET.encode("utf-8"), exported)
			self.assertEqual([topic for topic, _record in projection.records], ["nodes", "uia", "semantics"])

			outline = tuple(f"{node.id} {node.role} {node.name}" for node in admission.index.outline)
			current = [True]
			controller = InspectorFrameController(
				lambda _kind, _raw: _EVIDENCE,
				lambda _parent: None,
				lambda: current[0],
			)
			controller.openBundle(lambda nodeId, _format: service.selectNode(nodeId).toJsonBytes(), outline)
			self.assertEqual(controller.bundleOutline, outline)
			self.assertEqual(controller.exportSelectedNode("n13"), exported)

			current[0] = False
			with self.assertRaises(RuntimeError):
				_ = controller.exportSelectedNode("n13")

	def test_default_limit_does_not_change_when_an_explicit_local_retry_is_used(self) -> None:
		service = BundleService()
		self.assertEqual(sb.COMPLETE_HARD_BYTES, sb.DEFAULT_BUNDLE_LIMITS.maximumBytes)
		self.assertEqual(64 * 1024 * 1024, sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumBytes)
		self.assertNotEqual(sb.DEFAULT_BUNDLE_LIMITS, sb.LOCAL_SELECTED_BUNDLE_LIMITS)
		self.assertIsNotNone(service)

	def test_local_size_retry_preserves_prior_service_state_and_default_limits(self) -> None:
		service = BundleService()
		with TemporaryDirectory() as temporary:
			root = Path(temporary)
			firstDirectory = root / "first"
			firstDirectory.mkdir()
			for name, payload in sb.prepareBundle(_source(representativeCapture())).artifacts():
				_ = (firstDirectory / name).write_bytes(payload)
			first = service.openDirectory(firstDirectory)

			largeDirectory = root / "large"
			largeDirectory.mkdir()
			writeLocalRetryLimitFixture(largeDirectory)

			with self.assertRaises(sb.BundleAdmissionLimitExceeded):
				_ = service.openDirectory(largeDirectory)
			self.assertIs(service.admission, first)
			self.assertEqual(1, service.currentGeneration)
			self.assertEqual(sb.DEFAULT_BUNDLE_LIMITS, service.defaultLimits)

			retried = service.openDirectory(largeDirectory, limits=sb.LOCAL_SELECTED_BUNDLE_LIMITS)
			self.assertEqual(2, retried.sourceGeneration)
			self.assertEqual(sb.DEFAULT_BUNDLE_LIMITS, service.defaultLimits)
			cached = service.selectNode("n0")

			tooLargeDirectory = root / "too-large"
			tooLargeDirectory.mkdir()
			writeLocalRetryLimitFixture(tooLargeDirectory, overLocalRetryLimit=True)
			with self.assertRaises(sb.BundleAdmissionLimitExceeded):
				_ = service.openDirectory(
					tooLargeDirectory,
					limits=sb.LOCAL_SELECTED_BUNDLE_LIMITS,
				)
			self.assertIs(service.admission, retried)
			self.assertEqual(2, service.currentGeneration)
			self.assertIs(cached, service.selectNode("n0"))

	def test_selected_subtree_excludes_ancestors_and_siblings_and_reopens(self) -> None:
		snapshot = makeSnapshot(
			(
				makeNode("root", children=("selected", "sibling"), name="Root", role="window"),
				makeNode(
					"selected",
					parent="root",
					children=("descendant",),
					name="Selected",
					role="pane",
					index=0,
				),
				makeNode("descendant", parent="selected", name="Descendant", role="button", index=0),
				makeNode("sibling", parent="root", name="Sibling", role="button", index=1),
			),
		)
		source = sb.projectSnapshotTopics(
			snapshot,
			generatedAt="2026-07-24T09:08:07Z",
			executable="reader.exe",
			processId=42,
			redactionEnabled=True,
			policyRevision=1,
			settingsRevision=1,
			snapshotKind="snapshot",
		)
		with TemporaryDirectory() as temporary:
			root = Path(temporary)
			original = root / "original"
			original.mkdir()
			for name, payload in sb.prepareBundle(source).artifacts():
				_ = (original / name).write_bytes(payload)
			service = BundleService()
			_ = service.openDirectory(original)
			subtree = service.selectSubtree("n1")
			self.assertEqual(("n1",), subtree.package.index.rootIds)
			self.assertEqual(2, subtree.package.index.nodeCount)
			payload = subtree.toJsonBytes()
			self.assertNotIn(b'"n0"', payload)
			self.assertNotIn(b'"n3"', payload)
			exported = writePortableBundle(subtree.package, root / "selected-subtree")
			reopened = sb.BundleSnapshotView(exported)
			self.assertEqual(("n1",), reopened.captureRoots)
			self.assertEqual(["n1", "n2"], [node.key for node in reopened.captureNodes])


if __name__ == "__main__":
	_ = unittest.main()
