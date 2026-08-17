from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.domain import snapshot_bundle as sb
from addon.globalPlugins.keystone.domain.document_records import (
	NodeRecord,
	ProviderSectionRecord,
	ProviderSections,
)
from addon.globalPlugins.keystone.domain.documents import Snapshot
from addon.globalPlugins.keystone.domain.evidence import (
	ErrorReference,
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Source,
)
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState, EvidenceValue
from addon.globalPlugins.keystone.domain import inspector as inspectorDomain
from tests.fixtures.representative_capture import (
	EXPECTED_RECORD_COUNTS,
	PROTECTED_SAMPLE_SECRET,
	RepresentativeCapture,
	estimatedTokens,
	representativeCapture,
	topicBytes,
)
from tests.fixtures.compact_snapshot_shapes import (
	firefoxRelationshipAnnotations,
	powerPointCyclicRibbonAnnotation,
)
from tests.unit.test_diffing import makeEvidence, makeNode, makeSnapshot


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


def _writeBundle(directory: Path, package: sb.BundlePackage) -> None:
	for name, payload in package.artifacts():
		_ = (directory / name).write_bytes(payload)


def _redactSecret(value: str) -> str:
	return value.replace("secret", "[redacted]")


def _retainText(value: str) -> str:
	return value


_PACKAGE = sb.prepareBundle(_source(representativeCapture()))


class SnapshotBundleEncodingTests(unittest.TestCase):
	def test_local_selected_limits_expand_the_confirmed_large_snapshot_budget(self) -> None:
		self.assertEqual(64 * 1024 * 1024, sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumBytes)
		self.assertEqual(4_000_000, sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumStringScalars)
		self.assertEqual(4_000_000, sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumCollectionItems)
		self.assertEqual(
			sb.DEFAULT_BUNDLE_LIMITS.maximumDepth,
			sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumDepth,
		)
		self.assertEqual(
			sb.DEFAULT_BUNDLE_LIMITS.maximumNodes,
			sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumNodes,
		)
		self.assertNotEqual(
			sb.DEFAULT_BUNDLE_LIMITS.maximumStringScalars,
			sb.LOCAL_SELECTED_BUNDLE_LIMITS.maximumStringScalars,
		)

	def test_format_one_point_one_index_carries_closed_compact_tables(self) -> None:
		package = sb.prepareBundle(_source(representativeCapture()))

		self.assertEqual((1, 1), (package.index.formatMajor, package.index.formatMinor))
		self.assertIsInstance(package.index.sharedTables, sb.CompactSharedTables)
		self.assertIsInstance(package.index.uiaSchema, sb.CompactUiaSchema)
		self.assertEqual(
			package.index,
			sb.parseIndex(package.indexBytes),
		)

	def test_annotation_category_shortcuts_and_explicit_statuses(self) -> None:
		shortcut = cast(
			Callable[..., inspectorDomain.PropertyCategory],
			getattr(inspectorDomain, "propertyCategoryForShortcut"),
		)
		annotationCategory = getattr(inspectorDomain.PropertyCategory, "ANNOTATIONS")
		self.assertEqual(11, len(inspectorDomain.PROPERTY_CATEGORY_ORDER))
		self.assertIs(annotationCategory, inspectorDomain.PROPERTY_CATEGORY_ORDER[9])
		self.assertIs(
			inspectorDomain.PropertyCategory.DIAGNOSTICS,
			inspectorDomain.PROPERTY_CATEGORY_ORDER[10],
		)
		self.assertIs(annotationCategory, shortcut(0))
		self.assertIs(
			inspectorDomain.PropertyCategory.DIAGNOSTICS,
			shortcut(0, shift=True),
		)
		for digit, category in enumerate(inspectorDomain.PROPERTY_CATEGORY_ORDER[:9], start=1):
			self.assertIs(category, shortcut(digit))

		statusType = getattr(inspectorDomain, "AnnotationStatus")
		recordType = getattr(inspectorDomain, "AnnotationRecord")
		for statusName in ("NO_DATA", "UNSUPPORTED", "UNAVAILABLE", "STALE", "FAILED"):
			status = getattr(statusType, statusName)
			record = recordType(
				key=f"status-{status.value}",
				status=status,
				typeName="Annotations",
				source="NVDA",
			)
			self.assertIs(status, record.status)
			self.assertNotEqual("", record.typeName)
			self.assertNotEqual("", record.source)

	def test_semantics_topic_serializes_nested_privacy_transformed_annotations(self) -> None:
		writer = cast(
			Callable[..., sb.BundleTopicRecords],
			getattr(sb, "annotationTopicRecords"),
		)
		statusType = getattr(inspectorDomain, "AnnotationStatus")
		recordType = getattr(inspectorDomain, "AnnotationRecord")
		child = recordType(
			key="reply",
			status=statusType.VALUE,
			typeId="commentReply",
			typeName="Comment reply",
			source="UIA AnnotationObjects",
			summary="child secret",
			author="Reviewer",
			targetName="Submit",
			targetRole="button",
			targetIdentity="automationId=submit",
			relationship="replyTo",
		)
		parent = recordType(
			key="comment",
			status=statusType.VALUE,
			typeId="comment",
			typeName="Comment",
			source="NVDA annotations",
			summary="parent secret",
			author="Author",
			dateTime="2026-07-31T00:00:00Z",
			targetName="Form",
			targetRole="grouping",
			targetIdentity="ia2UniqueId=42",
			relationship="details",
			related=(child,),
		)
		topic = writer(
			{"n0": (parent,)},
			privacyTransform=_redactSecret,
		)
		self.assertEqual("semantics", topic.topic)
		base = _source(representativeCapture())
		source = replace(base, topics=(base.topics[0], topic))
		package = sb.prepareBundle(source)
		payloads = {name: payload for name, payload in package.artifacts()}
		self.assertIn("semantics.jsonl", payloads)
		self.assertNotIn(b"secret", payloads["semantics.jsonl"])
		self.assertEqual(
			payloads["semantics.jsonl"], dict(sb.prepareBundle(source).artifacts())["semantics.jsonl"]
		)

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			projected = sb.projectSelectedNode(admission, directory, "n0")
			semantics = dict(projected.records)["semantics"]
			annotations = cast(list[object], semantics["annotations"])
			self.assertEqual(1, len(annotations))

	def test_empty_annotation_collection_omits_semantics_topic(self) -> None:
		writer = cast(
			Callable[..., sb.BundleTopicRecords],
			getattr(sb, "annotationTopicRecords"),
		)
		topic = writer({}, privacyTransform=_retainText)
		self.assertEqual((), topic.records)
		source = replace(_source(representativeCapture()), topics=(topic,))
		package = sb.prepareBundle(source)
		self.assertIsNone(package.index.entry("semantics"))
		self.assertNotIn("semantics.jsonl", dict(package.artifacts()))

	def test_two_generations_serialise_to_byte_identical_artifacts(self) -> None:
		first = sb.prepareBundle(_source(representativeCapture()))
		second = sb.prepareBundle(_source(representativeCapture()))
		self.assertEqual(first.artifacts(), second.artifacts())

	def test_cooperative_preparation_preserves_artifacts(self) -> None:
		source = _source(representativeCapture())
		callbacks: list[None] = []

		cooperative = sb.prepareBundle(source, cooperate=lambda: callbacks.append(None))

		self.assertTrue(callbacks)
		self.assertEqual(sb.prepareBundle(source).artifacts(), cooperative.artifacts())

	def test_document_topic_serialization_cooperates_for_each_record(self) -> None:
		records = (
			sb.JsonObject((("id", "n0"), ("value", "first"))),
			sb.JsonObject((("id", "n1"), ("value", "second"))),
		)
		callbacks: list[None] = []

		payload, count = sb._serializeDocumentTopic(  # pyright: ignore[reportPrivateUsage]
			records,
			cooperate=lambda: callbacks.append(None),
		)

		self.assertEqual(2, count)
		self.assertEqual(b'{"id":"n0","value":"first"}\n{"id":"n1","value":"second"}\n', payload)
		self.assertEqual([None, None], callbacks)

	def test_topic_files_compact_the_deterministic_fixture_without_losing_topic_order(self) -> None:
		capture = representativeCapture()
		package = sb.prepareBundle(_source(capture))
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}
		self.assertEqual(
			tuple(topic for topic, _filename, _payload in package.topicFiles),
			tuple(topic.name for topic in capture.topics),
		)
		for topic in ("nodes", "uia", "patterns", "semantics", "screenshot", "captureConfiguration"):
			with self.subTest(topic=topic):
				self.assertTrue(payloads[topic].endswith(b"\n"))
				self.assertLessEqual(len(payloads[topic]), len(topicBytes(capture.topic(topic))))

	def test_index_round_trips_through_the_strict_parser(self) -> None:
		package = sb.prepareBundle(_source(representativeCapture()))
		parsed = sb.parseIndex(package.indexBytes)
		self.assertEqual(parsed, package.index)
		self.assertEqual(parsed.formatMajor, sb.BUNDLE_FORMAT_MAJOR)
		self.assertEqual(parsed.rootIds, ("n0",))
		self.assertEqual(parsed.nodeCount, EXPECTED_RECORD_COUNTS["nodes"])

	def test_publication_validation_returns_the_exact_artifact_order(self) -> None:
		package = sb.prepareBundle(_source(representativeCapture()))
		artifacts = package.artifacts()
		names = sb.validateBundleArtifacts(dict(artifacts))
		self.assertEqual(names, tuple(name for name, _payload in artifacts))
		self.assertEqual(names[0], sb.INDEX_FILENAME)

	def test_zero_record_topics_are_omitted_from_the_catalog(self) -> None:
		capture = representativeCapture()
		topics = tuple(
			sb.BundleTopicRecords(topic.name, () if topic.name == "jab" else topic.records)
			for topic in capture.topics
		)
		source = sb.BundleSource(
			snapshotKind="snapshot",
			generatedAt="2026-07-24T09:08:07Z",
			redactionEnabled=True,
			policyRevision=1,
			settingsRevision=1,
			executable="reader.exe",
			processId=42,
			rootIds=("n0",),
			topics=topics,
		)
		package = sb.prepareBundle(source)
		self.assertIsNone(package.index.entry("jab"))
		self.assertNotIn("jab.jsonl", [name for name, _payload in package.artifacts()])


class SnapshotBundleBenchmarkTests(unittest.TestCase):
	def test_token_estimate_matches_the_published_fixture_estimate(self) -> None:
		for byteLength in (0, 1, 3, 4, 5, 8239, 280309):
			with self.subTest(byteLength=byteLength):
				self.assertEqual(sb.estimateTokenCount(byteLength), estimatedTokens(byteLength))

	def test_index_stays_within_the_hard_and_target_budgets(self) -> None:
		indexBytes = _PACKAGE.indexByteLength
		self.assertLessEqual(indexBytes, sb.INDEX_HARD_BYTES)
		self.assertLessEqual(sb.estimateTokenCount(indexBytes), sb.INDEX_HARD_TOKENS)
		self.assertLessEqual(indexBytes, sb.INDEX_TARGET_BYTES)
		self.assertLessEqual(sb.estimateTokenCount(indexBytes), sb.INDEX_TARGET_TOKENS)

	def test_index_plus_nodes_stays_within_the_hard_budget(self) -> None:
		combined = _PACKAGE.indexByteLength + _PACKAGE.nodesByteLength
		self.assertGreater(_PACKAGE.nodesByteLength, 0)
		self.assertLessEqual(combined, sb.INDEX_NODES_HARD_BYTES)
		self.assertLessEqual(sb.estimateTokenCount(combined), sb.INDEX_NODES_HARD_TOKENS)

	def test_complete_non_image_bundle_stays_within_the_hard_and_target_budgets(self) -> None:
		total = _PACKAGE.nonImageByteLength
		self.assertLessEqual(total, sb.COMPLETE_HARD_BYTES)
		self.assertLessEqual(sb.estimateTokenCount(total), sb.COMPLETE_HARD_TOKENS)
		self.assertLessEqual(total, sb.COMPLETE_TARGET_BYTES)

	def test_admission_round_trips_every_expected_topic_count(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, _PACKAGE)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			counts = {entry.topic: entry.recordCount for entry in admission.index.catalog}
			self.assertEqual(counts, EXPECTED_RECORD_COUNTS)
			self.assertEqual(admission.totalByteLength, _PACKAGE.nonImageByteLength)

	def test_compression_or_deletion_cannot_satisfy_the_gate(self) -> None:
		# The complete-bundle byte gate must be met while every record survives the round trip,
		# so shrinking bytes by dropping records would fail the count assertion above.
		emitted = sum(entry.recordCount for entry in _PACKAGE.index.catalog)
		self.assertEqual(emitted, sum(EXPECTED_RECORD_COUNTS.values()))


class SnapshotBundleProjectionTests(unittest.TestCase):
	def _admit(self, directory: Path) -> sb.BundleAdmission:
		package = sb.prepareBundle(_source(representativeCapture()))
		_writeBundle(directory, package)
		return sb.admitBundle(directory, sourceGeneration=7)

	def test_selected_node_joins_only_its_present_topics(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			admission = self._admit(directory)
			projection = sb.projectSelectedNode(admission, directory, "n13")
			self.assertEqual([topic for topic, _record in projection.records], ["nodes", "uia", "semantics"])
			self.assertEqual(projection.sourceGeneration, 7)

	def test_redacted_protected_value_never_reaches_any_export(self) -> None:
		secret = PROTECTED_SAMPLE_SECRET.encode("utf-8")
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			admission = self._admit(directory)
			projection = sb.projectSelectedNode(admission, directory, "n13")
			self.assertNotIn(secret, projection.toJsonBytes())
			self.assertNotIn(PROTECTED_SAMPLE_SECRET, projection.toText())
			self.assertNotIn(PROTECTED_SAMPLE_SECRET, projection.toMarkdown())

	def test_projection_rejects_unknown_and_malformed_identifiers(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			admission = self._admit(directory)
			with self.assertRaises(ValueError):
				_ = sb.projectSelectedNode(admission, directory, "n999999")
			with self.assertRaises(ValueError):
				_ = sb.projectSelectedNode(admission, directory, "not-a-node")


def _withField(node: NodeRecord, name: str, envelope: EvidenceEnvelope) -> NodeRecord:
	fields = tuple(
		(fieldName, envelope if fieldName == name else current) for fieldName, current in node.fields
	)
	return replace(node, fields=fields)


def _failed(field: str) -> EvidenceEnvelope:
	return EvidenceEnvelope(
		EvidenceState.FAILED,
		Source("test", "ProjectionTests", field),
		Projection("normalNvda"),
		Confidence.INDETERMINATE,
		PrivacyReference("node", "public", "retain", 1),
		errorRef=ErrorReference("KS.PROVIDER.FAILED", f"diag-{field}"),
	)


def _empty(field: str) -> EvidenceEnvelope:
	return EvidenceEnvelope(
		EvidenceState.EMPTY,
		Source("test", "ProjectionTests", field),
		Projection("normalNvda"),
		Confidence.DIRECT,
		PrivacyReference("node", "public", "retain", 1),
	)


class SnapshotViewProjectionTests(unittest.TestCase):
	def test_uia_defaults_and_node_exception_round_trip_through_the_typed_view(self) -> None:
		root = makeNode(
			"root",
			children=("child",),
			name="Root",
			role="window",
			automationId="root-1",
		)
		child = makeNode("child", parent="root", name="Child", role="button", automationId="child-1")
		snapshot = makeSnapshot((root, child))
		package = sb.prepareBundle(self._project(snapshot))
		self.assertEqual(("status", "identity", "properties"), package.index.uiaSchema.columns)
		self.assertEqual(3, len(package.index.uiaDefaults))
		uiaPayload = dict((topic, payload) for topic, _filename, payload in package.topicFiles)["uia"]
		self.assertIn(b'"exceptions"', uiaPayload)
		self.assertNotIn(b'"status"', uiaPayload)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			selected = dict(sb.projectSelectedNode(admission, directory, "n1").records)["uia"]
			self.assertEqual({"id", "status", "identity", "properties"}, set(selected))
			view = sb.BundleSnapshotView(directory)
			restored = {node.key: node for node in view.captureNodes}

			self.assertEqual(root.providers.items, restored["n0"].providers.items)
			self.assertEqual(child.providers.items, restored["n1"].providers.items)

	def test_compact_defaults_are_parsed_once_and_exceptions_remain_strict(self) -> None:
		root = makeNode("root", children=("first", "second"), name="Root")
		first = makeNode("first", parent="root", name="First", index=0)
		second = makeNode("second", parent="root", name="Second", index=1)
		package = sb.prepareBundle(self._project(makeSnapshot((root, first, second))))
		expectedDefaultValidations = sum(len(schema.defaults) for schema in package.index.compactDefaults)
		defaultValidations = 0
		originalValidator = sb._validateCompactDefaultValue  # pyright: ignore[reportPrivateUsage]

		def countDefaultValidations(
			value: object,
			schema: sb.CompactDefaultsSchema,
			index: sb.BundleIndex,
		) -> None:
			nonlocal defaultValidations
			if any(value is default for default in schema.defaults):
				defaultValidations += 1
			originalValidator(value, schema, index)

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			with patch.object(sb, "_validateCompactDefaultValue", side_effect=countDefaultValidations):
				_ = sb.admitBundle(directory, sourceGeneration=1)

		self.assertEqual(expectedDefaultValidations, defaultValidations)

		malformedIndex = cast(dict[str, object], json.loads(package.indexBytes))
		schemas = cast(list[object], malformedIndex["compactDefaults"])
		firstSchema = cast(dict[str, object], schemas[0])
		defaults = cast(list[object], firstSchema["defaults"])
		defaults[0] = {}
		malformedIndexBytes = (
			json.dumps(malformedIndex, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n"
		).encode("utf-8")
		with self.assertRaisesRegex(ValueError, "compact default value"):
			_ = sb.parseIndex(malformedIndexBytes)

		nodesEntry = next(entry for entry in package.index.catalog if entry.topic == "nodes")
		nodesPayload = dict((topic, payload) for topic, _filename, payload in package.topicFiles)["nodes"]
		nodeRecords = [
			cast(dict[str, object], json.loads(line)) for line in nodesPayload.decode("utf-8").splitlines()
		]
		exceptionRecord = next(
			record for record in nodeRecords if cast(dict[str, object], record["fields"])["exceptions"]
		)
		exceptions = cast(
			list[list[object]], cast(dict[str, object], exceptionRecord["fields"])["exceptions"]
		)
		exceptions[0][0] = len(
			next(schema for schema in package.index.compactDefaults if schema.topic == "nodes").columns
		)
		malformedNodesPayload = (
			b"\n".join(
				json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
				for record in nodeRecords
			)
			+ b"\n"
		)
		malformedNodesEntry = replace(
			nodesEntry,
			byteLength=len(malformedNodesPayload),
			sha256=hashlib.sha256(malformedNodesPayload).hexdigest(),
		)
		malformedBundleIndex = replace(
			package.index,
			catalog=tuple(
				malformedNodesEntry if entry.topic == "nodes" else entry for entry in package.index.catalog
			),
		)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			_ = (directory / nodesEntry.filename).write_bytes(malformedNodesPayload)
			_ = (directory / sb.INDEX_FILENAME).write_bytes(malformedBundleIndex.encode())
			with self.assertRaisesRegex(ValueError, "compact core fields exception columns"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_format_one_zero_bundle_without_default_schemas_remains_readable(self) -> None:
		ia2 = ProviderSectionRecord(
			makeEvidence("available", field="ia2.status"),
			makeEvidence("ia2", field="ia2.identity"),
			makeEvidence(("legacy",), field="ia2.properties"),
		)
		overlay = ProviderSectionRecord(
			makeEvidence("available", field="overlay.status"),
			makeEvidence("overlay", field="overlay.identity"),
			makeEvidence(("legacy",), field="overlay.properties"),
		)
		root = makeNode("root", name="Legacy", role="window", automationId="legacy-id")
		root = replace(
			root,
			providers=ProviderSections(
				tuple(
					(
						name,
						ia2 if name == "ia2Msaa" else overlay if name == "overlay" else section,
					)
					for name, section in root.providers.items
				),
			),
		)
		snapshot = makeSnapshot((root,))
		package = sb.prepareBundle(self._project(snapshot))
		topicFiles: list[tuple[str, str, bytes]] = []
		catalog: list[sb.BundleCatalogEntry] = []
		for topic, filename, payload in package.topicFiles:
			records = [
				cast(dict[str, object], json.loads(line)) for line in payload.decode("utf-8").splitlines()
			]
			if topic == "nodes":
				records = [
					sb._expandCompactCoreRecord(record, package.index)  # pyright: ignore[reportPrivateUsage]
					for record in records
				]
			elif (
				sb._compactDefaultsForTopic(  # pyright: ignore[reportPrivateUsage]
					package.index,
					topic,
				)
				is not None
			):
				records = [
					sb._expandCompactDefaultRecord(  # pyright: ignore[reportPrivateUsage]
						record,
						package.index,
						topic,
					)
					for record in records
				]
			serializable = tuple(
				sb._fromPlainObject(record)  # pyright: ignore[reportPrivateUsage]
				for record in records
			)
			legacyPayload, count = (
				sb._serializeNodeTopic(serializable)  # pyright: ignore[reportPrivateUsage]
				if topic in sb.NODE_TOPICS
				else sb._serializeDocumentTopic(serializable)  # pyright: ignore[reportPrivateUsage]
			)
			topicFiles.append((topic, filename, legacyPayload))
			catalog.append(
				sb.BundleCatalogEntry(
					topic,
					filename,
					count,
					len(legacyPayload),
					hashlib.sha256(legacyPayload).hexdigest(),
				),
			)
		legacyIndex = replace(
			package.index,
			formatMinor=0,
			catalog=tuple(catalog),
			compactDefaults=(),
		)
		legacy = sb.BundlePackage(
			legacyIndex,
			legacyIndex.encode(),
			tuple(topicFiles),
			package.screenshotImage,
		)

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, legacy)
			view = sb.BundleSnapshotView(directory)
			restoredProviders = view.captureNodes[0].providers

		self.assertEqual(0, view.index.formatMinor)
		self.assertEqual(snapshot.captureNodes[0].field("name"), view.captureNodes[0].field("name"))
		self.assertEqual(snapshot.captureNodes[0].providers, restoredProviders)

	def test_core_defaults_preserve_envelopes_and_mark_an_absent_exception(self) -> None:
		nodes = tuple(
			makeNode(
				f"node-{index}",
				name="Repeated",
				role="button",
				automationId="same-id",
			)
			for index in range(3)
		)
		source = self._project(makeSnapshot(nodes))
		rewrittenTopics: list[sb.BundleTopicRecords] = []
		for topic in source.topics:
			if topic.topic != "nodes":
				rewrittenTopics.append(topic)
				continue
			records: list[sb.JsonObject] = []
			for record in topic.records:
				plain = sb._plainObject(record)  # pyright: ignore[reportPrivateUsage]
				if plain["id"] == "n2":
					_ = cast(dict[str, object], plain["fields"]).pop("windowControlId")
				records.append(sb._fromPlainObject(plain))  # pyright: ignore[reportPrivateUsage]
			rewrittenTopics.append(sb.BundleTopicRecords("nodes", tuple(records)))
		package = sb.prepareBundle(replace(source, topics=tuple(rewrittenTopics)))
		schema = next(schema for schema in package.index.compactDefaults if schema.topic == "nodes")
		windowControlColumn = schema.columns.index("windowControlId")
		nodesPayload = dict((topic, payload) for topic, _filename, payload in package.topicFiles)["nodes"]

		self.assertNotEqual({"absent": True}, schema.defaults[windowControlColumn])
		self.assertIn(b'{"absent":true}', nodesPayload)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			view = sb.BundleSnapshotView(directory)
		restored = {node.key: node for node in view.captureNodes}
		self.assertEqual(nodes[0].field("name"), restored["n0"].field("name"))
		self.assertEqual(nodes[1].field("stableIds"), restored["n1"].field("stableIds"))
		self.assertIs(EvidenceState.NOT_APPLICABLE, restored["n2"].field("windowControlId").status)

	def test_ia2_and_overlay_defaults_round_trip_lazily_with_exceptions(self) -> None:
		nodes: list[NodeRecord] = []
		for index in range(3):
			ia2 = ProviderSectionRecord(
				makeEvidence("available", field="ia2.status"),
				makeEvidence("ia2", field="ia2.identity"),
				makeEvidence(("shared", index == 2), field="ia2.properties"),
			)
			overlay = ProviderSectionRecord(
				makeEvidence("available", field="overlay.status"),
				makeEvidence("overlay", field="overlay.identity"),
				makeEvidence(("shared", index == 2), field="overlay.properties"),
			)
			node = makeNode(f"node-{index}", name="Repeated", role="button", automationId="same-id")
			nodes.append(
				replace(
					node,
					providers=ProviderSections(
						tuple(
							(
								name,
								ia2 if name == "ia2Msaa" else overlay if name == "overlay" else section,
							)
							for name, section in node.providers.items
						),
					),
				),
			)
		snapshot = makeSnapshot(tuple(nodes))
		package = sb.prepareBundle(self._project(snapshot))
		schemas = {schema.topic: schema for schema in package.index.compactDefaults}
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}

		self.assertEqual(("status", "identity", "properties"), schemas["ia2Msaa"].columns)
		self.assertEqual(("status", "identity", "properties"), schemas["overlay"].columns)
		self.assertIn(b'"exceptions"', payloads["ia2Msaa"])
		self.assertIn(b'"exceptions"', payloads["overlay"])
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			view = sb.BundleSnapshotView(directory)
			self.assertEqual(0, view.deepOpens)
			restored = {node.key: node for node in view.captureNodes}
			self.assertEqual(nodes[2].providers.items, restored["n2"].providers.items)
			self.assertGreater(view.deepOpens, 0)

	def test_core_default_compaction_is_deterministic_and_reduces_node_bytes(self) -> None:
		snapshot = makeSnapshot(
			tuple(
				makeNode(f"node-{index}", name="Repeated", role="button", automationId="same-id")
				for index in range(24)
			),
		)
		source = self._project(snapshot)
		first = sb.prepareBundle(source)
		second = sb.prepareBundle(source)
		rawNodes = next(topic.records for topic in source.topics if topic.topic == "nodes")
		rawPayload, _ = sb._serializeNodeTopic(rawNodes)  # pyright: ignore[reportPrivateUsage]
		nodesPayload = dict((topic, payload) for topic, _filename, payload in first.topicFiles)["nodes"]

		self.assertEqual(first.artifacts(), second.artifacts())
		self.assertLess(len(nodesPayload), len(rawPayload) // 2)

	def _project(
		self,
		snapshot: Snapshot,
		*,
		captureConfiguration: Mapping[str, object] | None = None,
		screenshot: Mapping[str, object] | None = None,
		screenshotImage: bytes | None = None,
	) -> sb.BundleSource:
		return sb.projectSnapshotTopics(
			snapshot,
			generatedAt="2026-07-24T09:08:07Z",
			executable="reader.exe",
			processId=42,
			redactionEnabled=True,
			policyRevision=1,
			settingsRevision=1,
			snapshotKind="snapshot",
			captureConfiguration=captureConfiguration,
			screenshot=screenshot,
			screenshotImage=screenshotImage,
		)

	def _reconstruct(self, directory: Path, snapshot: Snapshot) -> sb.BundleSnapshotView:
		package = sb.prepareBundle(self._project(snapshot))
		for name, payload in package.artifacts():
			_ = (directory / name).write_bytes(payload)
		return sb.BundleSnapshotView(directory)

	def _twoNodeSnapshot(self) -> Snapshot:
		root = makeNode(
			"root",
			children=("child",),
			name="Root Window",
			role="window",
			automationId="root-1",
		)
		child = makeNode("child", parent="root", name="Child Button", role="button", automationId="child-9")
		return makeSnapshot((root, child))

	def test_present_fields_structure_and_providers_reconstruct_losslessly(self) -> None:
		snapshot = self._twoNodeSnapshot()
		root, child = snapshot.captureNodes
		with TemporaryDirectory() as temporary:
			view = self._reconstruct(Path(temporary), snapshot)
			self.assertEqual(view.captureRoots, ("n0",))
			restored = {node.key: node for node in view.captureNodes}
			self.assertEqual(set(restored), {"n0", "n1"})
			restoredRoot = restored["n0"]
			self.assertEqual(restoredRoot.structure.childKeys, ("n1",))
			self.assertIsNone(restoredRoot.structure.parentKey)
			self.assertEqual(restored["n1"].structure.parentKey, "n0")
			self.assertEqual(restoredRoot.field("name"), root.field("name"))
			self.assertEqual(restoredRoot.field("role"), root.field("role"))
			self.assertEqual(restoredRoot.field("stableIds"), root.field("stableIds"))
			self.assertEqual(restored["n1"].field("name"), child.field("name"))
			for name, envelope in root.fields:
				if name not in (
					"annotations",
					"children",
					"developerInformation",
					"apiDetails",
					"diagnostics",
				):
					with self.subTest(field=name):
						self.assertEqual(envelope, restoredRoot.field(name))
			self.assertEqual(restoredRoot.providers, root.providers)
			self.assertEqual(restored["n1"].providers, child.providers)

	def test_not_applicable_fields_compact_without_losing_their_envelopes(self) -> None:
		snapshot = self._twoNodeSnapshot()
		package = sb.prepareBundle(self._project(snapshot))
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}
		self.assertIn(b'"exceptions"', payloads["nodes"])
		self.assertNotIn(b'"placeholder"', payloads["nodes"])
		with TemporaryDirectory() as temporary:
			view = self._reconstruct(Path(temporary), snapshot)
			restored = {node.key: node for node in view.captureNodes}
			original = {node.key: node for node in snapshot.captureNodes}
			self.assertEqual(original["root"].field("placeholder"), restored["n0"].field("placeholder"))
			self.assertEqual(original["root"].field("landmark"), restored["n0"].field("landmark"))

	def test_all_clear_traversal_flags_are_omitted_and_reconstructed(self) -> None:
		snapshot = self._twoNodeSnapshot()
		package = sb.prepareBundle(self._project(snapshot))
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}

		self.assertNotIn(b'"flags"', payloads["nodes"])
		with TemporaryDirectory() as temporary:
			view = self._reconstruct(Path(temporary), snapshot)

		self.assertFalse(view.captureNodes[0].structure.cycleDetected)
		self.assertFalse(view.captureNodes[0].structure.truncated)
		self.assertFalse(view.captureNodes[0].structure.childFetchFailed)

	def test_normal_projection_excludes_developer_data_and_canonical_uia_absence(self) -> None:
		root = _withField(
			makeNode("root", name="Root", role="window", automationId="root-1"),
			"developerInformation",
			makeEvidence("private developer diagnostics", field="developerInformation"),
		)
		uiaProperties = (
			("propertyInventory", ("value", 99, "", False)),
			("Name", ("value", "Save", "", False)),
			("ControlType", ("unsupported", "", "", False)),
			("HelpText", ("failed", "", "KS.UIA.READ_FAILED", False)),
			("patternInventory", ("value", 12, "", False)),
		)
		uia = ProviderSectionRecord(
			makeEvidence("available", field="uiaStatus"),
			makeEvidence("uia", field="uiaIdentity"),
			makeEvidence(uiaProperties, field="uiaProperties"),
		)
		generic = ProviderSectionRecord(
			makeEvidence("available", field="genericStatus"),
			makeEvidence("generic", field="genericIdentity"),
			makeEvidence(
				(
					("developerInformation", ("value", "developer detail", "", False)),
					("namedActions", ("unsupported", "", "", False)),
				),
				field="genericProperties",
			),
		)
		custom = ProviderSectionRecord(
			makeEvidence("available", field="customStatus"),
			makeEvidence(
				(("known.sample.reading-mode.identity", ("value", "definition", "", False)),),
				field="customIdentity",
			),
			makeEvidence(
				(
					("potentialProperties", ("value", "discovery", "", False)),
					(
						"known.sample.reading-mode.registration",
						("value", "registration inventory", "", False),
					),
					("known.sample.reading-mode.current", ("value", "current", "", False)),
				),
				field="customProperties",
			),
		)
		root = replace(
			root,
			providers=ProviderSections(
				tuple(
					(
						name,
						uia
						if name == "uia"
						else generic
						if name == "generic"
						else custom
						if name == "customUia"
						else section,
					)
					for name, section in root.providers.items
				),
			),
		)
		package = sb.prepareBundle(self._project(makeSnapshot((root,))))
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}

		self.assertNotIn(b"developerInformation", payloads["nodes"])
		self.assertNotIn(b"private developer diagnostics", payloads["nodes"])
		self.assertNotIn(b"developer detail", payloads["nodes"])
		self.assertNotIn(b"propertyInventory", payloads["uia"])
		self.assertNotIn(b"patternInventory", payloads["uia"])
		self.assertNotIn(b"ControlType", payloads["uia"])
		self.assertNotIn(b"potentialProperties", payloads["customUia"])
		self.assertNotIn(b"registration inventory", payloads["customUia"])
		self.assertIn(b"known.sample.reading-mode.current", payloads["customUia"])
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			selected = dict(sb.projectSelectedNode(admission, directory, "n0").records)["uia"]
			properties = cast(dict[str, object], selected["properties"])
			values = cast(list[list[object]], properties["value"])

		self.assertEqual(("Name", "HelpText"), tuple(value[0] for value in values))
		statuses: list[object] = []
		for value in values:
			result = value[1]
			self.assertIsInstance(result, list)
			statuses.append(cast(list[object], result)[0])
		self.assertEqual(("value", "failed"), tuple(statuses))

	def test_powerpoint_shaped_normal_capture_admits_within_the_default_budget(self) -> None:
		unsupported = tuple(
			(f"InstalledProperty{index}", ("unsupported", "", "", False)) for index in range(166)
		)
		retained = (
			("Name", ("value", "Slide canvas", "", False)),
			("ControlType", ("value", "document", "", False)),
			("HelpText", ("empty", "", "", False)),
			("TextRange", ("failed", "", "KS.UIA.TEXT_UNAVAILABLE", False)),
		)
		uia = ProviderSectionRecord(
			makeEvidence("available", field="uiaStatus"),
			makeEvidence("uia", field="uiaIdentity"),
			makeEvidence((*unsupported, *retained), field="uiaProperties"),
		)
		nodes: list[NodeRecord] = []
		for index in range(363):
			node = makeNode(
				f"node-{index}",
				name=f"PowerPoint object {index}",
				role="pane",
				automationId=f"slide-{index}",
			)
			node = _withField(
				node,
				"developerInformation",
				makeEvidence("developer trace " * 128, field="developerInformation"),
			)
			nodes.append(
				replace(
					node,
					providers=ProviderSections(
						tuple(
							(name, uia if name == "uia" else section)
							for name, section in node.providers.items
						),
					),
				),
			)
		package = sb.prepareBundle(self._project(makeSnapshot(tuple(nodes))))

		self.assertLessEqual(package.nonImageByteLength, sb.COMPLETE_HARD_BYTES)
		self.assertNotIn(b"developer trace", dict(package.artifacts())["nodes.jsonl"])
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			admission = sb.admitBundle(directory, sourceGeneration=1)

		self.assertLessEqual(admission.totalByteLength, sb.COMPLETE_HARD_BYTES)

	def test_exceptional_empty_failed_and_zero_values_survive_projection(self) -> None:
		root = makeNode("root", name="Root", role="window", automationId="root-1", controlId=0)
		root = _withField(root, "value", _empty("value"))
		root = _withField(root, "description", _failed("description"))
		snapshot = makeSnapshot((root,))
		with TemporaryDirectory() as temporary:
			view = self._reconstruct(Path(temporary), snapshot)
			(restored,) = view.captureNodes
			self.assertEqual(restored.field("value"), _empty("value"))
			self.assertEqual(restored.field("description"), _failed("description"))
			windowControlId = restored.field("windowControlId")
			self.assertIs(windowControlId.status, EvidenceState.VALUE)
			self.assertEqual(windowControlId.value, 0)

	def test_scan_plan_is_recorded_once_and_never_in_a_node_topic(self) -> None:
		snapshot = self._twoNodeSnapshot()
		configuration = {
			"maximumDepth": 32,
			sb.INSTALLED_SCAN_PLAN_FIELD: {"uiaPropertyCount": 42, "cacheRequest": "reuseCurrent"},
		}
		package = sb.prepareBundle(self._project(snapshot, captureConfiguration=configuration))
		payloads = {topic: payload for topic, _filename, payload in package.topicFiles}
		needle = sb.INSTALLED_SCAN_PLAN_FIELD.encode("utf-8")
		for topic in sb.NODE_TOPICS:
			if topic in payloads:
				with self.subTest(topic=topic):
					self.assertNotIn(needle, payloads[topic])
		self.assertIn(needle, payloads["captureConfiguration"])

	def test_deep_provider_topics_open_only_when_providers_are_read(self) -> None:
		snapshot = self._twoNodeSnapshot()
		with TemporaryDirectory() as temporary:
			view = self._reconstruct(Path(temporary), snapshot)
			nodes = view.captureNodes
			for node in nodes:
				_ = node.structure.childKeys
				_ = node.field("name")
			self.assertEqual(view.deepOpens, 0)
			_ = nodes[0].providers
			self.assertGreater(view.deepOpens, 0)
			self.assertEqual(view.openHandles, 0)

	def test_snapshot_annotations_publish_once_and_reconstruct_for_offline_inspection(self) -> None:
		record = inspectorDomain.AnnotationRecord(
			key="comment",
			status=inspectorDomain.AnnotationStatus.VALUE,
			typeId="comment",
			typeName="Comment",
			source="NVDA annotations",
			summary="Review this field",
			targetName="Root",
			targetRole="window",
			targetIdentity="captured node root",
			targetNodeId="root",
			targetIdentityProven=True,
			relationship="details",
		)
		root = makeNode("root", name="Root", role="window", automationId="root-1")
		root = _withField(
			root,
			"annotations",
			EvidenceEnvelope(
				EvidenceState.VALUE,
				Source("nvdaSelected", "CaptureService", "annotations"),
				Projection("normalNvda"),
				Confidence.DIRECT,
				PrivacyReference("relation", "public", "retain", 1),
				cast(EvidenceValue, inspectorDomain.annotationRecordsPlain((record,))),
			),
		)
		snapshot = makeSnapshot((root,))
		package = sb.prepareBundle(self._project(snapshot))
		payloads = dict(package.artifacts())

		self.assertIn("semantics.jsonl", payloads)
		self.assertNotIn(b'"annotations"', payloads["nodes.jsonl"])
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			view = sb.BundleSnapshotView(directory)
			(restored,) = view.annotations("n0")
			self.assertEqual("Review this field", restored.summary)
			self.assertEqual("n0", restored.targetNodeId)
			self.assertTrue(restored.canNavigate)

	def test_no_data_annotation_state_round_trips_through_semantics(self) -> None:
		record = inspectorDomain.AnnotationRecord(
			key="annotations-status",
			status=inspectorDomain.AnnotationStatus.NO_DATA,
			typeName="Annotations",
			source="NVDA",
		)
		root = makeNode("root", name="Root", role="window", automationId="root-1")
		root = _withField(
			root,
			"annotations",
			EvidenceEnvelope(
				EvidenceState.VALUE,
				Source("nvdaSelected", "CaptureService", "annotations"),
				Projection("normalNvda"),
				Confidence.DIRECT,
				PrivacyReference("relation", "public", "retain", 1),
				cast(EvidenceValue, inspectorDomain.annotationRecordsPlain((record,))),
			),
		)
		package = sb.prepareBundle(self._project(makeSnapshot((root,))))
		self.assertIn("semantics.jsonl", dict(package.artifacts()))

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			(restored,) = sb.BundleSnapshotView(directory).annotations("n0")

		self.assertIs(inspectorDomain.AnnotationStatus.NO_DATA, restored.status)

	def test_failed_annotation_round_trips_safe_error_identity_and_selected_export(self) -> None:
		record = powerPointCyclicRibbonAnnotation()
		root = makeNode("root", name="Ribbon", role="toolbar", automationId="ribbon-1")
		root = _withField(
			root,
			"annotations",
			EvidenceEnvelope(
				EvidenceState.VALUE,
				Source("nvdaSelected", "CaptureService", "annotations"),
				Projection("normalNvda"),
				Confidence.DIRECT,
				PrivacyReference("relation", "public", "retain", 1),
				cast(EvidenceValue, inspectorDomain.annotationRecordsPlain((record,))),
			),
		)
		package = sb.prepareBundle(self._project(makeSnapshot((root,))))
		payloads = dict(package.artifacts())
		semantics = payloads["semantics.jsonl"]
		self.assertIn(b"KS.ANNOTATION.CONVERSION_FAILED", semantics)
		self.assertIn(b"annotation-conversion-powerpoint-cyclic-ribbon", semantics)
		self.assertNotIn(b"com_error", semantics)
		self.assertNotIn(b"Traceback", semantics)

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			view = sb.BundleSnapshotView(directory)
			(restored,) = view.annotations("n0")
			selected = sb.projectSelectedNode(
				sb.admitBundle(directory, sourceGeneration=1),
				directory,
				"n0",
			).toJsonBytes()

		self.assertIs(inspectorDomain.AnnotationStatus.FAILED, restored.status)
		self.assertEqual(record.errorRef, restored.errorRef)
		self.assertIn(b"KS.ANNOTATION.CONVERSION_FAILED", selected)
		self.assertIn(b"annotation-conversion-powerpoint-cyclic-ribbon", selected)

	def test_firefox_relationship_fixture_reconstructs_as_nested_typed_annotations(self) -> None:
		root = makeNode("root", name="Firefox content", role="document", automationId="firefox-1")
		root = _withField(
			root,
			"annotations",
			EvidenceEnvelope(
				EvidenceState.VALUE,
				Source("ia2Msaa", "CaptureService", "annotations"),
				Projection("normalNvda"),
				Confidence.DIRECT,
				PrivacyReference("relation", "public", "retain", 1),
				cast(EvidenceValue, inspectorDomain.annotationRecordsPlain(firefoxRelationshipAnnotations())),
			),
		)
		package = sb.prepareBundle(self._project(makeSnapshot((root,))))

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeBundle(directory, package)
			(restored,) = sb.BundleSnapshotView(directory).annotations("n0")

		self.assertEqual("labelledBy", restored.relationship)
		self.assertEqual("Firefox relationship evidence", restored.summary)
		self.assertEqual("Relationship target", restored.related[0].targetName)

	def test_semantics_publication_rejects_nested_key_collisions(self) -> None:
		child = inspectorDomain.AnnotationRecord(
			key="duplicate",
			status=inspectorDomain.AnnotationStatus.VALUE,
			typeName="Child",
			source="NVDA",
			summary="child",
		)
		records = (
			inspectorDomain.AnnotationRecord(
				key="first",
				status=inspectorDomain.AnnotationStatus.VALUE,
				typeName="Parent",
				source="NVDA",
				related=(child,),
			),
			inspectorDomain.AnnotationRecord(
				key="second",
				status=inspectorDomain.AnnotationStatus.VALUE,
				typeName="Parent",
				source="NVDA",
				related=(child,),
			),
		)

		with self.assertRaisesRegex(ValueError, "unique"):
			_ = sb.annotationTopicRecords({"n0": records}, privacyTransform=str)


if __name__ == "__main__":
	_ = unittest.main()
