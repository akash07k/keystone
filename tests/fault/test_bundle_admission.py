from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from typing import Never, cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.domain import snapshot_bundle as sb
from addon.globalPlugins.keystone.domain.document_records import JsonArray, JsonObject, JsonValue


def _core(
	nodeId: str,
	parent: str | None,
	depth: int,
	childCount: int,
	*,
	children: tuple[str, ...] | None = (),
	indexInParent: int = 0,
) -> JsonObject:
	items: list[tuple[str, JsonValue]] = [
		("id", nodeId),
		("parent", parent),
		("depth", depth),
		("indexInParent", indexInParent),
		("childCount", childCount),
		("role", "button"),
		("name", "Item"),
	]
	if children is not None:
		items.append(("children", JsonArray(children)))
	return JsonObject(tuple(items))


def _nodesSource(count: int = 3, *, document: bool = False) -> sb.BundleSource:
	records = [_core("n0", None, 0, count - 1, children=tuple(f"n{index}" for index in range(1, count)))]
	for index in range(1, count):
		records.append(_core(f"n{index}", "n0", 1, 0, indexInParent=index - 1))
	topics = [sb.BundleTopicRecords("nodes", tuple(records))]
	if document:
		shot = JsonObject((("width", 1280), ("height", 720)))
		topics.append(sb.BundleTopicRecords("screenshot", (shot, shot)))
	return sb.BundleSource(
		snapshotKind="snapshot",
		generatedAt="2026-07-24T09:08:07Z",
		redactionEnabled=True,
		policyRevision=1,
		settingsRevision=1,
		executable="reader.exe",
		processId=42,
		rootIds=("n0",),
		topics=tuple(topics),
	)


class _NoValuesCoreChildren(dict[str, tuple[str, ...]]):
	@override
	def values(self) -> Never:
		raise AssertionError("subtree projection must not scan every admitted parent")


def _deepNodesSource(depth: int, *, implicitChildren: bool = False) -> sb.BundleSource:
	records = tuple(
		_core(
			f"n{index}",
			None if index == 0 else f"n{index - 1}",
			index,
			1 if index + 1 < depth else 0,
			children=None if implicitChildren else (f"n{index + 1}",) if index + 1 < depth else (),
		)
		for index in range(depth)
	)
	return sb.BundleSource(
		snapshotKind="snapshot",
		generatedAt="2026-07-24T09:08:07Z",
		redactionEnabled=True,
		policyRevision=1,
		settingsRevision=1,
		executable="reader.exe",
		processId=42,
		rootIds=("n0",),
		topics=(sb.BundleTopicRecords("nodes", records),),
	)


def _writeValid(directory: Path, *, count: int = 3, document: bool = False) -> None:
	package = sb.prepareBundle(_nodesSource(count, document=document))
	for name, payload in package.artifacts():
		_ = (directory / name).write_bytes(payload)


def _readIndex(directory: Path) -> dict[str, object]:
	return cast("dict[str, object]", json.loads((directory / "index.json").read_bytes().decode("utf-8")))


def _writeIndex(directory: Path, data: dict[str, object]) -> None:
	text = json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
	_ = (directory / "index.json").write_bytes(text.encode("utf-8"))


def _rewriteTopic(directory: Path, data: dict[str, object], topic: str, records: Sequence[object]) -> None:
	payload = b"".join(
		(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
		for record in records
	)
	entry = _catalogEntry(data, topic)
	entry["recordCount"] = len(records)
	entry["byteLength"] = len(payload)
	entry["sha256"] = hashlib.sha256(payload).hexdigest()
	_ = (directory / str(entry["filename"])).write_bytes(payload)
	_writeIndex(directory, data)


def _nodeRecords(directory: Path) -> list[dict[str, object]]:
	return [
		cast("dict[str, object]", json.loads(line))
		for line in (directory / "nodes.jsonl").read_text(encoding="utf-8").splitlines()
	]


def _catalogEntry(data: dict[str, object], topic: str) -> dict[str, object]:
	for entry in cast("list[dict[str, object]]", data["catalog"]):
		if entry["topic"] == topic:
			return entry
	raise AssertionError(f"missing catalog entry for {topic}")


class BundleAdmissionFaultTests(unittest.TestCase):
	def test_admits_a_wellformed_bundle(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			self.assertEqual(admission.nodeIds(), ("n0", "n1", "n2"))
			self.assertEqual(admission.sourceGeneration, 1)

	def test_rejects_a_root_that_does_not_resolve_to_a_core_node(self) -> None:
		self._assertIndexRejected(lambda data: data.__setitem__("rootIds", ["n999"]))

	def test_rejects_a_root_that_has_a_parent(self) -> None:
		self._assertIndexRejected(lambda data: data.__setitem__("rootIds", ["n1"]))

	def test_rejects_a_node_topic_identifier_without_a_core_node(self) -> None:
		base = _nodesSource(1)
		source = replace(
			base,
			topics=(
				*base.topics,
				sb.BundleTopicRecords(
					"semantics",
					(JsonObject((("id", "n1"), ("annotations", JsonArray(())))),),
				),
			),
		)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in sb.prepareBundle(source).artifacts():
				_ = (directory / name).write_bytes(payload)

			with self.assertRaisesRegex(ValueError, "does not resolve to a core node"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_parent_and_child_disagreement(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			records[1]["parent"] = None
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "parent and children"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_multiple_parent_claims_for_one_child(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			records[1]["children"] = ["n2"]
			records[1]["childCount"] = 1
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "multiple structural parents"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_cycle_in_the_core_node_structure(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			records[0]["parent"] = "n2"
			records[0]["children"] = ["n1"]
			records[0]["childCount"] = 1
			records[1]["children"] = ["n2"]
			records[1]["childCount"] = 1
			records[2]["parent"] = "n1"
			records[2]["children"] = ["n0"]
			records[2]["childCount"] = 1
			records[2]["indexInParent"] = 0
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "contains a cycle"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_admits_maximum_distinct_nodes_across_node_keyed_topics(self) -> None:
		base = _nodesSource()
		source = replace(
			base,
			topics=(
				*base.topics,
				sb.BundleTopicRecords(
					"semantics",
					tuple(JsonObject((("id", f"n{index}"),)) for index in range(3)),
				),
			),
		)
		package = sb.prepareBundle(source)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in package.artifacts():
				_ = (directory / name).write_bytes(payload)

			admission = sb.admitBundle(
				directory,
				sourceGeneration=1,
				limits=sb.BundleAdmissionLimits(maximumNodes=3),
			)

		self.assertEqual(("n0", "n1", "n2"), admission.nodeIds())

	def test_rejects_deep_untrusted_record_before_recursive_validation(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			record = _nodeRecords(directory)[0]
			prefix = json.dumps(record, ensure_ascii=False, separators=(",", ":"))[:-1].encode("utf-8")
			nesting = sys.getrecursionlimit() + 100
			payload = prefix + b',"deep":' + (b"[" * nesting) + b"0" + (b"]" * nesting) + b"}\n"
			data = _readIndex(directory)
			entry = _catalogEntry(data, "nodes")
			entry["recordCount"] = 1
			entry["byteLength"] = len(payload)
			entry["sha256"] = hashlib.sha256(payload).hexdigest()
			_ = (directory / "nodes.jsonl").write_bytes(payload)
			_writeIndex(directory, data)

			with self.assertRaisesRegex(ValueError, "structural depth"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_projects_descendants_from_admitted_implicit_parent_edges(self) -> None:
		source = replace(
			_nodesSource(),
			topics=(
				sb.BundleTopicRecords(
					"nodes",
					(
						_core("n0", None, 0, 2, children=None),
						_core("n1", "n0", 1, 0, indexInParent=0),
						_core("n2", "n0", 1, 0, indexInParent=1),
					),
				),
			),
		)
		package = sb.prepareBundle(source)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in package.artifacts():
				_ = (directory / name).write_bytes(payload)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			projection = sb.projectSelectedSubtree(admission, directory, "n0")

			exported = directory / "exported"
			exported.mkdir()
			for name, payload in projection.package.artifacts():
				_ = (exported / name).write_bytes(payload)
			reopened = sb.admitBundle(exported, sourceGeneration=2)

		self.assertEqual(("n1", "n2"), admission.coreChildren["n0"])
		self.assertEqual(3, projection.package.index.nodeCount)
		self.assertEqual(("n0", "n1", "n2"), reopened.nodeIds())

	def test_rejects_child_order_that_disagrees_with_index_in_parent(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			records[2]["indexInParent"] = 0
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "index in parent"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_duplicate_implicit_child_indexes(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			_ = records[0].pop("children")
			records[2]["indexInParent"] = 0
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "index in parent"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_implicit_child_indexes_that_do_not_match_position(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			records = _nodeRecords(directory)
			_ = records[0].pop("children")
			records[1]["indexInParent"] = 1
			records[2]["indexInParent"] = 2
			_rewriteTopic(directory, _readIndex(directory), "nodes", records)

			with self.assertRaisesRegex(ValueError, "index in parent"):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_projects_leaf_without_scanning_unselected_parent_children(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			restrictedAdmission = replace(
				admission,
				coreChildren=_NoValuesCoreChildren(admission.coreChildren),
			)
			projection = sb.projectSelectedSubtree(restrictedAdmission, directory, "n1")

		self.assertEqual(1, projection.package.index.nodeCount)
		self.assertEqual(("n1",), projection.package.index.rootIds)

	def test_subtree_projection_rejects_an_invalid_admission_without_a_core_record(self) -> None:
		projection = sb.SelectedNodeProjection("n0", 1, (("uia", {}),))
		with (
			patch.object(sb, "projectSelectedNode", return_value=projection),
			self.assertRaisesRegex(ValueError, "no core node record"),
		):
			_ = sb.projectSelectedSubtree(cast("sb.BundleAdmission", object()), Path("unused"), "n0")

	def _assertNodesRejected(self, content: bytes) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			_ = (directory / "nodes.jsonl").write_bytes(content)
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_byte_order_mark(self) -> None:
		self._assertNodesRejected(b'\xef\xbb\xbf{"id":"n0"}\n')

	def test_rejects_invalid_utf8(self) -> None:
		self._assertNodesRejected(b'{"id":"n0","label":"\xff\xfe"}\n')

	def test_rejects_duplicate_object_keys(self) -> None:
		self._assertNodesRejected(b'{"id":"n0","id":"n0"}\n')

	def test_rejects_non_finite_numbers(self) -> None:
		self._assertNodesRejected(b'{"id":"n0","score":Infinity}\n')

	def test_rejects_a_line_without_newline_termination(self) -> None:
		self._assertNodesRejected(b'{"id":"n0"}')

	def test_rejects_an_oversized_unterminated_topic_before_reading_its_line(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			_ = (directory / "nodes.jsonl").write_bytes(b"x" * sb.COMPLETE_HARD_BYTES)

			with self.assertRaises(sb.BundleAdmissionLimitExceeded):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_non_monotonic_node_identifiers(self) -> None:
		for content in (b'{"id":"n1"}\n{"id":"n0"}\n', b'{"id":"n0"}\n{"id":"n0"}\n'):
			with self.subTest(content=content):
				self._assertNodesRejected(content)

	def _assertIndexRejected(
		self,
		mutate: Callable[[dict[str, object]], None],
		*,
		limits: sb.BundleAdmissionLimits = sb.DEFAULT_BUNDLE_LIMITS,
	) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			data = _readIndex(directory)
			mutate(data)
			_writeIndex(directory, data)
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1, limits=limits)

	def test_rejects_an_unknown_snapshot_kind(self) -> None:
		def mutate(data: dict[str, object]) -> None:
			data["snapshotKind"] = "mystery"

		self._assertIndexRejected(mutate)

	def test_rejects_an_unsupported_format_major(self) -> None:
		def mutate(data: dict[str, object]) -> None:
			data["formatMajor"] = 2

		self._assertIndexRejected(mutate)

	def test_rejects_unsupported_format_minors(self) -> None:
		for minor in (-1, 2):
			with self.subTest(minor=minor):
				self._assertIndexRejected(lambda data: data.__setitem__("formatMinor", minor))

	def test_rejects_malformed_compact_uia_exception_references(self) -> None:
		source = sb.BundleSource(
			snapshotKind="snapshot",
			generatedAt="2026-07-24T09:08:07Z",
			redactionEnabled=True,
			policyRevision=1,
			settingsRevision=1,
			executable="reader.exe",
			processId=42,
			rootIds=("n0",),
			topics=(
				sb.BundleTopicRecords("nodes", (_core("n0", None, 0, 0),)),
				sb.BundleTopicRecords(
					"uia",
					(
						JsonObject(
							(
								("id", "n0"),
								("status", JsonObject(())),
								("identity", JsonObject(())),
								("properties", JsonObject(())),
							),
						),
					),
				),
			),
		)
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in sb.prepareBundle(source).artifacts():
				_ = (directory / name).write_bytes(payload)
			data = _readIndex(directory)
			cases: tuple[list[list[object]], ...] = (
				[[3, {}]],
				[[0, "wrong-type"]],
				[[1, {}], [0, {}]],
			)
			for exceptions in cases:
				with self.subTest(exceptions=exceptions):
					_rewriteTopic(
						directory,
						data,
						"uia",
						[{"id": "n0", "exceptions": exceptions}],
					)
					with self.assertRaises(ValueError):
						_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_cataloged_record_count_mismatch(self) -> None:
		def mutate(data: dict[str, object]) -> None:
			entry = _catalogEntry(data, "nodes")
			entry["recordCount"] = cast("int", entry["recordCount"]) + 1

		self._assertIndexRejected(mutate)

	def test_rejects_a_cataloged_byte_length_mismatch(self) -> None:
		def mutate(data: dict[str, object]) -> None:
			entry = _catalogEntry(data, "nodes")
			entry["byteLength"] = cast("int", entry["byteLength"]) + 1

		self._assertIndexRejected(mutate)

	def test_rejects_a_cataloged_hash_mismatch(self) -> None:
		def mutate(data: dict[str, object]) -> None:
			entry = _catalogEntry(data, "nodes")
			entry["sha256"] = "0" * 64

		self._assertIndexRejected(mutate)

	def test_rejects_an_index_over_the_byte_ceiling(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(
					directory,
					sourceGeneration=1,
					limits=sb.BundleAdmissionLimits(indexMaximumBytes=8),
				)

	def test_rejects_an_index_that_is_not_an_ordinary_file(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			(directory / "index.json").unlink()
			(directory / "index.json").mkdir()
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_non_ordinary_directory_entry(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			(directory / "nested").mkdir()
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_an_undeclared_file(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			_ = (directory / "surprise.bin").write_bytes(b"x")
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_missing_declared_file(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			(directory / "nodes.jsonl").unlink()
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_document_topic_with_multiple_records(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory, document=True)
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=1)

	def test_rejects_a_negative_source_generation(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			with self.assertRaises(ValueError):
				_ = sb.admitBundle(directory, sourceGeneration=-1)

	def test_rejects_post_admission_artifact_content_changes_before_projection(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			nodes = directory / "nodes.jsonl"
			original = nodes.read_bytes()
			mutated = original.replace(b'"Item"', b'"Evil"')
			self.assertEqual(len(original), len(mutated))
			self.assertNotEqual(original, mutated)
			_ = nodes.write_bytes(mutated)

			with self.assertRaisesRegex(ValueError, "content hash"):
				_ = sb.projectSelectedNode(admission, directory, "n0")

	def test_rejects_post_admission_artifact_append_before_projection(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			with (directory / "nodes.jsonl").open("ab") as stream:
				_ = stream.write(b"x" * (1024 * 1024))

			with self.assertRaisesRegex(ValueError, "byte length"):
				_ = sb.projectSelectedNode(admission, directory, "n0")

	def test_rejects_post_admission_artifact_replacement_before_projection(self) -> None:
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			_writeValid(directory)
			admission = sb.admitBundle(directory, sourceGeneration=1)
			nodes = directory / "nodes.jsonl"
			replacement = directory / "replacement.jsonl"
			_ = replacement.write_bytes(nodes.read_bytes())
			os.replace(replacement, nodes)

			with self.assertRaisesRegex(ValueError, "identity"):
				_ = sb.projectSelectedNode(admission, directory, "n0")

	def test_projects_an_admitted_deep_subtree_without_recursion(self) -> None:
		depth = sys.getrecursionlimit() + 100
		limits = sb.BundleAdmissionLimits(maximumDepth=depth, maximumNodes=depth)
		package = sb.prepareBundle(_deepNodesSource(depth, implicitChildren=True))
		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in package.artifacts():
				_ = (directory / name).write_bytes(payload)
			admission = sb.admitBundle(directory, sourceGeneration=1, limits=limits)
			projection = sb.projectSelectedSubtree(admission, directory, "n0")

		self.assertEqual(("n0",), projection.package.index.rootIds)
		self.assertEqual(depth, projection.package.index.nodeCount)


if __name__ == "__main__":
	_ = unittest.main()
