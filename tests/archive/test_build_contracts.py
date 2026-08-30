"""Build and archive contract coverage for the converged Keystone add-on.

These tests build a real add-on archive from isolated working trees through SCons, then prove
the converged inventory: every declared production module and
each declared rich-theme sound is packaged exactly once and is byte- and hash-equal to its
current source. A temporary maintainer replacement at one declared sound path is validated
through the ordinary build/archive path, and every malformed or divergent condition is
rejected. The suite also proves the public representative-capture benchmark stays
reproducible with a stable closed record inventory.
"""

from __future__ import annotations

import io
from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
from tempfile import TemporaryDirectory
from typing import override
import unittest
import warnings
import wave
import zipfile

from addon.globalPlugins.keystone.domain.sounds import SOUND_ASSETS
from tests.archive.check_addon_archive import (
	ArchiveContractError,
	DocumentationMember,
	documentation_manifest,
	module_manifest,
	sound_manifest,
	staged_documentation_bytes,
	validate_documentation_links,
	validate_source_readme_links,
	verify_build,
)
from tests.fixtures.representative_capture import (
	EXPECTED_RECORD_COUNTS,
	NODE_COUNT,
	estimatedTokens,
	representativeCapture,
	topicBytes,
)
from tests.tools.build_sound_theme import EXPECTED_CUE_COUNT

_REPOSITORY = Path(__file__).resolve().parents[2]
_ARCHIVE_NAME = "keystone-0.0.0.nvda-addon"
_FIRST_LOCAL_BUILD_ARCHIVE_NAME = "keystone-0.0.1.nvda-addon"
_BUILD_INPUTS = (
	"addon",
	"docs",
	"site_scons",
	"build.bat",
	"buildVars.py",
	"COPYING.txt",
	"manifest.ini.tpl",
	"manifest-translated.ini.tpl",
	"README.md",
	"sconstruct",
	"style.css",
)


def _build_archive(workspace: Path) -> Path:
	"""Build an archive through the isolated workspace's SCons graph."""

	result = _run_batch(workspace / "build.bat", "version=0.0.0", "channel=dev")
	if result.returncode:
		raise AssertionError(result.stdout + result.stderr)
	archive = workspace / "dist" / _ARCHIVE_NAME
	if not archive.is_file():
		raise FileNotFoundError(f"SCons did not create the expected archive {archive}")
	return archive


def _new_build_archive(workspace: Path) -> Path:
	"""Copy the build inputs into a fresh workspace and build its archive."""

	_copy_build_workspace(workspace)
	return _build_archive(workspace)


def _read_members(archive: Path) -> dict[str, bytes]:
	with zipfile.ZipFile(archive) as bundle:
		return {info.filename: bundle.read(info) for info in bundle.infolist() if not info.is_dir()}


def _rewrite_archive(members: dict[str, bytes], dest: Path) -> Path:
	with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as bundle:
		for name in sorted(members):
			bundle.writestr(name, members[name])
	return dest


class _HTMLTextCollector(HTMLParser):
	def __init__(self) -> None:
		super().__init__()
		self.parts: list[str] = []

	@override
	def handle_data(self, data: str) -> None:
		self.parts.append(data)


def _rendered_text(data: bytes) -> str:
	"""Extract text from a rendered help member to prove source-derived content survived."""

	parser = _HTMLTextCollector()
	parser.feed(data.decode("utf-8"))
	parser.close()
	return "".join(parser.parts)


def _guide_heading(source: Path) -> str:
	"""Return the first ATX heading that SCons must render from a public guide."""

	for line in source.read_text(encoding="utf-8").splitlines():
		if line.startswith("# "):
			return line.removeprefix("# ").strip()
	raise AssertionError(f"public guide {source} has no level-one heading")


def _make_wav(seed: int, frames: int = 512) -> bytes:
	"""Render a deterministic, valid, content-unique stereo 16-bit 44.1-kHz WAV."""

	peak = 28000
	samples = [((seed * 211 + index * 13) % (2 * peak + 1)) - peak for index in range(frames)]
	buffer = io.BytesIO()
	with wave.open(buffer, "wb") as writer:
		writer.setnchannels(2)
		writer.setsampwidth(2)
		writer.setframerate(44100)
		writer.writeframes(struct.pack(f"<{frames * 2}h", *(sample for sample in samples for _ in range(2))))
	return buffer.getvalue()


def _copy_build_workspace(destination: Path) -> None:
	for relative in _BUILD_INPUTS:
		source = _REPOSITORY / relative
		target = destination / relative
		if source.is_dir():
			_ = shutil.copytree(source, target)
		else:
			_ = shutil.copy2(source, target)
	shutil.rmtree(destination / "addon" / "doc" / "en", ignore_errors=True)
	_ = (destination / ".keystone-build-number").write_text("0\n", encoding="utf-8")


def _temporary_workspace() -> TemporaryDirectory[str]:
	"""Create an ignored workspace beneath the repository so uv finds its project settings."""

	temp_root = _REPOSITORY / "tmp"
	temp_root.mkdir(exist_ok=True)
	return TemporaryDirectory(dir=temp_root)


def _run_batch(
	path: Path,
	*arguments: str,
	env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		[os.environ["COMSPEC"], "/d", "/c", str(path), *arguments],
		cwd=path.parent,
		env=env,
		check=False,
		capture_output=True,
		text=True,
	)


class BuildWrapperContractTests(unittest.TestCase):
	def test_real_build_publishes_to_dist_and_special_targets_stay_at_root(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			_copy_build_workspace(workspace)
			build = workspace / "build.bat"

			result = _run_batch(build)
			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertEqual(
				[path.name for path in (workspace / "dist").glob("*.nvda-addon")],
				[_FIRST_LOCAL_BUILD_ARCHIVE_NAME],
			)
			self.assertEqual(list(workspace.glob("*.nvda-addon")), [])

			result = _run_batch(build, "clean")
			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertFalse((workspace / "dist").exists())

			result = _run_batch(build, "pot")
			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertTrue((workspace / "keystone.pot").is_file())
			self.assertFalse((workspace / "dist").exists())

			result = _run_batch(build, "mergePot")
			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertTrue((workspace / "keystone-merge.pot").is_file())
			self.assertFalse((workspace / "dist").exists())

	def test_requested_version_rebuilds_the_packaged_manifest(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			_copy_build_workspace(workspace)
			build = workspace / "build.bat"

			first = _run_batch(build)
			self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

			second = _run_batch(build, "version=0.0.0", "channel=dev")
			self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
			manifest = _read_members(workspace / "dist" / _ARCHIVE_NAME)["manifest.ini"].decode("utf-8")
			self.assertIn("version = 0.0.0", manifest)
			self.assertIn("updateChannel = dev", manifest)

	def test_arguments_are_forwarded_and_scons_exit_code_is_preserved(self) -> None:
		with TemporaryDirectory(dir=_REPOSITORY / "tmp") as directory:
			workspace = Path(directory)
			_ = shutil.copy2(_REPOSITORY / "build.bat", workspace / "build.bat")
			fake_bin = workspace / "bin"
			fake_bin.mkdir()
			_ = (fake_bin / "uv.cmd").write_text(
				"\r\n".join(
					(
						"@echo off",
						">uv-args.txt echo(%*",
						"if defined UV_EXIT_CODE exit /b %UV_EXIT_CODE%",
						"if not exist dist mkdir dist",
						"type nul > dist\\keystone-1.2.3.nvda-addon",
						"exit /b 0",
						"",
					),
				),
				encoding="utf-8",
			)
			env = dict(os.environ)
			env["PATH"] = os.pathsep.join((str(fake_bin), os.environ["SystemRoot"] + r"\System32"))

			result = _run_batch(
				workspace / "build.bat",
				"version=1.2.3",
				"channel=beta",
				"dev=0",
				"target=pot",
				env=env,
			)
			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertEqual(
				(workspace / "uv-args.txt").read_text(encoding="utf-8").strip(),
				"run scons version=1.2.3 channel=beta dev=0 target=pot",
			)
			self.assertTrue((workspace / "dist" / "keystone-1.2.3.nvda-addon").is_file())

			env["UV_EXIT_CODE"] = "7"
			result = _run_batch(workspace / "build.bat", "version=1.2.3", env=env)
			self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

	def test_normal_build_clears_stale_dist_archives_and_rejects_multiple_dist_outputs(self) -> None:
		with TemporaryDirectory(dir=_REPOSITORY / "tmp") as directory:
			workspace = Path(directory)
			_ = shutil.copy2(_REPOSITORY / "build.bat", workspace / "build.bat")
			fake_bin = workspace / "bin"
			fake_bin.mkdir()
			_ = (fake_bin / "uv.cmd").write_text(
				"\r\n".join(
					(
						"@echo off",
						"if not exist dist mkdir dist",
						'if "%UV_ARCHIVE_MODE%"=="multiple" (',
						"  type nul > dist\\keystone-one.nvda-addon",
						"  type nul > dist\\keystone-two.nvda-addon",
						") else (",
						"  type nul > dist\\keystone-current.nvda-addon",
						")",
						"exit /b 0",
						"",
					),
				),
				encoding="utf-8",
			)
			env = dict(os.environ)
			env["PATH"] = os.pathsep.join((str(fake_bin), os.environ["SystemRoot"] + r"\System32"))
			dist = workspace / "dist"
			dist.mkdir()
			_ = (dist / "keystone-stale.nvda-addon").write_bytes(b"stale")

			result = _run_batch(workspace / "build.bat", env=env)

			self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
			self.assertEqual(
				[path.name for path in dist.glob("*.nvda-addon")],
				["keystone-current.nvda-addon"],
			)

			env["UV_ARCHIVE_MODE"] = "multiple"
			result = _run_batch(workspace / "build.bat", env=env)
			self.assertNotEqual(result.returncode, 0)
			self.assertIn("produced multiple", result.stdout + result.stderr)
			self.assertEqual(list(dist.glob("*.nvda-addon")), [])

	def test_all_scons_clean_aliases_remove_dist_and_exit_successfully(self) -> None:
		for alias in ("clean", "-c", "--clean", "--remove"):
			with self.subTest(alias=alias), _temporary_workspace() as directory:
				workspace = Path(directory)
				_ = shutil.copy2(_REPOSITORY / "build.bat", workspace / "build.bat")
				fake_bin = workspace / "bin"
				fake_bin.mkdir()
				_ = (fake_bin / "uv.cmd").write_text(
					"@echo off\r\nexit /b 0\r\n",
					encoding="utf-8",
				)
				dist = workspace / "dist"
				dist.mkdir()
				_ = (dist / "stale.nvda-addon").write_bytes(b"stale")
				env = dict(os.environ)
				env["PATH"] = os.pathsep.join((str(fake_bin), os.environ["SystemRoot"] + r"\System32"))

				result = _run_batch(workspace / "build.bat", alias, env=env)

				self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
				self.assertFalse(dist.exists())

	def test_missing_uv_fails_before_scons_with_one_clear_error(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			_ = shutil.copy2(_REPOSITORY / "build.bat", workspace / "build.bat")
			env = dict(os.environ)
			env["PATH"] = os.environ["SystemRoot"] + r"\System32"

			result = _run_batch(workspace / "build.bat", env=env)
			lines = [line.strip() for line in (result.stdout + result.stderr).splitlines() if line.strip()]
			self.assertNotEqual(result.returncode, 0)
			self.assertEqual(lines, ['Error: "uv" was not found on PATH.'])


class ArchiveInventoryTests(unittest.TestCase):
	def test_archive_self_test_command_succeeds(self) -> None:
		result = subprocess.run(
			[
				sys.executable,
				str(_REPOSITORY / "tests" / "archive" / "check_addon_archive.py"),
				"--self-test",
			],
			cwd=_REPOSITORY,
			check=False,
			capture_output=True,
			text=True,
		)

		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertEqual(result.stdout, "archive self-test passed\n")

	def test_converged_inventory_is_packaged_and_source_equal(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			archive = _new_build_archive(workspace)
			result = verify_build(workspace, archive)
			self.assertEqual(result.archive_name, _ARCHIVE_NAME)
			self.assertEqual(result.sound_count, EXPECTED_CUE_COUNT)
			self.assertEqual(result.module_count, len(module_manifest(workspace)))

			members = _read_members(archive)
			declared_sounds = {member for _, member in sound_manifest()}
			packaged_sounds = {name for name in members if name.casefold().endswith(".wav")}
			self.assertEqual(packaged_sounds, declared_sounds)
			self.assertEqual(len(packaged_sounds), EXPECTED_CUE_COUNT)
			for member in module_manifest(workspace):
				self.assertIn(member, members)
				self.assertEqual(members[member], (workspace / "addon" / member).read_bytes())

	def test_sound_manifest_matches_the_runtime_assets(self) -> None:
		manifest = sound_manifest()
		self.assertEqual(len(manifest), len(SOUND_ASSETS))
		self.assertEqual(
			[member for _, member in manifest],
			[f"globalPlugins/keystone/sounds/rich/{filename}" for _atom, filename in SOUND_ASSETS],
		)

	def test_every_focused_public_guide_has_source_and_rendered_members(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			archive = _new_build_archive(workspace)
			members = _read_members(archive)
			manifest = documentation_manifest(workspace)
			validate_source_readme_links(workspace)
			readme = next(record for record in manifest if record.source.name == "README.md")
			source_readme = readme.source.read_text(encoding="utf-8")
			self.assertIn("](docs/user-guide.md)", source_readme)
			self.assertIn("](docs/troubleshooting.md)", source_readme)
			self.assertIn("](docs/evidence-schema.md)", source_readme)
			self.assertEqual(
				members[readme.markdown_member],
				staged_documentation_bytes(readme),
			)
			self.assertIn(b'href="user-guide.html"', members[readme.html_member])
			self.assertNotIn(b'href="user-guide.md"', members[readme.html_member])
			self.assertIn(
				b'href="user-guide.html#monitor-events"',
				members["doc/en/settings-and-privacy.html"],
			)
			self.assertIn(b'id="monitor-events"', members["doc/en/user-guide.html"])
			self.assertNotIn("doc/en/developer-guide.md", members)
			self.assertNotIn("doc/en/developer-guide.html", members)
			self.assertEqual(members["doc/en/COPYING.txt"], (workspace / "COPYING.txt").read_bytes())
			self.assertIn(
				b"license = GNU General Public License v2 or later",
				members["manifest.ini"],
			)

			self.assertEqual(
				{member for record in manifest for member in (record.markdown_member, record.html_member)},
				{
					member
					for member in members
					if member.startswith("doc/en/") and Path(member).suffix.casefold() in {".md", ".html"}
				},
			)
			for record in manifest:
				self.assertIn(record.markdown_member, members)
				self.assertIn(record.html_member, members)
				self.assertEqual(members[record.markdown_member], staged_documentation_bytes(record))
				self.assertIn(_guide_heading(record.source), _rendered_text(members[record.html_member]))
			validate_documentation_links(manifest, members)

	def test_build_removes_stale_contributor_help_pages(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			_copy_build_workspace(workspace)
			staged_docs = workspace / "addon" / "doc" / "en"
			staged_docs.mkdir(parents=True)
			_ = (staged_docs / "developer-guide.md").write_text("# Stale guide\n", encoding="utf-8")
			_ = (staged_docs / "developer-guide.html").write_text("<h1>Stale guide</h1>", encoding="utf-8")

			members = _read_members(_build_archive(workspace))

			self.assertNotIn("doc/en/developer-guide.md", members)
			self.assertNotIn("doc/en/developer-guide.html", members)

	def test_packaged_help_rejects_a_broken_documentation_link(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			members = _read_members(_new_build_archive(workspace))
			manifest = documentation_manifest(workspace)
			readme = next(record for record in manifest if record.source.name == "README.md")
			original = members[readme.html_member]
			tampered = original.replace(b'href="user-guide.html"', b'href="missing-guide.html"')
			self.assertNotEqual(tampered, original)
			members[readme.html_member] = tampered

			with self.assertRaises(ArchiveContractError):
				validate_documentation_links(manifest, members)

	def test_packaged_help_validates_local_anchors_and_packaged_resources(self) -> None:
		readme = DocumentationMember(
			source=Path("README.md"),
			markdown_member="doc/en/README.md",
			html_member="doc/en/README.html",
		)
		guide = DocumentationMember(
			source=Path("guide.md"),
			markdown_member="doc/en/guide.md",
			html_member="doc/en/guide.html",
		)
		members = {
			readme.markdown_member: b"# Readme\n",
			readme.html_member: (
				b'<a href="https://example.com">External</a>'
				b'<a href="mailto:maintainer@example.com">Email</a>'
				b'<a href="#license">Anchor</a>'
				b'<a href="guide.html#topic">Guide</a>'
				b'<link href="../style.css" rel="stylesheet">'
				b'<h2 id="license">License</h2>'
			),
			guide.markdown_member: b"# Guide\n",
			guide.html_member: b'<h2 id="topic">Topic</h2>',
			"doc/style.css": b"",
		}

		validate_documentation_links((readme, guide), members)

		markdown_target = dict(members)
		markdown_target[readme.html_member] = markdown_target[readme.html_member].replace(
			b"guide.html#topic",
			b"guide.md#topic",
		)
		with self.assertRaises(ArchiveContractError):
			validate_documentation_links((readme, guide), markdown_target)

		missing_anchor = dict(members)
		missing_anchor[guide.html_member] = b"<p>Guide</p>"
		with self.assertRaises(ArchiveContractError):
			validate_documentation_links((readme, guide), missing_anchor)

	def test_documentation_member_failures_are_rejected(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			good = _read_members(_new_build_archive(workspace))
			record = documentation_manifest(workspace)[0]
			cases = {
				"missing markdown": {
					name: data for name, data in good.items() if name != record.markdown_member
				},
				"missing html": {name: data for name, data in good.items() if name != record.html_member},
				"divergent markdown": {**good, record.markdown_member: b"# divergent\n"},
				"undeclared documentation": {**good, "doc/en/private.md": b"# private\n"},
			}
			for label, members in cases.items():
				case_directory = workspace / label.replace(" ", "-")
				case_directory.mkdir()
				tampered = _rewrite_archive(members, case_directory / _ARCHIVE_NAME)
				with self.subTest(case=label), self.assertRaises(ArchiveContractError):
					_ = verify_build(workspace, tampered)

	def test_duplicate_and_unsafe_documentation_members_are_rejected(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			good = _read_members(_new_build_archive(workspace))
			record = documentation_manifest(workspace)[0]
			for label, member in {
				"duplicate": record.markdown_member,
				"unsafe": "doc/en/../unsafe.md",
			}.items():
				case_directory = workspace / label
				case_directory.mkdir()
				archive = case_directory / _ARCHIVE_NAME
				with warnings.catch_warnings():
					warnings.simplefilter("ignore", UserWarning)
					with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
						for name, data in good.items():
							bundle.writestr(name, data)
						bundle.writestr(member, b"# invalid\n")
				with self.subTest(case=label), self.assertRaises(ArchiveContractError):
					_ = verify_build(workspace, archive)

	def test_over_limit_compressed_member_is_rejected_before_decompression(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			good = _read_members(_new_build_archive(workspace))
			member = "globalPlugins/keystone/oversized.bin"
			tampered = _rewrite_archive(
				{**good, member: b"0" * (2 * 1024 * 1024)},
				workspace / _ARCHIVE_NAME,
			)
			with zipfile.ZipFile(tampered) as bundle:
				info = bundle.getinfo(member)
				self.assertGreater(info.file_size, 1024 * 1024)
				self.assertLess(info.compress_size * 100, info.file_size)
			with self.assertRaises(ArchiveContractError):
				_ = verify_build(workspace, tampered)

	def test_temporary_source_replacement_rebuilds_and_matches(self) -> None:
		target = sound_manifest()[0][1]
		replacement = _make_wav(seed=4099, frames=733)
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			_copy_build_workspace(workspace)
			addon = workspace / "addon"
			source_path = addon / target
			original = source_path.read_bytes()
			self.assertNotEqual(replacement, original)
			_ = source_path.write_bytes(replacement)

			archive = _build_archive(workspace)
			result = verify_build(workspace, archive)
			self.assertEqual(result.sound_count, EXPECTED_CUE_COUNT)
			members = _read_members(archive)
			self.assertEqual(members[target], replacement)

	def test_every_invalid_condition_is_rejected(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			archive = _new_build_archive(workspace)
			_ = verify_build(workspace, archive)
			good = _read_members(archive)
			sound_target = sound_manifest()[0][1]
			module_target = module_manifest(workspace)[0]

			mismatch = dict(good)
			mismatch[sound_target] = _make_wav(seed=13, frames=444)
			missing_sound = {name: data for name, data in good.items() if name != sound_target}
			missing_module = {name: data for name, data in good.items() if name != module_target}
			undeclared_sound = dict(good)
			undeclared_sound["globalPlugins/keystone/sounds/rich/undeclared.wav"] = _make_wav(seed=71)
			undeclared_module = dict(good)
			undeclared_module["globalPlugins/keystone/undeclared.py"] = b"UNDECLARED = True\n"

			cases = {
				"source/archive mismatch": mismatch,
				"missing sound": missing_sound,
				"missing module": missing_module,
				"undeclared sound": undeclared_sound,
				"undeclared module": undeclared_module,
			}
			for label, members in cases.items():
				case_directory = workspace / label.replace("/", "-")
				case_directory.mkdir()
				tampered = _rewrite_archive(members, case_directory / _ARCHIVE_NAME)
				with self.subTest(case=label), self.assertRaises(ArchiveContractError):
					_ = verify_build(workspace, tampered)

	def test_wrong_named_archive_is_rejected(self) -> None:
		with _temporary_workspace() as directory:
			workspace = Path(directory)
			good = _read_members(_new_build_archive(workspace))
			renamed = _rewrite_archive(good, workspace / "keystone-latest.nvda-addon")
			with self.assertRaises(ArchiveContractError):
				_ = verify_build(workspace, renamed)


class RepresentativeBenchmarkTests(unittest.TestCase):
	def test_generator_is_reproducible_and_closed(self) -> None:
		first = representativeCapture()
		second = representativeCapture()
		self.assertEqual(first.nodeCount, NODE_COUNT)
		self.assertEqual(first.recordCounts, EXPECTED_RECORD_COUNTS)
		self.assertEqual(second.recordCounts, EXPECTED_RECORD_COUNTS)
		for name in EXPECTED_RECORD_COUNTS:
			self.assertEqual(topicBytes(first.topic(name)), topicBytes(second.topic(name)))

	def test_uncompressed_byte_and_token_economics_are_deterministic(self) -> None:
		capture = representativeCapture()
		for name, expected in EXPECTED_RECORD_COUNTS.items():
			topic = capture.topic(name)
			self.assertEqual(len(topic.records), expected)
			payload = topicBytes(topic)
			self.assertEqual(payload, topicBytes(capture.topic(name)))
			self.assertEqual(estimatedTokens(len(payload)), -(-len(payload) // 4))


if __name__ == "__main__":
	_ = unittest.main()
