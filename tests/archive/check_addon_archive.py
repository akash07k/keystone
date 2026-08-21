"""Verify a built add-on archive against the closed product module and sound inventory.

The checker reads the product-owned build inventory (``buildVars``) and the closed
runtime sound manifest (``SOUND_ASSETS``) and proves that a freshly built add-on archive
contains every declared Python module and each of the declared rich-theme WAV resources
exactly once, with no undeclared sound, and that every such archive member is byte- and
SHA-256-equal to that build's current source file on disk.

Each declared sound source is validated as signed 16-bit little-endian stereo 44,100-Hz PCM
that holds 1..44,100 frames, lasts at most 1,000 ms, weighs at most 96 KiB, and is
byte-distinct from every other cue. No canonical or authored asset digest is stored or
consulted: the current bytes are judged on their own and required only to equal the archive
that was produced from them, so an ordinary maintainer replacement at a declared path is
validated on its own merits before it ships.

Run ``python tests/archive/check_addon_archive.py --self-test`` for a self-contained proof
that a converged inventory is accepted and that every malformed or divergent condition is
rejected. Pass an archive path to verify a real built package against the working tree.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import io
import posixpath
from pathlib import Path, PurePosixPath
import re
import struct
import sys
from tempfile import TemporaryDirectory
import tomllib
from typing import Final, cast, override
import unicodedata
from urllib.parse import unquote, urlsplit
import warnings
import wave
import zipfile

_REPOSITORY: Final = Path(__file__).resolve().parents[2]
if str(_REPOSITORY) not in sys.path:
	sys.path.insert(0, str(_REPOSITORY))

import buildVars  # noqa: E402
from addon.globalPlugins.keystone.domain.sounds import SOUND_ASSETS  # noqa: E402
from tests.tools.build_sound_theme import (  # noqa: E402
	CHANNELS,
	EXPECTED_CUE_COUNT,
	MAX_DURATION_MS,
	MAX_FRAMES,
	MAX_SIZE_BYTES,
	SAMPLE_RATE_HZ,
	SAMPLE_WIDTH_BYTES,
)

_ARCHIVE_NAME: Final = "keystone-0.0.0.nvda-addon"
_ADDON_DIRNAME: Final = "addon"
_SOUND_MEMBER_ROOT: Final = "globalPlugins/keystone/sounds/rich"
_DOCUMENTATION_MEMBER_ROOT: Final = "doc/en"
_DOCUMENTATION_SUFFIXES: Final = frozenset((".md", ".html"))
_ROOT_README_DOC_LINK: Final = re.compile(r"\]\((docs/[^)\s]+)")
_GPL_LICENSE_DECLARATION: Final = "GNU General Public License v2 or later"
_GPL_PYPROJECT_IDENTIFIER: Final = "GPL-2.0-or-later"
_HASH_LENGTH: Final = 64
_MAX_ARCHIVE_MEMBERS: Final = 256
_MAX_ARCHIVE_MEMBER_SIZE_BYTES: Final = 1 * 1024 * 1024
_MAX_ARCHIVE_TOTAL_SIZE_BYTES: Final = 8 * 1024 * 1024
_MAX_ARCHIVE_COMPRESSION_RATIO: Final = 100
_ARCHIVE_READ_CHUNK_SIZE: Final = 64 * 1024


class ArchiveContractError(ValueError):
	"""Raised when an archive or inventory violates the package contract."""


@dataclass(frozen=True, slots=True)
class SoundMember:
	"""What the checker measured for one declared sound member in this build."""

	path: str
	frames: int
	size: int
	sha256: str


@dataclass(frozen=True, slots=True)
class ArchiveResult:
	"""The closed inventory proven present and source-equal in one built archive."""

	archive_name: str
	module_count: int
	sound_count: int


@dataclass(frozen=True, slots=True)
class DocumentationMember:
	"""One public source guide and its two installed-help archive members."""

	source: Path
	markdown_member: str
	html_member: str


class _HrefCollector(HTMLParser):
	"""Collect href attribute values from one rendered help page."""

	def __init__(self) -> None:
		super().__init__()
		self.hrefs: list[str] = []
		self.anchors: set[str] = set()

	@override
	def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
		for name, value in attrs:
			attribute = name.casefold()
			if attribute == "href" and value is not None:
				self.hrefs.append(value)
			elif attribute in {"id", "name"} and value:
				self.anchors.add(value)


def _sha256(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()


def _safe_member_name(name: str) -> str:
	if not name or name != unicodedata.normalize("NFC", name):
		raise ArchiveContractError("archive member names must be non-empty NFC text")
	if "\\" in name or name.startswith("/") or name.endswith("/"):
		raise ArchiveContractError(f"unsafe archive member path {name!r}")
	path = PurePosixPath(name)
	if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
		raise ArchiveContractError(f"unsafe archive member path {name!r}")
	if ":" in path.parts[0]:
		raise ArchiveContractError(f"unsafe archive member path {name!r}")
	lowered_parts = tuple(part.casefold() for part in path.parts)
	if "__pycache__" in lowered_parts or path.suffix.casefold() in (".pyc", ".pyo"):
		raise ArchiveContractError(f"generated cache member {name!r} is forbidden")
	if (
		any("credential" in part or "secret" in part for part in lowered_parts)
		or path.suffix.casefold() in (".key", ".pem")
		or any(part == ".env" or part.startswith(".env.") for part in lowered_parts)
	):
		raise ArchiveContractError(f"secret-bearing archive member {name!r} is forbidden")
	return path.as_posix()


def sound_manifest() -> tuple[tuple[str, str], ...]:
	"""Resolve the closed cue-to-member sound manifest from ``SOUND_ASSETS``.

	Every cue maps to one bare WAV filename joined onto the single bundled theme root, so
	the result is the closed set of archive member paths the build must ship exactly once.
	"""

	manifest: list[tuple[str, str]] = []
	seen_paths: set[str] = set()
	seen_cues: set[str] = set()
	for atom, filename in SOUND_ASSETS:
		cue = atom.value
		if "/" in filename or "\\" in filename or not filename.endswith(".wav"):
			raise ArchiveContractError(f"sound cue {cue!r} declares an invalid filename {filename!r}")
		member = _safe_member_name(f"{_SOUND_MEMBER_ROOT}/{filename}")
		if cue in seen_cues:
			raise ArchiveContractError(f"sound cue {cue!r} is declared more than once")
		if member in seen_paths:
			raise ArchiveContractError(f"sound member {member!r} is mapped by more than one cue")
		seen_cues.add(cue)
		seen_paths.add(member)
		manifest.append((cue, member))
	if len(manifest) != EXPECTED_CUE_COUNT:
		raise ArchiveContractError(
			f"expected {EXPECTED_CUE_COUNT} declared sounds, found {len(manifest)}",
		)
	return tuple(manifest)


def _expand_inventory(repository: Path, patterns: Sequence[str], label: str) -> tuple[str, ...]:
	addon_root = repository / _ADDON_DIRNAME
	members: set[str] = set()
	for pattern in patterns:
		relative = (
			pattern[len(f"{_ADDON_DIRNAME}/") :] if pattern.startswith(f"{_ADDON_DIRNAME}/") else pattern
		)
		for path in addon_root.glob(relative):
			if path.is_file():
				members.add(_safe_member_name(path.relative_to(addon_root).as_posix()))
	if not members:
		raise ArchiveContractError(f"{label} inventory resolved to no files")
	return tuple(sorted(members))


def module_manifest(repository: Path) -> tuple[str, ...]:
	"""Resolve the product Python module member paths from ``buildVars.pythonSources``."""

	return _expand_inventory(repository, buildVars.pythonSources, "python module")


def resource_manifest(repository: Path) -> tuple[str, ...]:
	"""Resolve the product resource member paths from ``buildVars.resourceSources``."""

	return _expand_inventory(repository, buildVars.resourceSources, "resource")


def documentation_manifest(repository: Path) -> tuple[DocumentationMember, ...]:
	"""Resolve the focused public guides that SCons stages as Markdown and HTML."""

	guides = tuple(buildVars.productGuides)
	if len(guides) != len(set(guides)) or any(Path(guide).name != guide for guide in guides):
		raise ArchiveContractError("product guide inventory must contain unique bare filenames")
	if any(Path(guide).suffix.casefold() != ".md" for guide in guides):
		raise ArchiveContractError("product guide inventory must contain Markdown files")
	sources = (repository / "README.md", *(repository / "docs" / guide for guide in guides))
	manifest: list[DocumentationMember] = []
	seen_members: set[str] = set()
	for source in sources:
		if not source.is_file():
			raise ArchiveContractError(f"documentation source {source!s} is missing")
		staged_name = source.name
		markdown_member = _safe_member_name(f"{_DOCUMENTATION_MEMBER_ROOT}/{staged_name}")
		html_member = _safe_member_name(
			f"{_DOCUMENTATION_MEMBER_ROOT}/{source.with_suffix('.html').name}",
		)
		if markdown_member in seen_members or html_member in seen_members:
			raise ArchiveContractError(f"documentation source {source!s} has a duplicate staged member")
		seen_members.update((markdown_member, html_member))
		manifest.append(
			DocumentationMember(
				source=source,
				markdown_member=markdown_member,
				html_member=html_member,
			),
		)
	if not manifest:
		raise ArchiveContractError("documentation manifest resolved to no public guides")
	return tuple(manifest)


def staged_documentation_bytes(record: DocumentationMember) -> bytes:
	"""Return source bytes as staged for installed add-on help."""

	try:
		source = record.source.read_bytes()
	except OSError as error:
		raise ArchiveContractError(
			f"cannot read documentation source {record.source!s}: {error}",
		) from error
	if record.source.name == "README.md":
		return source.replace(b"](docs/", b"](")
	return source


def validate_source_readme_links(repository: Path) -> None:
	"""Require root README documentation links to resolve from the repository root."""

	readme = repository / "README.md"
	try:
		text = readme.read_text(encoding="utf-8")
	except OSError as error:
		raise ArchiveContractError(f"cannot read root README {readme!s}: {error}") from error
	links = cast(list[str], _ROOT_README_DOC_LINK.findall(text))
	if not links:
		raise ArchiveContractError("root README must link to product guides through docs/")
	for href in links:
		parsed = urlsplit(href)
		try:
			target = _safe_member_name(unquote(parsed.path))
		except ArchiveContractError as error:
			raise ArchiveContractError(
				f"root README has an unsafe documentation target {href!r}",
			) from error
		if not target.startswith("docs/") or not (repository / target).is_file():
			raise ArchiveContractError(
				f"root README documentation link {href!r} does not resolve from the repository root",
			)


def validate_documentation_set(
	declared: Sequence[DocumentationMember],
	archive_bytes: Mapping[str, bytes],
) -> None:
	"""Validate exact focused public documentation membership in a built archive."""

	declared_markdown = {record.markdown_member for record in declared}
	declared_html = {record.html_member for record in declared}
	declared_members = declared_markdown | declared_html
	for record in declared:
		if record.markdown_member not in archive_bytes:
			raise ArchiveContractError(
				f"archive omits declared documentation Markdown {record.markdown_member!r}",
			)
		if record.html_member not in archive_bytes:
			raise ArchiveContractError(
				f"archive omits declared documentation HTML {record.html_member!r}",
			)
		if archive_bytes[record.markdown_member] != staged_documentation_bytes(record):
			raise ArchiveContractError(
				f"archive documentation Markdown {record.markdown_member!r} does not match source bytes",
			)
	documentation_members = {
		name
		for name in archive_bytes
		if name.startswith(f"{_DOCUMENTATION_MEMBER_ROOT}/")
		and PurePosixPath(name).suffix.casefold() in _DOCUMENTATION_SUFFIXES
	}
	if documentation_members != declared_members:
		extra = sorted(documentation_members - declared_members)
		missing = sorted(declared_members - documentation_members)
		raise ArchiveContractError(
			f"archive documentation members differ from the public manifest: missing={missing!r}, extra={extra!r}",
		)
	validate_documentation_links(declared, archive_bytes)


def _resolve_help_href(source: str, href: str) -> str | None:
	"""Resolve one local href against an archive member, ignoring external links and query-only links."""

	parsed = urlsplit(href)
	if parsed.scheme or parsed.netloc or (not parsed.path and not parsed.fragment):
		return None
	if parsed.path.startswith("/"):
		raise ArchiveContractError(f"help link in {source!r} has an unsafe target {href!r}")
	try:
		path = parsed.path or PurePosixPath(source).name
		return _safe_member_name(posixpath.normpath(f"{PurePosixPath(source).parent}/{unquote(path)}"))
	except ArchiveContractError as error:
		raise ArchiveContractError(f"help link in {source!r} has an unsafe target {href!r}") from error


def _help_document(member: str, data: bytes) -> tuple[tuple[str, ...], frozenset[str]]:
	try:
		text = data.decode("utf-8")
	except UnicodeDecodeError as error:
		raise ArchiveContractError(f"packaged help member {member!r} is not UTF-8") from error
	parser = _HrefCollector()
	parser.feed(text)
	parser.close()
	return tuple(parser.hrefs), frozenset(parser.anchors)


def validate_documentation_links(
	declared: Sequence[DocumentationMember],
	archive_bytes: Mapping[str, bytes],
) -> None:
	"""Require local links in every rendered help page to resolve inside the archive."""

	documentation_members = {
		member for record in declared for member in (record.markdown_member, record.html_member)
	}
	rendered_anchors = {
		record.html_member: _help_document(record.html_member, archive_bytes[record.html_member])[1]
		for record in declared
	}
	for record in declared:
		hrefs, _anchors = _help_document(record.html_member, archive_bytes[record.html_member])
		for href in hrefs:
			target = _resolve_help_href(record.html_member, href)
			if target is None:
				continue
			suffix = PurePosixPath(target).suffix.casefold()
			if suffix == ".md":
				raise ArchiveContractError(
					f"help link in {record.html_member!r} targets Markdown instead of rendered HTML {target!r}",
				)
			if suffix == ".html":
				if target not in documentation_members:
					raise ArchiveContractError(
						f"help link in {record.html_member!r} targets undeclared documentation "
						+ f"member {target!r}",
					)
			elif target not in archive_bytes:
				raise ArchiveContractError(
					f"help link in {record.html_member!r} targets missing archive resource {target!r}",
				)
			fragment = unquote(urlsplit(href).fragment)
			if fragment and suffix == ".html" and fragment not in rendered_anchors[target]:
				raise ArchiveContractError(
					f"help link in {record.html_member!r} targets missing anchor {fragment!r} in {target!r}",
				)


def validate_license_consistency(repository: Path, archive_bytes: Mapping[str, bytes]) -> None:
	"""Require each public declaration and the shipped license copy to agree on GPLv2-or-later."""

	try:
		copying = (repository / "COPYING.txt").read_bytes()
		readme = (repository / "README.md").read_text(encoding="utf-8")
		pyproject = repository / "pyproject.toml"
		if not pyproject.is_file():
			pyproject = _REPOSITORY / "pyproject.toml"
		with pyproject.open("rb") as pyproject_file:
			metadata = tomllib.load(pyproject_file)
	except (OSError, tomllib.TOMLDecodeError) as error:
		raise ArchiveContractError(f"cannot read project license metadata: {error}") from error
	project = cast(dict[str, object], metadata.get("project"))
	if project.get("license") != _GPL_PYPROJECT_IDENTIFIER:
		raise ArchiveContractError("pyproject.toml must declare GPL-2.0-or-later")
	license_files = project.get("license-files")
	if not isinstance(license_files, list) or "COPYING.txt" not in license_files:
		raise ArchiveContractError("pyproject.toml must distribute COPYING.txt as its license file")
	if buildVars.addon_info["addon_license"] != _GPL_LICENSE_DECLARATION:
		raise ArchiveContractError("buildVars must declare GNU GPL version 2 or later")
	if "GNU General Public License, version 2 or later" not in readme or "(COPYING.txt)" not in readme:
		raise ArchiveContractError("README.md must declare GPL version 2 or later and link to COPYING.txt")
	if archive_bytes.get(f"{_DOCUMENTATION_MEMBER_ROOT}/COPYING.txt") != copying:
		raise ArchiveContractError("archive must ship COPYING.txt with the declared GPL license text")
	manifest = archive_bytes.get("manifest.ini", b"").decode("utf-8", errors="replace")
	if f"license = {_GPL_LICENSE_DECLARATION}" not in manifest:
		raise ArchiveContractError("archive manifest must declare GNU GPL version 2 or later")
	if f"licenseURL = {buildVars.addon_info['addon_licenseURL']}" not in manifest:
		raise ArchiveContractError("archive manifest must link to the declared GPL license")


def _validate_pcm(data: bytes, label: str) -> int:
	"""Validate one WAV payload as the supported PCM format within the safety ceilings."""

	if len(data) > MAX_SIZE_BYTES:
		raise ArchiveContractError(f"{label}: {len(data)} bytes exceeds {MAX_SIZE_BYTES}")
	try:
		with wave.open(io.BytesIO(data), "rb") as reader:
			if reader.getnchannels() != CHANNELS:
				raise ArchiveContractError(f"{label}: expected stereo audio")
			if reader.getsampwidth() != SAMPLE_WIDTH_BYTES:
				raise ArchiveContractError(f"{label}: expected 16-bit samples")
			if reader.getframerate() != SAMPLE_RATE_HZ:
				raise ArchiveContractError(f"{label}: expected {SAMPLE_RATE_HZ} Hz")
			frames = reader.getnframes()
			_ = reader.readframes(frames)
	except wave.Error as error:
		raise ArchiveContractError(f"{label}: not a supported WAV: {error}") from error
	if frames < 1:
		raise ArchiveContractError(f"{label}: empty audio")
	if frames > MAX_FRAMES:
		raise ArchiveContractError(f"{label}: {frames} frames exceeds {MAX_FRAMES}")
	if frames * 1000.0 / SAMPLE_RATE_HZ > MAX_DURATION_MS:
		raise ArchiveContractError(f"{label}: audio exceeds {MAX_DURATION_MS} ms")
	return frames


def validate_sound_set(
	declared: Sequence[tuple[str, str]],
	source_bytes: Mapping[str, bytes],
	archive_bytes: Mapping[str, bytes],
) -> tuple[SoundMember, ...]:
	"""Validate the closed sound set for this build with source/archive byte equality.

	``declared`` is the closed cue-to-member manifest. ``source_bytes`` and ``archive_bytes``
	map each member path to its current source file bytes and its sole archive member bytes.
	Every declared member must be a valid, unique-content source, present once in the archive
	with byte- and hash-equal contents, and no undeclared sound may appear on either side.
	"""

	members: list[SoundMember] = []
	content_owner: dict[str, str] = {}
	declared_paths: set[str] = set()
	for cue, member in declared:
		if member in declared_paths:
			raise ArchiveContractError(f"sound member {member!r} is mapped by more than one cue")
		declared_paths.add(member)
	for cue, member in declared:
		if member not in source_bytes:
			raise ArchiveContractError(f"sound source {member!r} for cue {cue!r} is missing")
		source = source_bytes[member]
		frames = _validate_pcm(source, f"sound source {member!r}")
		digest = _sha256(source)
		if member not in archive_bytes:
			raise ArchiveContractError(f"archive omits declared sound member {member!r}")
		packaged = archive_bytes[member]
		if packaged != source or _sha256(packaged) != digest:
			raise ArchiveContractError(
				f"archive member {member!r} does not match its current source bytes",
			)
		if digest in content_owner:
			raise ArchiveContractError(
				f"sound member {member!r} has identical audio to {content_owner[digest]!r}",
			)
		content_owner[digest] = member
		members.append(SoundMember(path=member, frames=frames, size=len(source), sha256=digest))
	for member in source_bytes:
		if member not in declared_paths:
			raise ArchiveContractError(f"undeclared sound source {member!r} is present")
	for member in archive_bytes:
		if member not in declared_paths:
			raise ArchiveContractError(f"undeclared sound member {member!r} is present in the archive")
	return tuple(members)


def _read_member_with_limit(
	bundle: zipfile.ZipFile,
	info: zipfile.ZipInfo,
	name: str,
	maximum_size: int,
) -> bytes:
	"""Stream one member while enforcing the remaining uncompressed byte budget."""

	data = bytearray()
	with bundle.open(info) as reader:
		while True:
			chunk = reader.read(min(_ARCHIVE_READ_CHUNK_SIZE, maximum_size - len(data) + 1))
			if not chunk:
				break
			data.extend(chunk)
			if len(data) > maximum_size:
				raise ArchiveContractError(f"archive member {name!r} exceeds the read byte limit")
	if len(data) != info.file_size:
		raise ArchiveContractError(f"archive member {name!r} has an inconsistent uncompressed size")
	return bytes(data)


def _read_archive_members(archive: Path) -> dict[str, bytes]:
	"""Read bounded archive members, rejecting unsafe, duplicate, or bomb-like entries."""

	try:
		with zipfile.ZipFile(archive) as bundle:
			actual: dict[str, bytes] = {}
			folded: set[str] = set()
			entries = [info for info in bundle.infolist() if not info.is_dir()]
			if len(entries) > _MAX_ARCHIVE_MEMBERS:
				raise ArchiveContractError(
					f"archive has {len(entries)} members, exceeding {_MAX_ARCHIVE_MEMBERS}",
				)
			declared_total = 0
			validated_entries: list[tuple[zipfile.ZipInfo, str]] = []
			for info in entries:
				name = _safe_member_name(info.filename)
				folded_name = name.casefold()
				if folded_name in folded:
					raise ArchiveContractError(f"archive member {name!r} is duplicate or colliding")
				if info.flag_bits & 0x1:
					raise ArchiveContractError(f"archive member {name!r} is encrypted")
				if ((info.external_attr >> 16) & 0o170000) == 0o120000:
					raise ArchiveContractError(f"archive member {name!r} is a symbolic link")
				if info.file_size > _MAX_ARCHIVE_MEMBER_SIZE_BYTES:
					raise ArchiveContractError(
						f"archive member {name!r} exceeds {_MAX_ARCHIVE_MEMBER_SIZE_BYTES} bytes",
					)
				declared_total += info.file_size
				if declared_total > _MAX_ARCHIVE_TOTAL_SIZE_BYTES:
					raise ArchiveContractError(
						f"archive uncompressed size exceeds {_MAX_ARCHIVE_TOTAL_SIZE_BYTES} bytes",
					)
				if info.file_size and (
					not info.compress_size
					or info.file_size / info.compress_size > _MAX_ARCHIVE_COMPRESSION_RATIO
				):
					raise ArchiveContractError(
						f"archive member {name!r} exceeds compression ratio {_MAX_ARCHIVE_COMPRESSION_RATIO}",
					)
				validated_entries.append((info, name))
				folded.add(folded_name)

			read_total = 0
			for info, name in validated_entries:
				actual[name] = _read_member_with_limit(
					bundle,
					info,
					name,
					min(
						_MAX_ARCHIVE_MEMBER_SIZE_BYTES,
						_MAX_ARCHIVE_TOTAL_SIZE_BYTES - read_total,
					),
				)
				read_total += len(actual[name])
	except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
		raise ArchiveContractError(f"cannot inspect archive: {error}") from error
	if not actual:
		raise ArchiveContractError("archive contains no members")
	return actual


def verify_build(repository: Path, archive: Path) -> ArchiveResult:
	"""Verify one built archive against the converged module and sound inventory."""

	if archive.name != _ARCHIVE_NAME:
		raise ArchiveContractError("archive path does not use the expected exact name")
	modules = module_manifest(repository)
	declared_sounds = sound_manifest()
	declared_sound_paths = {member for _, member in declared_sounds}
	if set(resource_manifest(repository)) != declared_sound_paths:
		raise ArchiveContractError(
			"build resource inventory does not match the closed sound manifest",
		)
	members = _read_archive_members(archive)
	addon_root = repository / _ADDON_DIRNAME
	validate_source_readme_links(repository)
	validate_documentation_set(documentation_manifest(repository), members)
	validate_license_consistency(repository, members)

	declared_modules = set(modules)
	archive_modules = {member for member in members if PurePosixPath(member).suffix.casefold() == ".py"}
	if archive_modules != declared_modules:
		missing = sorted(declared_modules - archive_modules)
		extra = sorted(archive_modules - declared_modules)
		raise ArchiveContractError(
			f"archive Python modules differ from the build manifest: missing={missing!r}, extra={extra!r}",
		)

	for member in modules:
		try:
			source = (addon_root / member).read_bytes()
		except OSError as error:
			raise ArchiveContractError(f"cannot read module source {member!r}: {error}") from error
		if members[member] != source:
			raise ArchiveContractError(
				f"archive member {member!r} does not match its current source bytes",
			)

	source_bytes: dict[str, bytes] = {}
	for _cue, member in declared_sounds:
		source_path = addon_root / member
		if not source_path.is_file():
			raise ArchiveContractError(f"sound source {member!r} is missing from the working tree")
		source_bytes[member] = source_path.read_bytes()
	archive_sound_bytes = {name: data for name, data in members.items() if name.casefold().endswith(".wav")}
	sound_members = validate_sound_set(declared_sounds, source_bytes, archive_sound_bytes)
	return ArchiveResult(
		archive_name=archive.name,
		module_count=len(modules),
		sound_count=len(sound_members),
	)


def _synth_wav(
	*,
	channels: int = CHANNELS,
	framerate: int = SAMPLE_RATE_HZ,
	frames: int = 256,
	seed: int = 1,
	trailer: bytes = b"",
) -> bytes:
	"""Render a deterministic in-memory WAV for the self-test, seedable for uniqueness."""

	peak = 30000
	total = frames * channels
	samples = [((seed * 131 + index * 17) % (2 * peak + 1)) - peak for index in range(total)]
	buffer = io.BytesIO()
	with wave.open(buffer, "wb") as writer:
		writer.setnchannels(channels)
		writer.setsampwidth(SAMPLE_WIDTH_BYTES)
		writer.setframerate(framerate)
		writer.writeframes(struct.pack(f"<{total}h", *samples))
	return buffer.getvalue() + trailer


def _expect_rejected(
	label: str,
	declared: Sequence[tuple[str, str]],
	source_bytes: Mapping[str, bytes],
	archive_bytes: Mapping[str, bytes],
) -> None:
	try:
		_ = validate_sound_set(declared, source_bytes, archive_bytes)
	except ArchiveContractError:
		return
	raise AssertionError(f"self-test accepted the {label} case")


def _self_test() -> None:
	root = _SOUND_MEMBER_ROOT
	first = f"{root}/a.wav"
	second = f"{root}/b.wav"
	third = f"{root}/c.wav"
	declared: tuple[tuple[str, str], ...] = (("cueA", first), ("cueB", second), ("cueC", third))
	good: dict[str, bytes] = {
		first: _synth_wav(seed=1, frames=200),
		second: _synth_wav(seed=2, frames=240),
		third: _synth_wav(seed=3, frames=280),
	}

	accepted = validate_sound_set(declared, good, dict(good))
	if len(accepted) != len(declared):
		raise AssertionError("self-test rejected the converged inventory")

	replacement = _synth_wav(seed=997, frames=321)
	replaced = dict(good)
	replaced[first] = replacement
	proven = validate_sound_set(declared, replaced, dict(replaced))
	if next(member for member in proven if member.path == first).sha256 != _sha256(replacement):
		raise AssertionError("self-test failed to prove the temporary replacement equality")

	wrong_format = dict(good)
	wrong_format[first] = _synth_wav(channels=1, seed=4)
	_expect_rejected("wrong-format", declared, wrong_format, wrong_format)

	over_duration = dict(good)
	over_duration[first] = _synth_wav(frames=MAX_FRAMES + 1, seed=5)
	_expect_rejected("over-duration", declared, over_duration, over_duration)

	over_size = dict(good)
	over_size[first] = _synth_wav(seed=6, trailer=b"\x00" * (MAX_SIZE_BYTES + 1))
	_expect_rejected("over-size", declared, over_size, over_size)

	duplicate_content = dict(good)
	duplicate_content[second] = duplicate_content[first]
	_expect_rejected("duplicate-content", declared, duplicate_content, duplicate_content)

	missing_source = dict(good)
	del missing_source[first]
	_expect_rejected("missing-source", declared, missing_source, dict(good))

	undeclared = dict(good)
	undeclared[f"{root}/extra.wav"] = _synth_wav(seed=7, frames=190)
	_expect_rejected("undeclared-source", declared, undeclared, undeclared)

	mismatch = dict(good)
	mismatch[first] = _synth_wav(seed=8, frames=201)
	_expect_rejected("source-archive-mismatch", declared, good, mismatch)

	_expect_rejected("duplicate-mapping", (*declared, ("cueDup", first)), good, dict(good))

	with TemporaryDirectory() as directory:
		archive = Path(directory) / _ARCHIVE_NAME
		with warnings.catch_warnings():
			warnings.simplefilter("ignore", UserWarning)
			with zipfile.ZipFile(archive, "w") as bundle:
				bundle.writestr("manifest.ini", b"name = keystone\n")
				bundle.writestr("manifest.ini", b"name = other\n")
		try:
			_ = _read_archive_members(archive)
		except ArchiveContractError:
			pass
		else:
			raise AssertionError("self-test accepted a duplicate archive member")


def _parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	_ = parser.add_argument("--self-test", action="store_true")
	_ = parser.add_argument("archive", nargs="?", type=Path)
	return parser.parse_args()


def main() -> int:
	args = _parse_args()
	if cast(bool, args.self_test):
		_self_test()
		print("archive self-test passed")
		return 0
	archive = cast("Path | None", args.archive)
	if archive is None:
		raise ArchiveContractError("an archive path is required unless --self-test is given")
	result = verify_build(_REPOSITORY, archive)
	print(
		f"verified {result.archive_name}: {result.module_count} modules, {result.sound_count} sounds",
	)
	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except ArchiveContractError as error:
		print(f"Archive contract rejected: {error}", file=sys.stderr)
		raise SystemExit(1) from error
