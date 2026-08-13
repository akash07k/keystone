"""Deterministic authoring and replacement-safe validation for the Keystone sound theme.

This is a test-only tool. It renders the bundled-default WAV set from a closed
35-entry specification and separately validates a current source set (default or
maintainer-replaced) for format, duration, size, mapping, and uniqueness. It stores
no canonical source-byte digest: per expanded D-29 a maintainer may drop a new WAV at
the same manifest path before a build, and validation must judge the current bytes on
their own, not against an authored hash pin.

Production never imports this module and no runtime or end-user theme directory is
created by it.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import struct
import sys
import wave
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

# Supported bundled PCM format. RIFF/WAVE, signed 16-bit little-endian, stereo, 44.1 kHz.
SAMPLE_RATE_HZ = 44100
CHANNELS = 2
SAMPLE_WIDTH_BYTES = 2
SAMPLE_WIDTH_BITS = SAMPLE_WIDTH_BYTES * 8
PCM_ENCODING = "pcm_s16le"

# Safety ceilings for every source asset (current build, not an authored pin).
MAX_FRAMES = 44100
MAX_DURATION_MS = 1000
MAX_SIZE_BYTES = 96 * 1024

MANIFEST_ROOT = "addon/globalPlugins/keystone/sounds/rich"

_INT16_PEAK = 32767

# The closed, ordered inventory. This is the product-language answer to research
# questions 3 and 4; it is authoritative here and is never read from a planning
# document at runtime. Order matches the approved UI-SPEC bundled asset inventory.
EXPECTED_INVENTORY: tuple[tuple[str, str, str], ...] = (
	("layerEntered", "layer-enter.wav", "Short neutral doorway interval"),
	("layerInvalidKey", "layer-invalid.wav", "Dry two-note rejection"),
	("layerTimeout", "layer-timeout.wav", "Soft falling timeout"),
	("layerExplicitExit", "layer-exit.wav", "Short closed cadence"),
	("boundedFullFamily", "family-full-bounded.wav", "Low-to-mid capture identifier"),
	("unlimitedFullFamily", "family-full-unlimited.wav", "Wider version of full identifier"),
	("diffFamily", "family-diff.wav", "Alternating comparison interval"),
	("boundedNavigatorFamily", "family-navigator-bounded.wav", "Focused high-mid identifier"),
	("unlimitedNavigatorFamily", "family-navigator-unlimited.wav", "Wider navigator identifier"),
	("startState", "state-start.wav", "Short rising motif"),
	("progressState", "state-progress.wav", "Soft single pulse"),
	("cancellationRequested", "state-cancel-requested.wav", "Two restrained descending pulses"),
	("cancelledOutcome", "outcome-cancelled.wav", "Gentle descending resolution"),
	("successOutcome", "outcome-success.wav", "Short resolved cadence"),
	("truncatedSuccessOutcome", "outcome-truncated.wav", "Resolved cadence with measured qualifier"),
	("partialScreenshotOutcome", "outcome-partial-screenshot.wav", "Resolved cadence with soft warning tail"),
	("noChangeOutcome", "outcome-no-change.wav", "Stable repeated tone"),
	("baselineCreatedOutcome", "outcome-baseline-created.wav", "Open resolved cadence"),
	("failureOutcome", "outcome-failure.wav", "Short non-harsh error motif"),
	("focusInspectorFamily", "family-inspector-focus.wav", "Focus-target identifier"),
	("navigatorInspectorFamily", "family-inspector-navigator.wav", "Navigator-target identifier"),
	("inspectorRefresh", "inspector-refresh.wav", "Circular two-note refresh"),
	("inspectorReady", "inspector-ready.wav", "Compact ready cadence"),
	("inspectorClose", "inspector-close.wav", "Gentle closed cadence"),
	("eventMonitorStart", "event-monitor-start.wav", "Rising event pulse"),
	("eventMonitorStop", "event-monitor-stop.wav", "Descending event pulse"),
	("pendingQueueDrop", "event-drop-pending.wav", "Measured double warning pulse"),
	("retainedRowDrop", "event-drop-retained.wav", "Measured lower double warning pulse"),
	("eventExportFamily", "family-event-export.wav", "Export identifier"),
	("outputPathCopied", "confirm-output-copy.wav", "Single confirmation tick"),
	("explorerReveal", "confirm-explorer-reveal.wav", "Opening confirmation interval"),
	("commandHelpOpened", "confirm-help-open.wav", "Light two-note confirmation"),
	("quickPropertyBrowsableMessage", "confirm-quick-browse.wav", "Open confirmation tick"),
	("quickPropertyCopy", "confirm-quick-copy.wav", "Closed confirmation tick"),
	("sharedWarning", "warning-shared.wav", "Recognizable measured warning motif"),
)

EXPECTED_CUE_COUNT = 35


class SoundThemeError(ValueError):
	"""Raised for a malformed specification or an invalid source set."""


@dataclass(frozen=True, slots=True)
class Partial:
	"""A single sine component of one tone segment."""

	freqHz: float
	amp: float


@dataclass(frozen=True, slots=True)
class Segment:
	"""One time-bounded tone made of summed sine partials with a linear envelope."""

	offsetMs: float
	durationMs: float
	attackMs: float
	releaseMs: float
	partials: tuple[Partial, ...]


@dataclass(frozen=True, slots=True)
class Cue:
	"""One atomic cue: identity, manifest path, tonal role, and default recipe."""

	index: int
	cueId: str
	path: str
	tonalRole: str
	masterGain: float
	segments: tuple[Segment, ...]

	def totalDurationMs(self) -> float:
		return max(seg.offsetMs + seg.durationMs for seg in self.segments)


@dataclass(frozen=True, slots=True)
class SoundThemeSpec:
	"""The parsed closed specification."""

	formatVersion: int
	sampleRateHz: int
	channels: int
	sampleWidthBits: int
	encoding: str
	manifestRoot: str
	cues: tuple[Cue, ...]


@dataclass(frozen=True, slots=True)
class SourceObservation:
	"""What validation measured for one current source asset, with no authored pin."""

	cueId: str
	path: str
	frames: int
	durationMs: float
	sizeBytes: int
	sha256: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
	"""Outcome of one validation pass."""

	errors: tuple[str, ...]
	observations: tuple[SourceObservation, ...]

	@property
	def ok(self) -> bool:
		return not self.errors


# --- typed JSON access -------------------------------------------------------


def _as_dict(value: object, where: str) -> dict[str, object]:
	if not isinstance(value, dict):
		raise SoundThemeError(f"{where}: expected an object")
	narrowed = cast("dict[object, object]", value)
	return {str(key): item for key, item in narrowed.items()}


def _as_list(value: object, where: str) -> list[object]:
	if not isinstance(value, list):
		raise SoundThemeError(f"{where}: expected an array")
	return list(cast("list[object]", value))


def _as_str(value: object, where: str) -> str:
	if not isinstance(value, str):
		raise SoundThemeError(f"{where}: expected a string")
	return value


def _as_int(value: object, where: str) -> int:
	if isinstance(value, bool) or not isinstance(value, int):
		raise SoundThemeError(f"{where}: expected an integer")
	return value


def _as_number(value: object, where: str) -> float:
	if isinstance(value, bool) or not isinstance(value, (int, float)):
		raise SoundThemeError(f"{where}: expected a number")
	return float(value)


def _field(obj: dict[str, object], key: str, where: str) -> object:
	if key not in obj:
		raise SoundThemeError(f"{where}: missing '{key}'")
	return obj[key]


# --- specification parsing ---------------------------------------------------


def _parse_partial(raw: object, where: str) -> Partial:
	obj = _as_dict(raw, where)
	freq = _as_number(_field(obj, "freqHz", where), f"{where}.freqHz")
	amp = _as_number(_field(obj, "amp", where), f"{where}.amp")
	if not (0.0 < freq <= SAMPLE_RATE_HZ / 2):
		raise SoundThemeError(f"{where}.freqHz: out of range")
	if not (0.0 <= amp <= 1.0):
		raise SoundThemeError(f"{where}.amp: out of range")
	return Partial(freqHz=freq, amp=amp)


def _parse_segment(raw: object, where: str) -> Segment:
	obj = _as_dict(raw, where)
	offset = _as_number(_field(obj, "offsetMs", where), f"{where}.offsetMs")
	duration = _as_number(_field(obj, "durationMs", where), f"{where}.durationMs")
	attack = _as_number(_field(obj, "attackMs", where), f"{where}.attackMs")
	release = _as_number(_field(obj, "releaseMs", where), f"{where}.releaseMs")
	partials_raw = _as_list(_field(obj, "partials", where), f"{where}.partials")
	if offset < 0 or duration <= 0 or attack < 0 or release < 0:
		raise SoundThemeError(f"{where}: negative or empty timing")
	if attack + release > duration:
		raise SoundThemeError(f"{where}: envelope longer than segment")
	if not partials_raw:
		raise SoundThemeError(f"{where}.partials: at least one partial required")
	partials = tuple(_parse_partial(item, f"{where}.partials[{i}]") for i, item in enumerate(partials_raw))
	return Segment(
		offsetMs=offset,
		durationMs=duration,
		attackMs=attack,
		releaseMs=release,
		partials=partials,
	)


def _parse_cue(raw: object, index: int) -> Cue:
	where = f"cues[{index}]"
	obj = _as_dict(raw, where)
	declared_index = _as_int(_field(obj, "index", where), f"{where}.index")
	if declared_index != index:
		raise SoundThemeError(f"{where}.index: expected {index}, found {declared_index}")
	cue_id = _as_str(_field(obj, "cueId", where), f"{where}.cueId")
	path = _as_str(_field(obj, "path", where), f"{where}.path")
	role = _as_str(_field(obj, "tonalRole", where), f"{where}.tonalRole")
	synthesis = _as_dict(_field(obj, "synthesis", where), f"{where}.synthesis")
	if "sha256" in obj or "digest" in obj or "hash" in synthesis:
		raise SoundThemeError(f"{where}: authored digests are not allowed")
	master_gain = _as_number(
		_field(synthesis, "masterGain", f"{where}.synthesis"),
		f"{where}.synthesis.masterGain",
	)
	if not (0.0 < master_gain <= 1.0):
		raise SoundThemeError(f"{where}.synthesis.masterGain: out of range")
	segments_raw = _as_list(
		_field(synthesis, "segments", f"{where}.synthesis"),
		f"{where}.synthesis.segments",
	)
	if not segments_raw:
		raise SoundThemeError(f"{where}.synthesis.segments: at least one segment required")
	segments = tuple(
		_parse_segment(item, f"{where}.synthesis.segments[{i}]") for i, item in enumerate(segments_raw)
	)
	return Cue(
		index=index,
		cueId=cue_id,
		path=path,
		tonalRole=role,
		masterGain=master_gain,
		segments=segments,
	)


def parseSpec(raw: object) -> SoundThemeSpec:
	"""Parse and structurally validate a decoded specification object."""

	root = _as_dict(raw, "spec")
	fmt = _as_dict(_field(root, "audioFormat", "spec"), "spec.audioFormat")
	spec = SoundThemeSpec(
		formatVersion=_as_int(_field(root, "formatVersion", "spec"), "spec.formatVersion"),
		sampleRateHz=_as_int(
			_field(fmt, "sampleRateHz", "spec.audioFormat"),
			"spec.audioFormat.sampleRateHz",
		),
		channels=_as_int(_field(fmt, "channels", "spec.audioFormat"), "spec.audioFormat.channels"),
		sampleWidthBits=_as_int(
			_field(fmt, "sampleWidthBits", "spec.audioFormat"),
			"spec.audioFormat.sampleWidthBits",
		),
		encoding=_as_str(_field(fmt, "encoding", "spec.audioFormat"), "spec.audioFormat.encoding"),
		manifestRoot=_as_str(_field(root, "manifestRoot", "spec"), "spec.manifestRoot"),
		cues=tuple(
			_parse_cue(item, i) for i, item in enumerate(_as_list(_field(root, "cues", "spec"), "spec.cues"))
		),
	)
	if (
		spec.sampleRateHz != SAMPLE_RATE_HZ
		or spec.channels != CHANNELS
		or spec.sampleWidthBits != SAMPLE_WIDTH_BITS
	):
		raise SoundThemeError("spec.audioFormat: unsupported PCM format")
	if spec.encoding != PCM_ENCODING:
		raise SoundThemeError("spec.audioFormat.encoding: unsupported")
	if spec.manifestRoot != MANIFEST_ROOT:
		raise SoundThemeError("spec.manifestRoot: unexpected")
	return spec


def loadSpec(path: Path) -> SoundThemeSpec:
	"""Load a specification from a JSON file on disk."""

	try:
		decoded: object = json.loads(path.read_text(encoding="utf-8"))
	except OSError as err:
		raise SoundThemeError(f"cannot read spec: {err}") from err
	except json.JSONDecodeError as err:
		raise SoundThemeError(f"spec is not valid JSON: {err}") from err
	return parseSpec(decoded)


# --- rendering ---------------------------------------------------------------


def renderPcm(cue: Cue) -> bytes:
	"""Render one cue to raw signed 16-bit little-endian stereo PCM frames."""

	total_ms = cue.totalDurationMs()
	total_frames = round(SAMPLE_RATE_HZ * total_ms / 1000.0)
	accum = [0.0] * total_frames
	for seg in cue.segments:
		start = round(SAMPLE_RATE_HZ * seg.offsetMs / 1000.0)
		seg_frames = round(SAMPLE_RATE_HZ * seg.durationMs / 1000.0)
		attack = max(1, round(SAMPLE_RATE_HZ * seg.attackMs / 1000.0))
		release = max(1, round(SAMPLE_RATE_HZ * seg.releaseMs / 1000.0))
		for i in range(seg_frames):
			frame = start + i
			if frame < 0 or frame >= total_frames:
				continue
			if i < attack:
				envelope = i / attack
			elif i >= seg_frames - release:
				envelope = max(0.0, (seg_frames - i) / release)
			else:
				envelope = 1.0
			seconds = i / SAMPLE_RATE_HZ
			value = 0.0
			for partial in seg.partials:
				value += partial.amp * math.sin(2.0 * math.pi * partial.freqHz * seconds)
			accum[frame] += value * envelope
	samples = bytearray()
	for value in accum:
		scaled = value * cue.masterGain
		scaled = min(1.0, max(-1.0, scaled))
		sample = struct.pack("<h", int(round(scaled * _INT16_PEAK)))
		samples += sample * CHANNELS
	return bytes(samples)


def renderWav(cue: Cue) -> bytes:
	"""Render one cue to a complete RIFF/WAVE container."""

	pcm = renderPcm(cue)
	buffer = io.BytesIO()
	with wave.open(buffer, "wb") as writer:
		writer.setnchannels(CHANNELS)
		writer.setsampwidth(SAMPLE_WIDTH_BYTES)
		writer.setframerate(SAMPLE_RATE_HZ)
		writer.writeframes(pcm)
	return buffer.getvalue()


def writeTheme(spec: SoundThemeSpec, outputDir: Path, *, only: frozenset[str] | None = None) -> list[Path]:
	"""Render default cues to WAV files under ``outputDir``. Returns written paths.

	With ``only`` unset every cue is rendered. With ``only`` set to a set of manifest
	paths, just those cues are rendered, so a single plan can author a subset of the
	closed inventory without touching the assets a later plan owns.
	"""

	outputDir.mkdir(parents=True, exist_ok=True)
	written: list[Path] = []
	for cue in spec.cues:
		if only is not None and cue.path not in only:
			continue
		destination = outputDir / cue.path
		destination.parent.mkdir(parents=True, exist_ok=True)
		_ = destination.write_bytes(renderWav(cue))
		written.append(destination)
	return written


# --- validation --------------------------------------------------------------


def validateSpecStructure(spec: SoundThemeSpec) -> ValidationReport:
	"""Check the closed inventory: count, order, identity, mapping, and no digests.

	The obsolete draft inventory is rejected here because it neither matches the
	expected count nor the expected cue identities and paths.
	"""

	errors: list[str] = []
	if len(spec.cues) != EXPECTED_CUE_COUNT:
		errors.append(f"expected {EXPECTED_CUE_COUNT} cues, found {len(spec.cues)}")
	seen_ids: set[str] = set()
	seen_paths: set[str] = set()
	for position, cue in enumerate(spec.cues):
		if position < len(EXPECTED_INVENTORY):
			expected_id, expected_path, expected_role = EXPECTED_INVENTORY[position]
			if cue.cueId != expected_id:
				errors.append(f"cue[{position}]: expected id '{expected_id}', found '{cue.cueId}'")
			if cue.path != expected_path:
				errors.append(f"cue[{position}]: expected path '{expected_path}', found '{cue.path}'")
			if cue.tonalRole != expected_role:
				errors.append(f"cue[{position}]: unexpected tonal role for '{cue.cueId}'")
		else:
			errors.append(f"cue[{position}]: '{cue.cueId}' is outside the closed inventory")
		if cue.cueId in seen_ids:
			errors.append(f"cue[{position}]: duplicate cue id '{cue.cueId}'")
		if cue.path in seen_paths:
			errors.append(f"cue[{position}]: duplicate path '{cue.path}'")
		seen_ids.add(cue.cueId)
		seen_paths.add(cue.path)
	return ValidationReport(errors=tuple(errors), observations=())


def _read_wav_source(path: Path, where: str) -> tuple[int, int, bytes]:
	"""Return (frames, sizeBytes, rawPcm), rejecting unsupported PCM format."""

	size_bytes = path.stat().st_size
	try:
		with wave.open(str(path), "rb") as reader:
			if reader.getnchannels() != CHANNELS:
				raise SoundThemeError(f"{where}: expected stereo")
			if reader.getsampwidth() != SAMPLE_WIDTH_BYTES:
				raise SoundThemeError(f"{where}: expected 16-bit samples")
			if reader.getframerate() != SAMPLE_RATE_HZ:
				raise SoundThemeError(f"{where}: expected {SAMPLE_RATE_HZ} Hz")
			frames = reader.getnframes()
			pcm = reader.readframes(frames)
	except wave.Error as err:
		raise SoundThemeError(f"{where}: not a supported WAV: {err}") from err
	return frames, size_bytes, pcm


def validateSourceSet(
	spec: SoundThemeSpec,
	sourceDir: Path,
	*,
	only: frozenset[str] | None = None,
) -> ValidationReport:
	"""Validate the current source set at the closed manifest paths.

	Each asset must exist, decode as the supported PCM format, hold 1..44100 frames,
	last at most 1000 ms, weigh at most 96 KiB, and be byte-distinct from every other
	cue. No file outside the closed inventory may be present. Observations are computed
	for the current bytes; there is no comparison against an authored digest.

	With ``only`` set, existence and per-asset checks cover just the named subset (the
	assets authored so far), while any file present outside the full closed inventory is
	still rejected as undeclared. Uniqueness is enforced across the validated subset.
	"""

	errors: list[str] = []
	observations: list[SourceObservation] = []
	content_owner: dict[str, str] = {}
	expected_names = {cue.path for cue in spec.cues}

	for cue in spec.cues:
		if only is not None and cue.path not in only:
			continue
		where = f"source '{cue.path}'"
		asset = sourceDir / cue.path
		if not asset.is_file():
			errors.append(f"{where}: missing")
			continue
		try:
			frames, size_bytes, pcm = _read_wav_source(asset, where)
		except SoundThemeError as err:
			errors.append(str(err))
			continue
		duration_ms = frames * 1000.0 / SAMPLE_RATE_HZ
		digest = hashlib.sha256(pcm).hexdigest()
		if frames < 1:
			errors.append(f"{where}: empty audio")
		if frames > MAX_FRAMES:
			errors.append(f"{where}: {frames} frames exceeds {MAX_FRAMES}")
		if duration_ms > MAX_DURATION_MS:
			errors.append(f"{where}: {duration_ms:.1f} ms exceeds {MAX_DURATION_MS} ms")
		if size_bytes > MAX_SIZE_BYTES:
			errors.append(f"{where}: {size_bytes} bytes exceeds {MAX_SIZE_BYTES}")
		if digest in content_owner:
			errors.append(f"{where}: identical audio to '{content_owner[digest]}'")
		else:
			content_owner[digest] = cue.path
		observations.append(
			SourceObservation(
				cueId=cue.cueId,
				path=cue.path,
				frames=frames,
				durationMs=duration_ms,
				sizeBytes=size_bytes,
				sha256=digest,
			),
		)

	for found in sorted(_iter_wav_names(sourceDir)):
		if found not in expected_names:
			errors.append(f"source '{found}': undeclared file")

	return ValidationReport(errors=tuple(errors), observations=tuple(observations))


def _iter_wav_names(sourceDir: Path) -> list[str]:
	if not sourceDir.is_dir():
		return []
	return [entry.name for entry in sourceDir.iterdir() if entry.is_file() and entry.suffix == ".wav"]


# --- CLI ---------------------------------------------------------------------


def _print_errors(title: str, report: ValidationReport) -> None:
	_ = sys.stderr.write(f"{title}: {len(report.errors)} error(s)\n")
	for message in report.errors:
		_ = sys.stderr.write(f"  - {message}\n")


def main(argv: Sequence[str] | None = None) -> int:
	parser = argparse.ArgumentParser(description="Render and validate the Keystone sound theme.")
	_ = parser.add_argument(
		"--spec",
		required=True,
		type=Path,
		help="path to the sound theme specification JSON",
	)
	_ = parser.add_argument("--output", type=Path, help="directory to render bundled-default WAV files into")
	_ = parser.add_argument(
		"--source",
		type=Path,
		help="directory of current source WAV files to validate (defaults to --output)",
	)
	_ = parser.add_argument(
		"--verify",
		action="store_true",
		help="validate structure and the current source set",
	)
	_ = parser.add_argument(
		"--only",
		nargs="+",
		metavar="NAME",
		help="restrict rendering and validation to these manifest filenames (subset authoring)",
	)
	_ = parser.add_argument(
		"--check-complete",
		action="store_true",
		help="validate that the whole closed inventory is present and valid (no subset)",
	)
	args = parser.parse_args(argv)

	try:
		spec = loadSpec(args.spec)
	except SoundThemeError as err:
		_ = sys.stderr.write(f"spec error: {err}\n")
		return 2

	structure = validateSpecStructure(spec)
	if not structure.ok:
		_print_errors("specification", structure)
		return 3

	only: frozenset[str] | None = None
	raw_only: object = args.only
	if raw_only is not None:
		requested = frozenset(str(name) for name in cast("list[object]", raw_only))
		unknown = sorted(requested - {cue.path for cue in spec.cues})
		if unknown:
			_ = sys.stderr.write(f"only error: unknown manifest file(s): {', '.join(unknown)}\n")
			return 2
		only = requested

	if args.output is not None:
		_ = writeTheme(spec, args.output, only=only)

	if args.verify:
		source_dir = args.source if args.source is not None else args.output
		if source_dir is None:
			_ = sys.stderr.write("verify error: provide --output or --source\n")
			return 2
		sources = validateSourceSet(spec, source_dir, only=only)
		if not sources.ok:
			_print_errors("source set", sources)
			return 3
		_ = sys.stdout.write(f"sound theme verified: {len(sources.observations)} assets under {source_dir}\n")

	if args.check_complete:
		complete_dir = args.source if args.source is not None else args.output
		if complete_dir is None:
			_ = sys.stderr.write("check-complete error: provide --output or --source\n")
			return 2
		complete = validateSourceSet(spec, complete_dir)
		if not complete.ok:
			_print_errors("incomplete theme", complete)
			return 3
		_ = sys.stdout.write(
			f"sound theme complete: {len(complete.observations)} assets under {complete_dir}\n",
		)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
