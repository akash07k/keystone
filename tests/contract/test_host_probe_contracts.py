"""Contract tests for the host-probe support tooling.

``SoundThemeContractTests`` freezes the closed 35-entry sound-theme contract: inventory
identity and order, deterministic rendering, per-asset format and budget limits, path and
content uniqueness, and rejection of every malformed or obsolete input. ``RawUiaProbeContractTests``
and ``SoundProbeContractTests`` freeze the two installed-host probe evaluators: their emitted
schema, and that every budget breach, safety-counter violation, and teardown breach maps to the
exact documented exit code while a clean baseline passes. Importing the probe modules does no
host, COM, or audio work, so these contracts run anywhere.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import io
import json
import struct
import tempfile
import unittest
import wave
from pathlib import Path
from typing import Any, cast

from tests.live import probe_live_inspector_capture as inspectorProbe
from tests.live import probe_raw_uia_subscription as uiaProbe
from tests.live import probe_sound_playback as soundProbe
from tests.tools.build_sound_theme import (
	EXPECTED_CUE_COUNT,
	EXPECTED_INVENTORY,
	MAX_SIZE_BYTES,
	SAMPLE_RATE_HZ,
	SoundThemeError,
	loadSpec,
	main,
	parseSpec,
	renderWav,
	validateSourceSet,
	validateSpecStructure,
	writeTheme,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "sound_theme.json"

# The committed specification is the source of truth; load it once for the suite.
SPEC = loadSpec(FIXTURE_PATH)


def _raw_fixture() -> dict[str, Any]:
	decoded: object = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
	assert isinstance(decoded, dict)
	narrowed = cast("dict[object, object]", decoded)
	return {str(key): value for key, value in narrowed.items()}


def _write_wav(
	path: Path,
	*,
	framerate: int = SAMPLE_RATE_HZ,
	channels: int = 2,
	sampwidth: int = 2,
	frames: int = 200,
) -> None:
	with wave.open(str(path), "wb") as writer:
		writer.setnchannels(channels)
		writer.setsampwidth(sampwidth)
		writer.setframerate(framerate)
		writer.writeframes(struct.pack("<h", 1000) * channels * frames)


class SoundThemeContractTests(unittest.TestCase):
	"""The committed specification and its tooling must honor the closed contract."""

	def _empty_dir(self) -> Path:
		holder = tempfile.TemporaryDirectory()
		self.addCleanup(holder.cleanup)
		return Path(holder.name)

	def _rendered_dir(self) -> Path:
		target = self._empty_dir()
		_ = writeTheme(SPEC, target)
		return target

	# --- inventory identity and order ---------------------------------------

	def test_structure_matches_closed_inventory(self) -> None:
		report = validateSpecStructure(SPEC)
		self.assertTrue(report.ok, report.errors)
		self.assertEqual(len(SPEC.cues), EXPECTED_CUE_COUNT)
		for position, cue in enumerate(SPEC.cues):
			expected_id, expected_path, expected_role = EXPECTED_INVENTORY[position]
			self.assertEqual(cue.index, position)
			self.assertEqual(cue.cueId, expected_id)
			self.assertEqual(cue.path, expected_path)
			self.assertEqual(cue.tonalRole, expected_role)

	def test_ids_and_paths_are_unique(self) -> None:
		ids = [cue.cueId for cue in SPEC.cues]
		paths = [cue.path for cue in SPEC.cues]
		self.assertEqual(len(set(ids)), EXPECTED_CUE_COUNT)
		self.assertEqual(len(set(paths)), EXPECTED_CUE_COUNT)

	def test_fixture_carries_no_authored_digest(self) -> None:
		text = FIXTURE_PATH.read_text(encoding="utf-8").lower()
		for banned in ("sha256", "digest", '"hash"'):
			self.assertNotIn(banned, text)

	# --- deterministic rendering --------------------------------------------

	def test_rendering_is_byte_identical(self) -> None:
		for cue in SPEC.cues:
			self.assertEqual(renderWav(cue), renderWav(cue))

	def test_theme_generation_is_byte_identical_across_runs(self) -> None:
		first = self._empty_dir()
		second = self._empty_dir()
		_ = writeTheme(SPEC, first)
		_ = writeTheme(SPEC, second)
		for cue in SPEC.cues:
			self.assertEqual((first / cue.path).read_bytes(), (second / cue.path).read_bytes())

	# --- source-set validation on a good render -----------------------------

	def test_rendered_source_set_passes(self) -> None:
		source = self._rendered_dir()
		report = validateSourceSet(SPEC, source)
		self.assertTrue(report.ok, report.errors)
		self.assertEqual(len(report.observations), EXPECTED_CUE_COUNT)
		digests = {obs.sha256 for obs in report.observations}
		self.assertEqual(len(digests), EXPECTED_CUE_COUNT)
		for obs in report.observations:
			self.assertGreaterEqual(obs.frames, 1)
			self.assertLessEqual(obs.frames, SAMPLE_RATE_HZ)
			self.assertLessEqual(obs.durationMs, 1000)
			self.assertLessEqual(obs.sizeBytes, MAX_SIZE_BYTES)

	# --- rejection cases -----------------------------------------------------

	def test_missing_asset_is_rejected(self) -> None:
		source = self._rendered_dir()
		(source / SPEC.cues[0].path).unlink()
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("missing" in message for message in report.errors))

	def test_undeclared_file_is_rejected(self) -> None:
		source = self._rendered_dir()
		_write_wav(source / "intruder.wav")
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("undeclared" in message for message in report.errors))

	def test_duplicate_content_is_rejected(self) -> None:
		source = self._rendered_dir()
		donor = (source / SPEC.cues[0].path).read_bytes()
		_ = (source / SPEC.cues[1].path).write_bytes(donor)
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("identical audio" in message for message in report.errors))

	def test_wrong_format_is_rejected(self) -> None:
		source = self._rendered_dir()
		_write_wav(source / SPEC.cues[0].path, framerate=22050)
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("44100" in message for message in report.errors))

	def test_mono_is_rejected(self) -> None:
		source = self._rendered_dir()
		_write_wav(source / SPEC.cues[0].path, channels=1)
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("stereo" in message for message in report.errors))

	def test_over_duration_is_rejected(self) -> None:
		source = self._rendered_dir()
		_write_wav(source / SPEC.cues[0].path, frames=SAMPLE_RATE_HZ + 5000)
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("exceeds" in message for message in report.errors))

	def test_over_size_is_rejected(self) -> None:
		source = self._rendered_dir()
		target = source / SPEC.cues[0].path
		with target.open("ab") as handle:
			_ = handle.write(b"\x00" * (MAX_SIZE_BYTES + 64))
		report = validateSourceSet(SPEC, source)
		self.assertFalse(report.ok)
		self.assertTrue(any("bytes exceeds" in message for message in report.errors))

	def test_duplicate_path_in_spec_is_rejected(self) -> None:
		cues = list(SPEC.cues)
		cues[1] = dataclasses.replace(cues[1], path=cues[0].path)
		mutated = dataclasses.replace(SPEC, cues=tuple(cues))
		report = validateSpecStructure(mutated)
		self.assertFalse(report.ok)
		self.assertTrue(any("duplicate path" in message for message in report.errors))

	def test_positional_identity_mismatch_is_rejected(self) -> None:
		cues = list(SPEC.cues)
		cues[3] = dataclasses.replace(cues[3], cueId="renamedCue")
		mutated = dataclasses.replace(SPEC, cues=tuple(cues))
		report = validateSpecStructure(mutated)
		self.assertFalse(report.ok)
		self.assertTrue(any("expected id" in message for message in report.errors))

	def test_reordered_cues_are_rejected(self) -> None:
		raw = _raw_fixture()
		cues = list(raw["cues"])
		assert isinstance(cues, list)
		cues[5], cues[6] = cues[6], cues[5]
		raw["cues"] = cues
		with self.assertRaises(SoundThemeError):
			_ = parseSpec(raw)

	def test_authored_digest_is_rejected(self) -> None:
		raw = copy.deepcopy(_raw_fixture())
		first_cue = raw["cues"][0]
		assert isinstance(first_cue, dict)
		first_cue["sha256"] = "0" * 64
		with self.assertRaises(SoundThemeError):
			_ = parseSpec(raw)

	def test_obsolete_23_asset_inventory_is_rejected(self) -> None:
		cues = tuple(SPEC.cues[:23])
		mutated = dataclasses.replace(SPEC, cues=cues)
		report = validateSpecStructure(mutated)
		self.assertFalse(report.ok)
		self.assertTrue(any("expected 35" in message for message in report.errors))

	def test_extra_cue_beyond_inventory_is_rejected(self) -> None:
		extra = dataclasses.replace(SPEC.cues[0], index=35, cueId="extraCue", path="extra.wav")
		mutated = dataclasses.replace(SPEC, cues=(*SPEC.cues, extra))
		report = validateSpecStructure(mutated)
		self.assertFalse(report.ok)
		self.assertTrue(any("outside the closed inventory" in message for message in report.errors))

	# --- complete-inventory CLI gate ----------------------------------------

	def _run_cli(self, *argv: str) -> int:
		"""Drive the tool CLI against the committed spec, swallowing its output."""

		full = ["--spec", str(FIXTURE_PATH), *argv]
		with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			return main(full)

	def test_check_complete_passes_on_full_render(self) -> None:
		source = self._rendered_dir()
		self.assertEqual(self._run_cli("--source", str(source), "--check-complete"), 0)

	def test_check_complete_rejects_incomplete_inventory(self) -> None:
		source = self._rendered_dir()
		(source / SPEC.cues[0].path).unlink()
		self.assertEqual(self._run_cli("--source", str(source), "--check-complete"), 3)

	def test_check_complete_rejects_subset_only_directory(self) -> None:
		source = self._empty_dir()
		_ = writeTheme(SPEC, source, only=frozenset({SPEC.cues[0].path}))
		self.assertEqual(self._run_cli("--source", str(source), "--check-complete"), 3)


# --- probe evaluator contracts ------------------------------------------------

# Both probe evaluators map each exit code to exactly one status string.
STATUS_BY_EXIT = {0: "pass", 2: "unavailable", 3: "failed", 4: "unsafe"}


def _clean_uia() -> uiaProbe.RawUiaObservations:
	"""A fully valid raw-UIA observation set that must judge as a clean pass."""

	return uiaProbe.RawUiaObservations(
		callbackMaxMs=1.0,
		forwardingMaxMs=1.0,
		burst100MaxMs=10.0,
		receiptToProcessingMaxMs=5.0,
		receiptToPropertyReadMaxMs=5.0,
		eventFamiliesObserved=uiaProbe.EXPECTED_EVENT_FAMILIES,
		forwardingCount=1010,
		receiptCount=1010,
		observationWindowMs=uiaProbe.OBSERVATION_WINDOW_MS,
	)


def _clean_audio() -> soundProbe.AudioObservations:
	"""A fully valid audio observation set that must judge as a clean pass."""

	return soundProbe.AudioObservations(
		dispatchMaxMs=1.0,
		speechSubmitMaxMs=1.0,
		replacementStartMaxMs=1.0,
		interAtomGapMinMs=30.0,
		interAtomGapMaxMs=30.0,
		failureCasesObserved=soundProbe.EXPECTED_FAILURE_CASES,
		observationWindowMs=soundProbe.OBSERVATION_WINDOW_MS,
	)


class RawUiaProbeContractTests(unittest.TestCase):
	"""The raw-UIA probe evaluator must honor its schema, budgets, and exit matrix."""

	def test_clean_baseline_passes(self) -> None:
		result = uiaProbe.evaluate(_clean_uia())
		self.assertEqual(result.status, "pass")
		self.assertEqual(result.exitCode, uiaProbe.EXIT_PASS)

	def test_payload_emits_status_and_every_observation_field(self) -> None:
		result = uiaProbe.evaluate(_clean_uia())
		fields = {field.name for field in dataclasses.fields(uiaProbe.RawUiaObservations)}
		self.assertEqual(set(result.payload.keys()), {"status"} | fields)

	def test_result_prefix_is_stable(self) -> None:
		self.assertEqual(uiaProbe.RESULT_PREFIX, "KEYSTONE_RAW_UIA_PROBE_RESULT=")

	def test_every_violation_maps_to_its_exit_code(self) -> None:
		base = _clean_uia()
		replace = dataclasses.replace
		unavail = uiaProbe.EXIT_UNAVAILABLE
		failed = uiaProbe.EXIT_FAILED
		teardown = uiaProbe.EXIT_TEARDOWN
		cases: list[tuple[str, uiaProbe.RawUiaObservations, int]] = [
			("unavailable", replace(base, unavailableObservations=("client",)), unavail),
			("skipped", replace(base, skippedObservations=("focus",)), unavail),
			("missing", replace(base, missingObservations=("burst",)), unavail),
			("callback_over", replace(base, callbackMaxMs=uiaProbe.CALLBACK_MAX_MS + 0.1), failed),
			("forwarding_over", replace(base, forwardingMaxMs=uiaProbe.FORWARDING_MAX_MS + 0.1), failed),
			("burst_over", replace(base, burst100MaxMs=uiaProbe.BURST100_MAX_MS + 0.1), failed),
			(
				"processing_over",
				replace(base, receiptToProcessingMaxMs=uiaProbe.RECEIPT_TO_PROCESSING_MAX_MS + 0.1),
				failed,
			),
			(
				"property_read_over",
				replace(base, receiptToPropertyReadMaxMs=uiaProbe.RECEIPT_TO_PROPERTY_READ_MAX_MS + 0.1),
				failed,
			),
			(
				"missing_family",
				replace(base, eventFamiliesObserved=uiaProbe.EXPECTED_EVENT_FAMILIES[:-1]),
				failed,
			),
			("count_mismatch", replace(base, forwardingCount=base.receiptCount - 1), failed),
			("no_receipts", replace(base, forwardingCount=0, receiptCount=0), failed),
			("pid_mismatch", replace(base, pidMismatchAccepted=1), failed),
			("ownership", replace(base, ownershipViolations=1), failed),
			("window", replace(base, observationWindowMs=200), failed),
			("late_callback", replace(base, lateCallbacksAccepted=1), teardown),
			("subs_after_teardown", replace(base, subscriptionsAfterTeardown=1), teardown),
			("retained_after_teardown", replace(base, retainedMutationsAfterTeardown=1), teardown),
			("secure_mutation", replace(base, secureMutations=1), teardown),
			(
				"unavailable_outranks_teardown",
				replace(base, missingObservations=("x",), lateCallbacksAccepted=1),
				unavail,
			),
			(
				"teardown_outranks_failed",
				replace(base, lateCallbacksAccepted=1, ownershipViolations=1),
				teardown,
			),
		]
		for label, obs, expected_exit in cases:
			with self.subTest(case=label):
				result = uiaProbe.evaluate(obs)
				self.assertEqual(result.exitCode, expected_exit)
				self.assertEqual(result.status, STATUS_BY_EXIT[expected_exit])


class SoundProbeContractTests(unittest.TestCase):
	"""The sound-playback probe evaluator must honor its schema, budgets, and exit matrix."""

	def test_clean_baseline_passes(self) -> None:
		result = soundProbe.evaluate(_clean_audio())
		self.assertEqual(result.status, "pass")
		self.assertEqual(result.exitCode, soundProbe.EXIT_PASS)

	def test_payload_emits_status_and_every_observation_field(self) -> None:
		result = soundProbe.evaluate(_clean_audio())
		fields = {field.name for field in dataclasses.fields(soundProbe.AudioObservations)}
		self.assertEqual(set(result.payload.keys()), {"status"} | fields)

	def test_result_prefix_is_stable(self) -> None:
		self.assertEqual(soundProbe.RESULT_PREFIX, "KEYSTONE_AUDIO_PROBE_RESULT=")

	def test_every_violation_maps_to_its_exit_code(self) -> None:
		base = _clean_audio()
		replace = dataclasses.replace
		unavail = soundProbe.EXIT_UNAVAILABLE
		failed = soundProbe.EXIT_FAILED
		teardown = soundProbe.EXIT_TEARDOWN
		extra_cases = (*soundProbe.EXPECTED_FAILURE_CASES, "surprise")
		cases: list[tuple[str, soundProbe.AudioObservations, int]] = [
			("unavailable", replace(base, unavailableObservations=("device",)), unavail),
			("skipped", replace(base, skippedObservations=("playback",)), unavail),
			("missing", replace(base, missingObservations=("startsAccepted",)), unavail),
			("dispatch_over", replace(base, dispatchMaxMs=soundProbe.DISPATCH_MAX_MS + 0.1), failed),
			("speech_over", replace(base, speechSubmitMaxMs=soundProbe.SPEECH_SUBMIT_MAX_MS + 0.1), failed),
			(
				"replacement_over",
				replace(base, replacementStartMaxMs=soundProbe.REPLACEMENT_START_MAX_MS + 0.1),
				failed,
			),
			(
				"gap_too_small",
				replace(base, interAtomGapMinMs=soundProbe.INTER_ATOM_GAP_MIN_MS - 0.1),
				failed,
			),
			(
				"gap_too_large",
				replace(base, interAtomGapMaxMs=soundProbe.INTER_ATOM_GAP_MAX_MS + 0.1),
				failed,
			),
			("gap_inverted", replace(base, interAtomGapMinMs=30.0, interAtomGapMaxMs=25.0), failed),
			("overlap", replace(base, overlapCount=1), failed),
			("stale_atom", replace(base, staleAtomsStarted=1), failed),
			("workflow_mutation", replace(base, workflowMutationFailures=1), failed),
			(
				"missing_failure_case",
				replace(base, failureCasesObserved=soundProbe.EXPECTED_FAILURE_CASES[:-1]),
				failed,
			),
			("extra_failure_case", replace(base, failureCasesObserved=extra_cases), failed),
			("window", replace(base, observationWindowMs=200), failed),
			("late_callback", replace(base, lateCallbacksAccepted=1), teardown),
			("queued_after_teardown", replace(base, queuedSoundsAfterTeardown=1), teardown),
			("started_after_teardown", replace(base, soundsStartedAfterTeardown=1), teardown),
			(
				"unavailable_outranks_teardown",
				replace(base, missingObservations=("x",), lateCallbacksAccepted=1),
				unavail,
			),
			("teardown_outranks_failed", replace(base, lateCallbacksAccepted=1, overlapCount=1), teardown),
		]
		for label, obs, expected_exit in cases:
			with self.subTest(case=label):
				result = soundProbe.evaluate(obs)
				self.assertEqual(result.exitCode, expected_exit)
				self.assertEqual(result.status, STATUS_BY_EXIT[expected_exit])


def _clean_inspector() -> inspectorProbe.LiveInspectorObservations:
	"""A fully valid live-Inspector observation set that must judge as a clean pass."""

	return inspectorProbe.LiveInspectorObservations(
		sourceBuilt=True,
		identityKind="live",
		executable="reader.exe",
		processId=42,
		rawReason="",
		followFocusAvailable=True,
		rootCount=3,
		serviceIdentityLive=True,
		closedCleanly=True,
		buildMaxMs=12.0,
		focusExecutable="reader.exe",
		focusProcessId=42,
		foregroundExecutable="reader.exe",
		foregroundProcessId=42,
	)


class LiveInspectorProbeContractTests(unittest.TestCase):
	"""The live-Inspector probe evaluator must honor its schema, budget, and exit matrix."""

	def test_clean_baseline_passes(self) -> None:
		result = inspectorProbe.evaluate(_clean_inspector())
		self.assertEqual(result.status, "pass")
		self.assertEqual(result.exitCode, inspectorProbe.EXIT_PASS)

	def test_payload_emits_status_and_every_observation_field(self) -> None:
		result = inspectorProbe.evaluate(_clean_inspector())
		fields = {field.name for field in dataclasses.fields(inspectorProbe.LiveInspectorObservations)}
		self.assertEqual(set(result.payload.keys()), {"status"} | fields)

	def test_result_prefix_is_stable(self) -> None:
		self.assertEqual(inspectorProbe.RESULT_PREFIX, "KEYSTONE_LIVE_INSPECTOR_PROBE_RESULT=")

	def test_default_run_is_withheld_without_composition(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			root = Path(tmp)
			executable = root / "nvda.exe"
			_ = executable.write_bytes(b"stub")
			profile = root / "profile"
			profile.mkdir()
			observations = inspectorProbe.collect(executable, profile, root / "ws")
		self.assertTrue(observations.skippedObservations)
		self.assertFalse(observations.sourceBuilt)
		result = inspectorProbe.evaluate(observations)
		self.assertEqual(result.exitCode, inspectorProbe.EXIT_UNAVAILABLE)

	def test_missing_executable_is_unavailable(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			root = Path(tmp)
			profile = root / "profile"
			profile.mkdir()
			observations = inspectorProbe.collect(
				root / "absent.exe",
				profile,
				root / "ws",
				allowComposition=True,
			)
		self.assertTrue(observations.unavailableObservations)
		self.assertEqual(inspectorProbe.evaluate(observations).exitCode, inspectorProbe.EXIT_UNAVAILABLE)

	def test_every_violation_maps_to_its_exit_code(self) -> None:
		base = _clean_inspector()
		replace = dataclasses.replace
		unavail = inspectorProbe.EXIT_UNAVAILABLE
		failed = inspectorProbe.EXIT_FAILED
		cases: list[tuple[str, inspectorProbe.LiveInspectorObservations, int]] = [
			("unavailable", replace(base, unavailableObservations=("api",)), unavail),
			("skipped", replace(base, skippedObservations=("composition",)), unavail),
			("missing", replace(base, missingObservations=("focus",)), unavail),
			("not_built", replace(base, sourceBuilt=False), failed),
			("not_live", replace(base, identityKind="offline"), failed),
			("no_follow_focus", replace(base, followFocusAvailable=False), failed),
			("raw_reason_leak", replace(base, rawReason="budget"), failed),
			("empty_hierarchy", replace(base, rootCount=0), failed),
			("service_not_live", replace(base, serviceIdentityLive=False), failed),
			("dirty_close", replace(base, closedCleanly=False), failed),
			("no_executable", replace(base, executable=""), failed),
			("negative_pid", replace(base, processId=-1, focusProcessId=-1), failed),
			("pid_mismatch", replace(base, processId=99), failed),
			("over_budget", replace(base, buildMaxMs=inspectorProbe.BUILD_MAX_MS + 0.1), failed),
			(
				"unavailable_outranks_failed",
				replace(base, missingObservations=("x",), sourceBuilt=False),
				unavail,
			),
		]
		for label, obs, expected_exit in cases:
			with self.subTest(case=label):
				result = inspectorProbe.evaluate(obs)
				self.assertEqual(result.exitCode, expected_exit)
				self.assertEqual(result.status, STATUS_BY_EXIT[expected_exit])


if __name__ == "__main__":
	_ = unittest.main()
