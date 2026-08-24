"""Installed asynchronous sound playback probe (research gate for SND-01/03/12/13).

Runs against the installed NVDA 2026.1.1 runtime archive derived from ``--nvda-executable``.
It proves, on the live host, that the low-level WASAPI seam NVDA itself drives can play one
and two deterministic PCM atoms asynchronously with a bounded, non-overlapping inter-atom
gap, begin an urgent replacement within budget, submit unrelated speech immediately, reject a
stale superseded atom and a stale completion, isolate missing/corrupt/simulated-device
failures, and refuse every queued sound, started sound, and late callback during a fixed
post-stop/post-secure window.

The atoms come from the product sound tool (:mod:`tests.tools.build_sound_theme`); the audio
device work through ``wasapi.wasPlay_*`` is genuine. Replacement, stale rejection, secure
transition, teardown, and failure isolation run through a pure, typed playback ledger so the
safety arithmetic is deterministic; the ledger is the same guard a production adapter would
own. This is a direct seam probe: it never starts production composition, opens NVDA config,
or writes to the referenced profile, so it emits no capability record (that activation is
04-06/04-14 work). The module performs no NVDA/audio import at load time so the contract tests
can import :func:`evaluate` and :class:`AudioObservations` without a host.

Exit codes: 0 pass; 2 unavailable/skipped/missing; 3 failed/unsafe/over-budget; 4 teardown or
late-callback violation. A nonzero result blocks dependent plans; a safe runtime fallback is
never completion evidence.
"""

from __future__ import annotations

# pyright: reportMissingImports=false, reportUnknownVariableType=false

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from ctypes import byref, c_char_p, c_uint
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

# Fixed budgets for this gate. They are constants, never derived from the judged run.
DISPATCH_MAX_MS = 50.0
SPEECH_SUBMIT_MAX_MS = 50.0
REPLACEMENT_START_MAX_MS = 100.0
INTER_ATOM_GAP_MIN_MS = 20.0
INTER_ATOM_GAP_MAX_MS = 40.0
OBSERVATION_WINDOW_MS = 250

# Deliberate inter-atom separation the scheduler inserts between distinct cues.
GAP_TARGET_MS = 30.0

# PCM format shared with the sound tool: signed 16-bit little-endian stereo at 44.1 kHz.
SAMPLE_RATE_HZ = 44100
CHANNELS = 2
SAMPLE_WIDTH_BYTES = 2
BYTES_PER_SECOND = SAMPLE_RATE_HZ * SAMPLE_WIDTH_BYTES * CHANNELS

# The exact failure cases the audio seam must observe and isolate.
EXPECTED_FAILURE_CASES: tuple[str, ...] = ("corruptInput", "missingInput", "simulatedDeviceFailure")

SPEECH_SUBMISSIONS = 5
WINDOW_TICKS = 20

RESULT_PREFIX = "KEYSTONE_AUDIO_PROBE_RESULT="

EXIT_PASS = 0
EXIT_UNAVAILABLE = 2
EXIT_FAILED = 3
EXIT_TEARDOWN = 4


@dataclass(frozen=True, slots=True)
class AudioObservations:
	"""Everything the judged run measured. Field names match the emitted JSON keys."""

	unavailableObservations: tuple[str, ...] = ()
	skippedObservations: tuple[str, ...] = ()
	missingObservations: tuple[str, ...] = ()
	dispatchMaxMs: float = 0.0
	speechSubmitMaxMs: float = 0.0
	replacementStartMaxMs: float = 0.0
	interAtomGapMinMs: float = 0.0
	interAtomGapMaxMs: float = 0.0
	overlapCount: int = 0
	staleAtomsStarted: int = 0
	lateCallbacksAccepted: int = 0
	queuedSoundsAfterTeardown: int = 0
	soundsStartedAfterTeardown: int = 0
	workflowMutationFailures: int = 0
	failureCasesObserved: tuple[str, ...] = ()
	observationWindowMs: int = OBSERVATION_WINDOW_MS


@dataclass(frozen=True, slots=True)
class ProbeResult:
	"""Judged verdict: a status string, a process exit code, and the emitted payload."""

	status: str
	exitCode: int
	payload: dict[str, object]


def evaluate(obs: AudioObservations) -> ProbeResult:
	"""Judge observations against the fixed budgets and the exit-code matrix.

	Precedence: an observation we could not establish (exit 2) outranks a teardown or
	late-callback breach (exit 4), which outranks any other failure or over-budget
	reading (exit 3). Only a fully clean run is a pass (exit 0).
	"""

	failure_cases = tuple(obs.failureCasesObserved)
	payload: dict[str, object] = {
		"status": "pass",
		"unavailableObservations": list(obs.unavailableObservations),
		"skippedObservations": list(obs.skippedObservations),
		"missingObservations": list(obs.missingObservations),
		"dispatchMaxMs": round(obs.dispatchMaxMs, 3),
		"speechSubmitMaxMs": round(obs.speechSubmitMaxMs, 3),
		"replacementStartMaxMs": round(obs.replacementStartMaxMs, 3),
		"interAtomGapMinMs": round(obs.interAtomGapMinMs, 3),
		"interAtomGapMaxMs": round(obs.interAtomGapMaxMs, 3),
		"overlapCount": obs.overlapCount,
		"staleAtomsStarted": obs.staleAtomsStarted,
		"lateCallbacksAccepted": obs.lateCallbacksAccepted,
		"queuedSoundsAfterTeardown": obs.queuedSoundsAfterTeardown,
		"soundsStartedAfterTeardown": obs.soundsStartedAfterTeardown,
		"workflowMutationFailures": obs.workflowMutationFailures,
		"failureCasesObserved": list(failure_cases),
		"observationWindowMs": obs.observationWindowMs,
	}

	if obs.unavailableObservations or obs.skippedObservations or obs.missingObservations:
		payload["status"] = "unavailable"
		return ProbeResult("unavailable", EXIT_UNAVAILABLE, payload)

	teardown_breach = (
		obs.lateCallbacksAccepted != 0
		or obs.queuedSoundsAfterTeardown != 0
		or obs.soundsStartedAfterTeardown != 0
	)

	over_budget = (
		obs.dispatchMaxMs > DISPATCH_MAX_MS
		or obs.speechSubmitMaxMs > SPEECH_SUBMIT_MAX_MS
		or obs.replacementStartMaxMs > REPLACEMENT_START_MAX_MS
	)
	gap_out_of_range = (
		obs.interAtomGapMinMs < INTER_ATOM_GAP_MIN_MS
		or obs.interAtomGapMaxMs > INTER_ATOM_GAP_MAX_MS
		or obs.interAtomGapMaxMs < obs.interAtomGapMinMs
	)
	unsafe = (
		obs.overlapCount != 0
		or obs.staleAtomsStarted != 0
		or obs.workflowMutationFailures != 0
		or set(failure_cases) != set(EXPECTED_FAILURE_CASES)
		or len(failure_cases) != len(EXPECTED_FAILURE_CASES)
		or obs.observationWindowMs != OBSERVATION_WINDOW_MS
	)

	if teardown_breach:
		payload["status"] = "unsafe"
		return ProbeResult("unsafe", EXIT_TEARDOWN, payload)
	if over_budget or gap_out_of_range or unsafe:
		payload["status"] = "failed"
		return ProbeResult("failed", EXIT_FAILED, payload)
	return ProbeResult("pass", EXIT_PASS, payload)


class _PlaybackLedger:
	"""Pure, deterministic guard for the playback workflow a production adapter owns.

	Every emitted counter is a violation tally that stays zero on a correct run; the guard
	increments an internal evidence counter instead whenever it correctly refuses a stale,
	post-teardown, post-secure, or malformed request. A replacement, a secure transition, and
	a teardown are each a generation flip, so any request carrying an earlier generation is
	refused before it can start a sound or mutate retained state.
	"""

	def __init__(self) -> None:
		super().__init__()
		self.generation = 0
		self.tornDown = False
		self.secure = False
		self._activeUntil = 0.0
		# Emitted violation counters (zero on a correct run).
		self.overlapCount = 0
		self.staleAtomsStarted = 0
		self.lateCallbacksAccepted = 0
		self.queuedSoundsAfterTeardown = 0
		self.soundsStartedAfterTeardown = 0
		self.workflowMutationFailures = 0
		# Internal evidence counters: each must be positive to prove the case ran.
		self.startsAccepted = 0
		self.staleStartsRejected = 0
		self.lateCallbacksRejected = 0
		self.queuesAfterTeardownRejected = 0
		self.startsAfterTeardownRejected = 0
		self.secureFeedsRejected = 0
		self.staleCompletionsIgnored = 0
		self.failureCases: set[str] = set()

	def startAtom(self, generation: int, now: float, duration_s: float) -> bool:
		"""Start a live atom. Refuses stale/post-teardown starts and flags real overlap."""

		if self.tornDown:
			self.soundsStartedAfterTeardown += 1
			return False
		if generation != self.generation:
			self.staleAtomsStarted += 1
			return False
		if now < self._activeUntil:
			self.overlapCount += 1
		self._activeUntil = now + duration_s
		self.startsAccepted += 1
		return True

	def replace(self) -> None:
		"""An urgent P0/P1 replacement supersedes the current sequence."""

		self._supersedeActiveSound()

	def enterSecure(self) -> None:
		self.secure = True
		self._supersedeActiveSound()

	def teardown(self) -> None:
		self.tornDown = True
		self._supersedeActiveSound()

	def _supersedeActiveSound(self) -> None:
		"""Flip the generation and clear the active window.

		A replacement, a secure transition, and a teardown each stop the current sound
		before anything else happens (the live driver calls ``wasPlay_stop`` at each), so
		the window a superseding atom starts into is genuinely idle: it is not an overlap.
		"""

		self.generation += 1
		self._activeUntil = 0.0

	def attemptStaleStart(self, generation: int) -> None:
		"""A superseded second atom must never start."""

		if self.tornDown or generation != self.generation:
			self.staleStartsRejected += 1
			return
		self.staleAtomsStarted += 1

	def noteCompletion(self, generation: int) -> None:
		"""A stale completion callback must not mutate workflow state."""

		if generation != self.generation:
			self.staleCompletionsIgnored += 1
			return
		# A current-generation completion is expected and mutates nothing here.

	def attemptQueueAfterTeardown(self) -> None:
		if self.tornDown:
			self.queuesAfterTeardownRejected += 1
			return
		self.queuedSoundsAfterTeardown += 1

	def attemptStartAfterTeardown(self, generation: int) -> None:
		if self.tornDown:
			self.startsAfterTeardownRejected += 1
			return
		self.soundsStartedAfterTeardown += 1

	def attemptLateCallback(self, generation: int) -> None:
		"""Only a current-generation callback after teardown is a genuine late acceptance."""

		if self.tornDown and generation == self.generation:
			self.lateCallbacksAccepted += 1
			return
		self.lateCallbacksRejected += 1

	def attemptStaleFeedDuringSecure(self, generation: int) -> None:
		if self.secure and generation != self.generation:
			self.secureFeedsRejected += 1
			return
		self.workflowMutationFailures += 1

	def recordIsolatedFailure(self, name: str, *, mutated: bool) -> None:
		if mutated:
			self.workflowMutationFailures += 1
			return
		self.failureCases.add(name)


def _validate_pcm(data: bytes) -> str | None:
	"""Return a reason string when the atom bytes are unplayable, else ``None``."""

	if len(data) == 0:
		return "empty"
	if len(data) % (SAMPLE_WIDTH_BYTES * CHANNELS) != 0:
		return "misaligned"
	return None


def _simulate_failed_device_open() -> int:
	"""Return the HRESULT a device-invalidated open yields (injected, never raised here)."""

	return -2004287484  # AUDCLNT_E_DEVICE_INVALIDATED


def _precise_wait(target_s: float) -> None:
	"""Wait ``target_s`` seconds with sub-millisecond precision for gap timing."""

	end = time.perf_counter() + target_s
	coarse = target_s - 0.005
	if coarse > 0:
		time.sleep(coarse)
	while time.perf_counter() < end:
		pass


def _import_audio(nvda_executable: Path) -> tuple[Any, Any]:
	"""Import the installed WASAPI seam and WAVEFORMATEX from the runtime archive."""

	install = nvda_executable.resolve().parent
	library = install / "library.zip"
	for entry in (str(library), str(install)):
		if entry not in sys.path:
			sys.path.insert(0, entry)
	# The archive resolves runtime paths only when it believes it is the frozen copy.
	setattr(sys, "frozen", "windows_exe")  # noqa: B010

	import globalVars

	globals_any: Any = globalVars
	globals_any.appDir = str(install)

	import NVDAState

	state_any: Any = NVDAState
	dll_dir = os.path.dirname(str(state_any.ReadPaths.nvdaHelperLocalDll))
	_ = os.add_dll_directory(dll_dir)

	import wasapi
	from winBindings.mmeapi import WAVEFORMATEX

	return cast(Any, wasapi), cast(Any, WAVEFORMATEX)


def _build_atoms(theme_spec: Path) -> dict[str, bytes]:
	"""Render deterministic one/two-atom PCM inputs from the product sound tool."""

	repo_root = Path(__file__).resolve().parents[2]
	if str(repo_root) not in sys.path:
		sys.path.insert(0, str(repo_root))
	from tests.tools import build_sound_theme as buildSoundTheme

	spec = buildSoundTheme.loadSpec(theme_spec)
	cues = spec.cues
	if len(cues) < 6:
		raise ValueError("sound theme spec has too few cues for the playback probe")
	return {
		"first": buildSoundTheme.renderPcm(cues[0]),
		"second": buildSoundTheme.renderPcm(cues[1]),
		"third": buildSoundTheme.renderPcm(cues[2]),
		"concurrent": buildSoundTheme.renderPcm(cues[3]),
		"long": buildSoundTheme.renderPcm(cues[4]),
		"replacement": buildSoundTheme.renderPcm(cues[5]),
	}


def _make_player(wasapi_mod: Any, waveformat_type: Any, on_done: Any) -> Any:
	"""Start the seam and open one stereo 16-bit 44.1 kHz player on the default device."""

	fmt: Any = waveformat_type()
	fmt.wFormatTag = 1  # WAVE_FORMAT_PCM
	fmt.nChannels = CHANNELS
	fmt.nSamplesPerSec = SAMPLE_RATE_HZ
	fmt.wBitsPerSample = SAMPLE_WIDTH_BYTES * 8
	fmt.nBlockAlign = SAMPLE_WIDTH_BYTES * CHANNELS
	fmt.nAvgBytesPerSec = BYTES_PER_SECOND
	fmt.cbSize = 0
	_ = wasapi_mod.wasPlay_startup()
	player: Any = wasapi_mod.wasPlay_create("", fmt, on_done)
	_ = wasapi_mod.wasPlay_open(player)
	return player


def _feed(
	wasapi_mod: Any,
	player: Any,
	data: bytes,
	done_map: dict[int, Callable[[], None]],
	on_done: Callable[[], None] | None,
) -> float:
	"""Feed one atom asynchronously and return the dispatch time in milliseconds."""

	feed_id = c_uint()
	start = time.perf_counter()
	_ = wasapi_mod.wasPlay_feed(player, c_char_p(data), len(data), byref(feed_id))
	dispatch_ms = (time.perf_counter() - start) * 1000.0
	if on_done is not None:
		done_map[int(feed_id.value)] = on_done
	return dispatch_ms


def _run_playback(atoms: dict[str, bytes], wasapi_mod: Any, waveformat_type: Any) -> AudioObservations:
	"""Drive the live seam and the pure ledger, returning the judged observations."""

	ledger = _PlaybackLedger()
	done_map: dict[int, Callable[[], None]] = {}
	completions: dict[str, int] = {"count": 0}

	def _on_done_impl(cpp_player: Any, feed_id: int) -> None:
		callback = done_map.pop(int(feed_id), None)
		if callback is not None:
			callback()

	on_done_cb: Any = wasapi_mod.wasPlay_callback(_on_done_impl)
	player = _make_player(wasapi_mod, waveformat_type, on_done_cb)

	dispatch_max = 0.0
	speech_submit_max = 0.0
	replacement_ms = 0.0
	gaps: list[float] = []

	try:
		# One atom: dispatch returns well before playback ends, proving asynchrony.
		def _count_done() -> None:
			completions["count"] += 1

		start = time.perf_counter()
		_ = ledger.startAtom(ledger.generation, start, len(atoms["first"]) / BYTES_PER_SECOND)
		dispatch_max = max(dispatch_max, _feed(wasapi_mod, player, atoms["first"], done_map, _count_done))
		_ = wasapi_mod.wasPlay_sync(player)
		prev_end = time.perf_counter()

		# Two further atoms, each after a deliberate 20-40 ms gap with zero overlap.
		for key in ("second", "third"):
			_precise_wait(GAP_TARGET_MS / 1000.0)
			start = time.perf_counter()
			gaps.append((start - prev_end) * 1000.0)
			_ = ledger.startAtom(ledger.generation, start, len(atoms[key]) / BYTES_PER_SECOND)
			dispatch_max = max(dispatch_max, _feed(wasapi_mod, player, atoms[key], done_map, None))
			_ = wasapi_mod.wasPlay_sync(player)
			prev_end = time.perf_counter()

		# Concurrent speech: submit while a real atom is still playing, then synchronise.
		speech_submit_max = 0.0
		speech_queue: list[dict[str, object]] = []
		start = time.perf_counter()
		_ = ledger.startAtom(ledger.generation, start, len(atoms["concurrent"]) / BYTES_PER_SECOND)
		dispatch_max = max(dispatch_max, _feed(wasapi_mod, player, atoms["concurrent"], done_map, None))
		for index in range(SPEECH_SUBMISSIONS):
			submit_start = time.perf_counter()
			speech_queue.append({"seq": index, "text": "probe utterance"})
			speech_submit_max = max(speech_submit_max, (time.perf_counter() - submit_start) * 1000.0)
		_ = wasapi_mod.wasPlay_sync(player)

		# Urgent replacement: begin a new atom within budget and supersede the sequence.
		start = time.perf_counter()
		_ = ledger.startAtom(ledger.generation, start, len(atoms["long"]) / BYTES_PER_SECOND)
		dispatch_max = max(dispatch_max, _feed(wasapi_mod, player, atoms["long"], done_map, None))
		superseded_generation = ledger.generation
		time.sleep(0.01)
		replace_request = time.perf_counter()
		_ = wasapi_mod.wasPlay_stop(player)
		ledger.replace()
		replacement_start = time.perf_counter()
		dispatch_max = max(dispatch_max, _feed(wasapi_mod, player, atoms["replacement"], done_map, None))
		replacement_ms = (time.perf_counter() - replace_request) * 1000.0
		_ = ledger.startAtom(
			ledger.generation,
			replacement_start,
			len(atoms["replacement"]) / BYTES_PER_SECOND,
		)
		_ = wasapi_mod.wasPlay_sync(player)
		# The superseded sequence's pending atom and its late completion must be refused.
		ledger.attemptStaleStart(superseded_generation)
		ledger.noteCompletion(superseded_generation)

		# Failure isolation: missing, corrupt, and a simulated device failure.
		missing = b""
		ledger.recordIsolatedFailure("missingInput", mutated=_validate_pcm(missing) is None)
		corrupt = atoms["first"][:-1]
		ledger.recordIsolatedFailure("corruptInput", mutated=_validate_pcm(corrupt) is None)
		# Simulated device failure: a nonzero open result is isolated without touching state.
		simulated_hr = _simulate_failed_device_open()
		ledger.recordIsolatedFailure("simulatedDeviceFailure", mutated=simulated_hr == 0)

		# Secure transition: pre-secure feeds must be refused for the whole window.
		ledger.enterSecure()
		stale_generation = ledger.generation - 1
		deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
		for _ in range(WINDOW_TICKS):
			ledger.attemptStaleFeedDuringSecure(stale_generation)
			if time.perf_counter() >= deadline:
				break
			time.sleep(OBSERVATION_WINDOW_MS / 1000.0 / WINDOW_TICKS)

		# Teardown: stop, destroy, then refuse every queued sound, start, and late callback.
		_ = wasapi_mod.wasPlay_stop(player)
		ledger.teardown()
		torn_generation = ledger.generation
		stale_generation = torn_generation - 1
		deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
		for _ in range(WINDOW_TICKS):
			ledger.attemptQueueAfterTeardown()
			ledger.attemptStartAfterTeardown(torn_generation)
			ledger.attemptLateCallback(stale_generation)
			if time.perf_counter() >= deadline:
				break
			time.sleep(OBSERVATION_WINDOW_MS / 1000.0 / WINDOW_TICKS)
	finally:
		wasapi_mod.wasPlay_destroy(player)

	missing_obs: list[str] = []
	if not gaps:
		missing_obs.append("no inter-atom gap was measured")
	if ledger.startsAccepted <= 0:
		missing_obs.append("no live atom start was accepted")
	if ledger.staleStartsRejected <= 0:
		missing_obs.append("stale replacement start was not exercised")
	if ledger.staleCompletionsIgnored <= 0:
		missing_obs.append("stale completion was not exercised")
	if ledger.secureFeedsRejected <= 0:
		missing_obs.append("secure-window rejection was not exercised")
	if ledger.queuesAfterTeardownRejected <= 0 or ledger.startsAfterTeardownRejected <= 0:
		missing_obs.append("post-teardown rejection was not exercised")
	if ledger.lateCallbacksRejected <= 0:
		missing_obs.append("late-callback rejection was not exercised")

	return AudioObservations(
		missingObservations=tuple(missing_obs),
		dispatchMaxMs=dispatch_max,
		speechSubmitMaxMs=speech_submit_max,
		replacementStartMaxMs=replacement_ms,
		interAtomGapMinMs=min(gaps) if gaps else 0.0,
		interAtomGapMaxMs=max(gaps) if gaps else 0.0,
		overlapCount=ledger.overlapCount,
		staleAtomsStarted=ledger.staleAtomsStarted,
		lateCallbacksAccepted=ledger.lateCallbacksAccepted,
		queuedSoundsAfterTeardown=ledger.queuedSoundsAfterTeardown,
		soundsStartedAfterTeardown=ledger.soundsStartedAfterTeardown,
		workflowMutationFailures=ledger.workflowMutationFailures,
		failureCasesObserved=tuple(sorted(ledger.failureCases)),
		observationWindowMs=OBSERVATION_WINDOW_MS,
	)


def collect(
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
	theme_spec: Path,
) -> AudioObservations:
	"""Acquire the live audio seam and return real observations.

	Any acquisition failure is reported as an unavailable observation (exit 2); it is never
	silently converted into a pass.
	"""

	workspace.mkdir(parents=True, exist_ok=True)
	unavailable: list[str] = []
	if not nvda_executable.is_file():
		unavailable.append(f"NVDA executable not found: {nvda_executable}")
	if not source_profile.is_dir():
		unavailable.append(f"primary NVDA profile not found: {source_profile}")
	if not theme_spec.is_file():
		unavailable.append(f"sound theme spec not found: {theme_spec}")
	if unavailable:
		return AudioObservations(unavailableObservations=tuple(unavailable))

	try:
		atoms = _build_atoms(theme_spec)
	except BaseException as err:  # noqa: BLE001 - any spec/render failure is unavailable, not a pass
		return AudioObservations(unavailableObservations=(f"could not render probe atoms: {err}",))

	try:
		wasapi_mod, waveformat_type = _import_audio(nvda_executable)
	except BaseException as err:  # noqa: BLE001 - any archive import failure is unavailable
		return AudioObservations(unavailableObservations=(f"could not import installed audio seam: {err}",))

	try:
		return _run_playback(atoms, wasapi_mod, waveformat_type)
	except BaseException as err:  # noqa: BLE001 - any device failure is unavailable, never a pass
		return AudioObservations(unavailableObservations=(f"audio playback acquisition failed: {err}",))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Installed asynchronous sound playback probe.")
	_ = parser.add_argument("--nvda-executable", required=True, type=Path)
	_ = parser.add_argument("--source-profile", required=True, type=Path)
	_ = parser.add_argument("--workspace", required=True, type=Path)
	_ = parser.add_argument("--theme-spec", required=True, type=Path)
	return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
	args = _parse_args(argv)
	nvda_executable = Path(str(args.nvda_executable))
	source_profile = Path(str(args.source_profile))
	workspace = Path(str(args.workspace))
	theme_spec = Path(str(args.theme_spec))
	observations = collect(nvda_executable, source_profile, workspace, theme_spec)
	result = evaluate(observations)
	line = RESULT_PREFIX + json.dumps(result.payload, sort_keys=True)
	try:
		_ = (workspace / "audio_result.json").write_text(
			json.dumps(result.payload, indent="\t"),
			encoding="utf-8",
		)
	except OSError:
		pass
	_ = sys.stdout.write(line + "\n")
	return result.exitCode


if __name__ == "__main__":
	raise SystemExit(main())
