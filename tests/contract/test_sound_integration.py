from __future__ import annotations

# pyright: reportPrivateUsage=false

import io
import tempfile
import unittest
import wave
from collections.abc import Callable
from pathlib import Path

from addon.globalPlugins.keystone.adapters.nvda.audio import (
	AudioAtomRejected,
	AudioAtomUnavailable,
	NvdaWaveAudioPort,
	SoundThemeManifest,
	_WasapiWaveOut,
)
from addon.globalPlugins.keystone.application.sound_service import SoundService
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.settings import SettingId, SettingsSnapshot
from addon.globalPlugins.keystone.domain.sounds import (
	CUE_GRAMMAR,
	FIRST_PROGRESS_DELAY_MILLISECONDS,
	MINIMUM_PROGRESS_INTERVAL_MILLISECONDS,
	CueAtomId,
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	SoundScheduler,
	soundRequestFor,
)
from addon.globalPlugins.keystone.ports.audio import AudioOutcome, AudioPlayback
from addon.globalPlugins.keystone.ports.effects import EffectResult, FeedbackRequest, PortStatus


def _speech(messageId: str = "capture.start", generation: int = 1) -> FeedbackRequest:
	return FeedbackRequest(
		messageId=messageId,
		arguments=(),
		context=CorrelationFactory().admit(generation=generation),
	)


def _captureOwner(generation: int = 1) -> SoundOwner:
	return SoundOwner(SoundOwnerKind.CAPTURE, generation)


def _ownerKindFor(event: CueEventId) -> SoundOwnerKind:
	# The owner kind each surface stamps on its cue so invalidation stays scoped to that workflow.
	name = event.name
	if name.startswith("LAYER_"):
		return SoundOwnerKind.LAYER
	if name.startswith(("START_", "CAPTURE_", "DIFF_")):
		return SoundOwnerKind.CAPTURE
	if name.startswith(("OPEN_", "REFRESH_", "INSPECTOR_", "QUICK_PROPERTY_")):
		return SoundOwnerKind.INSPECTOR
	if name.startswith("EVENT_EXPORT_"):
		return SoundOwnerKind.EXPORT
	if name.startswith("EVENT_MONITOR_") or name.endswith("_DROP"):
		return SoundOwnerKind.MONITOR
	if name in ("OUTPUT_PATH_COPY", "EXPLORER_REVEAL", "COMMAND_HELP_OPENED"):
		return SoundOwnerKind.COMMAND
	# The cross-cutting safety warnings are owned by the shared system generation.
	return SoundOwnerKind.SYSTEM


def _activeFamilyAtomFor(event: CueEventId) -> CueAtomId:
	# Active-family cues bind their family atom at request time from the owning workflow.
	if _ownerKindFor(event) is SoundOwnerKind.INSPECTOR:
		return CueAtomId.FOCUS_INSPECTOR_FAMILY
	return CueAtomId.BOUNDED_FULL_FAMILY


class _RecordingFeedbackPort:
	def __init__(self, log: list[tuple[str, str]]) -> None:
		super().__init__()
		self._log = log
		self.requests: list[FeedbackRequest] = []

	def announce(self, request: FeedbackRequest) -> EffectResult:
		self.requests.append(request)
		self._log.append(("speech", request.messageId))
		return EffectResult(PortStatus("ready", 0))


class _ScriptedAudioPort:
	def __init__(
		self,
		log: list[tuple[str, str]],
		*,
		outcome: str = "started",
		outcomes: list[str] | None = None,
		raises: bool = False,
	) -> None:
		super().__init__()
		self._log = log
		self._outcome = outcome
		self._outcomes = list(outcomes) if outcomes is not None else []
		self._raises = raises
		self.plays: list[AudioPlayback] = []
		self.stops = 0
		self.closes = 0
		self._pending: list[tuple[AudioPlayback, Callable[[AudioPlayback], None]]] = []

	def play(self, playback: AudioPlayback, onFinished: Callable[[AudioPlayback], None]) -> AudioOutcome:
		self.plays.append(playback)
		self._log.append(("play", str(playback.atom.value)))
		if self._raises:
			raise RuntimeError("audio device failure")
		outcome = self._outcomes.pop(0) if self._outcomes else self._outcome
		if outcome == "started":
			self._pending.append((playback, onFinished))
		return AudioOutcome(outcome)

	def stop(self) -> None:
		self.stops += 1
		self._log.append(("stop", ""))
		self._pending.clear()

	def close(self) -> None:
		self.closes += 1
		self.stop()

	@property
	def pendingCount(self) -> int:
		return len(self._pending)

	def finishNext(self) -> None:
		playback, onFinished = self._pending.pop(0)
		onFinished(playback)


class _ManualSoundHost:
	def __init__(self) -> None:
		super().__init__()
		self._now = 0
		self._queue: list[tuple[int, Callable[[], None]]] = []

	def nowMilliseconds(self) -> int:
		return self._now

	def callLater(self, delayMilliseconds: int, action: Callable[[], None]) -> None:
		self._queue.append((delayMilliseconds, action))

	@property
	def pendingDelays(self) -> tuple[int, ...]:
		return tuple(delay for delay, _ in self._queue)

	def runPending(self) -> None:
		queue = self._queue
		self._queue = []
		for delay, action in queue:
			self._now += delay
			action()


class SoundSchedulerIntegrationTests(unittest.TestCase):
	def test_speech_precedes_a_noninterleaving_two_atom_sequence(self) -> None:
		log: list[tuple[str, str]] = []
		feedback = _RecordingFeedbackPort(log)
		audio = _ScriptedAudioPort(log)
		host = _ManualSoundHost()
		scheduler = SoundScheduler()
		service = SoundService(feedback=feedback, audio=audio, scheduler=scheduler, host=host)
		result = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertEqual(result.status.token, "ready")
		self.assertEqual(log[0], ("speech", "capture.start"))
		self.assertEqual(log[1], ("play", "boundedFullFamily"))
		self.assertEqual(len(audio.plays), 1)
		audio.finishNext()
		# The second atom does not sound until the inter-atom gap elapses (no interleaving).
		self.assertEqual(len(audio.plays), 1)
		host.runPending()
		self.assertEqual(len(audio.plays), 2)
		self.assertEqual(audio.plays[1].atom, CueAtomId.START_STATE)
		self.assertEqual(
			[entry for entry in log if entry[0] == "play"],
			[
				("play", "boundedFullFamily"),
				("play", "startState"),
			],
		)
		audio.finishNext()
		self.assertFalse(scheduler.state.occupied)

	def test_second_atom_carries_the_owner_generation(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		host = _ManualSoundHost()
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=SoundScheduler(),
			host=host,
		)
		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_DIFF, _captureOwner(7)))
		audio.finishNext()
		host.runPending()
		self.assertEqual(audio.plays[0].generation, 7)
		self.assertEqual(audio.plays[1].generation, 7)
		self.assertEqual(audio.plays[0].token, audio.plays[1].token)

	def test_speech_is_identical_regardless_of_sound_outcome(self) -> None:
		request = soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner())
		speech = _speech()
		for label, audio, enabled in (
			("disabled", _ScriptedAudioPort([]), False),
			("failedStart", _ScriptedAudioPort([], outcome="failed"), True),
			("unavailable", _ScriptedAudioPort([], outcome="unavailable"), True),
			("raises", _ScriptedAudioPort([], raises=True), True),
			("started", _ScriptedAudioPort([]), True),
		):
			with self.subTest(case=label):
				feedback = _RecordingFeedbackPort([])
				scheduler = SoundScheduler()
				service = SoundService(
					feedback=feedback,
					audio=audio,
					scheduler=scheduler,
					host=_ManualSoundHost(),
					enabled=enabled,
				)
				result = service.announce(speech, request)
				self.assertEqual(result.status.token, "ready")
				self.assertEqual(len(feedback.requests), 1)
				self.assertIs(feedback.requests[0], speech)
				if not enabled:
					self.assertEqual(audio.plays, [])
				if label in ("failedStart", "unavailable", "raises"):
					# A sound that cannot begin still frees the single voice for later cues.
					self.assertFalse(scheduler.state.occupied)

	def test_disabled_service_never_touches_the_audio_port(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=SoundScheduler(),
			host=_ManualSoundHost(),
			enabled=False,
		)
		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertEqual(log, [("speech", "capture.start")])
		self.assertEqual(audio.stops, 0)

	def test_workflow_sound_callback_dispatches_the_redaction_disabled_warning(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=SoundScheduler(),
			host=_ManualSoundHost(),
		)

		service.emit(
			soundRequestFor(
				CueEventId.REDACTION_DISABLED,
				SoundOwner(SoundOwnerKind.SYSTEM, 1),
			),
		)

		self.assertEqual([play.atom for play in audio.plays], [CueAtomId.SHARED_WARNING])

	def test_runtime_log_records_a_disabled_cue_without_touching_audio(self) -> None:
		records: list[tuple[str, tuple[tuple[str, str | int | bool], ...]]] = []
		audio = _ScriptedAudioPort([])
		service = SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=audio,
			scheduler=SoundScheduler(),
			host=_ManualSoundHost(),
			enabled=False,
			runtimeLog=lambda code, fields: records.append((code, fields)),
		)

		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner(4)))

		self.assertEqual(audio.plays, [])
		self.assertEqual(
			records,
			[
				(
					"KS.SOUND.PLAY_SUPPRESSED",
					(
						("transitionId", CueEventId.START_BOUNDED_FULL.value),
						("suppressionReason", "disabled"),
						("soundGeneration", 4),
					),
				),
			],
		)

	def test_runtime_log_records_the_atom_and_failed_outcome(self) -> None:
		records: list[tuple[str, tuple[tuple[str, str | int | bool], ...]]] = []
		service = SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=_ScriptedAudioPort([], outcome="failed"),
			scheduler=SoundScheduler(),
			host=_ManualSoundHost(),
			runtimeLog=lambda code, fields: records.append((code, fields)),
		)

		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner(3)))

		self.assertEqual(
			records,
			[
				(
					"KS.SOUND.PLAY_REQUESTED",
					(
						("transitionId", CueAtomId.BOUNDED_FULL_FAMILY.value),
						("motifCount", 1),
						("soundGeneration", 3),
					),
				),
				(
					"KS.SOUND.PLAY_FAILED",
					(
						("transitionId", CueAtomId.BOUNDED_FULL_FAMILY.value),
						("reasonCode", "failed"),
						("assetId", CueAtomId.BOUNDED_FULL_FAMILY.value),
					),
				),
			],
		)

	def test_urgent_replacement_stops_prior_playback_and_never_interleaves(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		host = _ManualSoundHost()
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)
		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertEqual(audio.plays[0].atom, CueAtomId.BOUNDED_FULL_FAMILY)
		_ = service.announce(
			_speech("secure.denied", generation=2),
			soundRequestFor(CueEventId.SECURE_DESKTOP_DENIAL, SoundOwner(SoundOwnerKind.SYSTEM, 1)),
		)
		self.assertGreaterEqual(audio.stops, 1)
		self.assertEqual(audio.plays[-1].atom, CueAtomId.SHARED_WARNING)
		# Draining the preempted sequence's queued gap must not resurrect its second atom.
		playCountBeforeGap = len(audio.plays)
		host.runPending()
		self.assertEqual(len(audio.plays), playCountBeforeGap)

	def test_capture_start_waits_for_the_layer_enter_cue_to_finish_then_plays(self) -> None:
		# Product policy: preserve the short layerEntered cue instead of cutting it off when
		# a capture-start command follows it immediately.
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		host = _ManualSoundHost()
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)
		_ = service.announce(
			_speech("layer.entered"),
			soundRequestFor(CueEventId.LAYER_ENTERED, SoundOwner(SoundOwnerKind.LAYER, 1)),
		)
		self.assertEqual(audio.plays[-1].atom, CueAtomId.LAYER_ENTERED)

		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		# Deferred, not replaced: the layer-enter cue's own playback is never stopped.
		self.assertEqual(audio.stops, 0)
		self.assertEqual(len(audio.plays), 1)

		audio.finishNext()  # layerEntered's own completion is discovered.
		self.assertEqual(len(audio.plays), 2)
		self.assertEqual(audio.plays[-1].atom, CueAtomId.BOUNDED_FULL_FAMILY)
		self.assertTrue(scheduler.state.occupied)

		audio.finishNext()
		host.runPending()
		self.assertEqual(audio.plays[-1].atom, CueAtomId.START_STATE)
		audio.finishNext()
		self.assertFalse(scheduler.state.occupied)

	def test_failed_replacement_plays_a_deferred_capture_start(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log, outcomes=["started", "failed", "started"])
		host = _ManualSoundHost()
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)

		service.emit(soundRequestFor(CueEventId.LAYER_ENTERED, SoundOwner(SoundOwnerKind.LAYER, 1)))
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		service.emit(
			soundRequestFor(CueEventId.SECURE_DESKTOP_DENIAL, SoundOwner(SoundOwnerKind.SYSTEM, 1)),
		)

		self.assertEqual(
			[play.atom for play in audio.plays],
			[
				CueAtomId.LAYER_ENTERED,
				CueAtomId.SHARED_WARNING,
				CueAtomId.BOUNDED_FULL_FAMILY,
			],
		)
		self.assertTrue(scheduler.state.occupied)
		self.assertEqual(audio.pendingCount, 1)


class _DictManifest:
	def __init__(self, atoms: dict[CueAtomId, bytes | Exception]) -> None:
		super().__init__()
		self._atoms = atoms

	def pcmFor(self, atom: CueAtomId) -> bytes:
		value = self._atoms.get(atom)
		if value is None:
			raise AudioAtomUnavailable(f"no entry for {atom.value}")
		if isinstance(value, Exception):
			raise value
		return value


class _FakeWaveOut:
	def __init__(
		self,
		onDone: Callable[[int], None],
		*,
		failOpen: bool = False,
		failFeed: bool = False,
		scriptIds: list[int] | None = None,
	) -> None:
		super().__init__()
		self._onDone = onDone
		self._failOpen = failOpen
		self._failFeed = failFeed
		self._scriptIds = list(scriptIds) if scriptIds is not None else None
		self._auto = 0
		self.opened = 0
		self.stops = 0
		self.closes = 0
		self.polls = 0
		self.feeds: list[bytes] = []
		# Mirrors the native player: a chunk becomes "outstanding" once fed and only
		# stops being outstanding once its completion is actually delivered, whether
		# that is the test driving it directly (``complete``) or a poll discovering it
		# (``poll``) -- matching the real player, which only ever notices a finished
		# chunk as a side effect of a later call, never on its own.
		self._outstanding: list[int] = []

	def open(self) -> None:
		self.opened += 1
		if self._failOpen:
			raise OSError("device open failed")

	def feed(self, data: bytes) -> int:
		if self._failFeed:
			raise OSError("device feed failed")
		self.feeds.append(data)
		if self._scriptIds:
			feedId = self._scriptIds.pop(0)
		else:
			self._auto += 1
			feedId = self._auto
		self._outstanding.append(feedId)
		return feedId

	def stop(self) -> None:
		self.stops += 1

	def close(self) -> None:
		self.closes += 1

	def complete(self, feedId: int) -> None:
		if feedId in self._outstanding:
			self._outstanding.remove(feedId)
		self._onDone(feedId)

	def poll(self) -> None:
		# The real native player only fires a fed chunk's completion as a side effect of
		# a later call into it; this fake reproduces that same "no completion without a
		# later call" behaviour so `poll` is the only path through which an atom with no
		# further feed and no explicit ``complete`` call ever resolves.
		self.polls += 1
		outstanding = self._outstanding
		self._outstanding = []
		for feedId in outstanding:
			self._onDone(feedId)


class _FakeWaveFactory:
	def __init__(
		self,
		*,
		failOpen: bool = False,
		failFeed: bool = False,
		scriptIds: list[int] | None = None,
	) -> None:
		super().__init__()
		self.failOpen = failOpen
		self.failFeed = failFeed
		self.scriptIds = scriptIds
		self.created: list[_FakeWaveOut] = []

	def __call__(self, onDone: Callable[[int], None]) -> _FakeWaveOut:
		wave = _FakeWaveOut(
			onDone,
			failOpen=self.failOpen,
			failFeed=self.failFeed,
			scriptIds=self.scriptIds,
		)
		self.created.append(wave)
		return wave


def _playback(atom: CueAtomId, *, generation: int = 1, token: int = 1) -> AudioPlayback:
	return AudioPlayback(atom=atom, generation=generation, token=token)


def _wav(
	frames: bytes,
	*,
	channels: int = 2,
	sampleWidth: int = 2,
	sampleRate: int = 44100,
) -> bytes:
	buffer = io.BytesIO()
	with wave.open(buffer, "wb") as writer:
		writer.setnchannels(channels)
		writer.setsampwidth(sampleWidth)
		writer.setframerate(sampleRate)
		writer.writeframes(frames)
	return buffer.getvalue()


class NvdaWaveAudioPortTests(unittest.TestCase):
	def test_native_player_uses_nvda_initialized_wasapi_and_destroys_its_handle(self) -> None:
		events: list[str] = []

		class _Format:
			pass

		class _Wasapi:
			@staticmethod
			def wasPlay_callback(callback: Callable[[object, int], None]) -> Callable[[object, int], None]:
				return callback

			@staticmethod
			def wasPlay_create(_endpoint: str, _format: object, _callback: object) -> str:
				events.append("create")
				return "player"

			@staticmethod
			def wasPlay_destroy(player: object) -> None:
				events.append(f"destroy:{player}")

		wave = _WasapiWaveOut(wasapi=_Wasapi(), waveFormat=_Format, onDone=lambda _feedId: None)

		wave.close()

		self.assertEqual(["create", "destroy:player"], events)

	def test_native_player_retains_pcm_until_the_host_signals_completion(self) -> None:
		callback: Callable[[object, int], None] | None = None

		class _Format:
			pass

		class _Wasapi:
			@staticmethod
			def wasPlay_callback(value: Callable[[object, int], None]) -> Callable[[object, int], None]:
				return value

			@staticmethod
			def wasPlay_create(_endpoint: str, _format: object, value: Callable[[object, int], None]) -> str:
				nonlocal callback
				callback = value
				return "player"

			@staticmethod
			def wasPlay_feed(_player: object, _data: object, _size: int, _identifier: object) -> None:
				return None

			@staticmethod
			def wasPlay_stop(_player: object) -> None:
				return None

			@staticmethod
			def wasPlay_destroy(_player: object) -> None:
				return None

		completed: list[int] = []
		wave = _WasapiWaveOut(wasapi=_Wasapi(), waveFormat=_Format, onDone=completed.append)
		frames = b"\x01\x00\x02\x00"

		self.assertEqual(0, wave.feed(frames))
		self.assertEqual({0: frames}, wave._buffers)
		assert callback is not None
		callback("player", 0)

		self.assertEqual([0], completed)
		self.assertEqual({}, wave._buffers)

	def test_poll_feeds_zero_bytes_with_no_identifier_to_check_for_completions(self) -> None:
		# The native player only notices a fed chunk has finished as a side effect of a
		# later call into it. `poll()` must be that later call without registering a new
		# pending completion of its own or touching the render buffer: zero size and a
		# null identifier pointer, per the native `feed()` contract.
		calls: list[tuple[object, object, int, object]] = []

		class _Format:
			pass

		class _Wasapi:
			@staticmethod
			def wasPlay_callback(value: Callable[[object, int], None]) -> Callable[[object, int], None]:
				return value

			@staticmethod
			def wasPlay_create(_endpoint: str, _format: object, value: Callable[[object, int], None]) -> str:
				return "player"

			@staticmethod
			def wasPlay_feed(player: object, data: object, size: int, identifier: object) -> None:
				calls.append((player, data, size, identifier))
				return None

			@staticmethod
			def wasPlay_destroy(_player: object) -> None:
				return None

		wave = _WasapiWaveOut(wasapi=_Wasapi(), waveFormat=_Format, onDone=lambda _feedId: None)

		wave.poll()

		self.assertEqual(calls, [("player", None, 0, None)])

	def test_missing_atom_is_unavailable_and_is_never_fed(self) -> None:
		factory = _FakeWaveFactory()
		port = NvdaWaveAudioPort(manifest=_DictManifest({}), marshal=_ManualSoundHost(), waveFactory=factory)
		outcome = port.play(_playback(CueAtomId.START_STATE), lambda _p: None)
		self.assertEqual(outcome.token, "unavailable")
		self.assertEqual(factory.created, [])

	def test_corrupt_atom_is_rejected_and_is_never_fed(self) -> None:
		factory = _FakeWaveFactory()
		manifest = _DictManifest({CueAtomId.START_STATE: AudioAtomRejected("misaligned")})
		port = NvdaWaveAudioPort(manifest=manifest, marshal=_ManualSoundHost(), waveFactory=factory)
		outcome = port.play(_playback(CueAtomId.START_STATE), lambda _p: None)
		self.assertEqual(outcome.token, "rejected")
		self.assertEqual(factory.created, [])

	def test_device_open_failure_is_isolated_and_recoverable(self) -> None:
		factory = _FakeWaveFactory(failOpen=True)
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00\x00\x00"})
		failures: list[tuple[CueAtomId, str]] = []
		port = NvdaWaveAudioPort(
			manifest=manifest,
			marshal=_ManualSoundHost(),
			waveFactory=factory,
			failureReporter=lambda atom, reason: failures.append((atom, reason)),
		)
		self.assertEqual(port.play(_playback(CueAtomId.START_STATE), lambda _p: None).token, "failed")
		self.assertEqual(failures, [(CueAtomId.START_STATE, "waveOpenFailed")])
		# The seam is rebuilt on the next attempt, so a later cue can still play.
		factory.failOpen = False
		self.assertEqual(port.play(_playback(CueAtomId.START_STATE), lambda _p: None).token, "started")
		self.assertEqual(len(factory.created), 2)
		self.assertEqual(factory.created[1].feeds, [b"\x00\x00\x00\x00"])

	def test_feed_failure_is_isolated_and_recoverable(self) -> None:
		factory = _FakeWaveFactory(failFeed=True)
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00\x00\x00"})
		port = NvdaWaveAudioPort(manifest=manifest, marshal=_ManualSoundHost(), waveFactory=factory)
		self.assertEqual(port.play(_playback(CueAtomId.START_STATE), lambda _p: None).token, "failed")
		self.assertEqual(factory.created[0].closes, 1)
		factory.failFeed = False
		self.assertEqual(port.play(_playback(CueAtomId.START_STATE), lambda _p: None).token, "started")

	def test_started_atom_feeds_once_and_routes_its_completion(self) -> None:
		factory = _FakeWaveFactory()
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x01\x00\x01\x00"})
		marshal = _ManualSoundHost()
		port = NvdaWaveAudioPort(manifest=manifest, marshal=marshal, waveFactory=factory)
		finished: list[AudioPlayback] = []
		outcome = port.play(_playback(CueAtomId.START_STATE, generation=7), finished.append)
		self.assertEqual(outcome.token, "started")
		wave = factory.created[0]
		self.assertEqual(wave.feeds, [b"\x01\x00\x01\x00"])
		# Completion is marshalled to the main thread, never delivered inline.
		wave.complete(1)
		self.assertEqual(finished, [])
		marshal.runPending()
		self.assertEqual(len(finished), 1)
		self.assertEqual(finished[0].generation, 7)
		self.assertEqual(finished[0].atom, CueAtomId.START_STATE)

	def test_a_stop_drops_a_superseded_completion_even_when_the_feed_id_is_reused(self) -> None:
		factory = _FakeWaveFactory(scriptIds=[7, 7])
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00", CueAtomId.SHARED_WARNING: b"\x00\x00"})
		marshal = _ManualSoundHost()
		port = NvdaWaveAudioPort(manifest=manifest, marshal=marshal, waveFactory=factory)
		superseded: list[AudioPlayback] = []
		replacement: list[AudioPlayback] = []
		_ = port.play(_playback(CueAtomId.START_STATE, generation=1), superseded.append)
		wave = factory.created[0]
		# The first atom's late completion is queued, then a stop supersedes it.
		wave.complete(7)
		port.stop()
		_ = port.play(_playback(CueAtomId.SHARED_WARNING, generation=2), replacement.append)
		marshal.runPending()
		# The recycled feed id must not deliver the stale completion to the new job.
		self.assertEqual(superseded, [])
		self.assertEqual(replacement, [])
		self.assertGreaterEqual(wave.stops, 1)

	def test_replace_reopens_the_stopped_device_before_feeding_the_replacement(self) -> None:
		# A REPLACE calls stop() on the still-live native player, which leaves the WASAPI
		# render client stopped. NVDA's own WavePlayer.feed() reopens the device on every
		# single feed for exactly this reason (nvwave.py: "not an error if...already open").
		# Skipping the reopen after a stop lets the replacement atom feed successfully
		# (no exception) while the underlying stream never resumes, so its completion is
		# never signalled and the scheduler's single voice is starved for the rest of the
		# owning operation -- this is the sound-scheduler-stall regression.
		factory = _FakeWaveFactory()
		manifest = _DictManifest(
			{CueAtomId.START_STATE: b"\x00\x00", CueAtomId.SHARED_WARNING: b"\x01\x00"},
		)
		marshal = _ManualSoundHost()
		port = NvdaWaveAudioPort(manifest=manifest, marshal=marshal, waveFactory=factory)
		_ = port.play(_playback(CueAtomId.START_STATE, generation=1), lambda _playback: None)
		wave = factory.created[0]
		openedBeforeReplace = wave.opened
		port.stop()
		outcome = port.play(_playback(CueAtomId.SHARED_WARNING, generation=2), lambda _playback: None)
		self.assertEqual(outcome.token, "started")
		self.assertGreater(wave.opened, openedBeforeReplace)

	def test_a_lone_atoms_completion_is_delivered_by_the_periodic_poll_alone(self) -> None:
		# The native WASAPI player only discovers a fed chunk has finished as a side
		# effect of a *later* call into it (another feed, or a sync/idle wait); it never
		# calls back spontaneously on its own. When a played atom has no follow-on atom
		# and nothing else supersedes it (the ordinary end of a capture: the last
		# outcome cue, with no later cue queued behind it), nothing would otherwise ever
		# call back into the player again, so its completion would never arrive and the
		# scheduler's single voice would stay occupied forever -- the 0.0.23 regression
		# where every captureProgress/captureSuccess after an audible capture-start was
		# permanently skip-suppressed. This proves the completion still arrives with no
		# stop(), no replacement, and no second feed() call: only the port's own
		# recurring poll ever calls back into the player again.
		factory = _FakeWaveFactory()
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00"})
		marshal = _ManualSoundHost()
		port = NvdaWaveAudioPort(manifest=manifest, marshal=marshal, waveFactory=factory)
		finished: list[AudioPlayback] = []
		outcome = port.play(_playback(CueAtomId.START_STATE, generation=3), finished.append)
		self.assertEqual(outcome.token, "started")
		wave = factory.created[0]
		self.assertEqual(wave.polls, 0)
		self.assertEqual(finished, [])

		# Nothing else ever calls stop(), feed(), or wave.complete() directly here: the
		# poll fires, discovers the finished chunk, and hands delivery to the main
		# thread exactly like any other completion -- one more pending-callback pass
		# is all that is needed to observe it, the same two-pass shape every other
		# marshalled completion in this suite already uses.
		marshal.runPending()
		marshal.runPending()

		self.assertGreaterEqual(wave.polls, 1)
		self.assertEqual(len(finished), 1)
		self.assertEqual(finished[0].generation, 3)
		self.assertEqual(finished[0].atom, CueAtomId.START_STATE)

	def test_the_poll_stops_once_a_supersede_clears_its_generation(self) -> None:
		# A scheduled poll must not keep nudging a player that a stop or teardown has
		# already superseded; it should observe the epoch mismatch and quietly stop
		# rescheduling itself instead of polling a generation nothing cares about anymore.
		factory = _FakeWaveFactory()
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00", CueAtomId.SHARED_WARNING: b"\x00\x00"})
		marshal = _ManualSoundHost()
		port = NvdaWaveAudioPort(manifest=manifest, marshal=marshal, waveFactory=factory)
		_ = port.play(_playback(CueAtomId.START_STATE, generation=1), lambda _playback: None)
		wave = factory.created[0]

		port.stop()
		marshal.runPending()

		self.assertEqual(wave.polls, 0)

	def test_close_destroys_the_reused_native_player_once(self) -> None:
		factory = _FakeWaveFactory()
		manifest = _DictManifest({CueAtomId.START_STATE: b"\x00\x00"})
		port = NvdaWaveAudioPort(manifest=manifest, marshal=_ManualSoundHost(), waveFactory=factory)
		_ = port.play(_playback(CueAtomId.START_STATE), lambda _playback: None)
		wave = factory.created[0]

		port.close()
		port.close()

		self.assertEqual(1, wave.closes)


class SoundThemeManifestTests(unittest.TestCase):
	def test_unknown_atom_is_unavailable(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			manifest = SoundThemeManifest(root=Path(raw), paths={})
			with self.assertRaises(AudioAtomUnavailable):
				_ = manifest.pcmFor(CueAtomId.START_STATE)

	def test_missing_file_is_unavailable(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			manifest = SoundThemeManifest(root=Path(raw), paths={CueAtomId.START_STATE: "gone.pcm"})
			with self.assertRaises(AudioAtomUnavailable):
				_ = manifest.pcmFor(CueAtomId.START_STATE)

	def test_a_path_escaping_the_root_is_unavailable(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			root = Path(raw) / "root"
			root.mkdir()
			_ = (Path(raw) / "secret.pcm").write_bytes(b"\x00\x00")
			manifest = SoundThemeManifest(root=root, paths={CueAtomId.START_STATE: "../secret.pcm"})
			with self.assertRaises(AudioAtomUnavailable):
				_ = manifest.pcmFor(CueAtomId.START_STATE)

	def test_empty_or_misaligned_bytes_are_rejected(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			root = Path(raw)
			_ = (root / "empty.wav").write_bytes(_wav(b""))
			_ = (root / "odd.wav").write_bytes(_wav(b"\x00"))
			manifest = SoundThemeManifest(
				root=root,
				paths={CueAtomId.START_STATE: "empty.wav", CueAtomId.SHARED_WARNING: "odd.wav"},
			)
			with self.assertRaises(AudioAtomRejected):
				_ = manifest.pcmFor(CueAtomId.START_STATE)
			with self.assertRaises(AudioAtomRejected):
				_ = manifest.pcmFor(CueAtomId.SHARED_WARNING)

	def test_valid_frames_are_returned(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			root = Path(raw)
			frames = b"\x01\x00\x02\x00"
			_ = (root / "cue.wav").write_bytes(_wav(frames))
			manifest = SoundThemeManifest(root=root, paths={CueAtomId.START_STATE: "cue.wav"})
			self.assertEqual(manifest.pcmFor(CueAtomId.START_STATE), frames)

	def test_unsupported_wav_format_is_rejected(self) -> None:
		with tempfile.TemporaryDirectory() as raw:
			root = Path(raw)
			_ = (root / "mono.wav").write_bytes(_wav(b"\x00\x00", channels=1))
			manifest = SoundThemeManifest(root=root, paths={CueAtomId.START_STATE: "mono.wav"})

			with self.assertRaises(AudioAtomRejected):
				_ = manifest.pcmFor(CueAtomId.START_STATE)


class SoundServiceThroughAdapterTests(unittest.TestCase):
	def test_two_atom_sequence_plays_family_then_primary_without_interleaving(self) -> None:
		host = _ManualSoundHost()
		factory = _FakeWaveFactory()
		manifest = _DictManifest(
			{
				CueAtomId.BOUNDED_FULL_FAMILY: b"\x00\x00\x00\x00",
				CueAtomId.START_STATE: b"\x01\x00\x01\x00",
			},
		)
		audio = NvdaWaveAudioPort(manifest=manifest, marshal=host, waveFactory=factory)
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)
		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		wave = factory.created[0]
		self.assertEqual(wave.feeds, [b"\x00\x00\x00\x00"])
		wave.complete(1)
		host.runPending()
		# The primary atom waits for the inter-atom gap; it does not interleave.
		self.assertEqual(wave.feeds, [b"\x00\x00\x00\x00"])
		host.runPending()
		self.assertEqual(wave.feeds, [b"\x00\x00\x00\x00", b"\x01\x00\x01\x00"])
		wave.complete(2)
		host.runPending()
		self.assertFalse(scheduler.state.occupied)

	def test_urgent_replacement_supersedes_through_the_adapter(self) -> None:
		host = _ManualSoundHost()
		factory = _FakeWaveFactory()
		manifest = _DictManifest(
			{
				CueAtomId.BOUNDED_FULL_FAMILY: b"\x00\x00\x00\x00",
				CueAtomId.START_STATE: b"\x01\x00\x01\x00",
				CueAtomId.SHARED_WARNING: b"\x02\x00\x02\x00",
			},
		)
		audio = NvdaWaveAudioPort(manifest=manifest, marshal=host, waveFactory=factory)
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)
		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		wave = factory.created[0]
		_ = service.announce(
			_speech("secure.denied", generation=2),
			soundRequestFor(CueEventId.SECURE_DESKTOP_DENIAL, SoundOwner(SoundOwnerKind.SYSTEM, 1)),
		)
		self.assertGreaterEqual(wave.stops, 1)
		self.assertEqual(wave.feeds[-1], b"\x02\x00\x02\x00")
		feedCountBeforeGap = len(wave.feeds)
		host.runPending()
		self.assertEqual(len(wave.feeds), feedCountBeforeGap)

	def test_capture_start_waits_for_the_layer_enter_cue_through_the_real_adapter(self) -> None:
		# Same product policy, exercised through the real NvdaWaveAudioPort and its
		# pull-based completion contract (a fed chunk's completion is only ever discovered
		# as a side effect of a later call into the native player - see the poll fix above).
		host = _ManualSoundHost()
		factory = _FakeWaveFactory()
		manifest = _DictManifest(
			{
				CueAtomId.LAYER_ENTERED: b"\x03\x00\x03\x00",
				CueAtomId.BOUNDED_FULL_FAMILY: b"\x00\x00\x00\x00",
				CueAtomId.START_STATE: b"\x01\x00\x01\x00",
			},
		)
		audio = NvdaWaveAudioPort(manifest=manifest, marshal=host, waveFactory=factory)
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=audio,
			scheduler=scheduler,
			host=host,
		)
		_ = service.announce(
			_speech("layer.entered"),
			soundRequestFor(CueEventId.LAYER_ENTERED, SoundOwner(SoundOwnerKind.LAYER, 1)),
		)
		wave = factory.created[0]
		self.assertEqual(wave.feeds, [b"\x03\x00\x03\x00"])

		_ = service.announce(_speech(), soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		# Deferred, not replaced: the native device backing the layer-enter cue is untouched.
		self.assertEqual(wave.stops, 0)
		self.assertEqual(wave.feeds, [b"\x03\x00\x03\x00"])

		wave.complete(1)  # layerEntered's completion, discovered by the periodic poll.
		host.runPending()
		self.assertEqual(wave.feeds, [b"\x03\x00\x03\x00", b"\x00\x00\x00\x00"])
		self.assertTrue(scheduler.state.occupied)


def _previewRequests(
	name: str = "Layer entered",
	generation: int = 1,
) -> tuple[FeedbackRequest, FeedbackRequest]:
	context = CorrelationFactory().admit(generation=generation)
	announcement = FeedbackRequest(messageId="sound.preview", arguments=(name,), context=context)
	unavailable = FeedbackRequest(messageId="sound.preview.failed", arguments=(name,), context=context)
	return announcement, unavailable


class SoundSettingsAndPreviewTests(unittest.TestCase):
	def _service(
		self,
		audio: _ScriptedAudioPort,
		*,
		log: list[tuple[str, str]],
		enabled: bool = True,
	) -> tuple[SoundService, SoundScheduler]:
		scheduler = SoundScheduler()
		service = SoundService(
			feedback=_RecordingFeedbackPort(log),
			audio=audio,
			scheduler=scheduler,
			host=_ManualSoundHost(),
			enabled=enabled,
		)
		return service, scheduler

	def test_preview_speaks_then_plays_one_atom_outside_the_scheduler(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, scheduler = self._service(audio, log=log)
		announcement, unavailable = _previewRequests("Layer entered", generation=5)

		outcome = service.preview(
			CueAtomId.LAYER_ENTERED,
			generation=5,
			announcement=announcement,
			unavailable=unavailable,
		)

		self.assertTrue(outcome.started)
		# Speech is submitted before any audio-port interaction, and the earlier preview is silenced first.
		self.assertEqual(
			log,
			[("speech", "sound.preview"), ("stop", ""), ("play", "layerEntered")],
		)
		self.assertEqual(len(audio.plays), 1)
		self.assertEqual(audio.plays[0].atom, CueAtomId.LAYER_ENTERED)
		self.assertEqual(audio.plays[0].generation, 5)
		# The operation scheduler's single voice is never entered by a preview.
		self.assertFalse(scheduler.state.occupied)

	def test_preview_replaces_only_the_earlier_preview(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, _scheduler = self._service(audio, log=log)
		first = _previewRequests("Layer entered")
		second = _previewRequests("Shared warning")

		_ = service.preview(
			CueAtomId.LAYER_ENTERED,
			generation=1,
			announcement=first[0],
			unavailable=first[1],
		)
		_ = service.preview(
			CueAtomId.SHARED_WARNING,
			generation=1,
			announcement=second[0],
			unavailable=second[1],
		)

		self.assertEqual(
			[play.atom for play in audio.plays],
			[CueAtomId.LAYER_ENTERED, CueAtomId.SHARED_WARNING],
		)
		# Each preview silences the prior one before starting.
		self.assertEqual(audio.stops, 2)

	def test_workflow_playback_stops_an_active_preview_first(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, _scheduler = self._service(audio, log=log)
		announcement, unavailable = _previewRequests()

		_ = service.preview(
			CueAtomId.LAYER_ENTERED,
			generation=1,
			announcement=announcement,
			unavailable=unavailable,
		)
		service.emit(soundRequestFor(CueEventId.OUTPUT_PATH_COPY, SoundOwner(SoundOwnerKind.COMMAND, 1)))

		workflowPlay = ("play", CueAtomId.OUTPUT_PATH_COPIED.value)
		self.assertEqual(log[log.index(workflowPlay) - 1], ("stop", ""))
		self.assertEqual(audio.stops, 2)

	def test_preview_survives_failure_and_adds_the_safe_fallback_line(self) -> None:
		for label in ("failed", "unavailable", "rejected", "raises"):
			with self.subTest(case=label):
				log: list[tuple[str, str]] = []
				audio = (
					_ScriptedAudioPort(log, raises=True)
					if label == "raises"
					else _ScriptedAudioPort(log, outcome=label)
				)
				service, scheduler = self._service(audio, log=log)
				announcement, unavailable = _previewRequests("Success outcome")

				outcome = service.preview(
					CueAtomId.SUCCESS_OUTCOME,
					generation=1,
					announcement=announcement,
					unavailable=unavailable,
				)

				self.assertFalse(outcome.started)
				spoken = [entry[1] for entry in log if entry[0] == "speech"]
				# The announcement is always spoken first; the fallback line follows a non-started asset.
				self.assertEqual(spoken, ["sound.preview", "sound.preview.failed"])
				self.assertFalse(scheduler.state.occupied)

	def test_preview_announcement_is_identical_regardless_of_outcome(self) -> None:
		for label, started in (("started", True), ("failed", False), ("raises", False)):
			with self.subTest(case=label):
				log: list[tuple[str, str]] = []
				audio = (
					_ScriptedAudioPort(log, raises=True)
					if label == "raises"
					else _ScriptedAudioPort(log, outcome=label)
				)
				feedback = _RecordingFeedbackPort(log)
				service = SoundService(
					feedback=feedback,
					audio=audio,
					scheduler=SoundScheduler(),
					host=_ManualSoundHost(),
				)
				announcement, unavailable = _previewRequests("Diff family")

				_ = service.preview(
					CueAtomId.DIFF_FAMILY,
					generation=1,
					announcement=announcement,
					unavailable=unavailable,
				)

				self.assertIs(feedback.requests[0], announcement)
				if started:
					self.assertEqual(len(feedback.requests), 1)
				else:
					self.assertIs(feedback.requests[1], unavailable)

	def test_preview_carries_the_dialog_generation_to_playback(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, _scheduler = self._service(audio, log=log)
		announcement, unavailable = _previewRequests("Inspector ready", generation=9)

		_ = service.preview(
			CueAtomId.INSPECTOR_READY,
			generation=9,
			announcement=announcement,
			unavailable=unavailable,
		)

		self.assertEqual(audio.plays[0].generation, 9)

	def test_preview_plays_even_when_global_sound_is_disabled(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, _scheduler = self._service(audio, log=log, enabled=False)
		announcement, unavailable = _previewRequests("Event monitor start")

		outcome = service.preview(
			CueAtomId.EVENT_MONITOR_START,
			generation=1,
			announcement=announcement,
			unavailable=unavailable,
		)

		# Preview is an explicit audition, never suppressed by the global enablement preference.
		self.assertTrue(outcome.started)
		self.assertEqual(len(audio.plays), 1)

	def test_stop_preview_silences_audio(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, _scheduler = self._service(audio, log=log)

		service.stopPreview()

		self.assertEqual(audio.stops, 1)

	def test_preview_and_stop_preview_release_an_interrupted_scheduled_cue(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, scheduler = self._service(audio, log=log)
		announcement, unavailable = _previewRequests()

		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertTrue(scheduler.state.occupied)
		self.assertEqual(audio.pendingCount, 1)

		_ = service.preview(
			CueAtomId.LAYER_ENTERED,
			generation=1,
			announcement=announcement,
			unavailable=unavailable,
		)

		self.assertFalse(scheduler.state.occupied)
		self.assertEqual(audio.pendingCount, 1)

		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner(2)))
		self.assertTrue(scheduler.state.occupied)
		self.assertEqual(audio.pendingCount, 1)

		service.stopPreview()

		self.assertFalse(scheduler.state.occupied)
		self.assertEqual(audio.pendingCount, 0)

	def test_close_stops_future_sound_and_closes_the_audio_port(self) -> None:
		log: list[tuple[str, str]] = []
		audio = _ScriptedAudioPort(log)
		service, scheduler = self._service(audio, log=log)

		service.close()
		service.close()
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))

		self.assertEqual(1, audio.closes)
		self.assertFalse(scheduler.state.occupied)
		self.assertEqual([], audio.plays)

	def test_sounds_default_enabled_and_round_trip_through_the_global_snapshot(self) -> None:
		snapshot = SettingsSnapshot.defaults(settingsRevision=1)
		self.assertIs(snapshot.soundsEnabled, True)
		named = dict(snapshot.asCandidate().namedValues())
		self.assertIs(named["soundsEnabled"], True)
		disabled = snapshot.asCandidate().withValue(SettingId.SOUNDS_ENABLED, False).toSnapshot(2)
		self.assertIs(disabled.soundsEnabled, False)


class CueTotalSetSpeechFirstTests(unittest.TestCase):
	"""Every SND-04..SND-11 row dispatches speech-first, owns its generation, and invalidates cleanly.

	The grammar's set totality is fixed in the unit suite; this drives the whole cue vocabulary
	through the real SoundService so no row can join without an integration case proving its
	localized speech is submitted before any atom sounds, the first atom carries the request
	generation, and invalidating the owner silences and frees the single voice.
	"""

	def test_cue_grammar_covers_the_entire_event_vocabulary(self) -> None:
		# The wired vocabulary is closed: a cue cannot exist in the enum without a grammar entry.
		self.assertEqual(set(CUE_GRAMMAR), set(CueEventId))

	def test_each_cue_is_spoken_first_then_owns_its_generation_and_invalidates(self) -> None:
		generation = 5
		for event in CueEventId:
			with self.subTest(event=event.value):
				composition = CUE_GRAMMAR[event]
				log: list[tuple[str, str]] = []
				audio = _ScriptedAudioPort(log)
				scheduler = SoundScheduler()
				service = SoundService(
					feedback=_RecordingFeedbackPort(log),
					audio=audio,
					scheduler=scheduler,
					host=_ManualSoundHost(),
				)
				owner = SoundOwner(_ownerKindFor(event), generation)
				request = soundRequestFor(
					event,
					owner,
					activeFamilyAtom=_activeFamilyAtomFor(event) if composition.activeFamily else None,
					coalescingKey="row" if composition.coalesces else None,
				)
				# The composed request is exactly the grammar: any family atom precedes the primary.
				self.assertEqual(request.atoms[-1], composition.primaryAtom)
				self.assertEqual(request.priority, composition.priority)

				result = service.announce(
					_speech("workflow.transition", generation=generation),
					request,
				)

				# Speech is the product outcome: it is logged before the first atom sounds.
				self.assertEqual(result.status.token, "ready")
				self.assertEqual(log[0], ("speech", "workflow.transition"))
				plays = [entry for entry in log if entry[0] == "play"]
				self.assertEqual(plays[0], ("play", request.atoms[0].value))
				self.assertEqual(audio.plays[0].generation, generation)

				# Invalidating the owner silences the voice and frees it: a stale cue cannot linger.
				stopsBefore = audio.stops
				service.invalidate(owner)
				self.assertEqual(audio.stops, stopsBefore + 1)
				self.assertFalse(scheduler.state.occupied)


class SoundProgressPumpTests(unittest.TestCase):
	"""A progress-opening cue drives a self-rescheduling pump that pulses the active track.

	The pump begins only after the first-progress delay, pulses at the configured interval while
	the single voice is free, and stops the instant a terminal outcome cue clears the track or the
	owner is invalidated. A synchronous capture that never yields simply ends its track before the
	first pulse, and speech stays byte-identical because the pump only ever runs optional audio.
	"""

	def _service(
		self,
		host: _ManualSoundHost,
		audio: _ScriptedAudioPort,
		*,
		enabled: bool = True,
	) -> SoundService:
		return SoundService(
			feedback=_RecordingFeedbackPort([]),
			audio=audio,
			scheduler=SoundScheduler(),
			host=host,
			enabled=enabled,
		)

	def _drainVoice(self, audio: _ScriptedAudioPort, host: _ManualSoundHost, *, rounds: int) -> None:
		# Alternate finishing the sounding atom and running the host loop so each deferred pump tick
		# advances the state machine deterministically under the manual clock.
		for _ in range(rounds):
			while audio.pendingCount:
				audio.finishNext()
			host.runPending()

	def test_a_progress_opening_cue_arms_one_deferred_pump_tick(self) -> None:
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort([])
		service = self._service(host, audio)
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertEqual(host.pendingDelays, (FIRST_PROGRESS_DELAY_MILLISECONDS,))

	def test_a_nonprogress_cue_never_arms_the_pump(self) -> None:
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort([])
		service = self._service(host, audio)
		service.emit(soundRequestFor(CueEventId.OUTPUT_PATH_COPY, SoundOwner(SoundOwnerKind.COMMAND, 1)))
		self.assertEqual(host.pendingDelays, ())

	def test_a_disabled_service_never_arms_the_pump(self) -> None:
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort([])
		service = self._service(host, audio, enabled=False)
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self.assertEqual(host.pendingDelays, ())

	def test_the_pump_pulses_the_active_track_after_the_first_delay(self) -> None:
		log: list[tuple[str, str]] = []
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort(log)
		service = self._service(host, audio)
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		self._drainVoice(audio, host, rounds=5)
		played = [entry[1] for entry in log if entry[0] == "play"]
		self.assertIn(CueAtomId.PROGRESS_STATE.value, played)
		self.assertEqual(MINIMUM_PROGRESS_INTERVAL_MILLISECONDS, host.pendingDelays[-1])

	def test_a_terminal_outcome_cue_stops_the_pump(self) -> None:
		log: list[tuple[str, str]] = []
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort(log)
		service = self._service(host, audio)
		owner = _captureOwner()
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, owner))
		# The terminal outcome shares the capture owner: its urgent priority clears the track.
		service.emit(
			soundRequestFor(
				CueEventId.CAPTURE_SUCCESS,
				owner,
				activeFamilyAtom=CueAtomId.BOUNDED_FULL_FAMILY,
			),
		)
		self._drainVoice(audio, host, rounds=5)
		played = [entry[1] for entry in log if entry[0] == "play"]
		self.assertNotIn(CueAtomId.PROGRESS_STATE.value, played)

	def test_invalidating_the_owner_stops_the_pump(self) -> None:
		log: list[tuple[str, str]] = []
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort(log)
		service = self._service(host, audio)
		owner = _captureOwner()
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, owner))
		service.invalidate(owner)
		self._drainVoice(audio, host, rounds=5)
		played = [entry[1] for entry in log if entry[0] == "play"]
		self.assertNotIn(CueAtomId.PROGRESS_STATE.value, played)

	def test_full_invalidation_stops_the_pump(self) -> None:
		# Secure-desktop entry, workspace close, reload, and shutdown all invalidate with no owner.
		log: list[tuple[str, str]] = []
		host = _ManualSoundHost()
		audio = _ScriptedAudioPort(log)
		service = self._service(host, audio)
		service.emit(soundRequestFor(CueEventId.START_BOUNDED_FULL, _captureOwner()))
		service.invalidate()
		self._drainVoice(audio, host, rounds=5)
		played = [entry[1] for entry in log if entry[0] == "play"]
		self.assertNotIn(CueAtomId.PROGRESS_STATE.value, played)


if __name__ == "__main__":
	_ = unittest.main()
