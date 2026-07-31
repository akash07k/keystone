"""Asynchronous host playback for compositional sound atoms.

This adapter turns scheduler-selected atoms into non-overlapping playback on the
installed host's low-level output seam. It is the direct playback path only: it
resolves atom bytes through an injected manifest, feeds them to a single reused
player asynchronously, and routes each completion back to the caller on the main
thread. Playback policy (priority, gaps, replacement, generations) lives entirely
in the pure scheduler; this seam owns none of it.

The module performs no host import at load time, so the contract tests import and
drive it without a running host. The real output seam is imported lazily the first
time a sound actually needs to play.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from ctypes import byref, c_char_p, c_uint
from importlib import import_module
from io import BytesIO
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable
import wave

from ...domain.sounds import CueAtomId
from ...ports.audio import AudioOutcome, AudioPlayback


__all__ = (
	"AudioAtomRejected",
	"AudioAtomUnavailable",
	"AudioManifest",
	"MainThreadMarshal",
	"NvdaWaveAudioPort",
	"SoundThemeManifest",
	"WaveOut",
	"WaveOutFactory",
)


# Signed 16-bit little-endian stereo at 44.1 kHz: the one format the sound tool packages in WAV files.
_WAVE_FORMAT_PCM = 1
_SAMPLE_RATE_HZ = 44100
_CHANNELS = 2
_SAMPLE_WIDTH_BYTES = 2
_BYTES_PER_SECOND = _SAMPLE_RATE_HZ * _SAMPLE_WIDTH_BYTES * _CHANNELS

# The native WASAPI player only fires a fed chunk's completion as a side effect of a
# *later* call into the player (another feed, or a sync/idle wait); nothing calls back
# spontaneously from a hardware interrupt or a background thread on its own. NVDA's own
# synth drivers rely on this by always calling back into the player soon after a feed
# (e.g. WavePlayer.idle() on their own dedicated audio thread). Keystone plays one
# fire-and-forget atom at a time and only ever feeds the next one once the current one's
# completion has already been delivered, so without an explicit poll nothing would ever
# call back into the player again for the sole in-flight atom, and its completion would
# never arrive. This interval drives that poll; it is short relative to an atom's
# sub-second length so a finished atom is detected promptly.
_COMPLETION_POLL_INTERVAL_MILLISECONDS = 50


class AudioAtomUnavailable(Exception):
	"""The requested atom has no playable source in the manifest."""


class AudioAtomRejected(Exception):
	"""The atom source exists but its bytes are not playable audio."""


def _validatePcm(data: bytes) -> str | None:
	"""Return a reason when the frames are unplayable, else ``None``."""

	if len(data) == 0:
		return "empty"
	if len(data) % (_SAMPLE_WIDTH_BYTES * _CHANNELS) != 0:
		return "misaligned"
	return None


def _decodeWav(data: bytes) -> bytes:
	"""Extract the supported PCM frames from one bundled RIFF/WAV asset."""

	try:
		with wave.open(BytesIO(data), "rb") as reader:
			if reader.getcomptype() != "NONE":
				raise AudioAtomRejected("compressed")
			if reader.getnchannels() != _CHANNELS:
				raise AudioAtomRejected("unexpected channel count")
			if reader.getsampwidth() != _SAMPLE_WIDTH_BYTES:
				raise AudioAtomRejected("unexpected sample width")
			if reader.getframerate() != _SAMPLE_RATE_HZ:
				raise AudioAtomRejected("unexpected sample rate")
			return reader.readframes(reader.getnframes())
	except AudioAtomRejected:
		raise
	except (EOFError, wave.Error) as error:
		raise AudioAtomRejected("not a supported WAV") from error


@runtime_checkable
class AudioManifest(Protocol):
	def pcmFor(self, atom: CueAtomId) -> bytes: ...


@runtime_checkable
class MainThreadMarshal(Protocol):
	def callLater(self, delayMilliseconds: int, action: Callable[[], None]) -> None: ...


@runtime_checkable
class WaveOut(Protocol):
	def open(self) -> None: ...

	def feed(self, data: bytes) -> int: ...

	def stop(self) -> None: ...

	def close(self) -> None: ...

	def poll(self) -> None: ...


WaveOutFactory = Callable[[Callable[[int], None]], WaveOut]
AudioFailureReporter = Callable[[CueAtomId, str], None]


class SoundThemeManifest:
	"""Resolve atoms to validated PCM frames under one fixed manifest directory.

	Paths are taken from the injected mapping and confirmed to stay within the
	manifest root before any bytes are read. Bundled assets are RIFF/WAV containers;
	their frames are extracted before they reach the raw PCM WASAPI seam.
	"""

	def __init__(self, *, root: Path, paths: Mapping[CueAtomId, str]) -> None:
		super().__init__()
		self._root = root.resolve()
		self._paths = dict(paths)

	def pcmFor(self, atom: CueAtomId) -> bytes:
		relative = self._paths.get(atom)
		if relative is None:
			raise AudioAtomUnavailable(f"no manifest entry for {atom.value}")
		candidate = (self._root / relative).resolve()
		if candidate != self._root and self._root not in candidate.parents:
			raise AudioAtomUnavailable(f"manifest path for {atom.value} escapes the root")
		try:
			data = candidate.read_bytes()
		except OSError as error:
			raise AudioAtomUnavailable(f"cannot read {atom.value}: {error}") from error
		frames = _decodeWav(data)
		reason = _validatePcm(frames)
		if reason is not None:
			raise AudioAtomRejected(f"{atom.value} is {reason}")
		return frames


class _WasapiWaveOut:
	"""Thin wrapper over the installed WASAPI seam for one stereo 16-bit player."""

	def __init__(self, *, wasapi: Any, waveFormat: Any, onDone: Callable[[int], None]) -> None:
		super().__init__()
		self._wasapi = wasapi
		fmt: Any = waveFormat()
		fmt.wFormatTag = _WAVE_FORMAT_PCM
		fmt.nChannels = _CHANNELS
		fmt.nSamplesPerSec = _SAMPLE_RATE_HZ
		fmt.wBitsPerSample = _SAMPLE_WIDTH_BYTES * 8
		fmt.nBlockAlign = _SAMPLE_WIDTH_BYTES * _CHANNELS
		fmt.nAvgBytesPerSec = _BYTES_PER_SECOND
		fmt.cbSize = 0
		self._buffers: dict[int, bytes] = {}

		# The C callback must outlive playback, so it is held on the instance.
		def forward(_player: object, feedId: int) -> None:
			completed = int(feedId)
			_ = self._buffers.pop(completed, None)
			onDone(completed)

		self._onDone: Any = wasapi.wasPlay_callback(forward)
		self._player: Any = wasapi.wasPlay_create("", fmt, self._onDone)

	def open(self) -> None:
		_ = self._wasapi.wasPlay_open(self._player)

	def feed(self, data: bytes) -> int:
		feedId = c_uint()
		# WASAPI consumes this buffer asynchronously. Keep the original bytes alive until its
		# completion callback, as NVDA's own WavePlayer does.
		_ = self._wasapi.wasPlay_feed(self._player, cast(c_char_p, data), len(data), byref(feedId))
		identifier = int(feedId.value)
		self._buffers[identifier] = data
		return identifier

	def stop(self) -> None:
		_ = self._wasapi.wasPlay_stop(self._player)
		self._buffers.clear()

	def close(self) -> None:
		self._buffers.clear()
		self._wasapi.wasPlay_destroy(self._player)

	def poll(self) -> None:
		# A zero-length, id-less feed touches no render buffer (there are no frames to
		# send) and starts nothing playing; it only lets the native player check its
		# already-fed chunks' positions and fire any that have finished. This is the
		# supported, side-effect-free way to service completions between real feeds.
		_ = self._wasapi.wasPlay_feed(self._player, None, 0, None)


def _defaultWaveFactory(onDone: Callable[[int], None]) -> WaveOut:
	"""Build the real installed-host player, importing the seam only when needed."""

	wasapi = import_module("wasapi")
	waveFormat = import_module("winBindings.mmeapi").WAVEFORMATEX
	return _WasapiWaveOut(wasapi=wasapi, waveFormat=waveFormat, onDone=onDone)


class NvdaWaveAudioPort:
	"""Play one atom at a time on the host seam, isolating every failure.

	A single player is created lazily and reused. Each started atom is registered
	under the seam's feed identity together with the current epoch; a stop or a
	device failure supersedes the epoch, so a completion that arrives afterward,
	even one reusing a recycled feed identity, is dropped instead of advancing a
	newer job.
	"""

	def __init__(
		self,
		*,
		manifest: AudioManifest,
		marshal: MainThreadMarshal,
		waveFactory: WaveOutFactory = _defaultWaveFactory,
		failureReporter: AudioFailureReporter | None = None,
	) -> None:
		super().__init__()
		self._manifest = manifest
		self._marshal = marshal
		self._waveFactory = waveFactory
		self._failureReporter = failureReporter
		self._wave: WaveOut | None = None
		self._pending: dict[int, tuple[AudioPlayback, Callable[[AudioPlayback], None]]] = {}
		self._epoch = 0

	def play(self, playback: AudioPlayback, onFinished: Callable[[AudioPlayback], None]) -> AudioOutcome:
		try:
			data = self._manifest.pcmFor(playback.atom)
		except AudioAtomUnavailable:
			self._reportFailure(playback.atom, "assetUnavailable")
			return AudioOutcome("unavailable")
		except AudioAtomRejected:
			self._reportFailure(playback.atom, "assetRejected")
			return AudioOutcome("rejected")
		except Exception:
			self._reportFailure(playback.atom, "assetReadFailed")
			return AudioOutcome("failed")
		try:
			wave = self._ensureWave()
			# NVDA's own WavePlayer.feed() reopens the device on every call, unconditionally,
			# because it is not an error to reopen an already-open device but a stopped one
			# (the outcome of the preceding REPLACE's ``stop()``) must be reopened before a fed
			# buffer will actually render and signal completion. Skipping this leaves a
			# replacement atom silently stuck: fed and pending forever, with its completion
			# never delivered and the scheduler's single voice never freed.
			wave.open()
		except Exception:
			self._teardown()
			self._reportFailure(playback.atom, "waveOpenFailed")
			return AudioOutcome("failed")
		try:
			feedId = wave.feed(data)
		except Exception:
			self._teardown()
			self._reportFailure(playback.atom, "waveFeedFailed")
			return AudioOutcome("failed")
		self._pending[feedId] = (playback, onFinished)
		# The native player never calls back on its own: a fed chunk's completion is
		# only ever discovered as a side effect of a *later* call into the player. A
		# one-shot atom with nothing else queued would otherwise never trigger that later
		# call, so this schedules the first of a short recurring poll that keeps
		# checking until the completion (or a supersede) clears this epoch's pending work.
		self._schedulePoll(self._epoch)
		return AudioOutcome("started")

	def stop(self) -> None:
		self._supersede()
		wave = self._wave
		if wave is None:
			return
		try:
			wave.stop()
		except Exception:
			self._teardown()

	def close(self) -> None:
		self._teardown()

	def _ensureWave(self) -> WaveOut:
		wave = self._wave
		if wave is not None:
			return wave
		created = self._waveFactory(self._onSeamDone)
		created.open()
		self._wave = created
		return created

	def _onSeamDone(self, feedId: int) -> None:
		# The native player invokes this callback synchronously, inline, from whichever
		# call (a feed or this adapter's own poll) noticed the chunk had finished; it is
		# not a spontaneous, separately-threaded hardware notification. Hand delivery to
		# the main thread regardless, so callers never depend on which call detected it.
		epoch = self._epoch
		self._marshal.callLater(0, lambda: self._deliver(feedId, epoch))

	def _deliver(self, feedId: int, epoch: int) -> None:
		if epoch != self._epoch:
			return
		entry = self._pending.pop(feedId, None)
		if entry is None:
			return
		playback, onFinished = entry
		onFinished(playback)

	def _schedulePoll(self, epoch: int) -> None:
		try:
			self._marshal.callLater(_COMPLETION_POLL_INTERVAL_MILLISECONDS, lambda: self._poll(epoch))
		except Exception:
			pass

	def _poll(self, epoch: int) -> None:
		# Stop as soon as this generation is superseded or every pending completion for it
		# has already been delivered; otherwise nudge the native player so it can notice a
		# finished chunk, then keep polling until one of those two things becomes true.
		if epoch != self._epoch or not self._pending:
			return
		wave = self._wave
		if wave is not None:
			try:
				wave.poll()
			except Exception:
				self._teardown()
				return
		if epoch == self._epoch and self._pending:
			self._schedulePoll(epoch)

	def _supersede(self) -> None:
		self._epoch += 1
		self._pending.clear()

	def _teardown(self) -> None:
		self._supersede()
		wave = self._wave
		self._wave = None
		if wave is None:
			return
		try:
			wave.close()
		except Exception:
			pass

	def _reportFailure(self, atom: CueAtomId, reasonCode: str) -> None:
		reporter = self._failureReporter
		if reporter is None:
			return
		try:
			reporter(atom, reasonCode)
		except Exception:
			pass
