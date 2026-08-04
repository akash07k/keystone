from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ..domain.sounds import (
	FIRST_PROGRESS_DELAY_MILLISECONDS,
	MINIMUM_PROGRESS_INTERVAL_MILLISECONDS,
	CueAtomId,
	DispatchDecision,
	SoundDispatch,
	SoundOwner,
	SoundRequest,
	SoundScheduler,
)
from ..ports.audio import AudioOutcome, AudioPlayback, AudioPort
from ..ports.effects import EffectResult, FeedbackPort, FeedbackRequest


type SoundRuntimeLog = Callable[[str, tuple[tuple[str, str | int | bool], ...]], None]


__all__ = (
	"SoundHost",
	"WorkflowSounds",
	"SoundService",
)


@runtime_checkable
class SoundHost(Protocol):
	def nowMilliseconds(self) -> int: ...

	def callLater(self, delayMilliseconds: int, action: Callable[[], None]) -> None: ...


@runtime_checkable
class WorkflowSounds(Protocol):
	"""The optional sound seam a workflow surface uses after it has already spoken.

	Every method is a no-op-safe addition to speech: a surface speaks its mandatory
	announcement first, then may ``emit`` a typed cue, ``tick`` an active progress track, or
	``invalidate`` an owner generation. Sound never blocks, alters, or reorders speech, and a
	``None`` seam (or a disabled service) leaves spoken output byte-identical.
	"""

	def emit(self, request: SoundRequest) -> None: ...

	def tick(self) -> None: ...

	def invalidate(self, owner: SoundOwner | None = None) -> None: ...


class SoundService:
	def __init__(
		self,
		*,
		feedback: FeedbackPort,
		audio: AudioPort,
		scheduler: SoundScheduler,
		host: SoundHost,
		enabled: bool = True,
		runtimeLog: SoundRuntimeLog | None = None,
	) -> None:
		super().__init__()
		self._feedback = feedback
		self._audio = audio
		self._scheduler = scheduler
		self._host = host
		self._enabled = enabled
		self._runtimeLog = runtimeLog
		self._previewToken = 0
		self._previewPlayingToken: int | None = None
		self._pumpEpoch = 0
		self._closed = False

	@property
	def enabled(self) -> bool:
		return self._enabled

	def setEnabled(self, enabled: bool) -> None:
		self._enabled = enabled

	def announce(self, speech: FeedbackRequest, request: SoundRequest | None = None) -> EffectResult:
		# Speech is the product outcome: it is submitted first and is unaffected by any sound.
		result = self._feedback.announce(speech)
		if request is not None:
			self.emit(request)
		return result

	def emit(self, request: SoundRequest) -> None:
		# The sound half of a transition the caller has already spoken. Isolated and skippable:
		# it does nothing when sound is disabled, so speech stays byte-identical either way.
		if self._closed or not self._enabled:
			self._record(
				"KS.SOUND.PLAY_SUPPRESSED",
				(
					("transitionId", request.event.value),
					("suppressionReason", "closed" if self._closed else "disabled"),
					("soundGeneration", request.owner.generation),
				),
			)
			return
		self._schedule(request)
		if request.startsProgress:
			self._armProgressPump()

	def preview(
		self,
		atom: CueAtomId,
		*,
		generation: int,
		announcement: FeedbackRequest,
		unavailable: FeedbackRequest,
	) -> AudioOutcome:
		# A settings-dialog audition: speech is submitted first and is never withheld by playback.
		# Preview bypasses the operation scheduler (its single voice and queue) entirely, owns the
		# supplied dialog generation, replaces any earlier preview, and is not gated by the global
		# enablement preference because it is an explicit user action. A failed, missing, corrupt, or
		# unsupported asset still leaves the spoken announcement intact and adds the safe fallback line.
		_ = self._feedback.announce(announcement)
		if self._closed:
			_ = self._feedback.announce(unavailable)
			return AudioOutcome("unavailable")
		outcome = self._previewPlay(atom, generation)
		if not outcome.started:
			_ = self._feedback.announce(unavailable)
		return outcome

	def stopPreview(self) -> None:
		self._interruptForPreview()

	def _previewPlay(self, atom: CueAtomId, generation: int) -> AudioOutcome:
		self._interruptForPreview()
		self._previewToken += 1
		try:
			playback = AudioPlayback(atom=atom, generation=generation, token=self._previewToken)
			self._previewPlayingToken = playback.token
			outcome = self._audio.play(playback, self._onPreviewFinished)
		except Exception:
			self._previewPlayingToken = None
			return AudioOutcome("failed")
		if not outcome.started:
			self._previewPlayingToken = None
		return outcome

	def tick(self) -> None:
		if self._closed or not self._enabled:
			return
		try:
			dispatch = self._scheduler.tick(self._host.nowMilliseconds())
			if dispatch.plays:
				self._play(dispatch)
		except Exception:
			self._recover()

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		self._silence()
		try:
			self._scheduler.invalidate(owner)
		except Exception:
			pass

	def close(self) -> None:
		if self._closed:
			return
		self._closed = True
		self._pumpEpoch += 1
		self.invalidate()
		close = getattr(self._audio, "close", None)
		if callable(close):
			try:
				_ = close()
			except Exception:
				pass

	def _armProgressPump(self) -> None:
		# A progress-opening cue starts a self-rescheduling pump on the host loop. It pulses the
		# active track once the first-progress delay elapses and then at the configured interval,
		# and it stops the instant the track is cleared - by a terminal outcome cue or by
		# invalidation - so a synchronous capture that never yields ends before the first pulse.
		# The epoch guards against overlapping pumps when a newer progress cue supersedes an old one.
		self._pumpEpoch += 1
		self._scheduleProgressPump(self._pumpEpoch, FIRST_PROGRESS_DELAY_MILLISECONDS)

	def _scheduleProgressPump(self, epoch: int, delayMilliseconds: int) -> None:
		# Any host-scheduling failure stays isolated: a missing pump never disturbs speech or cues.
		try:
			self._host.callLater(delayMilliseconds, lambda: self._pumpProgress(epoch))
		except Exception:
			pass

	def _pumpProgress(self, epoch: int) -> None:
		# Stop cleanly when superseded, disabled, or once no progress track remains active; otherwise
		# pulse the track (tick is a no-op while the single voice is busy) and reschedule.
		if epoch != self._pumpEpoch or not self._enabled:
			return
		if not self._scheduler.state.progressOwners:
			return
		self.tick()
		self._scheduleProgressPump(epoch, MINIMUM_PROGRESS_INTERVAL_MILLISECONDS)

	def _schedule(self, request: SoundRequest) -> None:
		try:
			dispatch = self._scheduler.dispatch(request, nowMilliseconds=self._host.nowMilliseconds())
			if not dispatch.plays:
				self._record(
					"KS.SOUND.PLAY_SUPPRESSED",
					(
						("transitionId", request.event.value),
						("suppressionReason", dispatch.decision.value),
						("soundGeneration", request.owner.generation),
					),
				)
			self._render(dispatch)
		except Exception:
			self._recover()

	def _render(self, dispatch: SoundDispatch) -> None:
		if dispatch.decision is DispatchDecision.REPLACE:
			self._audio.stop()
		if dispatch.plays:
			self._play(dispatch)

	def _play(self, dispatch: SoundDispatch) -> None:
		atom = dispatch.atom
		owner = dispatch.owner
		if atom is None or owner is None:
			return
		if self._previewPlayingToken is not None:
			self._silence()
		playback = AudioPlayback(atom=atom, generation=owner.generation, token=dispatch.token)
		self._record(
			"KS.SOUND.PLAY_REQUESTED",
			(
				("transitionId", atom.value),
				("motifCount", 1),
				("soundGeneration", playback.generation),
			),
		)
		outcome = self._audio.play(playback, self._completion(dispatch.hasFollowOn, dispatch.gapMilliseconds))
		if not outcome.started:
			self._record(
				"KS.SOUND.PLAY_FAILED",
				(
					("transitionId", atom.value),
					("reasonCode", outcome.token),
					("assetId", atom.value),
				),
			)
			self._release(dispatch.token)

	def _completion(self, hasFollowOn: bool, gapMilliseconds: int) -> Callable[[AudioPlayback], None]:
		def onFinished(finished: AudioPlayback) -> None:
			self._onAtomFinished(finished.token, hasFollowOn, gapMilliseconds)

		return onFinished

	def _onPreviewFinished(self, finished: AudioPlayback) -> None:
		if finished.token == self._previewPlayingToken:
			self._previewPlayingToken = None

	def _onAtomFinished(self, token: int, hasFollowOn: bool, gapMilliseconds: int) -> None:
		try:
			if hasFollowOn:
				self._host.callLater(gapMilliseconds, lambda: self._advance(token))
			else:
				# A final atom's own completion can now hand back a fresh PLAY: the deferred
				# capture-start (if any) that was waiting for exactly this cue to finish. See
				# SoundScheduler.completeAtom's promotion of a transient-layer-cue deferral.
				dispatch = self._scheduler.completeAtom(token, nowMilliseconds=self._host.nowMilliseconds())
				if dispatch.plays:
					self._play(dispatch)
		except Exception:
			self._recover()

	def _advance(self, token: int) -> None:
		try:
			dispatch = self._scheduler.completeAtom(token, nowMilliseconds=self._host.nowMilliseconds())
			if dispatch.plays:
				self._play(dispatch)
		except Exception:
			self._recover()

	def _release(self, token: int) -> None:
		# Playback never started; drain the remaining atoms so the single voice is freed at once.
		dispatch = self._scheduler.completeAtom(token, nowMilliseconds=self._host.nowMilliseconds())
		while dispatch.plays:
			if dispatch.token != token:
				# Completing the failed replacement released a capture-start that was deferred
				# behind layer-enter. It is a new sequence and must use the normal play path.
				self._play(dispatch)
				return
			dispatch = self._scheduler.completeAtom(
				dispatch.token,
				nowMilliseconds=self._host.nowMilliseconds(),
			)

	def _recover(self) -> None:
		self._silence()
		owner = self._scheduler.state.activeOwner
		if owner is not None:
			self._scheduler.invalidate(owner)

	def _interruptForPreview(self) -> None:
		# Preview shares the physical device with scheduled cues. Once it stops the device, discard
		# every scheduled state because the interrupted atom can no longer complete and release it.
		self._silence()
		try:
			self._scheduler.invalidate()
		except Exception:
			pass

	def _silence(self) -> None:
		self._previewPlayingToken = None
		try:
			self._audio.stop()
		except Exception:
			pass

	def _record(self, code: str, fields: tuple[tuple[str, str | int | bool], ...]) -> None:
		runtimeLog = self._runtimeLog
		if runtimeLog is None:
			return
		try:
			runtimeLog(code, fields)
		except Exception:
			pass
