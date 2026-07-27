from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..domain.sounds import CueAtomId
from ..domain.status import requireNonnegativeInteger


__all__ = (
	"AudioPlayback",
	"AudioOutcome",
	"AudioPort",
)


@dataclass(frozen=True, slots=True)
class AudioPlayback:
	atom: CueAtomId
	generation: int
	token: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.generation, "audio playback generation")
		if requireNonnegativeInteger(self.token, "audio playback token") == 0:
			raise ValueError("audio playback token must be positive")


@dataclass(frozen=True, slots=True)
class AudioOutcome:
	token: str

	def __post_init__(self) -> None:
		if self.token not in ("started", "unavailable", "rejected", "failed"):
			raise ValueError(f"unknown audio outcome {self.token!r}")

	@property
	def started(self) -> bool:
		return self.token == "started"


@runtime_checkable
class AudioPort(Protocol):
	def play(self, playback: AudioPlayback, onFinished: Callable[[AudioPlayback], None]) -> AudioOutcome: ...

	def stop(self) -> None: ...
