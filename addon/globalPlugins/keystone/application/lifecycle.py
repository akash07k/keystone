from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..domain.correlation import CorrelationContext, CorrelationFactory


@dataclass(frozen=True, slots=True)
class LifecycleAdmission:
	operation: str
	accepted: bool
	generation: int
	context: CorrelationContext | None = None
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if not self.operation:
			raise ValueError("lifecycle operation must not be empty")
		if self.generation < 0:
			raise ValueError("lifecycle generation must be nonnegative")
		if self.accepted == (self.errorCode is not None):
			raise ValueError("lifecycle admission state is inconsistent")
		if self.accepted != (self.context is not None):
			raise ValueError("accepted lifecycle admission must carry correlation")
		if self.context is not None and self.context.generation != self.generation:
			raise ValueError("lifecycle admission generation must match correlation")


@dataclass(frozen=True, slots=True)
class _Callback:
	name: str
	invoke: Callable[[], None]


class LifecycleService:
	def __init__(self, correlationFactory: CorrelationFactory | None = None) -> None:
		super().__init__()
		self._correlationFactory = correlationFactory or CorrelationFactory()
		self._state = "ordinary"
		self._generation = 1
		self._invalidators: list[_Callback] = []
		self._sources: list[_Callback] = []
		self._queues: list[_Callback] = []
		self._ui: list[_Callback] = []
		self._resources: list[_Callback] = []
		self._teardownStarted = False

	@property
	def state(self) -> str:
		return self._state

	@property
	def generation(self) -> int:
		return self._generation

	def _register(self, collection: list[_Callback], name: str, callback: Callable[[], None]) -> None:
		if self._state != "ordinary":
			raise RuntimeError("cannot register lifecycle ownership after shutdown begins")
		if not name or any(entry.name == name for entry in collection):
			raise ValueError("lifecycle ownership names must be nonblank and unique")
		collection.append(_Callback(name, callback))

	def registerInvalidator(self, name: str, callback: Callable[[], None]) -> None:
		self._register(self._invalidators, name, callback)

	def registerSource(self, name: str, callback: Callable[[], None]) -> None:
		self._register(self._sources, name, callback)

	def registerQueue(self, name: str, callback: Callable[[], None]) -> None:
		self._register(self._queues, name, callback)

	def registerUi(self, name: str, callback: Callable[[], None]) -> None:
		self._register(self._ui, name, callback)

	def registerResource(self, name: str, callback: Callable[[], None]) -> None:
		self._register(self._resources, name, callback)

	def admit(self, operation: str) -> LifecycleAdmission:
		if self._state == "ordinary":
			return LifecycleAdmission(
				operation,
				True,
				self._generation,
				self._correlationFactory.admit(generation=self._generation),
			)
		return LifecycleAdmission(
			operation,
			False,
			self._generation,
			errorCode=f"KS.LIFECYCLE.{self._state.upper()}",
		)

	def requireCurrent(self, context: CorrelationContext) -> CorrelationContext:
		if not self.isCurrent(context.generation if context.generation is not None else -1):
			raise ValueError("correlation context is not current for this lifecycle")
		return self._correlationFactory.requireCurrent(context, self._generation)

	def isCurrent(self, generation: int) -> bool:
		return self._state == "ordinary" and generation == self._generation

	def precommit(self, admission: LifecycleAdmission) -> bool:
		return admission.accepted and self.isCurrent(admission.generation)

	@staticmethod
	def _invoke(callbacks: list[_Callback], *, reverse: bool = False) -> None:
		entries = reversed(callbacks) if reverse else iter(callbacks)
		for entry in entries:
			try:
				entry.invoke()
			except Exception:
				continue

	def transition(self, state: str) -> None:
		if state not in ("secure", "indeterminate", "terminating"):
			raise ValueError("unknown lifecycle transition")
		if self._state == "terminated":
			return
		if self._state != "ordinary" and state != "terminating":
			return
		self._state = state
		self._generation += 1
		if not self._teardownStarted:
			self._teardownStarted = True
			self._invoke(self._invalidators)
			self._invoke(self._sources)
			self._invoke(self._queues)
			self._invoke(self._ui)
			self._invoke(self._resources, reverse=True)
		if state == "terminating":
			self._state = "terminated"
