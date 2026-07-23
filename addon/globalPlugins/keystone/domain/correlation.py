from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from .status import requireNonnegativeInteger


@dataclass(frozen=True, slots=True)
class CorrelationId:
	value: str

	def __post_init__(self) -> None:
		try:
			parsed = UUID(self.value)
		except (AttributeError, ValueError) as error:
			raise ValueError("correlation ID must be a canonical UUID") from error
		if self.value != str(parsed):
			raise ValueError("correlation ID must be lowercase canonical UUID text")

	@property
	def statusSuffix(self) -> str:
		return self.value.replace("-", "")[-8:]

	@classmethod
	def new(cls) -> CorrelationId:
		return cls(str(uuid4()))


@dataclass(frozen=True, slots=True)
class CorrelationContext:
	sessionId: CorrelationId
	operationId: CorrelationId | None = None
	jobId: CorrelationId | None = None
	generation: int | None = None

	def __post_init__(self) -> None:
		if self.generation is not None:
			_ = requireNonnegativeInteger(self.generation, "generation")

	@property
	def applicableId(self) -> CorrelationId:
		return self.jobId or self.operationId or self.sessionId


def requireCompleteCorrelation(context: object) -> CorrelationContext:
	if not isinstance(context, CorrelationContext):
		raise TypeError("correlation context must be a CorrelationContext")
	if context.operationId is None or context.jobId is None or context.generation is None:
		raise ValueError("admitted correlation context must be complete")
	return context


class CorrelationFactory:
	__slots__ = ("_contexts", "_idFactory", "_issuedIds", "_sessionId")

	def __init__(self, *, idFactory: Callable[[], object] = CorrelationId.new) -> None:
		super().__init__()
		self._idFactory = idFactory
		self._issuedIds: set[CorrelationId] = set()
		self._sessionId = self._allocateId()
		self._contexts: list[CorrelationContext] = []

	@property
	def sessionId(self) -> CorrelationId:
		return self._sessionId

	def _allocateId(self) -> CorrelationId:
		identifier = self._idFactory()
		if not isinstance(identifier, CorrelationId):
			raise TypeError("correlation ID factory must return CorrelationId")
		if identifier in self._issuedIds:
			raise ValueError("correlation ID factory returned a duplicate ID")
		self._issuedIds.add(identifier)
		return identifier

	def admit(self, *, generation: int) -> CorrelationContext:
		_ = requireNonnegativeInteger(generation, "generation")
		context = CorrelationContext(
			sessionId=self._sessionId,
			operationId=self._allocateId(),
			jobId=self._allocateId(),
			generation=generation,
		)
		self._contexts.append(context)
		return context

	def requireCurrent(self, context: CorrelationContext, generation: int) -> CorrelationContext:
		_ = requireCompleteCorrelation(context)
		_ = requireNonnegativeInteger(generation, "generation")
		if context.generation != generation:
			raise ValueError("correlation context generation is stale")
		if context.sessionId != self._sessionId:
			raise ValueError("correlation context belongs to another session")
		if not any(issued is context for issued in self._contexts):
			raise ValueError("correlation context was not admitted by this factory")
		return context
