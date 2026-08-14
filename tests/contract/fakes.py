from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import threading
from typing import Literal


type BoundaryStatus = Literal["success", "blocked", "slow", "failed", "cancelled"]


@dataclass(frozen=True, slots=True)
class ExecutionContext:
	threadId: int
	apartment: str
	generation: int


@dataclass(frozen=True, slots=True)
class BoundaryResult:
	status: BoundaryStatus
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status == "failed" and self.errorCode is None:
			raise ValueError("failed boundary results require an error code")
		if self.status != "failed" and self.errorCode is not None:
			raise ValueError("only failed boundary results accept an error code")


@dataclass(frozen=True, slots=True)
class ExpectedCall:
	member: str
	args: tuple[object, ...]
	result: object
	kwargs: tuple[tuple[str, object], ...] = ()
	threadId: int | None = None
	apartment: str | None = None
	generation: int | None = None
	releaseTokenArgument: int | None = None

	def __post_init__(self) -> None:
		if not self.member:
			raise ValueError("expected call member must not be empty")
		if len({name for name, _value in self.kwargs}) != len(self.kwargs):
			raise ValueError("expected call keyword names must be unique")
		if self.releaseTokenArgument is not None and self.releaseTokenArgument < 0:
			raise ValueError("release token argument index must be nonnegative")


class ResourceLedger:
	__slots__ = ("_adapter", "_owned", "_released")

	def __init__(self, adapter: str) -> None:
		super().__init__()
		self._adapter = adapter
		self._owned: set[str] = set()
		self._released: set[str] = set()

	def acquire(self, token: str) -> None:
		if token in self._owned or token in self._released:
			raise AssertionError(f"{self._adapter}: duplicate ownership for {token!r}")
		self._owned.add(token)

	def release(self, token: str, callIndex: int) -> None:
		if token in self._released:
			raise AssertionError(f"{self._adapter}: double release for {token!r} at call {callIndex}")
		if token not in self._owned:
			raise AssertionError(f"{self._adapter}: release of unknown token {token!r} at call {callIndex}")
		self._owned.remove(token)
		self._released.add(token)

	def assertEmpty(self) -> None:
		if self._owned:
			raise AssertionError(f"{self._adapter}: missing release for {sorted(self._owned)!r}")


class StrictCallFake:
	__slots__ = ("_adapter", "_contextProvider", "_expected", "_index", "_ledger")

	def __init__(
		self,
		adapter: str,
		expected: tuple[ExpectedCall, ...],
		*,
		contextProvider: Callable[[], ExecutionContext] | None = None,
		ledger: ResourceLedger | None = None,
	) -> None:
		super().__init__()
		if not adapter:
			raise ValueError("adapter name must not be empty")
		self._adapter = adapter
		self._expected = expected
		self._index = 0
		self._contextProvider = contextProvider or (
			lambda: ExecutionContext(
				threadId=threading.get_ident(),
				apartment="unspecified",
				generation=0,
			)
		)
		self._ledger = ledger

	@property
	def callIndex(self) -> int:
		return self._index

	def member(self, name: str) -> Callable[..., object]:
		return self.__getattr__(name)

	def __getattr__(self, name: str) -> Callable[..., object]:
		callIndex = self._index
		if callIndex >= len(self._expected):
			raise AssertionError(f"{self._adapter}.{name}: unexpected access at call {callIndex}")
		expected = self._expected[callIndex]
		if expected.member != name:
			raise AssertionError(
				f"{self._adapter}.{name}: expected {expected.member!r} at call {callIndex}",
			)

		def invoke(*args: object, **kwargs: object) -> object:
			return self._invoke(name, args, tuple(kwargs.items()))

		return invoke

	def _invoke(
		self,
		member: str,
		args: tuple[object, ...],
		kwargs: tuple[tuple[str, object], ...],
	) -> object:
		callIndex = self._index
		if callIndex >= len(self._expected):
			raise AssertionError(f"{self._adapter}.{member}: unexpected call at index {callIndex}")
		expected = self._expected[callIndex]
		if expected.member != member:
			raise AssertionError(
				f"{self._adapter}.{member}: expected {expected.member!r} at call {callIndex}",
			)
		if args != expected.args:
			raise AssertionError(
				f"{self._adapter}.{member}: argument mismatch at call {callIndex}: "
				+ f"expected {expected.args!r}, got {args!r}",
			)
		if kwargs != expected.kwargs:
			raise AssertionError(
				f"{self._adapter}.{member}: keyword mismatch at call {callIndex}: "
				+ f"expected {expected.kwargs!r}, got {kwargs!r}",
			)

		context = self._contextProvider()
		for label, required, actual in (
			("thread", expected.threadId, context.threadId),
			("apartment", expected.apartment, context.apartment),
			("generation", expected.generation, context.generation),
		):
			if required is not None and required != actual:
				raise AssertionError(
					f"{self._adapter}.{member}: {label} mismatch at call {callIndex}: "
					+ f"expected {required!r}, got {actual!r}",
				)

		if expected.releaseTokenArgument is not None:
			if expected.releaseTokenArgument >= len(args):
				raise AssertionError(
					f"{self._adapter}.{member}: missing release token argument at call {callIndex}",
				)
			token = args[expected.releaseTokenArgument]
			if not isinstance(token, str):
				raise AssertionError(
					f"{self._adapter}.{member}: release token must be a string at call {callIndex}",
				)
			if self._ledger is None:
				raise AssertionError(f"{self._adapter}.{member}: release ledger is not configured")
			self._ledger.release(token, callIndex)

		self._index += 1
		return expected.result

	def assertComplete(self) -> None:
		if self._index != len(self._expected):
			nextMember = self._expected[self._index].member
			raise AssertionError(
				f"{self._adapter}: missing call {self._index} ({nextMember!r}); "
				+ f"{len(self._expected) - self._index} call(s) remain",
			)
		if self._ledger is not None:
			self._ledger.assertEmpty()
