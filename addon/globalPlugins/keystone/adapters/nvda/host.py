from __future__ import annotations

from typing import Protocol

from ...application.lifecycle import LifecycleAdmission, LifecycleService
from ...capability import PlainValue, requireOpaqueId, requirePlainValue


class ImmutableScheduler(Protocol):
	def scheduleImmutable(
		self,
		taskId: str,
		generation: int,
		values: tuple[PlainValue, ...],
	) -> None: ...


class NvdaHostAdapter:
	def __init__(self, lifecycle: LifecycleService, scheduler: ImmutableScheduler) -> None:
		super().__init__()
		self._lifecycle = lifecycle
		self._scheduler = scheduler

	def desktopChanged(self, isSecure: bool | None) -> None:
		if isSecure is True:
			self._lifecycle.transition("secure")
		elif isSecure is None:
			self._lifecycle.transition("indeterminate")

	def schedule(
		self,
		taskId: str,
		admission: LifecycleAdmission,
		values: tuple[PlainValue, ...],
	) -> bool:
		requireOpaqueId(taskId, "taskId")
		requirePlainValue(values, "scheduled values")
		if not self._lifecycle.precommit(admission):
			return False
		self._scheduler.scheduleImmutable(taskId, admission.generation, values)
		return True
