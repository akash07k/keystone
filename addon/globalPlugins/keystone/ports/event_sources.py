"""Ports for pluggable event sources feeding the process-pinned monitor.

An event source turns a backend's callbacks (NVDA object events or raw UIA automation events) into
immutable :class:`~..domain.event_monitor.EventReceipt` primitives and delivers them to a sink. The
sink (the monitor service) owns all history, privacy, retention, and threading concerns; a source
only subscribes to approved families for the pinned scope, builds minimal receipts, and unsubscribes
on request. No source ever hands a live COM/NVDA reference across the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..domain.event_monitor import EventBackend, EventFilter, EventReceipt, MonitorScope


@dataclass(frozen=True, slots=True)
class SubscriptionRequest:
	"""The approved scope, filter, and lifecycle generation a source subscribes under."""

	scope: MonitorScope
	activeFilter: EventFilter
	generation: int

	def __post_init__(self) -> None:
		if self.generation < 0:
			raise ValueError("subscription generation must be nonnegative")


@runtime_checkable
class EventSink(Protocol):
	"""Where a source delivers immutable receipts; delivery must never block the callback."""

	def deliver(self, receipt: EventReceipt) -> None: ...


@runtime_checkable
class EventSource(Protocol):
	"""One backend's event stream, subscribed for a single pinned scope at a time."""

	@property
	def backend(self) -> EventBackend: ...

	@property
	def families(self) -> tuple[str, ...]: ...

	@property
	def active(self) -> bool: ...

	@property
	def subscriptionCount(self) -> int: ...

	def subscribe(self, sink: EventSink, request: SubscriptionRequest) -> None: ...

	def updateFilter(self, activeFilter: EventFilter) -> None: ...

	def unsubscribe(self) -> None: ...
