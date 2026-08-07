"""Production event-monitor session: the single owner-thread lifecycle for live monitoring.

``EventMonitorSession`` is the one production seam that ties the shipped pieces together: the
``NvdaEventSource`` the global plugin's forwarders already feed, an optional ``RawUiaEventSource``
bridged from NVDA's own ``event_UIA_*`` callbacks, the ``EventMonitorService`` that owns history and
privacy, and the singleton ``EventsWorkspace`` that renders it. Opening the session shows the stopped workspace. Its explicit
Start action pins a scope, subscribes those exact sources (never a disconnected duplicate), and starts
a bounded owner-thread drain pump. The pump moves at most one drain batch per tick off the service
queue and re-renders the open frame, so forwarded events reach retained history without ever blocking
an NVDA callback. Stop retains the workspace and history; closing the window, tearing the session
down, or a lifecycle boundary also stops the pump and unsubscribes every source cleanly, and no stale
pump tick survives the stop.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from time import monotonic
from typing import Protocol, runtime_checkable

from ...application.event_monitor_service import EventMonitorService
from ...domain.event_monitor import (
	BoundaryReason,
	EventRow,
	MonitorScope,
	MonitorScopeKind,
	MonitorScopeUnavailable,
	RawUiaFamily,
	ScopeUnavailableReason,
	TargetLifecycleReason,
)
from ...ports.event_sources import EventSource
from ..windows.raw_uia_events import RawUiaNotification
from ..wx.inspector_frame import EventsWorkspace
from .event_sources import NvdaEventSource, targetIdentityFromObject

# The owner-thread drain cadence. Short enough that live events feel immediate, long enough that a
# chatty control never starves NVDA's own core loop; each tick still drains at most one bounded batch.
_DRAIN_INTERVAL_MS = 100
TARGET_LIVENESS_INTERVAL_MS = 1_000

type _CancellableExecute = Callable[[Callable[[], bool]], bool]
type _WindowCheck = Callable[[int], bool]


def _monotonicMs() -> float:
	return monotonic() * 1_000.0


def _cancellableExecute(action: Callable[[], bool]) -> bool:
	try:
		executor = getattr(import_module("watchdog"), "cancellableExecute", None)
	except ImportError:
		executor = None
	return bool(executor(action)) if callable(executor) else action()


def _windowIsValid(windowHandle: int) -> bool:
	try:
		check = getattr(import_module("winUser"), "isWindow", None)
	except ImportError:
		return True
	return bool(check(windowHandle)) if callable(check) else True


def _windowIsHung(windowHandle: int) -> bool:
	try:
		check = getattr(import_module("winUser"), "isHungAppWindow", None)
	except ImportError:
		return False
	return bool(check(windowHandle)) if callable(check) else False


def _isComFailure(error: Exception) -> bool:
	return type(error).__name__ == "COMError" or hasattr(error, "hresult")


def _isCallCancelled(error: Exception) -> bool:
	try:
		callCancelled = getattr(import_module("exceptions"), "CallCancelled")
	except (ImportError, AttributeError):
		return type(error).__name__ == "CallCancelled"
	return isinstance(error, callCancelled)


@runtime_checkable
class _TimerHandle(Protocol):
	def Stop(self) -> None: ...


def _wxScheduleLater(delayMilliseconds: int, action: Callable[[], None]) -> object:
	return import_module("wx").CallLater(max(0, delayMilliseconds), action)


def _noInspectorSelection() -> object:
	"""Refuse to invent a selection when no Inspector hierarchy selection was wired in."""

	raise MonitorScopeUnavailable(ScopeUnavailableReason.NO_SELECTION)


class EventMonitorSession:
	"""One production monitoring lifecycle: subscribe the shipped sources, pump, and tear down once."""

	def __init__(
		self,
		*,
		service: EventMonitorService,
		workspace: EventsWorkspace,
		nvdaSource: NvdaEventSource,
		rawSource: EventSource | None = None,
		selectionResolver: Callable[[], object] = _noInspectorSelection,
		showSource: Callable[[EventRow], bool] | None = None,
		scheduleLater: Callable[[int, Callable[[], None]], object] = _wxScheduleLater,
		drainIntervalMs: int = _DRAIN_INTERVAL_MS,
		monotonicMs: Callable[[], float] = _monotonicMs,
		cancellableExecute: _CancellableExecute = _cancellableExecute,
		windowIsValid: _WindowCheck = _windowIsValid,
		windowIsHung: _WindowCheck = _windowIsHung,
		toggleDebounceMs: int = 500,
	) -> None:
		super().__init__()
		self._service = service
		self._workspace = workspace
		self._nvdaSource = nvdaSource
		self._rawSource = rawSource
		self._selectionResolver = selectionResolver
		self._showSource = showSource
		self._scheduleLater = scheduleLater
		self._drainIntervalMs = max(0, drainIntervalMs)
		self._monotonicMs = monotonicMs
		self._cancellableExecute = cancellableExecute
		self._windowIsValid = windowIsValid
		self._windowIsHung = windowIsHung
		self._toggleDebounceMs = max(0, toggleDebounceMs)
		self._lastTargetLivenessCheckMs: float | None = None
		self._lastToggleMs: float | None = None
		self._backgroundMonitoring = False
		self._pumpGeneration = 0
		self._pumpRunning = False
		self._timer: object | None = None
		self._closed = False
		self._scopeKind = MonitorScopeKind.ELEMENT
		self._pendingTargetObject: object | None = None
		self._frozenTargetObject: object | None = None
		self._lastScopeFailure: MonitorScopeUnavailable | None = None
		try:
			self._workspace.configureMonitoring(
				start=self.start,
				stop=self.stop,
				restart=self.restartWithCurrentInspectorSelection,
				showSource=self._showSource,
				scopeFailure=self.lastScopeFailure,
			)
		except TypeError:
			# Compatibility with an older host-side workspace double during add-on reload.
			self._workspace.configureMonitoring(start=self.start, stop=self.stop)

	@property
	def service(self) -> EventMonitorService:
		return self._service

	@property
	def workspace(self) -> EventsWorkspace:
		return self._workspace

	@property
	def pumpRunning(self) -> bool:
		return self._pumpRunning

	@property
	def rawSource(self) -> EventSource | None:
		return self._rawSource

	@property
	def nvdaSource(self) -> NvdaEventSource:
		return self._nvdaSource

	@property
	def sources(self) -> tuple[EventSource, ...]:
		return self._sources()

	def open(self) -> None:
		"""Show the singleton workspace without changing the monitoring state.

		Reusing the same ``NvdaEventSource`` the plugin's forwarders feed guarantees production events
		reach this service rather than a disconnected duplicate. Monitoring starts only through the
		workspace's explicit Start action; a second open just re-activates the existing frame.
		"""

		if self._closed:
			return
		self._workspace.show()
		if self._service.active:
			self._startPump()

	def lastScopeFailure(self) -> ScopeUnavailableReason | None:
		"""The exact reason the most recent Start or Restart refused to freeze a scope."""

		failure = self._lastScopeFailure
		return None if failure is None else failure.reason

	def resolveScopeFromInspectorSelection(self, kind: MonitorScopeKind) -> MonitorScope:
		"""Freeze the Inspector's current live selection for the requested scope kind.

		Every non-broad kind describes the object selected in the Inspector hierarchy. When that
		object is missing, offline, unresolvable, or carries no provider identity, this raises
		:class:`MonitorScopeUnavailable` with the exact reason rather than widening to the focused
		application or to every process.
		"""

		if kind is MonitorScopeKind.BROAD:
			self._pendingTargetObject = None
			return MonitorScope.broadScope()
		try:
			selected = self._selectionResolver()
		except MonitorScopeUnavailable as failure:
			raise MonitorScopeUnavailable(failure.reason, kind) from failure
		except Exception as error:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.NO_SELECTION, kind) from error
		if selected is None:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_UNRESOLVED, kind)
		try:
			processId = int(getattr(selected, "processID"))
			appModule = getattr(selected, "appModule", None)
			appName = getattr(appModule, "appName", None)
		except Exception as error:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.SELECTION_UNRESOLVED, kind) from error
		application = str(appName) if isinstance(appName, str) and appName else "selected application"
		if processId < 0:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.NO_PROCESS, kind)
		if kind is MonitorScopeKind.APPLICATION:
			self._pendingTargetObject = None
			return MonitorScope.pinned(application, processId)
		identity = targetIdentityFromObject(selected)
		if identity is None:
			raise MonitorScopeUnavailable(ScopeUnavailableReason.NO_IDENTITY, kind)
		self._pendingTargetObject = selected
		if kind is MonitorScopeKind.ELEMENT:
			return MonitorScope.element(application, processId, identity)
		if kind is MonitorScopeKind.SUBTREE:
			return MonitorScope.subtree(application, processId, identity)
		raise MonitorScopeUnavailable(ScopeUnavailableReason.UNSUPPORTED_SCOPE, kind)

	def start(self, kind: MonitorScopeKind = MonitorScopeKind.ELEMENT) -> bool:
		"""Start a new monitoring session from the explicit workspace action."""

		if self._closed:
			return False
		self._backgroundMonitoring = False
		if self._service.active:
			self._startPump()
			return True
		self._lastScopeFailure = None
		try:
			scope = self.resolveScopeFromInspectorSelection(kind)
			self._service.start(
				scope,
				self._sources(),
				targetName=self._announcementTargetName(),
			)
		except MonitorScopeUnavailable as failure:
			self._lastScopeFailure = failure
			self._workspace.refresh()
			return False
		except Exception:
			self._workspace.refresh()
			return False
		self._scopeKind = scope.kind
		self._frozenTargetObject = self._pendingTargetObject
		self._lastTargetLivenessCheckMs = None
		self._startPump()
		self._workspace.refresh()
		return True

	def toggle(self) -> bool:
		"""Stop an active session, or restart the last selected scope from the live Inspector."""

		if self._closed:
			return False
		now = self._monotonicMs()
		lastToggle = self._lastToggleMs
		if lastToggle is not None and now - lastToggle < self._toggleDebounceMs:
			return self._service.active
		self._lastToggleMs = now
		if self._service.active:
			self.stop()
			return False
		started = self.restartWithCurrentInspectorSelection()
		self._backgroundMonitoring = started
		return started

	def restartWithCurrentInspectorSelection(
		self,
		kind: MonitorScopeKind | None = None,
	) -> bool:
		"""Re-freeze the current Inspector selection while retaining prior rows.

		The selection contract is the one Start uses. A refusal leaves every retained row, the
		current session, and the frozen target exactly as they were.
		"""

		if self._closed:
			return False
		self._backgroundMonitoring = False
		requestedKind = self._scopeKind if kind is None else kind
		self._lastScopeFailure = None
		try:
			scope = self.resolveScopeFromInspectorSelection(requestedKind)
			if self._service.active:
				started = self._service.switchScope(scope, self._sources())
			else:
				self._service.start(
					scope,
					self._sources(),
					targetName=self._announcementTargetName(),
				)
				started = True
		except MonitorScopeUnavailable as failure:
			self._lastScopeFailure = failure
			self._workspace.refresh()
			return False
		except Exception:
			self._workspace.refresh()
			return False
		if not started:
			self._workspace.refresh()
			return False
		self._scopeKind = scope.kind
		self._frozenTargetObject = self._pendingTargetObject
		self._lastTargetLivenessCheckMs = None
		self._startPump()
		self._workspace.refresh()
		return True

	def _announcementTargetName(self) -> str | None:
		"""Return the bounded non-protected name used only in start feedback."""

		target = self._pendingTargetObject
		if target is None:
			return None
		try:
			if bool(getattr(target, "isProtected", False)):
				return None
			name = getattr(target, "name", None)
		except Exception:
			return None
		if not isinstance(name, str):
			return None
		name = " ".join(name.split())
		return name[:200] or None

	def stop(self, *, reason: BoundaryReason = BoundaryReason.STOPPED) -> None:
		"""Stop monitoring while retaining history and leaving the workspace available."""

		self._backgroundMonitoring = False
		self._stopPump()
		if self._service.active:
			self._service.stop(reason=reason)
		self._frozenTargetObject = None
		self._lastTargetLivenessCheckMs = None
		self._workspace.refresh()

	def targetUnavailable(self, reason: TargetLifecycleReason) -> None:
		"""Stop one frozen target with its exact provider lifecycle reason."""

		self._stopPump()
		self._service.targetUnavailable(reason)
		self._frozenTargetObject = None
		self._workspace.refresh()

	def forwardRaw(
		self,
		family: RawUiaFamily,
		obj: object,
		*,
		notification: RawUiaNotification | None = None,
		activeTextRange: object | None = None,
	) -> bool:
		"""Bridge one NVDA ``event_UIA_*`` object into the raw source; a no-op when raw is unwired.

		Returns whether the event was retained-bound. Any raw source failure is contained so a
		monitoring fault can never interrupt NVDA's event pipeline.
		"""

		source = self._rawSource
		forward = getattr(source, "forward", None)
		if source is None or not callable(forward):
			return False
		try:
			return bool(forward(family, obj, notification=notification, activeTextRange=activeTextRange))
		except TypeError:
			# A source double predating the notification data still receives the object itself.
			try:
				return bool(forward(family, obj))
			except Exception:
				return False
		except Exception:
			return False

	def close(self, *, reason: BoundaryReason = BoundaryReason.STOPPED) -> None:
		"""Stop the pump, stop the service session, and close the workspace frame. Idempotent."""

		self.stop(reason=reason)
		self._workspace.close()

	def dispose(self) -> None:
		"""Permanently tear down the session at plugin/lifecycle teardown; no reopen afterwards."""

		if self._closed:
			return
		self._closed = True
		self.close(reason=BoundaryReason.CLOSED)

	# -- internals ---------------------------------------------------------

	def _sources(self) -> tuple[EventSource, ...]:
		if self._rawSource is None:
			return (self._nvdaSource,)
		return (self._nvdaSource, self._rawSource)

	def _startPump(self) -> None:
		if self._pumpRunning:
			return
		self._pumpRunning = True
		self._pumpGeneration += 1
		self._scheduleTick(self._pumpGeneration)

	def _stopPump(self) -> None:
		self._pumpRunning = False
		# Bump the generation so any tick already queued on the owner thread returns without draining
		# or rescheduling, then proactively cancel the pending timer if the host exposed a handle.
		self._pumpGeneration += 1
		timer = self._timer
		self._timer = None
		if isinstance(timer, _TimerHandle):
			try:
				timer.Stop()
			except Exception:
				pass

	def _scheduleTick(self, generation: int) -> None:
		try:
			self._timer = self._scheduleLater(self._drainIntervalMs, lambda: self._pump(generation))
		except Exception:
			# A scheduler that cannot arm leaves the pump stopped rather than half-running; retained
			# history and the started session are unaffected and a later open can retry.
			self._pumpRunning = False
			self._timer = None

	def _pump(self, generation: int) -> None:
		if not self._pumpRunning or generation != self._pumpGeneration:
			return
		self._timer = None
		if self._targetWindowGone():
			self.targetUnavailable(TargetLifecycleReason.DESTROYED)
			return
		if self._targetIsHung():
			self.targetUnavailable(TargetLifecycleReason.HUNG)
			return
		if self._targetLivenessDue() and self._targetHasComFailure():
			self.targetUnavailable(TargetLifecycleReason.COM_FAILURE)
			return
		drained = 0
		try:
			drained = self._service.drain()
		except Exception:
			drained = 0
		if not self._workspace.isOpen and not self._backgroundMonitoring:
			# The user closed the Events window: end this monitoring session and stop pumping. The
			# retained history survives on the service for the next open.
			self.close()
			return
		if drained:
			try:
				if self._workspace.isOpen:
					self._workspace.refresh()
			except Exception:
				pass
		if self._pumpRunning and generation == self._pumpGeneration:
			self._scheduleTick(generation)

	def _targetWindowGone(self) -> bool:
		scope = self._service.scope
		if (
			scope is None
			or scope.kind not in (MonitorScopeKind.ELEMENT, MonitorScopeKind.SUBTREE)
			or scope.targetIdentity is None
		):
			return False
		try:
			return not self._windowIsValid(scope.targetIdentity.windowHandle)
		except Exception:
			return False

	def _targetIsHung(self) -> bool:
		scope = self._service.scope
		if (
			scope is None
			or scope.kind not in (MonitorScopeKind.ELEMENT, MonitorScopeKind.SUBTREE)
			or scope.targetIdentity is None
		):
			return False
		try:
			return self._windowIsHung(scope.targetIdentity.windowHandle)
		except Exception:
			return False

	def _targetLivenessDue(self) -> bool:
		now = self._monotonicMs()
		previous = self._lastTargetLivenessCheckMs
		if previous is not None and now - previous < TARGET_LIVENESS_INTERVAL_MS:
			return False
		self._lastTargetLivenessCheckMs = now
		return True

	def _targetHasComFailure(self) -> bool:
		target = self._frozenTargetObject
		if target is None:
			return False

		def check() -> bool:
			try:
				if getattr(target, "UIAElement", None) is None:
					return False
			except Exception as error:
				return _isComFailure(error)
			comFailed = False

			def noteFailure() -> None:
				nonlocal comFailed
				comFailed = True

			_ = targetIdentityFromObject(target, onComFailure=noteFailure)
			return comFailed

		try:
			return self._cancellableExecute(check)
		except Exception as error:
			if _isCallCancelled(error):
				return False
			return _isComFailure(error)
