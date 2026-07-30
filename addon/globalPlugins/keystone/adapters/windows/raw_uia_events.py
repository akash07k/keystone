"""Shipped raw UIA event source.

``RawUiaEventSource`` routes NVDA's settled ``event_UIA_*`` objects through immutable
:class:`RawUiaObjectDescriptor` values. It filters by pinned process before retention, refuses stale
or post-teardown callbacks before provider access, and never retains a live NVDA or COM object.

An injected client factory can additionally own one direct UIA focus subscription on the subscribing
thread for liveness observation. The production event families still arrive through NVDA's core event
chain; client acquisition failure disables only that optional observation and leaves NVDA monitoring
untouched.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import threading
from time import perf_counter
from typing import Any, Protocol, runtime_checkable

from ...domain.event_monitor import (
	RAW_UIA_FAMILIES,
	ChangeEvidence,
	EventBackend,
	EventFilter,
	EventReceipt,
	MonitorScope,
	MonitorScopeKind,
	RawUiaFamily,
	TargetIdentity,
)
from ...ports.event_sources import EventSink, SubscriptionRequest
from ..nvda.event_sources import boundedAncestorIdentities, targetIdentityFromObject


def _perfMs() -> float:
	return perf_counter() * 1_000.0


_RAW_DETAIL_CAP = 4_096


def _rawAttribute(source: object, attribute: str) -> object | None:
	"""Read one forwarded object attribute without letting a stale provider escape."""

	try:
		return getattr(source, attribute, None)
	except Exception:
		return None


def _rawInt(source: object, attribute: str) -> int:
	value = _rawAttribute(source, attribute)
	if isinstance(value, bool) or not isinstance(value, int):
		return -1
	return value


def _rawStr(source: object, attribute: str) -> str:
	value = _rawAttribute(source, attribute)
	if not isinstance(value, str):
		return ""
	return _capRawText(value)


def _rawExecutable(source: object) -> str:
	appModule = _rawAttribute(source, "appModule")
	appName = _rawAttribute(appModule, "appName")
	return appName if isinstance(appName, str) else ""


def _rawRole(source: object) -> str:
	role = _rawAttribute(source, "role")
	roleName = _rawAttribute(role, "name")
	if isinstance(roleName, str):
		return roleName
	if role is None:
		return ""
	try:
		return str(role)
	except Exception:
		return ""


@dataclass(frozen=True, slots=True)
class RawUiaNotification:
	"""The notification data NVDA hands to ``event_UIA_notification``, copied verbatim.

	NVDA queues ``notificationKind``, ``notificationProcessing``, ``displayString``, and ``activityId``
	straight from the UIA callback (``UIAHandler/__init__.py``). ``displayString`` is the text the
	provider asked to have announced, so it is the only truthful "changed value" a notification has;
	the remaining fields describe how the provider wanted it processed.
	"""

	notificationKind: int | None = None
	notificationProcessing: int | None = None
	displayString: str | None = None
	activityId: str | None = None

	@property
	def changedValue(self) -> str:
		return "" if self.displayString is None else _capRawText(self.displayString)

	def detailFields(self) -> tuple[str, ...]:
		fields: list[str] = []
		if self.notificationKind is not None:
			fields.append(f"notificationKind={self.notificationKind}")
		if self.notificationProcessing is not None:
			fields.append(f"notificationProcessing={self.notificationProcessing}")
		if self.activityId:
			fields.append(f"activityId={_capRawText(self.activityId)}")
		return tuple(fields)


def _capRawText(value: str) -> str:
	return value if len(value) <= _RAW_DETAIL_CAP else value[:_RAW_DETAIL_CAP]


def descriptorFromObject(obj: object) -> RawUiaObjectDescriptor:
	"""Copy the minimal cached primitives out of a forwarded NVDA object on the calling thread.

	The returned descriptor holds no live element, so the routing path can refuse a stale or
	cross-process callback without ever dereferencing a provider again.
	"""

	return RawUiaObjectDescriptor(
		processId=_rawInt(obj, "processID"),
		executable=_rawExecutable(obj),
		name=_rawStr(obj, "name"),
		role=_rawRole(obj),
		detail=_rawStr(obj, "value"),
		protected=_rawAttribute(obj, "isProtected") is True,
	)


@dataclass(frozen=True, slots=True)
class RawUiaObjectDescriptor:
	"""Minimal cached primitives copied from a raw UIA element inside the callback.

	The descriptor never holds a live element; it is the only surface the routing path reads, so a
	post-teardown or cross-process callback is refused before any of these fields would be produced.
	"""

	processId: int
	executable: str
	name: str = ""
	role: str = ""
	detail: str = ""
	protected: bool = False
	identity: TargetIdentity | None = None
	ancestorIdentities: tuple[TargetIdentity, ...] = ()
	sourceRef: str | None = None


@runtime_checkable
class RawUiaClient(Protocol):
	"""The owning-thread client surface used for optional direct focus observation."""

	def addFocusHandler(self, onFocus: Callable[[], None]) -> None: ...

	def removeAllHandlers(self) -> None: ...

	def release(self) -> None: ...

	def rootProcessId(self) -> int: ...


@runtime_checkable
class RawUiaClientFactory(Protocol):
	"""Builds a raw UIA client on the calling owner thread; injected for hostless imports."""

	def create(self) -> RawUiaClient: ...


class NvdaUiaClientFactory:
	"""Default factory that builds a genuine ``IUIAutomation`` client from the installed NVDA runtime."""

	def create(self) -> RawUiaClient:
		return _ComtypesRawUiaClient()


class _ComtypesRawUiaClient:
	"""Owns one genuine ``IUIAutomation`` client and its handler on its creating thread."""

	def __init__(self) -> None:
		super().__init__()
		import comtypes.client  # pyright: ignore[reportMissingImports, reportUnusedImport]  # noqa: F401

		ct: Any = __import__("comtypes")
		clientModule: Any = ct.client
		uia: Any = clientModule.GetModule("UIAutomationCore.dll")
		self._comtypes: Any = ct
		self._uia: Any = uia
		self._client: Any = clientModule.CreateObject(uia.CUIAutomation, interface=uia.IUIAutomation)
		self._ownerThread: int = threading.get_ident()
		self._handler: Any = None

	def _assertOwner(self) -> None:
		if threading.get_ident() != self._ownerThread:
			raise RuntimeError("KS.RAW_UIA_EVENTS.WRONG_THREAD")

	def addFocusHandler(self, onFocus: Callable[[], None]) -> None:
		self._assertOwner()
		comtypesMod: Any = self._comtypes
		uiaMod: Any = self._uia

		class _FocusHandler(comtypesMod.COMObject):
			_com_interfaces_ = [uiaMod.IUIAutomationFocusChangedEventHandler]

			def IUIAutomationFocusChangedEventHandler_HandleFocusChangedEvent(self, sender: Any) -> int:
				onFocus()
				return 0

		handler: Any = _FocusHandler()
		self._handler = handler
		self._client.AddFocusChangedEventHandler(None, handler)

	def removeAllHandlers(self) -> None:
		self._assertOwner()
		self._client.RemoveAllEventHandlers()
		self._handler = None

	def release(self) -> None:
		self._assertOwner()
		self._handler = None
		self._client = None

	def rootProcessId(self) -> int:
		root: Any = self._client.GetRootElement()
		return int(root.CurrentProcessId)


def _rawChangedValue(
	family: RawUiaFamily,
	*,
	notification: RawUiaNotification | None,
	activeTextRange: object | None,
) -> tuple[str, ChangeEvidence]:
	"""Say what a raw UIA family actually reports as changed, and nothing more.

	Only two of the ten families deliver anything about a changed value: a notification carries the
	provider's own display string, and an active text position change carries a text range whose
	presence is reported without reading across the process boundary. Every other family reports a
	structural occurrence with no value concept.
	"""

	if family is RawUiaFamily.NOTIFICATION:
		if notification is None:
			return "", ChangeEvidence.UNAVAILABLE
		reported = notification.changedValue
		if not reported:
			return "", ChangeEvidence.NOT_EXPOSED
		return reported, ChangeEvidence.PROVIDER_REPORTED
	if family is RawUiaFamily.ACTIVE_TEXT_POSITION:
		if activeTextRange is None:
			return "", ChangeEvidence.NOT_EXPOSED
		return "active text position range reported", ChangeEvidence.CARET_METADATA
	return "", ChangeEvidence.NOT_APPLICABLE


class RawUiaEventSource:
	"""Turns approved UIA event families into receipts for one pinned scope."""

	def __init__(
		self,
		*,
		clientFactory: RawUiaClientFactory | None = None,
		monotonicMs: Callable[[], float] = _perfMs,
	) -> None:
		super().__init__()
		self._clientFactory = clientFactory
		self._monotonic = monotonicMs
		self._sink: EventSink | None = None
		self._scope: MonitorScope | None = None
		self._filter: EventFilter = EventFilter.default()
		self._generation = 0
		self._active = False
		self._sequence = 0
		self._ownerThread: int | None = None
		self._client: RawUiaClient | None = None
		self._forwardCount = 0
		self._pidDropped = 0
		self._staleRefused = 0
		self._lateCallbacksAccepted = 0
		self._providerAccesses = 0
		self._ownershipViolations = 0
		self._realFocusEvents = 0
		self._callbackMaxMs = 0.0
		self._forwardingMaxMs = 0.0
		self._disableReason: str | None = None
		self._sourceRetainer: Callable[[object], str | None] | None = None

	@property
	def backend(self) -> EventBackend:
		return EventBackend.RAW_UIA

	@property
	def families(self) -> tuple[str, ...]:
		return tuple(family.value for family in RAW_UIA_FAMILIES)

	@property
	def active(self) -> bool:
		return self._active

	@property
	def subscriptionCount(self) -> int:
		return 1 if self._active else 0

	@property
	def generation(self) -> int:
		return self._generation

	@property
	def forwardCount(self) -> int:
		return self._forwardCount

	@property
	def pidDropped(self) -> int:
		return self._pidDropped

	@property
	def staleRefused(self) -> int:
		return self._staleRefused

	@property
	def lateCallbacksAccepted(self) -> int:
		return self._lateCallbacksAccepted

	@property
	def providerAccesses(self) -> int:
		return self._providerAccesses

	@property
	def ownershipViolations(self) -> int:
		return self._ownershipViolations

	@property
	def realFocusEvents(self) -> int:
		return self._realFocusEvents

	@property
	def callbackMaxMs(self) -> float:
		return self._callbackMaxMs

	@property
	def forwardingMaxMs(self) -> float:
		return self._forwardingMaxMs

	@property
	def disableReason(self) -> str | None:
		return self._disableReason

	@property
	def clientCleanupPending(self) -> bool:
		"""Whether a client is retained until its owning thread can safely release it."""

		return not self._active and self._client is not None

	def subscribe(self, sink: EventSink, request: SubscriptionRequest) -> None:
		"""Pin ``request.scope`` and acquire the raw client on this (owning) thread."""

		if self.clientCleanupPending:
			if self._ownerThread != threading.get_ident():
				self._ownershipViolations += 1
				return
			self._releaseClient()
		alreadyActive = self._active
		self._sink = sink
		self._scope = request.scope
		self._filter = request.activeFilter
		self._generation = request.generation
		self._active = True
		if self._client is None:
			self._ownerThread = threading.get_ident()
		if not alreadyActive and self._client is None:
			self._acquireClient()

	def _acquireClient(self) -> None:
		factory = self._clientFactory
		if factory is None:
			return
		try:
			client = factory.create()
			client.addFocusHandler(self._noteRealFocus)
		except Exception as error:  # noqa: BLE001 - raw acquisition failure disables raw safely
			self._disableReason = f"{type(error).__name__}: {error}"
			self._client = None
			return
		self._client = client
		self._disableReason = None

	def _noteRealFocus(self) -> None:
		start = perf_counter()
		self._realFocusEvents += 1
		self._callbackMaxMs = max(self._callbackMaxMs, (perf_counter() - start) * 1_000.0)

	def updateFilter(self, activeFilter: EventFilter) -> None:
		"""Adopt a new filter for the live subscription without a new generation or resubscribe.

		A family disabled here stops being forwarded at once; a family enabled here begins forwarding
		on its next NVDA callback. The pinned scope, client, and generation are untouched.
		"""

		self._filter = activeFilter

	def configureSourceNavigation(self, retain: Callable[[object], str | None] | None) -> None:
		"""Attach the owner-thread registry used by Show Source in Inspector."""

		self._sourceRetainer = retain

	def forward(
		self,
		family: RawUiaFamily,
		obj: object,
		*,
		receivedAtMs: float | None = None,
		notification: RawUiaNotification | None = None,
		activeTextRange: object | None = None,
	) -> bool:
		"""Bridge one forwarded NVDA ``event_UIA_*`` object into the raw routing path.

		NVDA already resolved the UIA callback to a settled ``NVDAObject`` and queued it through the
		core event chain. This copies minimal primitives into a descriptor and routes it through
		:meth:`observe` under the current generation. No live element is retained. A refusal (inactive,
		filtered, wrong process) is normal and never raises.

		``notification`` and ``activeTextRange`` carry the extra data NVDA delivers alongside those two
		families. The text range is only inspected for presence: reading its contents would be a
		cross-process call, and its position is the only thing the monitor claims.
		"""

		sink = self._sink
		scope = self._scope
		if not self._active or sink is None or scope is None:
			return False
		if not self._filter.admits(EventBackend.RAW_UIA, family.value):
			return False
		received = self._monotonic() if receivedAtMs is None else receivedAtMs
		descriptor = descriptorFromObject(obj)
		if notification is not None:
			details = " ".join((descriptor.detail, *notification.detailFields())).strip()
			descriptor = replace(descriptor, detail=_capRawText(details))
		if scope.acceptsProcess(descriptor.processId, descriptor.executable):
			identity = targetIdentityFromObject(obj)
			sourceRef: str | None = None
			if identity is not None and self._sourceRetainer is not None:
				try:
					sourceRef = self._sourceRetainer(obj)
				except Exception:
					sourceRef = None
			descriptor = replace(
				descriptor,
				identity=identity,
				ancestorIdentities=(
					boundedAncestorIdentities(obj, stopAt=scope.targetIdentity)
					if scope.kind is MonitorScopeKind.SUBTREE
					and not scope.accepts(
						descriptor.processId,
						descriptor.executable,
						candidateIdentity=identity,
					)
					else ()
				),
				sourceRef=sourceRef,
			)
		return self.observe(
			family,
			descriptor,
			issuedGeneration=self._generation,
			receivedAtMs=received,
			notification=notification,
			activeTextRange=activeTextRange,
		)

	def unsubscribe(self) -> None:
		"""Invalidate the generation, remove handlers, and release the client on the owning thread."""

		self._invalidate()
		client = self._client
		if client is not None:
			if self._ownerThread is not None and threading.get_ident() != self._ownerThread:
				self._ownershipViolations += 1
				self._sink = None
				self._scope = None
				return
			self._releaseClient()
		self._sink = None
		self._scope = None
		self._ownerThread = None

	def _releaseClient(self) -> None:
		"""Release the client after its owner-thread check has already succeeded."""

		client = self._client
		if client is not None:
			try:
				client.removeAllHandlers()
				client.release()
			except Exception:  # noqa: BLE001 - teardown must not raise into the caller
				pass
		self._client = None
		self._ownerThread = None

	def _invalidate(self) -> None:
		self._active = False
		self._generation += 1

	def invalidate(self) -> None:
		"""Model a secure transition: flip the generation so pre-transition callbacks are refused."""

		self._generation += 1

	def observe(
		self,
		family: RawUiaFamily,
		descriptor: RawUiaObjectDescriptor,
		*,
		issuedGeneration: int,
		receivedAtMs: float | None = None,
		notification: RawUiaNotification | None = None,
		activeTextRange: object | None = None,
	) -> bool:
		"""Route one raw callback issued under ``issuedGeneration``; return whether it was forwarded.

		Ordering guarantees no stale dereference: an inactive source, a stale generation, an unselected
		family, and a mismatched process are each refused before the descriptor's fields reach retention.
		A refusal is normal and never raises.
		"""

		start = perf_counter()
		sink = self._sink
		scope = self._scope
		if not self._active or sink is None or scope is None:
			if self._active and issuedGeneration == self._generation:
				self._lateCallbacksAccepted += 1
			self._noteCallback(start)
			return False
		if issuedGeneration != self._generation:
			self._staleRefused += 1
			self._noteCallback(start)
			return False
		if not self._filter.admits(EventBackend.RAW_UIA, family.value):
			self._noteCallback(start)
			return False
		self._providerAccesses += 1
		if not scope.accepts(
			descriptor.processId,
			descriptor.executable,
			candidateIdentity=descriptor.identity,
			ancestorIdentities=descriptor.ancestorIdentities,
		):
			self._pidDropped += 1
			self._noteCallback(start)
			return False
		received = self._monotonic() if receivedAtMs is None else receivedAtMs
		self._sequence += 1
		self._forwardCount += 1
		forwardStart = perf_counter()
		changedValue, changeEvidence = _rawChangedValue(
			family,
			notification=notification,
			activeTextRange=activeTextRange,
		)
		receipt = EventReceipt(
			backend=EventBackend.RAW_UIA,
			eventType=family.value,
			processId=descriptor.processId,
			executable=descriptor.executable,
			application=descriptor.executable or scope.application,
			sequence=self._sequence,
			receivedAtMs=received,
			readAtMs=self._monotonic(),
			generation=self._generation,
			objectName=descriptor.name,
			objectRole=descriptor.role,
			detail=descriptor.detail,
			protectedName=descriptor.protected,
			protectedDetail=descriptor.protected,
			changedValue=changedValue,
			changeEvidence=changeEvidence,
			protectedChangedValue=descriptor.protected and changeEvidence.carriesValue,
			sourceRef=descriptor.sourceRef,
			sourceIdentity=descriptor.identity,
		)
		sink.deliver(receipt)
		self._forwardingMaxMs = max(self._forwardingMaxMs, (perf_counter() - forwardStart) * 1_000.0)
		self._noteCallback(start)
		return True

	def _noteCallback(self, start: float) -> None:
		self._callbackMaxMs = max(self._callbackMaxMs, (perf_counter() - start) * 1_000.0)
