"""Shipped NVDA object-event source.

``NvdaEventSource`` receives the thin, exactly-once forwarded NVDA events (see the global plugin
handlers), reads only minimal cached fields, filters by pinned process before anything is retained,
and delivers immutable receipts to the monitor sink. It never touches speech, UI, or the event
queue, and it holds no live NVDAObject beyond the synchronous read of the fields it copies into a
receipt.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from time import monotonic
from typing import Any, Protocol, cast, runtime_checkable

from ...domain.event_monitor import (
	EMPTY_VALUE_TEXT,
	NVDA_EVENT_TYPES,
	ChangeEvidence,
	EventBackend,
	EventFilter,
	EventReceipt,
	MonitorScope,
	MonitorScopeKind,
	NvdaEventType,
	ProviderIdentityEvidence,
	TargetIdentity,
)
from ...ports.event_sources import EventSink, SubscriptionRequest

# Upper bound on how many characters of a free-text detail (value, description, caret line, ...) the
# source copies out of a live object. The monitor service later trims to the user's finer
# ``eventDetailCharacters`` setting; this cap only stops a single event from copying a whole document
# (an editor reporting its entire content on every keystroke) into a receipt before that trim runs.
_SOURCE_DETAIL_CAP = 4_096
_ANCESTRY_DEPTH_LIMIT = 40
# How many (object, field) readings the source remembers so a later event can be reported as a
# change from the previous value rather than only as a current reading.
_OBSERVED_VALUE_LIMIT = 512


@runtime_checkable
class NvdaEventObject(Protocol):
	"""The minimal cached surface read from a forwarded NVDAObject."""

	name: str
	role: object
	processID: int


def _monotonicMs() -> float:
	return monotonic() * 1_000.0


def _readAttribute(source: object, attribute: str) -> object | None:
	"""Read one cached object attribute without letting a stale provider escape."""

	try:
		return getattr(source, attribute, None)
	except Exception:
		return None


def _readInt(source: object, attribute: str) -> int:
	value = _readAttribute(source, attribute)
	if isinstance(value, bool) or not isinstance(value, int):
		return -1
	return value


def _readStr(source: object, attribute: str) -> str:
	value = _readAttribute(source, attribute)
	return value if isinstance(value, str) else ""


def _readProtected(source: object) -> bool:
	"""Return false only for a reliably read, explicit unprotected marker."""

	try:
		return getattr(source, "isProtected", None) is not False
	except Exception:
		return True


def _readRole(source: object) -> str:
	role = _readAttribute(source, "role")
	roleName = _readAttribute(role, "name")
	if isinstance(roleName, str):
		return roleName
	if role is None:
		return ""
	try:
		return str(role)
	except Exception:
		return ""


def _readExecutable(source: object) -> str:
	appModule = _readAttribute(source, "appModule")
	appName = _readAttribute(appModule, "appName")
	return appName if isinstance(appName, str) else ""


def _isComFailure(error: Exception) -> bool:
	return type(error).__name__ == "COMError" or hasattr(error, "hresult")


def _positiveInt(
	source: object,
	attribute: str,
	onComFailure: Callable[[], None] | None = None,
) -> int | None:
	try:
		value = getattr(source, attribute, None)
	except Exception as error:
		if onComFailure is not None and _isComFailure(error):
			onComFailure()
		return None
	return value if type(value) is int and value > 0 else None


def _integer(
	source: object,
	attribute: str,
	onComFailure: Callable[[], None] | None = None,
) -> int | None:
	try:
		value = getattr(source, attribute, None)
	except Exception as error:
		if onComFailure is not None and _isComFailure(error):
			onComFailure()
		return None
	return value if type(value) is int else None


def _providerIdentifier(
	source: object,
	onComFailure: Callable[[], None] | None = None,
) -> str | None:
	try:
		automationId = getattr(source, "UIAAutomationId", None)
		if isinstance(automationId, str) and automationId:
			return automationId
		attributes = getattr(source, "IA2Attributes", None)
		if isinstance(attributes, Mapping):
			identifier = cast(Mapping[str, object], attributes).get("id")
			if isinstance(identifier, str) and identifier:
				return identifier
	except Exception as error:
		if onComFailure is not None and _isComFailure(error):
			onComFailure()
		return None
	return None


def _uiaRuntimeIdentity(
	source: object,
	onComFailure: Callable[[], None] | None = None,
) -> str | None:
	"""Read one live UIA element's runtime ID as ordered dotted integers.

	Most shipped UIA controls leave ``UIAAutomationId`` empty, so requiring an automation ID, an IA2
	unique ID, or a JAB context would leave the whole common case with no identity at all. The UIA
	runtime ID is the provider's own per-element identifier and is exactly what NVDA itself uses to
	compare two live UIA elements (``NVDAObjects/UIA/__init__.py`` ``isDescendantOf`` builds a
	``UIA_RuntimeIdPropertyId`` condition from ``UIAElement.GetRuntimeId()``). It is only unique
	within one desktop and one element lifetime, so it is never used on its own: :class:`TargetIdentity`
	always pairs it with the already-required process ID and window handle.
	"""

	try:
		element = getattr(source, "UIAElement", None)
		if element is None:
			return None
		runtimeId: object = None
		for accessor in ("GetRuntimeId", "getRuntimeId", "getRuntimeID"):
			getter = getattr(element, accessor, None)
			if callable(getter):
				runtimeId = getter()
				break
		else:
			runtimeId = getattr(element, "CurrentRuntimeId", None)
	except Exception as error:
		if onComFailure is not None and _isComFailure(error):
			onComFailure()
		return None
	if runtimeId is None or isinstance(runtimeId, (str, bytes)):
		return None
	try:
		parts = [int(part) for part in cast(Iterable[object], runtimeId)]  # pyright: ignore[reportArgumentType]
	except (TypeError, ValueError):
		return None
	if not parts:
		return None
	return ".".join(str(part) for part in parts)


def _jabProviderIdentity(source: object) -> str | None:
	try:
		context = getattr(source, "jabContext", None)
		vmId = getattr(context, "vmID", None)
		rawContext = getattr(context, "accContext", None)
		accContext = getattr(rawContext, "value", rawContext)
	except Exception:
		return None
	if type(vmId) is not int or vmId <= 0 or type(accContext) is not int or accContext <= 0:
		return None
	return f"{vmId}:{accContext}"


def targetIdentityFromObject(
	source: object,
	*,
	onComFailure: Callable[[], None] | None = None,
) -> TargetIdentity | None:
	"""Freeze process, window, and strong provider identifiers from one live object.

	Named evidence is collected in descending strength: an automation/IA2 identifier, the UIA runtime
	ID, the IA2 unique ID, the MSAA object/child pair, and the JAB context. A common UIA control that
	exposes no automation ID is still identifiable through its runtime ID, and every identifier is
	only ever compared alongside the process ID and window handle this function requires.
	"""

	processId = _positiveInt(source, "processID", onComFailure)
	windowHandle = _positiveInt(source, "windowHandle", onComFailure) or _positiveInt(
		source,
		"IA2WindowHandle",
		onComFailure,
	)
	if processId is None or windowHandle is None:
		return None
	evidence: list[ProviderIdentityEvidence] = []
	identifier = _providerIdentifier(source, onComFailure)
	if identifier is not None:
		evidence.append(("providerIdentifier", identifier))
	runtimeId = _uiaRuntimeIdentity(source, onComFailure)
	if runtimeId is not None:
		evidence.append(("uiaRuntimeId", runtimeId))
	ia2UniqueId = _positiveInt(source, "IA2UniqueID", onComFailure)
	if ia2UniqueId is not None:
		evidence.append(("ia2UniqueId", ia2UniqueId))
	objectId = _integer(source, "event_objectID", onComFailure)
	if objectId is None:
		objectId = _integer(source, "IAccessibleObjectID", onComFailure)
	childId = _integer(source, "IAccessibleChildID", onComFailure)
	if objectId is not None and childId is not None:
		evidence.append(("msaaObject", f"{objectId}:{childId}"))
	jabIdentity = _jabProviderIdentity(source)
	if jabIdentity is not None:
		evidence.append(("jabObject", jabIdentity))
	if not evidence:
		return None
	return TargetIdentity(
		processId=processId,
		windowHandle=windowHandle,
		providerEvidence=tuple(evidence),
	)


def _providerParent(source: object) -> object | None:
	for attribute in ("parent", "simpleParent"):
		try:
			parent = getattr(source, attribute, None)
		except Exception:
			continue
		if parent is not None:
			return parent
	try:
		element = getattr(source, "UIAElement", source)
	except Exception:
		return None
	for attribute in ("GetCachedParent", "CurrentParent"):
		try:
			parent = getattr(element, attribute, None)
			parent = parent() if callable(parent) else parent
		except Exception:
			continue
		if parent is not None:
			return parent
	return None


def boundedAncestorIdentities(
	source: object,
	*,
	stopAt: TargetIdentity | None = None,
) -> tuple[TargetIdentity, ...]:
	"""Read at most forty ancestors, stopping on the first correlated target."""

	identities: list[TargetIdentity] = []
	seen: set[int] = {id(source)}
	current = source
	for _depth in range(_ANCESTRY_DEPTH_LIMIT):
		parent = _providerParent(current)
		if parent is None or id(parent) in seen:
			break
		seen.add(id(parent))
		identity = targetIdentityFromObject(parent)
		if identity is not None:
			identities.append(identity)
			if stopAt is not None and stopAt.correlates(identity):
				break
		current = parent
	return tuple(identities)


def _cap(text: str) -> str:
	return text if len(text) <= _SOURCE_DETAIL_CAP else text[:_SOURCE_DETAIL_CAP]


def _readText(source: object, attribute: str) -> str:
	value = _readAttribute(source, attribute)
	if value is None or value == "":
		return ""
	try:
		return _cap(str(value))
	except Exception:
		return ""


def _stateNames(source: object) -> tuple[str, ...] | None:
	"""Read one object's state names in a stable order, or ``None`` when states are not exposed."""

	states = _readAttribute(source, "states")
	if states is None:
		return None
	names: list[str] = []
	try:
		for state in cast(Iterable[object], states):
			name = _readAttribute(state, "name")
			names.append(name if isinstance(name, str) else str(state))
	except Exception:
		return None
	return tuple(sorted(names))


def _readStates(source: object) -> str:
	names = _stateNames(source)
	if not names:
		return ""
	return _cap("states=[{}]".format(", ".join(names)))


def _readPoliteness(source: object) -> str:
	politeness = _readAttribute(source, "liveRegionPoliteness")
	if politeness is None:
		return ""
	name = _readAttribute(politeness, "name")
	try:
		return _cap("politeness={}".format(name if isinstance(name, str) else politeness))
	except Exception:
		return ""


def _readCaretLine(source: object) -> str:
	caller: Any = _readAttribute(source, "makeTextInfo")
	if not callable(caller):
		return ""
	try:
		textInfos: Any = __import__("textInfos")
	except ImportError:
		return ""
	parts: list[str] = []
	try:
		info: Any = caller(textInfos.POSITION_CARET)
		info.expand(textInfos.UNIT_LINE)
		lineText = str(info.text)
		if lineText:
			parts.append("line={!r}".format(_cap(lineText)))
	except Exception:
		pass
	try:
		selection: Any = caller(textInfos.POSITION_SELECTION)
		selectionText = str(selection.text)
		if selectionText:
			parts.append("selection={!r}".format(_cap(selectionText)))
	except Exception:
		pass
	return " ".join(parts)


def _caretMetadata(source: object) -> tuple[str, ChangeEvidence]:
	"""Describe where the caret is, never what it is on.

	Only offset-based text implementations expose a numeric position: their bookmark is a
	``textInfos.offsets.Offsets`` carrying ``startOffset``/``endOffset``. Everything else (UIA text
	ranges, browse-mode bookmarks) exposes an opaque bookmark with no readable position, which is
	reported as not exposed rather than guessed at. No caret text is read here.
	"""

	caller: Any = _readAttribute(source, "makeTextInfo")
	if not callable(caller):
		return "", ChangeEvidence.NOT_EXPOSED
	try:
		textInfos: Any = __import__("textInfos")
		position: object = textInfos.POSITION_CARET
	except ImportError:
		# ``textInfos.POSITION_CARET`` is the literal "caret" (source/textInfos/__init__.py), so the
		# same request can be made without the host module present.
		position = "caret"
	try:
		info: Any = caller(position)
		bookmark: Any = info.bookmark
	except Exception:
		return "", ChangeEvidence.UNAVAILABLE
	start = _readAttribute(bookmark, "startOffset")
	end = _readAttribute(bookmark, "endOffset")
	if type(start) is not int or type(end) is not int:
		return "", ChangeEvidence.NOT_EXPOSED
	if start == end:
		return f"caret offset {start}", ChangeEvidence.CARET_METADATA
	return f"caret offsets {start} to {end}", ChangeEvidence.CARET_METADATA


def _observedField(eventType: NvdaEventType) -> str | None:
	"""The single object field whose value ``eventType`` reports changing, if any."""

	return {
		NvdaEventType.VALUE_CHANGE: "value",
		NvdaEventType.NAME_CHANGE: "name",
		NvdaEventType.DESCRIPTION_CHANGE: "description",
		# NVDA's own live-region handler announces the object's name, so that is the changed text.
		NvdaEventType.LIVE_REGION: "name",
	}.get(eventType)


def _eventDetail(
	eventType: NvdaEventType,
	obj: object,
	*,
	isFocus: bool,
	protected: bool,
) -> tuple[str, bool]:
	"""Return the privacy-safe raw detail and whether it is protected-sensitive for ``eventType``.

	Every read is a bounded, synchronous copy of an already-settled cached field; no live reference is
	retained. The boolean marks whether the detail carries user text the monitor must redact when the
	object is protected (value, description, caret text, name) versus a public structural summary
	(state list, live-region politeness, navigator flag) that is safe even for a protected object.
	"""

	if eventType is NvdaEventType.VALUE_CHANGE:
		value = _readText(obj, "value")
		return ("" if not value else f"value={value}"), protected
	if eventType is NvdaEventType.DESCRIPTION_CHANGE:
		description = _readText(obj, "description")
		return ("" if not description else f"description={description}"), protected
	if eventType is NvdaEventType.NAME_CHANGE:
		name = _readText(obj, "name")
		return ("" if not name else f"name={name}"), protected
	if eventType is NvdaEventType.STATE_CHANGE:
		return _readStates(obj), False
	if eventType is NvdaEventType.LIVE_REGION:
		return _readPoliteness(obj), False
	if eventType is NvdaEventType.CARET:
		return _readCaretLine(obj), protected
	if eventType is NvdaEventType.NAVIGATOR_OBJECT:
		return ("isFocus=True" if isFocus else ""), False
	return "", False


class NvdaEventSource:
	"""Turns forwarded NVDA events into receipts for one pinned scope at a time."""

	def __init__(self, *, monotonicMs: Callable[[], float] = _monotonicMs) -> None:
		super().__init__()
		self._monotonic = monotonicMs
		self._sink: EventSink | None = None
		self._scope: MonitorScope | None = None
		self._filter: EventFilter = EventFilter.default()
		self._generation = 0
		self._active = False
		self._sequence = 0
		self._forwardCount = 0
		self._sourceRetainer: Callable[[object], str | None] | None = None
		self._observedValues: OrderedDict[str, str] = OrderedDict()

	@property
	def backend(self) -> EventBackend:
		return EventBackend.NVDA

	@property
	def families(self) -> tuple[str, ...]:
		return tuple(eventType.value for eventType in NVDA_EVENT_TYPES)

	@property
	def active(self) -> bool:
		return self._active

	@property
	def subscriptionCount(self) -> int:
		return 1 if self._active else 0

	@property
	def forwardCount(self) -> int:
		return self._forwardCount

	@property
	def observedValueCount(self) -> int:
		"""How many prior readings are currently remembered for change comparison."""

		return len(self._observedValues)

	def subscribe(self, sink: EventSink, request: SubscriptionRequest) -> None:
		self._sink = sink
		self._scope = request.scope
		self._filter = request.activeFilter
		self._generation = request.generation
		self._active = True
		# A new session compares nothing against the previous one: prior observations belong to the
		# scope that was being monitored when they were read.
		self._observedValues.clear()

	def updateFilter(self, activeFilter: EventFilter) -> None:
		"""Adopt a new filter for the live subscription without a new generation or resubscribe.

		Future forwards are admitted against ``activeFilter`` immediately: a type disabled here stops
		being forwarded at once, and a type enabled here begins forwarding on its next event.
		"""

		self._filter = activeFilter

	def configureSourceNavigation(self, retain: Callable[[object], str | None] | None) -> None:
		"""Attach the owner-thread registry used by Show Source in Inspector."""

		self._sourceRetainer = retain

	def unsubscribe(self) -> None:
		self._active = False
		self._sink = None
		self._scope = None
		self._observedValues.clear()

	def _rememberObserved(self, key: str, current: str) -> str | None:
		"""Return the value last seen under ``key`` and remember ``current`` in its place.

		The table is bounded and least-recently-observed entries are evicted first, so a chatty
		application cannot grow it without limit. It is cleared whenever a session starts or ends.
		"""

		prior = self._observedValues.pop(key, None)
		self._observedValues[key] = current
		while len(self._observedValues) > _OBSERVED_VALUE_LIMIT:
			_ = self._observedValues.popitem(last=False)
		return prior

	def _changedValue(
		self,
		eventType: NvdaEventType,
		obj: object,
		identity: TargetIdentity | None,
		protected: bool,
	) -> tuple[str, ChangeEvidence, bool]:
		"""Read what this event changed, or state why nothing can be said about it.

		A delta against a previous reading is only produced when the object carries a stable identity,
		because without one there is no way to know the earlier reading came from the same object.
		"""

		if eventType is NvdaEventType.CARET:
			text, evidence = _caretMetadata(obj)
			# A caret position is structural: it names an offset, never the text at that offset.
			return text, evidence, False
		if eventType is NvdaEventType.STATE_CHANGE:
			return self._changedStates(obj, identity)
		field = _observedField(eventType)
		if field is None:
			return "", ChangeEvidence.NOT_APPLICABLE, False
		try:
			raw = getattr(obj, field, None)
		except Exception:
			return "", ChangeEvidence.UNAVAILABLE, protected
		if raw is None:
			return "", ChangeEvidence.NOT_EXPOSED, protected
		try:
			current = _cap(str(raw))
		except Exception:
			return "", ChangeEvidence.UNAVAILABLE, protected
		if identity is None:
			return current, ChangeEvidence.READ_AFTER_EVENT, protected
		prior = self._rememberObserved(f"{identity.stableKey}#{field}", current)
		if prior is None or prior == current:
			return current, ChangeEvidence.READ_AFTER_EVENT, protected
		delta = f"{prior or EMPTY_VALUE_TEXT} changed to {current or EMPTY_VALUE_TEXT}"
		return _cap(delta), ChangeEvidence.PRIOR_OBSERVATION_DELTA, protected

	def _changedStates(
		self,
		obj: object,
		identity: TargetIdentity | None,
	) -> tuple[str, ChangeEvidence, bool]:
		names = _stateNames(obj)
		if names is None:
			return "", ChangeEvidence.NOT_EXPOSED, False
		current = ", ".join(names)
		if identity is None:
			return _cap(current), ChangeEvidence.READ_AFTER_EVENT, False
		prior = self._rememberObserved(f"{identity.stableKey}#states", current)
		if prior is None or prior == current:
			return _cap(current), ChangeEvidence.READ_AFTER_EVENT, False
		previous = frozenset(part for part in prior.split(", ") if part)
		added = tuple(name for name in names if name not in previous)
		removed = tuple(name for name in sorted(previous) if name not in names)
		parts: list[str] = []
		if added:
			parts.append("added {}".format(", ".join(added)))
		if removed:
			parts.append("removed {}".format(", ".join(removed)))
		if not parts:
			return _cap(current), ChangeEvidence.READ_AFTER_EVENT, False
		return _cap("; ".join(parts)), ChangeEvidence.PRIOR_OBSERVATION_DELTA, False

	def forward(
		self,
		eventType: NvdaEventType,
		obj: object,
		*,
		isFocus: bool = False,
		receivedAtMs: float | None = None,
	) -> bool:
		"""Build and deliver one receipt for a forwarded event; return whether it was retained-bound.

		Returning ``False`` (inactive source, filtered family, or a process outside the pinned scope)
		is normal and never raises; the caller still invokes ``nextHandler`` exactly once.
		"""

		sink = self._sink
		scope = self._scope
		if not self._active or sink is None or scope is None:
			return False
		received = self._monotonic() if receivedAtMs is None else receivedAtMs
		if not self._filter.admits(EventBackend.NVDA, eventType.value):
			return False
		processId = _readInt(obj, "processID")
		executable = _readExecutable(obj)
		if not scope.acceptsProcess(processId, executable):
			return False
		candidateIdentity = targetIdentityFromObject(obj)
		ancestorIdentities: tuple[TargetIdentity, ...] = ()
		if scope.kind is MonitorScopeKind.SUBTREE and not scope.accepts(
			processId,
			executable,
			candidateIdentity=candidateIdentity,
		):
			ancestorIdentities = boundedAncestorIdentities(obj, stopAt=scope.targetIdentity)
		if not scope.accepts(
			processId,
			executable,
			candidateIdentity=candidateIdentity,
			ancestorIdentities=ancestorIdentities,
		):
			return False
		name = _readStr(obj, "name")
		role = _readRole(obj)
		protected = _readProtected(obj)
		detail, protectedDetail = _eventDetail(eventType, obj, isFocus=isFocus, protected=protected)
		changedValue, changeEvidence, protectedChange = self._changedValue(
			eventType,
			obj,
			candidateIdentity,
			protected,
		)
		sourceRef: str | None = None
		if candidateIdentity is not None and self._sourceRetainer is not None:
			try:
				sourceRef = self._sourceRetainer(obj)
			except Exception:
				sourceRef = None
		self._sequence += 1
		self._forwardCount += 1
		receipt = EventReceipt(
			backend=EventBackend.NVDA,
			eventType=eventType.value,
			processId=processId,
			executable=executable,
			application=executable or scope.application,
			sequence=self._sequence,
			receivedAtMs=received,
			readAtMs=self._monotonic(),
			generation=self._generation,
			objectName=name,
			objectRole=role,
			detail=detail,
			protectedName=protected,
			protectedDetail=protectedDetail,
			changedValue=changedValue,
			changeEvidence=changeEvidence,
			protectedChangedValue=protectedChange,
			sourceRef=sourceRef,
			sourceIdentity=candidateIdentity,
		)
		sink.deliver(receipt)
		return True
