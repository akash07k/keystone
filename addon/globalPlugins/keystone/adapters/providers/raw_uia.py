from __future__ import annotations

import importlib
import threading
from collections.abc import Callable, Iterable, Mapping
from ctypes.wintypes import POINT
from dataclasses import dataclass
from time import monotonic_ns
from typing import Literal, Protocol, cast, override

from ...capability import PlainValue
from ...domain.projection import (
	IdentityProbe,
	ProjectionCandidate,
	ProjectionEvidence,
	ProjectionMethod,
	ProjectionRequest,
	ProjectionStatus,
	SelectedIdentity,
	decideProjection,
)
from ...ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ProviderRelationRequest,
	ProviderTextRequest,
	ReadBudget,
)
from .common import (
	ObjectBatch,
	ObjectRead,
	ProviderDatum,
	ProviderSectionData,
	encodeProviderSections,
	normalizeProviderRead,
	normalizeProviderValue,
)
from .uia import NvdaUiaGetter, UiaProviderAdapter

type RawTargetKind = str
type RawEvidenceQuality = Literal["native", "noNativeProvider", "synthesizedProxy", "incomplete"]


class RawUiaGetterPort(Protocol):
	def nvdaProcessId(self) -> int: ...

	def selectedIdentity(self, target: object, budget: ReadBudget) -> SelectedIdentity: ...

	def candidateElements(
		self,
		target: object,
		targetKind: RawTargetKind,
		maximumCandidates: int,
		*,
		preferPoint: bool = False,
	) -> ObjectBatch: ...

	def processId(self, element: object) -> ProviderReadResult: ...

	def evidenceQuality(
		self,
		element: object,
		*,
		windowHandle: int | None = None,
	) -> RawEvidenceQuality: ...

	def candidateIdentity(
		self,
		element: object,
		processId: int,
		budget: ReadBudget,
	) -> ProjectionCandidate: ...

	def readProperty(self, element: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult: ...

	def rawChildren(self, element: object, budget: ReadBudget) -> ObjectBatch: ...

	def releaseElement(self, element: object) -> None: ...


@dataclass(frozen=True, slots=True)
class RawProjectionOutcome:
	rootRef: str | None
	evidence: ProjectionEvidence
	evidenceQuality: RawEvidenceQuality | None = None


class _RawTargetLookupError(Exception):
	def __init__(self, errorCode: str) -> None:
		super().__init__(errorCode)
		self.errorCode = errorCode


class NvdaRawUiaGetter:
	"""Getter-only access to NVDA's existing UIA client and raw-view walker."""

	_PROPERTY_NAMES: dict[str, str] = {
		"name": "UIA_NamePropertyId",
		"role": "UIA_ControlTypePropertyId",
		"description": "UIA_HelpTextPropertyId",
		"value": "UIA_ValueValuePropertyId",
		"geometry": "UIA_BoundingRectanglePropertyId",
		"windowHandle": "UIA_NativeWindowHandlePropertyId",
		"process": "UIA_ProcessIdPropertyId",
		"focusable": "UIA_IsKeyboardFocusablePropertyId",
		"focused": "UIA_HasKeyboardFocusPropertyId",
		"protection": "UIA_IsPasswordPropertyId",
	}

	def __init__(self, *, diagnostic: Callable[[str], None] | None = None) -> None:
		super().__init__()
		self._diagnostic = diagnostic
		self._controlTypeNames: dict[int, str] | None = None
		self._selectedElement: object | None = None
		self._selectedIdentity: SelectedIdentity | None = None
		self._selectedName: str | None = None
		self._trustedElement: object | None = None
		self._spatialElement: object | None = None
		self._pointResolvedElement: object | None = None
		self._windowScopedElement: tuple[object, int] | None = None
		self._qualityByIdentity: dict[int, tuple[object, RawEvidenceQuality, int | None]] = {}

	def _trace(self, event: str, **fields: object) -> None:
		if self._diagnostic is None:
			return
		details = ", ".join(f"{name}={value}" for name, value in sorted(fields.items()))
		self._diagnostic(f"{event}; {details}")

	@staticmethod
	def _module() -> object:
		return importlib.import_module("UIAHandler")

	@classmethod
	def _handler(cls) -> object:
		return cls._module().__getattribute__("handler")

	@staticmethod
	def _watchdog() -> object | None:
		try:
			return importlib.import_module("watchdog")
		except ImportError:
			return None

	@staticmethod
	def _windowBlockReason(hwnd: int | None) -> str | None:
		if not hwnd:
			return None
		try:
			user32 = importlib.import_module("winBindings.user32")
			ghostFromHung = getattr(user32, "_GhostWindowFromHungWindow", None)
			if callable(ghostFromHung) and ghostFromHung(hwnd):
				return "KS.RAW_UIA.GHOST_TARGET"
			winUser = importlib.import_module("winUser")
			isHung = getattr(winUser, "isHungAppWindow", None)
			if callable(isHung) and isHung(hwnd):
				return "KS.RAW_UIA.HUNG_TARGET"
		except ImportError:
			# Pure contract tests run without NVDA's host modules.
			return None
		except Exception:
			return "KS.RAW_UIA.WINDOW_CHECK_FAILED"
		return None

	@staticmethod
	def _isWatchdogCancellation(error: Exception) -> bool:
		try:
			exceptions = importlib.import_module("exceptions")
			callCancelled = getattr(exceptions, "CallCancelled")
			return isinstance(error, callCancelled)
		except (ImportError, AttributeError, TypeError):
			return type(error).__name__ == "CallCancelled"

	@staticmethod
	def _isComFailure(error: Exception) -> bool:
		try:
			comtypes = importlib.import_module("comtypes")
			comError = getattr(comtypes, "COMError")
			return isinstance(error, comError)
		except (ImportError, AttributeError, TypeError):
			return type(error).__name__ == "COMError"

	@staticmethod
	def _comHresult(error: Exception) -> int | None:
		try:
			value = getattr(error, "hresult", None)
		except Exception:
			return None
		return value if type(value) is int else None

	@staticmethod
	def _traceHresult(value: int | None) -> str:
		return f"0x{value & 0xFFFFFFFF:08X}" if value is not None else "none"

	@staticmethod
	def _cachedInt(element: object, name: str) -> int | None:
		try:
			value = getattr(element, name, None)
		except Exception:
			return None
		return value if type(value) is int and value > 0 else None

	@classmethod
	def _cachedWindowHandle(cls, element: object) -> int | None:
		return cls._cachedInt(element, "CachedNativeWindowHandle")

	@staticmethod
	def _cachedText(element: object, name: str) -> str | None:
		try:
			value = getattr(element, name, None)
		except Exception:
			return None
		return value if isinstance(value, str) and value else None

	def _execute(
		self,
		func: Callable[..., object],
		*args: object,
		hwnd: int | None = None,
	) -> ObjectRead:
		blockReason = self._windowBlockReason(hwnd)
		if blockReason is not None:
			return ObjectRead("unavailable", errorCode=blockReason)
		try:
			watchdog = self._watchdog()
			executor = getattr(watchdog, "cancellableExecute", None) if watchdog is not None else None
			value = executor(func, *args) if callable(executor) else func(*args)
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception as error:
			if self._isWatchdogCancellation(error):
				return ObjectRead("unavailable", errorCode="KS.RAW_UIA.WATCHDOG_CANCELLED")
			if self._isComFailure(error):
				return ObjectRead(
					"failed",
					errorCode="KS.RAW_UIA.COM_FAILED",
					hresult=self._comHresult(error),
				)
			return ObjectRead("failed", errorCode="KS.RAW_UIA.CALL_FAILED")
		if value is None:
			return ObjectRead("empty")
		return ObjectRead("value", value)

	def _executeOnOwnerThread(
		self,
		func: Callable[..., object],
		*args: object,
		hwnd: int | None = None,
	) -> ObjectRead:
		"""Run one trusted retained-element call where NVDA itself performs UIA object access."""

		blockReason = self._windowBlockReason(hwnd)
		if blockReason is not None:
			return ObjectRead("unavailable", errorCode=blockReason)
		try:
			value = func(*args)
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception as error:
			if self._isWatchdogCancellation(error):
				return ObjectRead("unavailable", errorCode="KS.RAW_UIA.WATCHDOG_CANCELLED")
			if self._isComFailure(error):
				return ObjectRead(
					"failed",
					errorCode="KS.RAW_UIA.COM_FAILED",
					hresult=self._comHresult(error),
				)
			return ObjectRead("failed", errorCode="KS.RAW_UIA.CALL_FAILED")
		if value is None:
			return ObjectRead("empty")
		return ObjectRead("value", value)

	@classmethod
	def _identifier(cls, name: str) -> int:
		module = cls._module()
		for source in (module, getattr(module, "UIA", None)):
			if source is None:
				continue
			value = getattr(source, name, None)
			if type(value) is int:
				return value
		raise LookupError("installed UIA identifier is unavailable")

	def _controlTypeName(self, value: int) -> str | None:
		if self._controlTypeNames is None:
			names: dict[int, str] = {}
			module = self._module()
			for source in (module, getattr(module, "UIA", None)):
				if source is None:
					continue
				for identifier in dir(source):
					if (
						not identifier.startswith("UIA_")
						or not identifier.endswith("ControlTypeId")
						or identifier == "UIA_ControlTypePropertyId"
					):
						continue
					controlType = getattr(source, identifier)
					if type(controlType) is int:
						names[controlType] = identifier[len("UIA_") : -len("ControlTypeId")]
			self._controlTypeNames = names
		return self._controlTypeNames.get(value)

	def _element(self, target: object) -> ObjectRead:
		blockReason = self._windowBlockReason(self._targetWindowHandle(target))
		if blockReason is not None:
			return ObjectRead("unavailable", errorCode=blockReason)
		try:
			value = target.__getattribute__("UIAElement")
		except (AttributeError, NotImplementedError):
			return ObjectRead("unsupported")
		except Exception as error:
			return ObjectRead(
				"failed",
				errorCode="KS.RAW_UIA.COM_FAILED" if self._isComFailure(error) else "KS.RAW_UIA.CALL_FAILED",
			)
		return ObjectRead("empty" if value is None else "value", value)

	@staticmethod
	def nvdaProcessId() -> int:
		import os

		return os.getpid()

	def _runtimeKey(self, element: object, budget: ReadBudget) -> tuple[tuple[str, object], ...]:
		try:
			runtimeRead = self._invoke(
				element,
				("getRuntimeId",),
				(),
				ownerThread=element is self._selectedElement,
			)
			if runtimeRead.status != "value":
				return ()
			runtime = runtimeRead.value
			plain, truncated = normalizeProviderValue(
				runtime,
				maximumItems=budget.maximumItems,
				maximumTextLength=budget.maximumTextLength,
			)
		except Exception:
			return ()
		if truncated or plain is None:
			return ()
		return (("runtime", plain),)

	def selectedIdentity(self, target: object, budget: ReadBudget) -> SelectedIdentity:
		process = target.__getattribute__("processID")
		if type(process) is not int:
			raise ValueError("selected process ID is unavailable")
		roleValue = getattr(target, "role", None)
		role = str(roleValue) if roleValue is not None else None
		window = getattr(target, "windowHandle", None)
		windowHandle = window if type(window) is int else None
		# Raw UIA projection always resolves within UIA scope regardless of the
		# selected object's own accessibility API, so candidates (always "uia")
		# remain comparable for a cross-backend (IA2/MSAA/JAB) source object.
		providerScope = "uia"
		elementRead = self._element(target)
		self._selectedElement = elementRead.value if elementRead.status == "value" else None
		stableKeys = (
			self._runtimeKey(elementRead.value, budget)
			if elementRead.status == "value" and elementRead.value is not None
			else ()
		)
		identity = SelectedIdentity(
			process,
			providerScope,
			role,
			stableKeys,
			windowHandle,
			role == "window",
		)
		self._selectedIdentity = identity
		name = getattr(target, "name", None)
		self._selectedName = name if isinstance(name, str) and name.strip() else None
		return identity

	@staticmethod
	def _targetProcessId(target: object) -> int | None:
		try:
			value = target.__getattribute__("processID")
		except Exception:
			return None
		return value if type(value) is int else None

	@staticmethod
	def _targetWindowHandle(target: object) -> int | None:
		try:
			value = getattr(target, "windowHandle", None)
		except Exception:
			return None
		return value if type(value) is int and value else None

	@staticmethod
	def _locationRect(value: object) -> tuple[float, float, float, float] | None:
		try:
			if isinstance(value, Mapping):
				mapping = cast("Mapping[str, object]", value)
				parts: tuple[object, ...] = tuple(
					mapping.get(name) for name in ("left", "top", "width", "height")
				)
			elif isinstance(value, (list, tuple)):
				parts = tuple(cast("list[object] | tuple[object, ...]", value))
			else:
				parts = tuple(
					cast(object, getattr(value, name, None)) for name in ("left", "top", "width", "height")
				)
		except Exception:
			return None
		if len(parts) != 4:
			return None
		left, top, width, height = (
			part if isinstance(part, (int, float)) and not isinstance(part, bool) else None for part in parts
		)
		if left is None or top is None or width is None or height is None or width <= 0 or height <= 0:
			return None
		return left, top, width, height

	@classmethod
	def _centerPoint(cls, target: object) -> tuple[int, int] | None:
		try:
			location = getattr(target, "location", None)
			if location is None:
				return None
			rect = cls._locationRect(location)
		except Exception:
			return None
		if rect is None:
			return None
		left, top, width, height = rect
		return int(left + width / 2), int(top + height / 2)

	_MAXIMUM_ANCESTOR_DEPTH = 8

	@classmethod
	def _fallbackAncestorHandle(cls, target: object) -> int | None:
		current: object | None = target
		for _ in range(cls._MAXIMUM_ANCESTOR_DEPTH):
			try:
				current = getattr(current, "parent", None)
			except Exception:
				return None
			if current is None:
				return None
			handle = cls._targetWindowHandle(current)
			if handle:
				return handle
		return None

	def _client(self) -> object | None:
		try:
			return self._handler().__getattribute__("clientObject")
		except Exception:
			return None

	def _invoke(
		self,
		client: object,
		names: tuple[str, ...],
		args: tuple[object, ...],
		*,
		hwnd: int | None = None,
		ownerThread: bool = False,
	) -> ObjectRead:
		cacheRequest: object | None = None
		cacheRequestLoaded = False
		lastResult = ObjectRead("unsupported")
		for name in names:
			method = getattr(client, name, None)
			if not callable(method):
				continue
			callArgs = args
			if name.endswith("BuildCache"):
				if not cacheRequestLoaded:
					try:
						cacheRequest = getattr(self._handler(), "baseCacheRequest", None)
					except Exception:
						cacheRequest = None
					cacheRequestLoaded = True
				if cacheRequest is None:
					continue
				callArgs = (*args, cacheRequest)
			result = (
				self._executeOnOwnerThread(method, *callArgs, hwnd=hwnd)
				if ownerThread
				else self._execute(method, *callArgs, hwnd=hwnd)
			)
			if result.status == "value":
				return result
			if result.status == "unavailable":
				return result
			if result.status == "failed" and result.errorCode == "KS.RAW_UIA.COM_FAILED":
				lastResult = result
				continue
			if result.status == "empty":
				lastResult = result
				continue
			if lastResult.status == "unsupported":
				lastResult = result
		return lastResult

	def _acquireByHandle(self, client: object | None, hwnd: int | None) -> ObjectRead:
		if client is None or not hwnd:
			return ObjectRead(
				"unavailable",
				errorCode="KS.RAW_UIA.NO_CLIENT" if client is None else "KS.RAW_UIA.NO_WINDOW",
			)
		return self._invoke(
			client,
			("ElementFromHandleBuildCache", "ElementFromHandle"),
			(hwnd,),
			hwnd=hwnd,
		)

	@staticmethod
	def _accessibleInputs(target: object) -> tuple[object, int] | None:
		try:
			accessible = getattr(target, "IAccessibleObject", None)
			childId = getattr(target, "IAccessibleChildID", None)
		except Exception:
			return None
		if accessible is None or type(childId) is not int:
			return None
		return accessible, childId

	def _acquireByIAccessible(
		self,
		client: object | None,
		target: object,
		hwnd: int | None,
	) -> ObjectRead:
		inputs = self._accessibleInputs(target)
		if client is None or inputs is None:
			return ObjectRead(
				"unavailable",
				errorCode="KS.RAW_UIA.NO_CLIENT" if client is None else "KS.RAW_UIA.NO_IACCESSIBLE",
			)
		return self._invoke(
			client,
			("ElementFromIAccessibleBuildCache", "ElementFromIAccessible"),
			inputs,
			hwnd=hwnd,
			ownerThread=True,
		)

	def _acquireByPoint(
		self,
		client: object | None,
		point: tuple[int, int] | None,
		hwnd: int | None = None,
	) -> ObjectRead:
		if client is None or point is None:
			return ObjectRead(
				"unavailable",
				errorCode="KS.RAW_UIA.NO_CLIENT" if client is None else "KS.RAW_UIA.NO_POINT",
			)
		try:
			pointStruct = POINT(point[0], point[1])
		except Exception:
			return ObjectRead("unavailable", errorCode="KS.RAW_UIA.INVALID_POINT")
		return self._invoke(
			client,
			("ElementFromPointBuildCache", "ElementFromPoint"),
			(pointStruct,),
			hwnd=hwnd,
		)

	def _acquireFocused(self, client: object | None, hwnd: int | None = None) -> ObjectRead:
		if client is None:
			return ObjectRead("unavailable", errorCode="KS.RAW_UIA.NO_CLIENT")
		return self._invoke(
			client,
			(
				"GetFocusedElementBuildCache",
				"getFocusedElementBuildCache",
				"GetFocusedElement",
				"getFocusedElement",
			),
			(),
			hwnd=hwnd,
		)

	@staticmethod
	def _focusedObjectIsNvda(nvdaProcess: int) -> bool:
		"""Avoid global UIA sources after Keystone's Inspector has taken focus."""

		try:
			focus = importlib.import_module("api").getFocusObject()
			return getattr(focus, "processID", None) == nvdaProcess
		except Exception:
			return False

	@staticmethod
	def _windowClass(hwnd: int | None) -> str:
		if not hwnd:
			return "unavailable"
		try:
			name = getattr(importlib.import_module("winUser"), "getClassName", None)
			value = name(hwnd) if callable(name) else None
			return value if isinstance(value, str) and value else "unavailable"
		except Exception:
			return "unavailable"

	def _serverSideProviderAvailability(self, hwnd: int | None) -> ObjectRead:
		if not hwnd:
			return ObjectRead("unavailable", errorCode="KS.RAW_UIA.NO_WINDOW")
		try:
			probe = getattr(
				importlib.import_module("winBindings.uiAutomationCore"),
				"UiaHasServerSideProvider",
				None,
			)
		except Exception:
			probe = None
		if not callable(probe):
			return ObjectRead("unsupported", errorCode="KS.RAW_UIA.PROVIDER_PROBE_UNAVAILABLE")
		# This raw DLL call is deliberately watchdog-contained. It does not
		# belong to IUIAutomation/clientObject and must not borrow its COM surface.
		return self._execute(probe, hwnd, hwnd=hwnd)

	def _sameElement(self, client: object | None, first: object, second: object) -> bool:
		if client is not None:
			comparison = self._invoke(client, ("CompareElements",), (first, second))
			if comparison.status == "value":
				return bool(comparison.value)
		firstRuntimeRead = self._invoke(first, ("getRuntimeId",), ())
		secondRuntimeRead = self._invoke(second, ("getRuntimeId",), ())
		firstRuntime = firstRuntimeRead.value if firstRuntimeRead.status == "value" else None
		secondRuntime = secondRuntimeRead.value if secondRuntimeRead.status == "value" else None
		if firstRuntime is not None and secondRuntime is not None:
			try:
				return tuple(cast(Iterable[object], firstRuntime)) == tuple(
					cast(Iterable[object], secondRuntime),
				)
			except Exception:
				pass
		return first is second

	def _classifyEvidence(
		self,
		element: object,
		hwnd: int | None = None,
	) -> RawEvidenceQuality:
		identity = id(element)
		cached = self._qualityByIdentity.get(identity)
		if cached is not None and cached[0] is element and (hwnd is None or cached[2] == hwnd):
			return cached[1]
		providerRead = self._serverSideProviderAvailability(hwnd)
		providerAvailable = bool(providerRead.value) if providerRead.status == "value" else None
		providerStatus = (
			"available"
			if providerAvailable is True
			else "absent"
			if providerAvailable is False
			else "unavailable"
		)
		classificationStatus = "notNeeded"
		classificationError = "none"
		if providerAvailable is False:
			quality: RawEvidenceQuality = "noNativeProvider"
		elif providerAvailable is True:
			quality = "native"
		else:
			classificationStatus = "unavailable"
			classificationError = "handlerUnavailable"
			try:
				handler = self._handler()
			except Exception:
				quality = "incomplete"
			else:
				classificationRead = self._invoke(
					handler,
					("isNativeUIAElement",),
					(element,),
					hwnd=hwnd,
					ownerThread=True,
				)
				classificationStatus = classificationRead.status
				classificationError = classificationRead.errorCode or "none"
				classification = classificationRead.value if classificationRead.status == "value" else None
				quality = (
					"native"
					if classification is True
					else "synthesizedProxy"
					if classification is False
					else "incomplete"
				)
		self._trace(
			"raw.classification",
			classification=quality,
			error=classificationError,
			execution="owner",
			providerAvailability=providerStatus,
			providerError=providerRead.errorCode or "none",
			providerStatus=providerRead.status,
			status=classificationStatus,
			windowClass=self._windowClass(hwnd),
		)
		self._qualityByIdentity[identity] = (element, quality, hwnd)
		return quality

	def evidenceQuality(
		self,
		element: object,
		*,
		windowHandle: int | None = None,
	) -> RawEvidenceQuality:
		return self._classifyEvidence(element, windowHandle)

	def candidateElements(
		self,
		target: object,
		targetKind: RawTargetKind,
		maximumCandidates: int,
		*,
		preferPoint: bool = False,
	) -> ObjectBatch:
		"""Gather a deterministic, bounded, deduplicated sequence of raw candidates.

		Sources are ranked, rather than accumulated: retained UIA, IAccessible
		bridge, selected window, geometry point, focused element, then ancestor
		window. A viable higher-ranked candidate prevents all lower-ranked reads,
		so a window root remains a last-resort root and cannot create identity
		ambiguity beside a stronger element. Each candidate still passes the
		process and NVDA-self gates before it is considered viable.
		"""
		_ = targetKind
		if maximumCandidates <= 0:
			return ObjectBatch("empty", (), 0, False)

		nvdaProcess = self.nvdaProcessId()
		targetProcess = self._targetProcessId(target)
		client = self._client()
		self._trustedElement = None
		self._spatialElement = None
		self._pointResolvedElement = None
		self._windowScopedElement = None
		accepted: list[object] = []
		rejected: list[object] = []
		acquisitionFailures: list[ObjectRead] = []
		bestRank: int | None = None

		def consider(
			acquire: Callable[[], ObjectRead],
			*,
			order: int,
			rank: int,
			source: str,
			primary: bool = False,
			trusted: bool = False,
			spatial: bool = False,
			pointResolved: bool = False,
			windowScoped: bool = False,
			windowHint: int | None = None,
		) -> None:
			nonlocal bestRank
			if bestRank is not None and rank > bestRank:
				self._trace(
					"raw.candidate",
					acquisition="skipped",
					classification="notEvaluated",
					error="strongerCandidate",
					gate="candidateRank",
					order=order,
					outcome="rejected",
					source=source,
					trust="construction" if trusted else "window" if windowScoped else "none",
				)
				return
			elementRead = acquire()
			if elementRead.status != "value" or elementRead.value is None:
				if elementRead.status in ("unavailable", "failed"):
					acquisitionFailures.append(elementRead)
				self._trace(
					"raw.candidate",
					classification="notRead",
					error=elementRead.errorCode or "none",
					order=order,
					outcome="rejected",
					source=source,
					status=elementRead.status,
				)
				return
			element = elementRead.value
			pidResult = self.processId(element)
			pid = pidResult.value if pidResult.status == "value" and type(pidResult.value) is int else None
			if pid is None:
				rejected.append(element)
				self._trace(
					"raw.candidate",
					classification="notEvaluated",
					error=pidResult.errorCode or "processUnavailable",
					order=order,
					outcome="rejected",
					source=source,
					status=pidResult.status,
				)
				return
			if pid == nvdaProcess:
				rejected.append(element)
				self._trace(
					"raw.candidate",
					classification="notEvaluated",
					error="nvdaProcess",
					order=order,
					outcome="rejected",
					source=source,
					status="value",
				)
				return
			if targetProcess is not None and pid != targetProcess:
				rejected.append(element)
				self._trace(
					"raw.candidate",
					classification="notEvaluated",
					error="crossProcess",
					order=order,
					outcome="rejected",
					source=source,
					status="value",
				)
				return
			# Provider classification can call into NVDA and COM.  Process gates
			# are deliberately evaluated first so Inspector-owned candidates never
			# pay that cost or influence evidence.
			classification = self._classifyEvidence(element, windowHint)
			for existing in accepted:
				if element is existing:
					# The exact same reference is already retained; nothing new
					# to release, and releasing it here would drop the kept one.
					if trusted:
						self._trustedElement = existing
					if spatial:
						self._spatialElement = existing
					if pointResolved:
						self._pointResolvedElement = existing
					if windowScoped and windowHint is not None:
						self._windowScopedElement = (existing, windowHint)
					bestRank = min(bestRank, rank) if bestRank is not None else rank
					self._trace(
						"raw.candidate",
						classification=classification,
						error="duplicateExact",
						order=order,
						outcome="deduplicated",
						source=source,
						status="value",
					)
					return
				try:
					duplicate = self._sameElement(client, existing, element)
				except Exception:
					duplicate = False
				if duplicate:
					if trusted:
						self._trustedElement = existing
					if spatial:
						self._spatialElement = existing
					if pointResolved:
						self._pointResolvedElement = existing
					if windowScoped and windowHint is not None:
						self._windowScopedElement = (existing, windowHint)
					bestRank = min(bestRank, rank) if bestRank is not None else rank
					rejected.append(element)
					self._trace(
						"raw.candidate",
						classification=classification,
						error="duplicateProvider",
						order=order,
						outcome="deduplicated",
						source=source,
						status="value",
					)
					return
			accepted.append(element)
			bestRank = rank
			if primary:
				self._selectedElement = element
			if trusted:
				self._trustedElement = element
			if spatial:
				self._spatialElement = element
			if pointResolved:
				self._pointResolvedElement = element
			if windowScoped and windowHint is not None:
				self._windowScopedElement = (element, windowHint)
			self._trace(
				"raw.candidate",
				classification=classification,
				error="none",
				order=order,
				outcome="accepted",
				source=source,
				status="value",
				trust="construction" if trusted else "window" if windowScoped else "none",
			)

		# 1. The target's own UIA element: already resolved by NVDA, most trusted.
		ownHandle = self._targetWindowHandle(target)
		elementRead = self._element(target)
		consider(
			lambda: elementRead,
			order=1,
			rank=1,
			source="retainedElement",
			primary=True,
			trusted=True,
			windowHint=ownHandle,
		)

		# 2. A backend-neutral MSAA/IA2/JAB bridge is direct evidence for this
		# selected object, even when NVDA retained no UIAElement.
		consider(
			lambda: self._acquireByIAccessible(client, target, ownHandle),
			order=2,
			rank=2,
			source="iAccessibleBridge",
			trusted=True,
			windowHint=ownHandle,
		)

		if preferPoint:
			# Resolve the selected object's own screen position before accepting its enclosing window.
			# This never changes NVDA's object model; it queries the existing UIA client directly.
			consider(
				lambda: self._acquireByPoint(client, self._centerPoint(target), ownHandle),
				order=3,
				rank=3,
				source="geometryPoint",
				spatial=True,
				pointResolved=True,
				windowHint=ownHandle,
			)
			windowOrder = 4
			windowRank = 4
		else:
			windowOrder = 3
			windowRank = 3

		# The selected target's own window is a window-level root, never a claim that a
		# particular child/item was identified.
		consider(
			lambda: self._acquireByHandle(client, ownHandle),
			order=windowOrder,
			rank=windowRank,
			source="windowHandle",
			windowScoped=True,
			windowHint=ownHandle,
		)

		# 4-5. Point and focus are global sources. Do not let the Inspector's
		# own focus replace the external target while it is open.
		if self._focusedObjectIsNvda(nvdaProcess):
			for order, source in ((5, "geometryPoint"), (6, "focusedElement")):
				self._trace(
					"raw.candidate",
					acquisition="skipped",
					error="nvdaProcess",
					gate="globalFocusProcess",
					order=order,
					outcome="rejected",
					source=source,
				)
		else:
			consider(
				lambda: self._acquireByPoint(client, self._centerPoint(target), ownHandle),
				order=5,
				rank=5,
				source="geometryPoint",
				spatial=targetKind == "navigator",
				windowHint=ownHandle,
			)
			consider(
				lambda: self._acquireFocused(client, ownHandle),
				order=6,
				rank=6,
				source="focusedElement",
				trusted=targetKind == "focus",
				windowHint=ownHandle,
			)

		# 6. A native ancestor window handle, only when the target has none of its own.
		if not ownHandle:
			ancestorHandle = self._fallbackAncestorHandle(target)
			consider(
				lambda: self._acquireByHandle(client, ancestorHandle),
				order=6,
				rank=6,
				source="ancestorWindow",
				trusted=targetKind == "foreground",
				windowHint=ancestorHandle,
			)

		for element in rejected:
			self.releaseElement(element)

		observed = len(accepted)
		retained = tuple(accepted[:maximumCandidates])
		for element in accepted[maximumCandidates:]:
			self.releaseElement(element)

		if not retained:
			for failure in acquisitionFailures:
				if failure.errorCode in (
					"KS.RAW_UIA.WATCHDOG_CANCELLED",
					"KS.RAW_UIA.GHOST_TARGET",
					"KS.RAW_UIA.HUNG_TARGET",
					"KS.RAW_UIA.WINDOW_CHECK_FAILED",
					"KS.RAW_UIA.COM_FAILED",
					"KS.RAW_UIA.NO_CLIENT",
				):
					return ObjectBatch(
						failure.status,
						(),
						0,
						False,
						failure.errorCode,
					)
			return ObjectBatch("empty", (), 0, False)
		return ObjectBatch("value", retained, observed, observed > len(retained))

	def processId(self, element: object) -> ProviderReadResult:
		selectedIdentity = self._selectedIdentity
		if element is self._selectedElement and selectedIdentity is not None:
			return ProviderReadResult("value", selectedIdentity.providerProcessId)
		cachedProcess = self._cachedInt(element, "CachedProcessId")
		if cachedProcess is not None:
			return ProviderReadResult("value", cachedProcess)
		return self.readProperty(element, "process", ReadBudget(1, 32, 100))

	def candidateIdentity(
		self,
		element: object,
		processId: int,
		budget: ReadBudget,
	) -> ProjectionCandidate:
		selected = self._selectedIdentity
		if element is self._selectedElement and selected is not None:
			return ProjectionCandidate(
				f"candidate-{id(element)}",
				processId,
				selected.providerScope,
				selected.role,
				selected.stableKeys,
				selected.windowHandle,
				selected.wholeWindow,
				IdentityProbe(
					pythonIdentity=True,
					providerComparison="same",
					trustedAcquisition=True,
					geometryGuidance=element is self._spatialElement,
				),
			)
		role = self._cachedText(element, "CachedLocalizedControlType")
		if role is None:
			roleResult = self.readProperty(element, "role", budget)
			role = (
				roleResult.value
				if roleResult.status == "value" and isinstance(roleResult.value, str) and roleResult.value
				else None
			)
		window = self._cachedWindowHandle(element)
		if window is None:
			windowResult = self.readProperty(element, "windowHandle", budget)
			window = (
				windowResult.value
				if windowResult.status == "value" and type(windowResult.value) is int
				else None
			)
		stableKeys = self._runtimeKey(element, budget)
		windowScoped = (
			self._windowScopedElement is not None
			and self._windowScopedElement[0] is element
			and self._windowScopedElement[1] == window
			and selected is not None
			and selected.windowHandle == window
		)
		positionAndNameMatch = False
		if element is self._pointResolvedElement and self._selectedName is not None:
			nameResult = self.readProperty(element, "name", budget)
			positionAndNameMatch = (
				nameResult.status == "value"
				and isinstance(nameResult.value, str)
				and nameResult.value.casefold().strip() == self._selectedName.casefold().strip()
			)
		providerComparison = None
		if self._selectedElement is not None:
			try:
				client = self._handler().__getattribute__("clientObject")
			except Exception:
				client = None
			if client is not None:
				comparison = self._invoke(
					client,
					("CompareElements",),
					(self._selectedElement, element),
				)
				if comparison.status == "value":
					providerComparison = "same" if bool(comparison.value) else "different"
		return ProjectionCandidate(
			f"candidate-{id(element)}",
			processId,
			"uia",
			role,
			stableKeys,
			window,
			windowScoped or role == "window",
			IdentityProbe(
				pythonIdentity=element is self._selectedElement,
				providerComparison=providerComparison,
				trustedAcquisition=element is self._trustedElement,
				windowScopedAcquisition=windowScoped,
				geometryGuidance=element is self._spatialElement,
				positionAndNameMatch=positionAndNameMatch,
			),
		)

	def readProperty(self, element: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		name = self._PROPERTY_NAMES.get(fieldId)
		if name is None:
			return ProviderReadResult("unsupported")
		try:
			identifier = self._identifier(name)
			valueRead = self._invoke(
				element,
				("getCurrentPropertyValueEx",),
				(identifier, True),
				hwnd=(
					self._selectedIdentity.windowHandle
					if element is self._selectedElement and self._selectedIdentity is not None
					else None
				),
				ownerThread=element is self._selectedElement,
			)
			if valueRead.status != "value":
				errorCode = valueRead.errorCode
				if valueRead.status == "failed" and errorCode == "KS.RAW_UIA.CALL_FAILED":
					errorCode = "KS.RAW_UIA.PROPERTY_FAILED"
				return ProviderReadResult(valueRead.status, errorCode=errorCode)
			value = valueRead.value
			handler = self._handler()
			sentinel = getattr(handler, "reservedNotSupportedValue", object())
			try:
				unsupported = (value == sentinel) is True
			except Exception:
				unsupported = False
			if unsupported:
				return ProviderReadResult("unsupported")
			try:
				if fieldId == "role" and type(value) is int:
					controlTypeName = self._controlTypeName(value)
					value = (
						f"{controlTypeName} ({value})"
						if controlTypeName is not None
						else f"UIA control type ({value})"
					)
				return normalizeProviderRead(value, budget)
			except (TypeError, ValueError):
				return ProviderReadResult("unsupported")
		except LookupError:
			return ProviderReadResult("unsupported")
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.RAW_UIA.PROPERTY_FAILED")

	def _readFirstChild(
		self,
		walker: object,
		element: object,
		*,
		trusted: bool,
		hwnd: int | None,
	) -> tuple[ObjectRead, str, str]:
		execution = "owner" if trusted else "watchdog"
		lastResult = ObjectRead("unsupported")
		selectedMethod = "none"
		fallbackMethod = "none"
		for methodName, role in (
			("GetFirstChildElementBuildCache", "selected"),
			("GetFirstChildElement", "fallback"),
		):
			method = getattr(walker, methodName, None)
			if not callable(method):
				self._trace(
					"raw.children.attempt",
					error="methodUnavailable",
					execution=execution,
					hresult="none",
					method=methodName,
					role=role,
					status="unsupported",
					trusted=str(trusted).lower(),
				)
				continue
			args: tuple[object, ...] = (element,)
			if methodName.endswith("BuildCache"):
				try:
					cacheRequest = getattr(self._handler(), "baseCacheRequest", None)
				except Exception:
					cacheRequest = None
				if cacheRequest is None:
					self._trace(
						"raw.children.attempt",
						error="cacheUnavailable",
						execution=execution,
						hresult="none",
						method=methodName,
						role=role,
						status="unsupported",
						trusted=str(trusted).lower(),
					)
					continue
				args = (*args, cacheRequest)
			else:
				fallbackMethod = methodName
			result = (
				self._executeOnOwnerThread(method, *args, hwnd=hwnd)
				if trusted
				else self._execute(method, *args, hwnd=hwnd)
			)
			self._trace(
				"raw.children.attempt",
				error=result.errorCode or "none",
				execution=execution,
				hresult=self._traceHresult(result.hresult),
				method=methodName,
				role=role,
				status=result.status,
				trusted=str(trusted).lower(),
			)
			if result.status in ("value", "empty"):
				return result, methodName, fallbackMethod
			if result.status == "unavailable":
				return result, selectedMethod, fallbackMethod
			if result.status == "failed":
				lastResult = result
				selectedMethod = "none"
				continue
			if lastResult.status == "unsupported":
				lastResult = result
		return lastResult, selectedMethod, fallbackMethod

	def _readNextSibling(
		self,
		walker: object,
		element: object,
		*,
		index: int,
		trusted: bool,
		hwnd: int | None,
	) -> tuple[ObjectRead, str, str]:
		execution = "owner" if trusted else "watchdog"
		lastResult = ObjectRead("unsupported")
		selectedMethod = "none"
		fallbackMethod = "none"
		for methodName, role in (
			("GetNextSiblingElementBuildCache", "selected"),
			("GetNextSiblingElement", "fallback"),
		):
			method = getattr(walker, methodName, None)
			if not callable(method):
				self._trace(
					"raw.children.sibling",
					error="methodUnavailable",
					execution=execution,
					hresult="none",
					index=index,
					method=methodName,
					role=role,
					status="unsupported",
					trusted=str(trusted).lower(),
				)
				continue
			args: tuple[object, ...] = (element,)
			if methodName.endswith("BuildCache"):
				try:
					cacheRequest = getattr(self._handler(), "baseCacheRequest", None)
				except Exception:
					cacheRequest = None
				if cacheRequest is None:
					self._trace(
						"raw.children.sibling",
						error="cacheUnavailable",
						execution=execution,
						hresult="none",
						index=index,
						method=methodName,
						role=role,
						status="unsupported",
						trusted=str(trusted).lower(),
					)
					continue
				args = (*args, cacheRequest)
			else:
				fallbackMethod = methodName
			result = (
				self._executeOnOwnerThread(method, *args, hwnd=hwnd)
				if trusted
				else self._execute(method, *args, hwnd=hwnd)
			)
			self._trace(
				"raw.children.sibling",
				error=result.errorCode or "none",
				execution=execution,
				hresult=self._traceHresult(result.hresult),
				index=index,
				method=methodName,
				role=role,
				status=result.status,
				trusted=str(trusted).lower(),
			)
			if result.status in ("value", "empty"):
				return result, methodName, fallbackMethod
			if result.status == "unavailable":
				return result, selectedMethod, fallbackMethod
			if result.status == "failed":
				lastResult = result
				selectedMethod = "none"
				continue
			if lastResult.status == "unsupported":
				lastResult = result
		return lastResult, selectedMethod, fallbackMethod

	def rawChildren(self, element: object, budget: ReadBudget) -> ObjectBatch:
		trusted = element is self._selectedElement
		selectedIdentity = self._selectedIdentity if trusted else None
		hwnd = (
			selectedIdentity.windowHandle
			if selectedIdentity is not None and selectedIdentity.windowHandle
			else self._cachedWindowHandle(element)
		)
		firstMethod = "none"
		firstFallbackMethod = "none"
		siblingMethod = "none"
		siblingFallbackMethod = "none"

		def finish(batch: ObjectBatch, *, outcome: str, error: str | None = None) -> ObjectBatch:
			self._trace(
				"raw.children.final",
				error=error or batch.errorCode or "none",
				fallbackMethod=firstFallbackMethod,
				firstMethod=firstMethod,
				outcome=outcome,
				observed=batch.observedCount,
				retained=len(batch.values),
				selectedMethod=firstMethod,
				siblingFallbackMethod=siblingFallbackMethod,
				siblingMethod=siblingMethod,
				status=batch.status,
				truncated=str(batch.truncated).lower(),
				trusted=str(trusted).lower(),
			)
			return batch

		try:
			handler = self._handler()
			walker = getattr(handler, "baseTreeWalker", None)
			if walker is None:
				return finish(
					ObjectBatch("unavailable", (), 0, False, "KS.RAW_UIA.WALKER_UNAVAILABLE"),
					outcome="reject",
				)
			childRead, selectedMethod, fallbackMethod = self._readFirstChild(
				walker,
				element,
				trusted=trusted,
				hwnd=hwnd,
			)
			firstMethod = selectedMethod
			firstFallbackMethod = fallbackMethod
			if trusted and childRead.status == "failed" and childRead.errorCode == "KS.RAW_UIA.COM_FAILED":
				# NVDA's own UIA first-child implementation treats this COM failure as a leaf.
				return finish(
					ObjectBatch("empty", (), 0, False),
					outcome="leaf",
					error=childRead.errorCode,
				)
			if childRead.status not in ("value", "empty"):
				return finish(
					ObjectBatch(childRead.status, (), 0, False, childRead.errorCode),
					outcome="reject",
				)
			child = childRead.value
			values: list[object] = []
			observed = 0
			while child is not None and len(values) < budget.maximumItems:
				observed += 1
				values.append(child)
				childRead, siblingMethod, siblingFallbackMethod = self._readNextSibling(
					walker,
					child,
					index=observed,
					trusted=trusted,
					hwnd=hwnd,
				)
				if childRead.status not in ("value", "empty"):
					if childRead.status == "failed" and childRead.errorCode == "KS.RAW_UIA.COM_FAILED":
						return finish(
							ObjectBatch("value", tuple(values), observed, True),
							outcome="partial",
							error=childRead.errorCode,
						)
					for value in reversed(values):
						self.releaseElement(value)
					return finish(
						ObjectBatch(childRead.status, (), 0, False, childRead.errorCode),
						outcome="reject",
					)
				child = childRead.value
			truncated = child is not None
			if child is not None:
				observed += 1
				self.releaseElement(child)
			return finish(
				ObjectBatch(
					"value" if observed else "empty",
					tuple(values),
					observed,
					truncated,
				),
				outcome="value" if observed else "leaf",
			)
		except Exception:
			return finish(
				ObjectBatch("failed", (), 0, False, "KS.RAW_UIA.CHILDREN_FAILED"),
				outcome="reject",
			)

	def releaseElement(self, element: object) -> None:
		identity = id(element)
		cached = self._qualityByIdentity.get(identity)
		if cached is not None and cached[0] is element:
			del self._qualityByIdentity[identity]
		if self._selectedElement is element:
			self._selectedElement = None
			self._selectedIdentity = None
		if self._trustedElement is element:
			self._trustedElement = None
		if self._spatialElement is element:
			self._spatialElement = None
		if self._windowScopedElement is not None and self._windowScopedElement[0] is element:
			self._windowScopedElement = None


class _RawElementUiaGetter(NvdaUiaGetter):
	"""Run the ordinary UIA collector against an already-acquired raw element."""

	@override
	def acquireElement(self, target: object) -> ObjectRead:
		return ObjectRead("value", target)


class RawUiaAdapter:
	"""One request-scoped raw projection; it never changes NVDA globals or selection."""

	def __init__(
		self,
		getter: RawUiaGetterPort,
		*,
		generation: int,
		uia: UiaProviderAdapter | None = None,
		diagnostic: Callable[[str], None] | None = None,
	) -> None:
		super().__init__()
		if generation < 0:
			raise ValueError("raw UIA generation must be nonnegative")
		self._getter = getter
		self._uia = uia or UiaProviderAdapter(_RawElementUiaGetter())
		self._diagnostic = diagnostic
		self._generation = generation
		self._ownerThread = threading.get_ident()
		self._objects: dict[str, object] = {}
		self._refsByIdentity: dict[int, str] = {}
		self._nextRef = 1
		self._projectionByRef: dict[str, ProjectionEvidence] = {}
		self._qualityByRef: dict[str, RawEvidenceQuality] = {}
		self._windowHandleByRef: dict[str, int | None] = {}
		self._preloadedChildren: dict[str, ObjectBatch] = {}

	def _trace(self, event: str, **fields: object) -> None:
		if self._diagnostic is None:
			return
		details = ", ".join(f"{name}={value}" for name, value in sorted(fields.items()))
		self._diagnostic(f"{event}; {details}")

	def _finish(self, outcome: RawProjectionOutcome, *, step: str) -> RawProjectionOutcome:
		evidence = outcome.evidence
		self._trace(
			"raw.final",
			applied=str(evidence.applied).lower(),
			gates="process,provider,identity",
			method=evidence.method.value,
			quality=outcome.evidenceQuality or "incomplete",
			reason=evidence.reasonCode,
			status=evidence.status.value,
			step=step,
			terminalReason=evidence.reasonCode,
		)
		return outcome

	def _rejectWithTrace(self, request: ProjectionRequest, reason: str, *, step: str) -> RawProjectionOutcome:
		return self._finish(self._rejected(request, reason), step=step)

	def _assertOwner(self) -> None:
		if threading.get_ident() != self._ownerThread:
			raise RuntimeError("KS.RAW_UIA.WRONG_THREAD")

	def owns(self, nodeRef: str) -> bool:
		return nodeRef in self._objects

	def _register(self, element: object) -> str:
		identity = id(element)
		existing = self._refsByIdentity.get(identity)
		if existing is not None and self._objects.get(existing) is element:
			return existing
		nodeRef = f"raw-{self._generation}-{self._nextRef}"
		self._nextRef += 1
		self._objects[nodeRef] = element
		self._refsByIdentity[identity] = nodeRef
		return nodeRef

	@staticmethod
	def _readBudget(request: ProjectionRequest) -> ReadBudget:
		return ReadBudget(
			request.budget.maximumItems,
			max(1, request.budget.maximumPropertyReads * 256),
			request.budget.maximumMilliseconds,
		)

	def project(
		self,
		selectedTarget: object,
		targetKind: RawTargetKind,
		request: ProjectionRequest,
	) -> RawProjectionOutcome:
		self._assertOwner()
		started = monotonic_ns()
		self._trace(
			"raw.request",
			candidateBudget=request.budget.maximumCandidates,
			propertyBudget=request.budget.maximumPropertyReads,
			requested=str(request.enabled).lower(),
			targetKind=targetKind,
		)
		if not request.enabled:
			decision = decideProjection(
				request,
				SelectedIdentity(0, "uia", None, (), None, False),
				(),
			)
			return self._finish(RawProjectionOutcome(None, decision.evidence), step="requestDisabled")
		budget = self._readBudget(request)
		try:
			selected = self._getter.selectedIdentity(selectedTarget, budget)
		except Exception:
			return self._rejectWithTrace(
				request,
				"KS.RAW_UIA.INVALID_SELECTED_IDENTITY",
				step="selectedIdentity",
			)
		self._trace(
			"raw.selected",
			providerScope=selected.providerScope,
			runtimeKeys=len(selected.stableKeys),
			status="value",
		)
		try:
			batch = self._getter.candidateElements(
				selectedTarget,
				targetKind,
				request.budget.maximumCandidates + 1,
				preferPoint=not request.allowWindowScoped and targetKind == "focus",
			)
		except Exception:
			return self._rejectWithTrace(request, "KS.RAW_UIA.CANDIDATE_FAILED", step="candidateCollection")
		self._trace(
			"raw.batch",
			count=len(batch.values),
			error=batch.errorCode or "none",
			status=batch.status,
			truncated=str(batch.truncated).lower(),
		)
		if batch.status not in ("value", "empty"):
			return self._rejectWithTrace(
				request,
				batch.errorCode or "KS.RAW_UIA.CANDIDATE_FAILED",
				step="candidateCollection",
			)
		if not batch.values:
			return self._rejectWithTrace(request, "KS.RAW_UIA.NO_CANDIDATE", step="candidateCollection")
		if batch.truncated or batch.observedCount > request.budget.maximumCandidates:
			self._releaseAll(batch.values)
			return self._rejectWithTrace(request, "KS.RAW_UIA.CANDIDATE_BUDGET", step="candidateBudget")
		if len(batch.values) * 5 > request.budget.maximumPropertyReads:
			self._releaseAll(batch.values)
			return self._rejectWithTrace(request, "KS.RAW_UIA.PROPERTY_BUDGET", step="propertyBudget")

		nvdaProcess = self._getter.nvdaProcessId()
		candidates: list[ProjectionCandidate] = []
		elementsById: dict[str, object] = {}
		qualityByCandidateId: dict[str, RawEvidenceQuality] = {}
		noNativeProviderCount = 0
		for element in batch.values:
			if (monotonic_ns() - started) // 1_000_000 > request.budget.maximumMilliseconds:
				self._releaseAll(batch.values)
				return self._rejectWithTrace(request, "KS.RAW_UIA.ELAPSED_BUDGET", step="candidateIdentity")
			process = self._getter.processId(element)
			if process.status != "value" or type(process.value) is not int:
				self._releaseAll(batch.values)
				reason = (
					"KS.RAW_UIA.STALE_ROOT"
					if process.status == "stale"
					else process.errorCode or "KS.RAW_UIA.INVALID_PROCESS"
				)
				return self._rejectWithTrace(request, reason, step="candidateProcess")
			if process.value == nvdaProcess:
				self._releaseAll(batch.values)
				return self._rejectWithTrace(request, "KS.RAW_UIA.NVDA_PROCESS", step="candidateProcess")
			if process.value != selected.providerProcessId:
				self._releaseAll(batch.values)
				return self._rejectWithTrace(request, "KS.RAW_UIA.CROSS_PROCESS", step="candidateProcess")
			try:
				quality = self._getter.evidenceQuality(element)
				if quality == "noNativeProvider":
					noNativeProviderCount += 1
					continue
				candidate = self._getter.candidateIdentity(element, process.value, budget)
			except Exception:
				self._releaseAll(batch.values)
				return self._rejectWithTrace(request, "KS.RAW_UIA.IDENTITY_FAILED", step="candidateIdentity")
			candidates.append(candidate)
			elementsById[candidate.candidateId] = element
			qualityByCandidateId[candidate.candidateId] = quality
		if not candidates and noNativeProviderCount:
			self._releaseAll(batch.values)
			return self._finish(
				RawProjectionOutcome(
					None,
					ProjectionEvidence(
						True,
						request.requestId,
						False,
						ProjectionStatus.DEGRADED,
						ProjectionMethod.NONE,
						selected.providerScope,
						"indeterminate",
						"KS.RAW_UIA.NO_NATIVE_PROVIDER",
						noNativeProviderCount,
						0,
					),
					"noNativeProvider",
				),
				step="providerEvidence",
			)

		decision = decideProjection(request, selected, tuple(candidates))
		if decision.selectedCandidateId is None:
			self._releaseAll(batch.values)
			return self._finish(RawProjectionOutcome(None, decision.evidence), step="identityDecision")
		element = elementsById[decision.selectedCandidateId]
		quality = qualityByCandidateId[decision.selectedCandidateId]
		if quality != "native":
			self._releaseAll(batch.values)
			return self._finish(
				self._degraded(
					request,
					"KS.RAW_UIA.SYNTHESIZED_PROXY"
					if quality == "synthesizedProxy"
					else "KS.RAW_UIA.INCOMPLETE_EVIDENCE",
					quality,
					decision.evidence,
				),
				step="evidenceClassification",
			)
		children = self._getter.rawChildren(element, budget)
		if (monotonic_ns() - started) // 1_000_000 > request.budget.maximumMilliseconds:
			self._releaseAll(batch.values)
			self._releaseAll(children.values)
			return self._rejectWithTrace(request, "KS.RAW_UIA.ELAPSED_BUDGET", step="rawChildren")
		if children.status not in ("value", "empty"):
			self._releaseAll(batch.values)
			self._releaseAll(children.values)
			reason = children.errorCode or "KS.RAW_UIA.CHILDREN_FAILED"
			return self._rejectWithTrace(request, reason, step="rawChildren")
		rootRef = self._register(element)
		self._projectionByRef[rootRef] = decision.evidence
		self._qualityByRef[rootRef] = quality
		candidate = next(
			candidate for candidate in candidates if candidate.candidateId == decision.selectedCandidateId
		)
		self._windowHandleByRef[rootRef] = (
			candidate.windowHandle if candidate.windowHandle is not None else selected.windowHandle
		)
		self._preloadedChildren[rootRef] = children
		for unused in batch.values:
			if unused is not element:
				self._getter.releaseElement(unused)
		return self._finish(
			RawProjectionOutcome(rootRef, decision.evidence, quality),
			step="applied",
		)

	def _releaseAll(self, values: tuple[object, ...]) -> None:
		for value in reversed(values):
			self._getter.releaseElement(value)

	@staticmethod
	def _rejected(request: ProjectionRequest, reason: str) -> RawProjectionOutcome:
		decision = decideProjection(
			request,
			SelectedIdentity(0, "uia", None, (), None, False),
			(),
		)
		evidence = ProjectionEvidence(
			True,
			request.requestId,
			False,
			ProjectionStatus.REJECTED,
			decision.evidence.method,
			"uia",
			"indeterminate",
			reason,
			decision.evidence.candidateCount,
			decision.evidence.propertyReads,
		)
		return RawProjectionOutcome(None, evidence)

	@staticmethod
	def _degraded(
		request: ProjectionRequest,
		reason: str,
		quality: RawEvidenceQuality,
		basis: ProjectionEvidence,
	) -> RawProjectionOutcome:
		evidence = ProjectionEvidence(
			True,
			request.requestId,
			False,
			ProjectionStatus.DEGRADED,
			basis.method,
			basis.providerScope,
			"indeterminate",
			reason,
			basis.candidateCount,
			basis.propertyReads,
		)
		return RawProjectionOutcome(None, evidence, quality)

	def _target(self, nodeRef: str, generation: int | None) -> object:
		self._assertOwner()
		if generation != self._generation:
			raise _RawTargetLookupError("KS.RAW_UIA.STALE_GENERATION")
		try:
			return self._objects[nodeRef]
		except KeyError as error:
			raise _RawTargetLookupError("KS.RAW_UIA.UNKNOWN_NODE_REF") from error

	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult:
		try:
			target = self._target(request.nodeRef, request.context.generation)
			return self._getter.readProperty(target, request.fieldId, request.budget)
		except _RawTargetLookupError as error:
			return ProviderReadResult("stale", errorCode=error.errorCode)
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.RAW_UIA.PROPERTY_FAILED")

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		classificationDeadline = monotonic_ns() + request.budget.maximumMilliseconds * 1_000_000
		try:
			target = self._target(request.nodeRef, request.context.generation)
			batch = self._preloadedChildren.pop(request.nodeRef, None)
			if batch is None:
				batch = self._getter.rawChildren(target, request.budget)
		except _RawTargetLookupError as error:
			return ProviderChildBatch("stale", (), 0, False, error.errorCode)
		except Exception:
			return ProviderChildBatch("failed", (), 0, False, "KS.RAW_UIA.CHILDREN_FAILED")
		if batch.status not in ("value", "empty"):
			for value in reversed(batch.values):
				self._getter.releaseElement(value)
			return ProviderChildBatch(batch.status, (), 0, False, batch.errorCode)
		retained = batch.values[: request.budget.maximumItems]
		dropped = batch.values[request.budget.maximumItems :]
		for value in reversed(dropped):
			self._getter.releaseElement(value)
		nodeRefs: list[str] = []
		windowHandle = self._windowHandleByRef.get(request.nodeRef)
		for value in retained:
			quality: RawEvidenceQuality = "incomplete"
			if monotonic_ns() < classificationDeadline:
				try:
					classifiedQuality = self._getter.evidenceQuality(value, windowHandle=windowHandle)
				except Exception:
					pass
				else:
					if monotonic_ns() < classificationDeadline:
						quality = classifiedQuality
			nodeRef = self._register(value)
			nodeRefs.append(nodeRef)
			self._qualityByRef[nodeRef] = quality
			self._windowHandleByRef[nodeRef] = windowHandle
		parentEvidence = self._projectionByRef.get(request.nodeRef)
		if parentEvidence is not None:
			for nodeRef in nodeRefs:
				self._projectionByRef[nodeRef] = parentEvidence
		return ProviderChildBatch(
			batch.status,
			tuple(nodeRefs),
			batch.observedCount,
			batch.truncated or bool(dropped),
		)

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		# Raw mode deliberately has no NVDA-corrected logical-child fallback.
		return ProviderChildBatch("empty", (), 0, False)

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult:
		_ = request
		return ProviderReadResult("unsupported")

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult:
		_ = request
		return ProviderReadResult("unsupported")

	@staticmethod
	def projectionPlain(
		evidence: ProjectionEvidence,
		evidenceQuality: RawEvidenceQuality,
	) -> PlainValue:
		return (
			("requested", evidence.requested),
			("requestId", evidence.requestId),
			("applied", evidence.applied),
			("status", evidence.status.value),
			("method", evidence.method.value),
			("providerScope", evidence.providerScope),
			("confidence", evidence.confidence),
			("reasonCode", evidence.reasonCode),
			("candidateCount", evidence.candidateCount),
			("propertyReads", evidence.propertyReads),
			("completenessClaimed", evidence.completenessClaimed),
			("evidenceQuality", evidenceQuality),
		)

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		try:
			target = self._target(request.nodeRef, request.context.generation)
		except _RawTargetLookupError as error:
			return ProviderReadResult("stale", errorCode=error.errorCode)
		evidence = self._projectionByRef.get(request.nodeRef)
		evidenceQuality = self._qualityByRef.get(request.nodeRef)
		if evidence is None or evidenceQuality is None:
			return ProviderReadResult("unsupported")
		projection = self.projectionPlain(evidence, evidenceQuality)
		if request.metadataId == "rawProjection":
			return ProviderReadResult("value", projection)
		if request.metadataId != "providerSections":
			return ProviderReadResult("unsupported")
		rawUia = ProviderSectionData(
			"rawUia",
			ProviderReadResult("value", "rawUia"),
			(),
			(ProviderDatum("projection", ProviderReadResult("value", projection)),),
		)
		try:
			uia = self._uia.collect(target, request.budget)
		except AssertionError:
			raise
		except Exception:
			uia = ProviderSectionData(
				"uia",
				ProviderReadResult("failed", errorCode="KS.PROVIDER.UIA_FAILED"),
			)
		return ProviderReadResult("value", encodeProviderSections((rawUia, uia)))

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		try:
			first = self._target(request.firstNodeRef, request.context.generation)
			second = self._target(request.secondNodeRef, request.context.generation)
		except _RawTargetLookupError as error:
			return IdentityComparisonResult("stale", "failed", (), error.errorCode)
		return IdentityComparisonResult(
			"value",
			"same" if first is second else "different",
			(("pythonIdentity", first is second),),
		)

	def close(self) -> None:
		self._assertOwner()
		registeredIdentities = {id(value) for value in self._objects.values()}
		releasedIdentities: set[int] = set()
		for batch in reversed(tuple(self._preloadedChildren.values())):
			for value in reversed(batch.values):
				identity = id(value)
				if identity not in registeredIdentities and identity not in releasedIdentities:
					self._getter.releaseElement(value)
					releasedIdentities.add(identity)
		for value in reversed(tuple(self._objects.values())):
			self._getter.releaseElement(value)
		self._objects.clear()
		self._refsByIdentity.clear()
		self._projectionByRef.clear()
		self._qualityByRef.clear()
		self._windowHandleByRef.clear()
		self._preloadedChildren.clear()
