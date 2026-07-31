from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import importlib
import threading
from typing import Literal, Protocol, cast

from ...capability import PlainValue
from ...domain.correlation import CorrelationContext
from ...domain.privacy import PrivacyPolicy, ProtectionEvidence
from ...domain.projection import ProjectionEvidence, ProjectionRequest
from ...domain.provider_measurement import BackendId
from ...ports.providers import (
	IdentityComparisonRequest,
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderChildrenRequest,
	ProviderFieldRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ProviderRelationRequest,
	ProviderSessionCloseRequest,
	ProviderTextRequest,
	ReadBudget,
	ReleaseResult,
	ResourceReleaseRequest,
)
from ..providers.common import (
	CommonProviderAdapter,
	NvdaObjectGetter,
	ObjectGetterPort,
	PROVIDER_SECTIONS_METADATA_ID,
	ProviderDatum,
	ProviderSectionData,
	encodeProviderSections,
)
from ..providers.custom_uia import (
	CustomUiaBudget,
	CustomUiaCaptureMode,
	CustomUiaProviderAdapter,
	NvdaCustomUiaGetter,
)
from ..providers.ia2_msaa import Ia2MsaaProviderAdapter, NvdaIa2MsaaGetter
from ..providers.jab import JabProviderAdapter, NvdaJabGetter
from ..providers.overlay import NvdaOverlayGetter, OverlayProviderAdapter
from ..providers.raw_uia import NvdaRawUiaGetter, RawProjectionOutcome, RawUiaAdapter
from ..providers.uia import NvdaUiaGetter, UiaProviderAdapter
from .custom_uia_registry import buildNvdaCustomUiaRegistry


type SelectedTargetKind = Literal["foreground", "focus", "navigator"]


def _fallbackProjectionPlain(outcome: RawProjectionOutcome) -> PlainValue:
	quality = outcome.evidenceQuality or "incomplete"
	return RawUiaAdapter.projectionPlain(outcome.evidence, quality)


class SelectedObjectSource(Protocol):
	def selectedObject(self, targetKind: SelectedTargetKind) -> object: ...


class NvdaSelectedObjectSource:
	"""Acquires NVDA's cached foreground or navigator object without changing selection."""

	@staticmethod
	def selectedObject(targetKind: SelectedTargetKind) -> object:
		api = importlib.import_module("api")
		member = {
			"foreground": "getForegroundObject",
			"focus": "getFocusObject",
			"navigator": "getNavigatorObject",
		}[targetKind]
		getter = api.__getattribute__(member)
		if not callable(getter):
			raise RuntimeError("NVDA selected-object getter is unavailable")
		return getter()


def _sameWholeWindow(first: object, second: object) -> bool:
	try:
		if getattr(first, "UIAElement", None) is not None or getattr(second, "UIAElement", None) is not None:
			return False
		firstAccessible = getattr(first, "IAccessibleObject", None)
		secondAccessible = getattr(second, "IAccessibleObject", None)
		if firstAccessible is None or secondAccessible is None:
			return False
		if getattr(first, "IAccessibleChildID", None) != 0:
			return False
		if getattr(second, "IAccessibleChildID", None) != 0:
			return False
		firstIa2Window = getattr(first, "IA2WindowHandle", None)
		secondIa2Window = getattr(second, "IA2WindowHandle", None)
		firstIa2UniqueId = getattr(first, "IA2UniqueID", None)
		secondIa2UniqueId = getattr(second, "IA2UniqueID", None)
		if (
			firstIa2Window
			and secondIa2Window
			and (firstIa2UniqueId or secondIa2UniqueId)
			and (firstIa2Window != secondIa2Window or firstIa2UniqueId != secondIa2UniqueId)
		):
			return False
		firstHandle = getattr(first, "windowHandle", None)
		secondHandle = getattr(second, "windowHandle", None)
		return bool(firstHandle) and firstHandle == secondHandle
	except Exception:
		return False


def _sameIAccessible2Object(first: object, second: object) -> bool:
	try:
		if getattr(first, "UIAElement", None) is not None or getattr(second, "UIAElement", None) is not None:
			return False
		firstAccessible = getattr(first, "IAccessibleObject", None)
		secondAccessible = getattr(second, "IAccessibleObject", None)
		if firstAccessible is None or secondAccessible is None:
			return False
		if getattr(first, "IAccessibleChildID", None) != getattr(second, "IAccessibleChildID", None):
			return False
		if firstAccessible == secondAccessible:
			return True
		firstWindow = getattr(first, "IA2WindowHandle", None)
		secondWindow = getattr(second, "IA2WindowHandle", None)
		firstUniqueId = getattr(first, "IA2UniqueID", None)
		secondUniqueId = getattr(second, "IA2UniqueID", None)
		return (
			bool(firstWindow)
			and firstWindow == secondWindow
			and bool(firstUniqueId or secondUniqueId)
			and firstUniqueId == secondUniqueId
		)
	except Exception:
		return False


def _location(value: object) -> tuple[int | float, int | float, int | float, int | float] | None:
	if isinstance(value, Mapping):
		mapping = cast(Mapping[str, object], value)
		parts: tuple[object, ...] = tuple(mapping.get(name) for name in ("left", "top", "width", "height"))
	elif isinstance(value, (list, tuple)):
		parts = tuple(cast(list[object] | tuple[object, ...], value))
	else:
		parts = tuple(cast(object, getattr(value, name, None)) for name in ("left", "top", "width", "height"))
	if len(parts) != 4:
		return None
	left, top, width, height = (
		part if isinstance(part, (int, float)) and not isinstance(part, bool) else None for part in parts
	)
	if left is None or top is None or width is None or height is None or width <= 0 or height <= 0:
		return None
	return left, top, width, height


def _crossBackendIdentifier(target: object) -> str | None:
	uiaIdentifier = getattr(target, "UIAAutomationId", None)
	if isinstance(uiaIdentifier, str) and uiaIdentifier:
		return uiaIdentifier
	ia2Attributes = getattr(target, "IA2Attributes", None)
	if isinstance(ia2Attributes, Mapping):
		ia2Identifier = cast(Mapping[str, object], ia2Attributes).get("id")
		if isinstance(ia2Identifier, str) and ia2Identifier:
			return ia2Identifier
	return None


def _sameCrossBackendSpatialNode(first: object, second: object) -> bool:
	"""Bridge exactly matching UIA and IAccessible wrappers for one live control."""

	try:
		firstUia = getattr(first, "UIAElement", None) is not None
		secondUia = getattr(second, "UIAElement", None) is not None
		firstAccessible = getattr(first, "IAccessibleObject", None) is not None
		secondAccessible = getattr(second, "IAccessibleObject", None) is not None
		if not (
			(firstUia and secondAccessible and not secondUia)
			or (secondUia and firstAccessible and not firstUia)
		):
			return False
		firstProcess = getattr(first, "processID", None)
		secondProcess = getattr(second, "processID", None)
		if (
			not isinstance(firstProcess, int)
			or isinstance(firstProcess, bool)
			or firstProcess <= 0
			or firstProcess != secondProcess
		):
			return False
		firstRole = getattr(first, "role", None)
		secondRole = getattr(second, "role", None)
		if firstRole is None or secondRole is None:
			return False
		if firstRole != secondRole:
			firstIdentifier = _crossBackendIdentifier(first)
			if firstIdentifier is None or firstIdentifier != _crossBackendIdentifier(second):
				return False
		firstName = getattr(first, "name", None)
		secondName = getattr(second, "name", None)
		if not isinstance(firstName, str) or not firstName or firstName != secondName:
			return False
		firstLocation = _location(getattr(first, "location", None))
		secondLocation = _location(getattr(second, "location", None))
		return firstLocation is not None and firstLocation == secondLocation
	except Exception:
		return False


def _sameUiaElement(first: object, second: object) -> bool:
	firstElement = getattr(first, "UIAElement", None)
	secondElement = getattr(second, "UIAElement", None)
	if firstElement is None or secondElement is None:
		return False
	try:
		handler = importlib.import_module("UIAHandler").handler
		compare = handler.clientObject.CompareElements
		return bool(compare(firstElement, secondElement))
	except Exception:
		return False


def _uiaRuntimeId(target: object) -> tuple[int, ...] | None:
	try:
		element = getattr(target, "UIAElement", None)
		getRuntimeId = getattr(element, "getRuntimeId", None)
		if not callable(getRuntimeId):
			return None
		values = tuple(cast(Iterable[object], getRuntimeId()))
	except Exception:
		return None
	if not values or not all(type(value) is int for value in values):
		return None
	return tuple(cast(int, value) for value in values)


def _sameUiaRuntimeId(first: object, second: object) -> bool:
	firstRuntimeId = _uiaRuntimeId(first)
	return firstRuntimeId is not None and firstRuntimeId == _uiaRuntimeId(second)


def _accessibleIdentityComparison(first: object, second: object) -> tuple[str, bool]:
	if first is second:
		return "pythonIdentity", True
	firstUia = getattr(first, "UIAElement", None) is not None
	secondUia = getattr(second, "UIAElement", None) is not None
	if firstUia and secondUia:
		if _sameUiaRuntimeId(first, second):
			return "uiaRuntimeId", True
		if _sameUiaElement(first, second):
			return "uiaElement", True
		return "uiaElement", False
	if not firstUia and not secondUia:
		try:
			if first == second:
				return "nvdaEquality", True
		except Exception:
			pass
		if _sameWholeWindow(first, second):
			return "wholeWindow", True
		if _sameIAccessible2Object(first, second):
			return "ia2Object", True
		return "ia2Object", False
	if _sameCrossBackendSpatialNode(first, second):
		return "crossBackendSpatial", True
	return "crossBackendSpatial", False


def accessibleIdentity(first: object, second: object) -> str | None:
	"""Return the matching identity criterion, if one establishes equality."""

	method, matches = _accessibleIdentityComparison(first, second)
	return method if matches else None


@dataclass(frozen=True, slots=True)
class SelectedObjectReference:
	rootRef: str
	providerScope: str
	processScope: str
	backend: BackendId
	originalRootRef: str | None = None
	projection: ProjectionEvidence | None = None


class SelectedObjectSession:
	"""Owns selected live objects while exposing only opaque refs and plain evidence."""

	def __init__(
		self,
		source: SelectedObjectSource,
		*,
		generation: int,
		objectGetter: ObjectGetterPort | None = None,
		common: CommonProviderAdapter | None = None,
		uia: UiaProviderAdapter | None = None,
		ia2Msaa: Ia2MsaaProviderAdapter | None = None,
		jab: JabProviderAdapter | None = None,
		overlay: OverlayProviderAdapter | None = None,
		rawUia: RawUiaAdapter | None = None,
		customUia: CustomUiaProviderAdapter | None = None,
		customUiaCaptureMode: CustomUiaCaptureMode = CustomUiaCaptureMode.NORMAL,
		rawDiagnostic: Callable[[str], None] | None = None,
	) -> None:
		super().__init__()
		if generation < 0:
			raise ValueError("selected-object generation must be nonnegative")
		getter = objectGetter or NvdaObjectGetter()
		self._source = source
		self._generation = generation
		self._ownerThread = threading.get_ident()
		self._objects: dict[str, object] = {}
		self._refsByIdentity: dict[int, str] = {}
		self._nextRef = 1
		self._closed = False
		self._fallbackProjection: dict[str, RawProjectionOutcome] = {}
		self._common = common or CommonProviderAdapter(getter)
		self._getter = getter
		self._uia = uia or UiaProviderAdapter(NvdaUiaGetter())
		self._ia2Msaa = ia2Msaa or Ia2MsaaProviderAdapter(NvdaIa2MsaaGetter())
		self._jab = jab or JabProviderAdapter(NvdaJabGetter())
		self._overlay = overlay or OverlayProviderAdapter(NvdaOverlayGetter())
		self._rawUia = rawUia or RawUiaAdapter(
			NvdaRawUiaGetter(diagnostic=rawDiagnostic),
			generation=generation,
			diagnostic=rawDiagnostic,
		)
		registeredProperties = buildNvdaCustomUiaRegistry().registeredProperties
		self._customUia = customUia or (
			CustomUiaProviderAdapter(NvdaCustomUiaGetter(), registeredProperties)
			if registeredProperties
			else None
		)
		self._customUiaCaptureMode = customUiaCaptureMode
		self._privacyPolicy = PrivacyPolicy(1, 1, False)

	def applyPrivacyPolicy(self, privacyPolicy: PrivacyPolicy) -> None:
		self._privacyPolicy = privacyPolicy

	def _assertOwner(self) -> None:
		if threading.get_ident() != self._ownerThread:
			raise RuntimeError("KS.PROVIDER.WRONG_THREAD")
		if self._closed:
			raise RuntimeError("KS.PROVIDER.SESSION_CLOSED")

	def _assertContext(self, context: CorrelationContext) -> None:
		self._assertOwner()
		if context.generation != self._generation:
			raise RuntimeError("KS.PROVIDER.STALE_GENERATION")

	def _register(self, target: object) -> str:
		identity = id(target)
		existing = self._refsByIdentity.get(identity)
		if existing is not None and self._objects.get(existing) is target:
			return existing
		nodeRef = f"selected-{self._generation}-{self._nextRef}"
		self._nextRef += 1
		self._objects[nodeRef] = target
		self._refsByIdentity[identity] = nodeRef
		return nodeRef

	def retain(self, target: object) -> str:
		"""Keep one owner-thread object available for the current session's identity comparisons."""

		self._assertOwner()
		return self._register(target)

	def acquire(
		self,
		targetKind: SelectedTargetKind,
		*,
		rawRequest: ProjectionRequest | None = None,
	) -> SelectedObjectReference:
		self._assertOwner()
		target = self._source.selectedObject(targetKind)
		originalRootRef = self.retain(target)
		process = self._common.readField(
			target,
			"process",
			_readBudget(),
		)
		processScope = (
			f"process-{process.value}"
			if process.status == "value" and type(process.value) is int
			else "selected-process"
		)
		backend = self._common.readField(target, "backend", _readBudget())
		backendValue = backend.value if backend.status == "value" else "nvdaSelected"
		backendId: BackendId = (
			"uia"
			if backendValue == "uia"
			else "ia2Msaa"
			if backendValue == "ia2Msaa"
			else "javaAccessBridge"
			if backendValue == "jab"
			else "nvdaSelected"
		)
		if rawRequest is None:
			return SelectedObjectReference(
				originalRootRef,
				"nvda-selected",
				processScope,
				backendId,
				originalRootRef,
			)
		raw = self._rawUia.project(target, targetKind, rawRequest)
		if raw.rootRef is None:
			self._fallbackProjection[originalRootRef] = raw
			return SelectedObjectReference(
				originalRootRef,
				"nvda-selected",
				processScope,
				backendId,
				originalRootRef,
				raw.evidence,
			)
		return SelectedObjectReference(
			raw.rootRef,
			"raw-uia",
			processScope,
			"uia",
			originalRootRef,
			raw.evidence,
		)

	def _target(self, nodeRef: str, context: CorrelationContext) -> object:
		self._assertContext(context)
		try:
			return self._objects[nodeRef]
		except KeyError as error:
			raise LookupError("KS.PROVIDER.UNKNOWN_NODE_REF") from error

	def readField(self, request: ProviderFieldRequest) -> ProviderReadResult:
		if self._rawUia.owns(request.nodeRef):
			return self._rawUia.readField(request)
		try:
			target = self._target(request.nodeRef, request.context)
			return self._common.readField(target, request.fieldId, request.budget)
		except LookupError:
			return ProviderReadResult("stale", errorCode="KS.PROVIDER.UNKNOWN_NODE_REF")
		except RuntimeError as error:
			return ProviderReadResult("stale", errorCode=str(error))
		except AssertionError:
			raise
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.FIELD_FAILED")

	def _children(self, request: ProviderChildrenRequest, *, logical: bool) -> ProviderChildBatch:
		if self._rawUia.owns(request.nodeRef):
			return (
				self._rawUia.readLogicalFirstChild(request) if logical else self._rawUia.readChildren(request)
			)
		try:
			target = self._target(request.nodeRef, request.context)
			batch = (
				self._getter.readLogicalFirstChild(target, request.budget)
				if logical
				else self._getter.readChildren(target, request.budget)
			)
		except LookupError:
			return ProviderChildBatch("stale", (), 0, False, "KS.PROVIDER.UNKNOWN_NODE_REF")
		except RuntimeError as error:
			return ProviderChildBatch("stale", (), 0, False, str(error))
		except AssertionError:
			raise
		except Exception:
			return ProviderChildBatch("failed", (), 0, False, "KS.PROVIDER.CHILDREN_FAILED")
		if batch.status in ("value", "empty"):
			retained = batch.values[: request.budget.maximumItems]
			return ProviderChildBatch(
				batch.status,
				tuple(self._register(item) for item in retained),
				batch.observedCount,
				batch.truncated or len(batch.values) > len(retained),
			)
		return ProviderChildBatch(
			batch.status,
			(),
			batch.observedCount,
			batch.truncated,
			batch.errorCode,
		)

	def readChildren(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		return self._children(request, logical=False)

	def readLogicalFirstChild(self, request: ProviderChildrenRequest) -> ProviderChildBatch:
		return self._children(request, logical=True)

	def readRelation(self, request: ProviderRelationRequest) -> ProviderReadResult:
		if self._rawUia.owns(request.nodeRef):
			return self._rawUia.readRelation(request)
		try:
			target = self._target(request.nodeRef, request.context)
			return self._getter.readAttribute(target, "relations", request.budget)
		except LookupError:
			return ProviderReadResult("stale", errorCode="KS.PROVIDER.UNKNOWN_NODE_REF")
		except RuntimeError as error:
			return ProviderReadResult("stale", errorCode=str(error))
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.RELATION_FAILED")

	def readText(self, request: ProviderTextRequest) -> ProviderReadResult:
		if self._rawUia.owns(request.nodeRef):
			return self._rawUia.readText(request)
		member = "textInfoSelection" if request.textReadId == "selection" else "textInfoDocument"
		try:
			target = self._target(request.nodeRef, request.context)
			return self._getter.readAttribute(target, member, request.budget)
		except LookupError:
			return ProviderReadResult("stale", errorCode="KS.PROVIDER.UNKNOWN_NODE_REF")
		except RuntimeError as error:
			return ProviderReadResult("stale", errorCode=str(error))
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.TEXT_FAILED")

	@staticmethod
	def _failedSection(sectionId: str) -> ProviderSectionData:
		return ProviderSectionData(
			sectionId,
			ProviderReadResult("failed", errorCode=f"KS.PROVIDER.{sectionId.upper()}_FAILED"),
		)

	def readMetadata(self, request: ProviderMetadataRequest) -> ProviderReadResult:
		if self._rawUia.owns(request.nodeRef):
			return self._rawUia.readMetadata(request)
		if request.metadataId != PROVIDER_SECTIONS_METADATA_ID:
			return ProviderReadResult("unsupported")
		try:
			target = self._target(request.nodeRef, request.context)
		except LookupError:
			return ProviderReadResult("stale", errorCode="KS.PROVIDER.UNKNOWN_NODE_REF")
		except RuntimeError as error:
			return ProviderReadResult("stale", errorCode=str(error))
		sections: list[ProviderSectionData] = []
		for sectionId, collect in (
			("generic", self._common.collect),
			("uia", self._uia.collect),
			("ia2Msaa", self._ia2Msaa.collect),
			("jab", self._jab.collect),
			("overlay", self._overlay.collect),
		):
			try:
				sections.append(collect(target, request.budget))
			except AssertionError:
				raise
			except Exception:
				sections.append(self._failedSection(sectionId))
		if self._customUia is not None:
			try:
				process = self._common.readField(target, "process", request.budget)
				processId = process.value if process.status == "value" and type(process.value) is int else 0
				protection = self._common.readField(target, "protection", request.budget)
				protectionEvidence = (
					ProtectionEvidence(True)
					if protection.status == "value" and protection.value is True
					else ProtectionEvidence.allClear()
					if protection.status == "value" and protection.value is False
					else ProtectionEvidence()
				)
				sections.append(
					self._customUia.collectCustomUia(
						target,
						mode=self._customUiaCaptureMode,
						captureSessionId=f"inspector-{self._generation}-{request.nodeRef}",
						providerProcessId=processId,
						budget=CustomUiaBudget.defaults(),
						privacyPolicy=self._privacyPolicy,
						protection=protectionEvidence,
					),
				)
			except AssertionError:
				raise
			except Exception:
				sections.append(self._failedSection("customUia"))
		fallback = self._fallbackProjection.get(request.nodeRef)
		if fallback is not None:
			sections.append(
				ProviderSectionData(
					"rawUia",
					ProviderReadResult("value", "rawUia"),
					(),
					(
						ProviderDatum(
							"projection",
							ProviderReadResult("value", _fallbackProjectionPlain(fallback)),
						),
					),
				),
			)
		try:
			return ProviderReadResult("value", encodeProviderSections(tuple(sections)))
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.SECTIONS_MALFORMED")

	def compareIdentity(self, request: IdentityComparisonRequest) -> IdentityComparisonResult:
		try:
			self._assertContext(request.context)
		except RuntimeError as error:
			return IdentityComparisonResult("stale", "failed", (), str(error))
		firstRaw = self._rawUia.owns(request.firstNodeRef)
		secondRaw = self._rawUia.owns(request.secondNodeRef)
		if firstRaw and secondRaw:
			return self._rawUia.compareIdentity(request)
		if firstRaw or secondRaw:
			return IdentityComparisonResult(
				"value",
				"conflict",
				(("providerScope", "mixed"),),
			)
		try:
			first = self._target(request.firstNodeRef, request.context)
			second = self._target(request.secondNodeRef, request.context)
		except LookupError:
			return IdentityComparisonResult(
				"stale",
				"failed",
				(),
				"KS.PROVIDER.UNKNOWN_NODE_REF",
			)
		except RuntimeError as error:
			return IdentityComparisonResult("stale", "failed", (), str(error))
		identity, matches = _accessibleIdentityComparison(first, second)
		return IdentityComparisonResult(
			"value",
			"same" if matches else "different",
			((identity, matches),),
		)

	def releaseResource(self, request: ResourceReleaseRequest) -> ReleaseResult:
		try:
			self._assertContext(request.context)
		except RuntimeError as error:
			return ReleaseResult("stale", str(error))
		return ReleaseResult("alreadyReleased")

	def closeSession(self, request: ProviderSessionCloseRequest) -> ReleaseResult:
		if self._closed:
			return ReleaseResult("alreadyReleased")
		try:
			self._assertContext(request.context)
		except RuntimeError as error:
			return ReleaseResult("stale", str(error))
		self.close()
		return ReleaseResult("released")

	def close(self) -> None:
		"""Release every retained object on the session's owner thread."""

		if self._closed:
			return
		self._assertOwner()
		self._rawUia.close()
		self._objects.clear()
		self._refsByIdentity.clear()
		self._fallbackProjection.clear()
		self._closed = True


def _readBudget() -> ReadBudget:
	return ReadBudget(64, 4_096, 250)
