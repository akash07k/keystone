from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ...ports.providers import ProviderReadResult, ReadBudget
from .common import ProviderDatum, ProviderSectionData, normalizeProviderRead


_IA2_FIELDS: tuple[tuple[str, str], ...] = (
	("attributes", "IA2Attributes"),
	("rawRole", "IAccessibleRole"),
	("rawStates", "IAccessibleStates"),
)

_IA2_INTERFACE_MEMBERS = frozenset(
	{
		"IAccessibleActionObject",
		"IAccessibleTable2Object",
		"IAccessibleTableObject",
		"IAccessibleTextObject",
	},
)

_ALLOWED_IA2_MEMBERS = frozenset(
	{
		"IA2UniqueID",
		"windowHandle",
		"IAccessibleChildID",
		"event_windowHandle",
		"event_objectID",
		"event_childID",
		*_IA2_INTERFACE_MEMBERS,
		*(native for _field, native in _IA2_FIELDS),
	},
)


@dataclass(frozen=True, slots=True)
class OwnedProviderRead:
	result: ProviderReadResult
	resourceToken: object | None = None


class Ia2MsaaGetterPort(Protocol):
	def acquire(self, target: object) -> ProviderReadResult: ...

	def supportsIa2(self, target: object) -> bool: ...

	def read(self, target: object, member: str, budget: ReadBudget) -> OwnedProviderRead: ...

	def releaseResource(self, resourceToken: object) -> None: ...


class NvdaIa2MsaaGetter:
	"""Reads only interfaces and metadata already materialized by NVDA."""

	@staticmethod
	def acquire(target: object) -> ProviderReadResult:
		if "IAccessible" not in {item.__name__ for item in type(target).__mro__}:
			return ProviderReadResult("unsupported")
		return ProviderReadResult("value", "selectedIAccessible")

	@staticmethod
	def supportsIa2(target: object) -> bool:
		try:
			return target.__getattribute__("IA2UniqueID") is not None
		except Exception:
			return False

	@staticmethod
	def read(target: object, member: str, budget: ReadBudget) -> OwnedProviderRead:
		if member not in _ALLOWED_IA2_MEMBERS:
			return OwnedProviderRead(ProviderReadResult("unsupported"))
		try:
			value = target.__getattribute__(member)
		except (AttributeError, NotImplementedError):
			return OwnedProviderRead(ProviderReadResult("unsupported"))
		except Exception:
			return OwnedProviderRead(
				ProviderReadResult("failed", errorCode="KS.PROVIDER.IA2_FIELD_FAILED"),
			)
		if member in _IA2_INTERFACE_MEMBERS:
			return OwnedProviderRead(ProviderReadResult("value", value is not None))
		try:
			result = normalizeProviderRead(value, budget)
		except (TypeError, ValueError):
			return OwnedProviderRead(ProviderReadResult("unsupported"))
		return OwnedProviderRead(result)

	@staticmethod
	def releaseResource(resourceToken: object) -> None:
		_ = resourceToken
		return None


class Ia2MsaaProviderAdapter:
	def __init__(self, getter: Ia2MsaaGetterPort) -> None:
		super().__init__()
		self._getter = getter

	def _read(self, target: object, member: str, budget: ReadBudget) -> ProviderReadResult:
		owned = self._getter.read(target, member, budget)
		try:
			return owned.result
		finally:
			if owned.resourceToken is not None:
				self._getter.releaseResource(owned.resourceToken)

	def collect(self, target: object, budget: ReadBudget) -> ProviderSectionData:
		acquired = self._getter.acquire(target)
		if acquired.status != "value":
			return ProviderSectionData(
				"ia2Msaa",
				ProviderReadResult(acquired.status, errorCode=acquired.errorCode),
			)
		isIa2 = self._getter.supportsIa2(target)
		identityMembers = (
			(("ia2WindowHandle", "windowHandle"), ("ia2UniqueId", "IA2UniqueID"))
			if isIa2
			else (
				("msaaParentWindow", "event_windowHandle"),
				("msaaObjectId", "event_objectID"),
				("msaaChildId", "event_childID"),
			)
		)
		identity = tuple(
			ProviderDatum(fieldId, self._read(target, member, budget)) for fieldId, member in identityMembers
		)
		properties: list[ProviderDatum] = [
			ProviderDatum("ia2Available", ProviderReadResult("value", isIa2)),
		]
		if isIa2:
			properties.extend(
				ProviderDatum(fieldId, self._read(target, member, budget)) for fieldId, member in _IA2_FIELDS
			)
			properties.extend(
				ProviderDatum(fieldId, self._read(target, member, budget))
				for fieldId, member in (
					("actionInterface", "IAccessibleActionObject"),
					("table2Interface", "IAccessibleTable2Object"),
					("tableInterface", "IAccessibleTableObject"),
					("textInterface", "IAccessibleTextObject"),
				)
			)
		return ProviderSectionData(
			"ia2Msaa",
			ProviderReadResult("value", "ia2" if isIa2 else "msaaOnly"),
			identity,
			tuple(properties),
		)
