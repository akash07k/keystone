from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ...ports.providers import ProviderReadResult, ReadBudget
from .common import ProviderDatum, ProviderSectionData, normalizeProviderRead


@dataclass(frozen=True, slots=True)
class OwnedJabRead:
	result: ProviderReadResult
	resourceToken: object | None = None


class JabGetterPort(Protocol):
	def acquire(self, target: object) -> ProviderReadResult: ...

	def read(self, target: object, fieldId: str, budget: ReadBudget) -> OwnedJabRead: ...

	def releaseResource(self, resourceToken: object) -> None: ...


class NvdaJabGetter:
	"""Reads the selected object's existing JAB context and cached capability info."""

	@staticmethod
	def acquire(target: object) -> ProviderReadResult:
		if "JAB" not in {item.__name__ for item in type(target).__mro__}:
			return ProviderReadResult("unsupported")
		try:
			_ = target.__getattribute__("jabContext")
		except (AttributeError, NotImplementedError):
			return ProviderReadResult("unsupported")
		except Exception:
			return ProviderReadResult("failed", errorCode="KS.PROVIDER.JAB_ACQUIRE_FAILED")
		return ProviderReadResult("value", "selectedJabContext")

	@staticmethod
	def _nested(target: object, fieldId: str) -> object:
		if fieldId == "vmId":
			context = target.__getattribute__("jabContext")
			return context.__getattribute__("vmID")
		info = target.__getattribute__("_JABAccContextInfo")
		mapping = {
			"rawRole": "role_en_US",
			"rawStates": "states_en_US",
			"componentCapable": "accessibleComponent",
			"actionCapable": "accessibleAction",
			"selectionCapable": "accessibleSelection",
			"textCapable": "accessibleText",
			"valueCapable": "accessibleValue",
		}
		member = mapping.get(fieldId)
		if member is None:
			raise AttributeError(fieldId)
		return info.__getattribute__(member)

	@classmethod
	def read(cls, target: object, fieldId: str, budget: ReadBudget) -> OwnedJabRead:
		try:
			value = cls._nested(target, fieldId)
		except (AttributeError, NotImplementedError):
			return OwnedJabRead(ProviderReadResult("unsupported"))
		except Exception:
			return OwnedJabRead(
				ProviderReadResult("failed", errorCode="KS.PROVIDER.JAB_FIELD_FAILED"),
			)
		if (
			fieldId
			in {
				"componentCapable",
				"actionCapable",
				"selectionCapable",
				"textCapable",
				"valueCapable",
			}
			and type(value) is int
		):
			value = bool(value)
		try:
			result = normalizeProviderRead(value, budget)
		except (TypeError, ValueError):
			return OwnedJabRead(ProviderReadResult("unsupported"))
		return OwnedJabRead(result)

	@staticmethod
	def releaseResource(resourceToken: object) -> None:
		_ = resourceToken
		return None


class JabProviderAdapter:
	def __init__(self, getter: JabGetterPort) -> None:
		super().__init__()
		self._getter = getter

	def _read(self, target: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		owned = self._getter.read(target, fieldId, budget)
		try:
			return owned.result
		finally:
			if owned.resourceToken is not None:
				self._getter.releaseResource(owned.resourceToken)

	def collect(self, target: object, budget: ReadBudget) -> ProviderSectionData:
		acquired = self._getter.acquire(target)
		if acquired.status != "value":
			return ProviderSectionData(
				"jab",
				ProviderReadResult(acquired.status, errorCode=acquired.errorCode),
			)
		identity = (ProviderDatum("jabVmId", self._read(target, "vmId", budget)),)
		properties: list[ProviderDatum] = [
			ProviderDatum(fieldId, self._read(target, fieldId, budget))
			for fieldId in (
				"rawRole",
				"rawStates",
				"componentCapable",
				"actionCapable",
				"selectionCapable",
				"textCapable",
				"valueCapable",
			)
		]
		capabilities = {item.fieldId: item.result for item in properties}
		for fieldId, flag in (
			("component", "componentCapable"),
			("actions", "actionCapable"),
			("selection", "selectionCapable"),
			("text", "textCapable"),
			("value", "valueCapable"),
		):
			flagResult = capabilities[flag]
			properties.append(
				ProviderDatum(
					fieldId,
					ProviderReadResult("unsupported")
					if flagResult.status != "value" or flagResult.value is not True
					else ProviderReadResult("value", ("capabilityConfirmed",)),
				),
			)
		return ProviderSectionData(
			"jab",
			ProviderReadResult("value", "available"),
			identity,
			tuple(properties),
		)
