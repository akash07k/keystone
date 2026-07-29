from __future__ import annotations

from typing import Protocol

from ...ports.providers import ProviderReadResult, ReadBudget
from .common import ProviderDatum, ProviderSectionData, normalizeProviderRead, readClassHierarchy


class OverlayGetterPort(Protocol):
	def read(self, target: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult: ...


class NvdaOverlayGetter:
	"""Projects only metadata already materialized on the selected NVDA overlay."""

	@staticmethod
	def read(target: object, fieldId: str, budget: ReadBudget) -> ProviderReadResult:
		if fieldId == "overlayClasses":
			return readClassHierarchy(target, budget)
		if fieldId == "logicalApplication":
			try:
				appModule = target.__getattribute__("appModule")
				value = appModule.__getattribute__("appName")
			except (AttributeError, NotImplementedError):
				return ProviderReadResult("unsupported")
			except Exception:
				return ProviderReadResult("failed", errorCode="KS.PROVIDER.OVERLAY_APP_FAILED")
		else:
			member = {
				"windowClass": "windowClassName",
				"presentationType": "presentationType",
				"shapeType": "shapeType",
			}.get(fieldId)
			if member is None:
				return ProviderReadResult("unsupported")
			try:
				value = target.__getattribute__(member)
			except (AttributeError, NotImplementedError):
				return ProviderReadResult("unsupported")
			except Exception:
				return ProviderReadResult("failed", errorCode="KS.PROVIDER.OVERLAY_FIELD_FAILED")
		try:
			return normalizeProviderRead(value, budget)
		except (TypeError, ValueError):
			return ProviderReadResult("unsupported")


class OverlayProviderAdapter:
	def __init__(self, getter: OverlayGetterPort) -> None:
		super().__init__()
		self._getter = getter

	def collect(self, target: object, budget: ReadBudget) -> ProviderSectionData:
		classes = self._getter.read(target, "overlayClasses", budget)
		if classes.status != "value":
			return ProviderSectionData(
				"overlay",
				ProviderReadResult(classes.status, errorCode=classes.errorCode),
			)
		properties = tuple(
			ProviderDatum(fieldId, self._getter.read(target, fieldId, budget))
			for fieldId in ("logicalApplication", "windowClass", "presentationType", "shapeType")
		)
		return ProviderSectionData(
			"overlay",
			ProviderReadResult("value", "selectedObject"),
			(ProviderDatum("overlayClasses", classes),),
			properties,
		)
