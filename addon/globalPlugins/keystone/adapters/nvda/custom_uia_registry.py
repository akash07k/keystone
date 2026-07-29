from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Protocol, cast

from ...domain.custom_uia import CustomUiaConfiguration, CustomUiaProperty, validateConfiguration


class NativePropertyRegistrar(Protocol):
	def isAvailable(self) -> bool: ...

	def registerProperty(self, guidBytes: bytes, name: str, propertyType: int) -> int: ...


@dataclass(frozen=True, slots=True)
class RegistrationStatus:
	stableKey: str
	canonicalGuid: str
	ordinal: int
	status: str
	runtimeId: int | None = None
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("registered", "failed", "unavailable", "disabled"):
			raise ValueError("unknown custom UIA registration status")
		if self.status == "registered" and (self.runtimeId is None or self.runtimeId <= 0 or self.errorCode):
			raise ValueError("successful custom UIA registration status is inconsistent")
		if self.status != "registered" and self.runtimeId is not None:
			raise ValueError("unsuccessful custom UIA registration cannot expose a runtime ID")


class NvdaNativePropertyRegistrar:
	"""Thin lazy adapter over NVDA's process-local native UIA registrar."""

	def isAvailable(self) -> bool:
		try:
			uiaHandler = import_module("UIAHandler")
			nvdaHelper = import_module("NVDAHelper")
		except ImportError:
			return False
		return getattr(uiaHandler, "handler", None) is not None and callable(
			getattr(getattr(nvdaHelper, "localLib", None), "registerUIAProperty", None),
		)

	def registerProperty(self, guidBytes: bytes, name: str, propertyType: int) -> int:
		if len(guidBytes) != 16:
			raise ValueError("custom UIA GUID must contain exactly 16 canonical bytes")
		comtypes = import_module("comtypes")
		nvdaHelper = import_module("NVDAHelper")
		guid = comtypes.GUID.from_buffer_copy(guidBytes)
		byref = getattr(comtypes, "byref")
		register = getattr(nvdaHelper.localLib, "registerUIAProperty")
		return int(register(byref(guid), name, propertyType))


class CustomUiaRegistry:
	def __init__(self, registrar: NativePropertyRegistrar) -> None:
		super().__init__()
		self._registrar = registrar
		self._byGuid: dict[str, tuple[CustomUiaProperty, RegistrationStatus]] = {}
		self._statuses: tuple[RegistrationStatus, ...] = ()
		self._started = False

	@property
	def statuses(self) -> tuple[RegistrationStatus, ...]:
		return self._statuses

	@property
	def registeredProperties(self) -> tuple[tuple[CustomUiaProperty, RegistrationStatus], ...]:
		return tuple(
			sorted(
				self._byGuid.values(),
				key=lambda item: (item[0].identityBytes, item[0].stableKey),
			),
		)

	def register(self, configuration: CustomUiaConfiguration) -> tuple[RegistrationStatus, ...]:
		validation = validateConfiguration(configuration)
		if not validation.isValid or validation.configuration is None:
			raise ValueError("only a wholly validated custom UIA configuration may register")
		if self._started:
			return self._statuses
		ordered = tuple(
			sorted(
				validation.configuration.properties,
				key=lambda property: (property.identityBytes, property.stableKey),
			),
		)
		available = self._registrar.isAvailable()
		self._started = True
		statuses: list[RegistrationStatus] = []
		for ordinal, property in enumerate(ordered, start=1):
			if not property.enabled:
				statuses.append(
					RegistrationStatus(
						property.stableKey,
						property.canonicalGuid,
						ordinal,
						"disabled",
						errorCode="disabledByConfiguration",
					),
				)
				continue
			existing = self._byGuid.get(property.canonicalGuid)
			if existing is not None:
				existingProperty, existingStatus = existing
				if existingProperty != property:
					raise RuntimeError("validated custom UIA registry metadata drifted")
				statuses.append(
					RegistrationStatus(
						existingStatus.stableKey,
						existingStatus.canonicalGuid,
						ordinal,
						existingStatus.status,
						existingStatus.runtimeId,
						existingStatus.errorCode,
					),
				)
				continue
			if not available:
				status = RegistrationStatus(
					property.stableKey,
					property.canonicalGuid,
					ordinal,
					"unavailable",
					errorCode="nativeRegistrationUnavailable",
				)
			else:
				try:
					runtimeId = self._registrar.registerProperty(
						property.guidBytes,
						property.name,
						property.typeCode,
					)
				except Exception:
					status = RegistrationStatus(
						property.stableKey,
						property.canonicalGuid,
						ordinal,
						"failed",
						errorCode="registrationFailed",
					)
				else:
					status = (
						RegistrationStatus(
							property.stableKey,
							property.canonicalGuid,
							ordinal,
							"registered",
							runtimeId=runtimeId,
						)
						if runtimeId > 0
						else RegistrationStatus(
							property.stableKey,
							property.canonicalGuid,
							ordinal,
							"failed",
							errorCode="idZero",
						)
					)
			self._byGuid[property.canonicalGuid] = (property, status)
			statuses.append(status)
		self._statuses = tuple(statuses)
		return self._statuses


_processRegistry: CustomUiaRegistry | None = None


def buildNvdaCustomUiaRegistry() -> CustomUiaRegistry:
	global _processRegistry
	if _processRegistry is None:
		_processRegistry = CustomUiaRegistry(cast(NativePropertyRegistrar, NvdaNativePropertyRegistrar()))
	return _processRegistry
