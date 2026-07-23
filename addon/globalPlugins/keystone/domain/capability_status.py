from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CapabilityStatus(StrEnum):
	ENABLED = "enabled"
	UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
	capabilityId: str


CAPABILITY_REGISTRY = (
	CapabilityDefinition("nvdaCompatibility"),
	CapabilityDefinition("providerThreadAffinity"),
	CapabilityDefinition("providerStallProtection"),
	CapabilityDefinition("uiaInspection"),
	CapabilityDefinition("ia2Inspection"),
	CapabilityDefinition("javaAccessBridgeInspection"),
	CapabilityDefinition("officeInspection"),
	CapabilityDefinition("overlayPreservation"),
	CapabilityDefinition("rawUiaInspection"),
	CapabilityDefinition("userInterface"),
	CapabilityDefinition("eventMonitoring"),
	CapabilityDefinition("captureStorage"),
	CapabilityDefinition("screenCapture"),
	CapabilityDefinition("offlineAnalysis"),
	CapabilityDefinition("audioFeedback"),
)
_CAPABILITY_IDS = tuple(definition.capabilityId for definition in CAPABILITY_REGISTRY)


@dataclass(frozen=True, slots=True)
class CapabilityRow:
	capabilityId: str
	status: CapabilityStatus
	reason: str

	def __post_init__(self) -> None:
		if self.capabilityId not in _CAPABILITY_IDS:
			raise ValueError(f"unknown capability {self.capabilityId!r}")
		object.__setattr__(self, "status", CapabilityStatus(self.status))
		if not self.reason or self.reason.strip() != self.reason:
			raise ValueError("capability reason must be nonblank trimmed text")


@dataclass(frozen=True, slots=True)
class CapabilitySnapshot:
	rows: tuple[CapabilityRow, ...]

	def __post_init__(self) -> None:
		if tuple(row.capabilityId for row in self.rows) != _CAPABILITY_IDS:
			raise ValueError("capability snapshot must contain the complete ordered registry")

	def row(self, capabilityId: str) -> CapabilityRow:
		for row in self.rows:
			if row.capabilityId == capabilityId:
				return row
		raise ValueError(f"unknown capability {capabilityId!r}")
