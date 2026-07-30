from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ...domain.capability_status import (
	CAPABILITY_REGISTRY,
	CapabilityRow,
	CapabilitySnapshot,
	CapabilityStatus,
)


RuntimeCheck = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class RuntimeCapabilityChecks:
	secureDesktop: RuntimeCheck
	uiaHandlerAvailable: RuntimeCheck
	userInterfaceAvailable: RuntimeCheck
	outputDirectoryWritable: RuntimeCheck
	soundPlaybackAvailable: RuntimeCheck
	screenshotAvailable: RuntimeCheck


_UIA_CAPABILITIES = frozenset(("uiaInspection", "rawUiaInspection", "eventMonitoring"))
_OUTPUT_CAPABILITIES = frozenset(("captureStorage",))


def _checked(check: RuntimeCheck) -> tuple[bool, bool]:
	try:
		return bool(check()), False
	except Exception:
		return False, True


class CapabilityStatusLoader:
	def __init__(self, checks: RuntimeCapabilityChecks) -> None:
		super().__init__()
		self._checks = checks

	def load(self) -> CapabilitySnapshot:
		secureDesktop, secureCheckFailed = _checked(self._checks.secureDesktop)
		if secureCheckFailed:
			return self._allUnavailable("Runtime availability check failed.")
		if secureDesktop:
			return self._allUnavailable("Unavailable on the secure desktop.")

		checkResults = {
			"uia": _checked(self._checks.uiaHandlerAvailable),
			"userInterface": _checked(self._checks.userInterfaceAvailable),
			"output": _checked(self._checks.outputDirectoryWritable),
			"sound": _checked(self._checks.soundPlaybackAvailable),
			"screenshot": _checked(self._checks.screenshotAvailable),
		}
		rows = tuple(self._row(definition.capabilityId, checkResults) for definition in CAPABILITY_REGISTRY)
		return CapabilitySnapshot(rows)

	def _row(
		self,
		capabilityId: str,
		checkResults: dict[str, tuple[bool, bool]],
	) -> CapabilityRow:
		if capabilityId in _UIA_CAPABILITIES:
			return self._fromCheck(
				capabilityId,
				checkResults["uia"],
				"Requires an active NVDA UIA handler.",
			)
		if capabilityId == "userInterface":
			return self._fromCheck(
				capabilityId,
				checkResults["userInterface"],
				"Requires the NVDA settings interface.",
			)
		if capabilityId in _OUTPUT_CAPABILITIES:
			return self._fromCheck(
				capabilityId,
				checkResults["output"],
				"Requires a writable Keystone output directory.",
			)
		if capabilityId == "audioFeedback":
			return self._fromCheck(
				capabilityId,
				checkResults["sound"],
				"Requires the bundled sound theme and NVDA audio output.",
			)
		if capabilityId == "screenCapture":
			return self._fromCheck(
				capabilityId,
				checkResults["screenshot"],
				"Requires the NVDA graphical interface.",
			)
		return CapabilityRow(capabilityId, CapabilityStatus.ENABLED, "Available.")

	@staticmethod
	def _fromCheck(
		capabilityId: str,
		result: tuple[bool, bool],
		unavailableReason: str,
	) -> CapabilityRow:
		available, failed = result
		if available:
			return CapabilityRow(capabilityId, CapabilityStatus.ENABLED, "Available.")
		reason = "Runtime availability check failed." if failed else unavailableReason
		return CapabilityRow(capabilityId, CapabilityStatus.UNAVAILABLE, reason)

	@staticmethod
	def _allUnavailable(reason: str) -> CapabilitySnapshot:
		return CapabilitySnapshot(
			tuple(
				CapabilityRow(
					definition.capabilityId,
					CapabilityStatus.UNAVAILABLE,
					reason,
				)
				for definition in CAPABILITY_REGISTRY
			),
		)
