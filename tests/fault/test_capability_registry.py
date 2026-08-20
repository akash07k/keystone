from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
import unittest

from addon.globalPlugins.keystone.adapters.windows import capability_registry as registryModule
from addon.globalPlugins.keystone.domain.capability_status import CapabilityStatus

_UNAVAILABLE = getattr(CapabilityStatus, "UNAVAILABLE", None)


def _checks(
	*,
	secure: Callable[[], bool] = lambda: False,
	uia: Callable[[], bool] = lambda: True,
	userInterface: Callable[[], bool] = lambda: True,
	output: Callable[[], bool] = lambda: True,
	sound: Callable[[], bool] = lambda: True,
	screenshot: Callable[[], bool] = lambda: True,
) -> Any:
	checkType = getattr(registryModule, "RuntimeCapabilityChecks", None)
	if checkType is None:
		return None
	return checkType(
		secureDesktop=secure,
		uiaHandlerAvailable=uia,
		userInterfaceAvailable=userInterface,
		outputDirectoryWritable=output,
		soundPlaybackAvailable=sound,
		screenshotAvailable=screenshot,
	)


def _statuses(snapshot: Any) -> dict[str, CapabilityStatus]:
	return {row.capabilityId: row.status for row in snapshot.rows}


class CapabilityRegistryTests(unittest.TestCase):
	def test_event_monitoring_uses_live_secure_and_uia_prerequisites(self) -> None:
		loaderType = cast(Any, getattr(registryModule, "CapabilityStatusLoader", None))
		self.assertIsNotNone(loaderType)

		available = loaderType(_checks()).load()
		withoutUia = loaderType(_checks(uia=lambda: False)).load()
		onSecureDesktop = loaderType(_checks(secure=lambda: True)).load()

		self.assertEqual(CapabilityStatus.ENABLED, _statuses(available)["eventMonitoring"])
		self.assertIsNotNone(_UNAVAILABLE)
		self.assertEqual(_UNAVAILABLE, _statuses(withoutUia)["eventMonitoring"])
		self.assertEqual(
			"Requires an active NVDA UIA handler.",
			next(row.reason for row in withoutUia.rows if row.capabilityId == "eventMonitoring"),
		)
		self.assertEqual(
			{_UNAVAILABLE},
			set(_statuses(onSecureDesktop).values()),
		)

	def test_each_remaining_runtime_check_affects_only_its_capabilities(self) -> None:
		loaderType = cast(Any, getattr(registryModule, "CapabilityStatusLoader", None))
		self.assertIsNotNone(loaderType)
		cases = (
			("uia", _checks(uia=lambda: False), {"uiaInspection", "rawUiaInspection", "eventMonitoring"}),
			("user interface", _checks(userInterface=lambda: False), {"userInterface"}),
			("output", _checks(output=lambda: False), {"captureStorage"}),
			("sound", _checks(sound=lambda: False), {"audioFeedback"}),
			("screenshot", _checks(screenshot=lambda: False), {"screenCapture"}),
		)
		for label, checks, expectedUnavailable in cases:
			with self.subTest(label=label):
				statuses = _statuses(loaderType(checks).load())
				self.assertEqual(
					expectedUnavailable,
					{capabilityId for capabilityId, status in statuses.items() if status is _UNAVAILABLE},
				)

	def test_prerequisite_exception_fails_only_the_affected_capability_group_closed(self) -> None:
		def failedCheck() -> bool:
			raise OSError("runtime check failed")

		loaderType = cast(Any, getattr(registryModule, "CapabilityStatusLoader", None))
		self.assertIsNotNone(loaderType)
		snapshot = loaderType(_checks(output=failedCheck)).load()

		self.assertEqual(
			{"captureStorage"},
			{row.capabilityId for row in snapshot.rows if row.status is _UNAVAILABLE},
		)
		self.assertEqual(
			{"Runtime availability check failed."},
			{row.reason for row in snapshot.rows if row.status is _UNAVAILABLE},
		)

	def test_registry_performs_no_installed_directory_or_status_file_work(self) -> None:
		source = Path(registryModule.__file__).read_text(encoding="utf-8")

		for removed in (
			"hashlib",
			"capability-status.v1.json",
		):
			with self.subTest(removed=removed):
				self.assertNotIn(removed, source)


if __name__ == "__main__":
	_ = unittest.main()
