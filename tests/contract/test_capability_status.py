from __future__ import annotations

from dataclasses import fields
from typing import Any
import unittest

from addon.globalPlugins.keystone.domain import capability_status as statusModule

_status: Any = statusModule


class CapabilityStatusTests(unittest.TestCase):
	def test_status_model_contains_only_runtime_identity_status_and_reason(self) -> None:
		unavailableStatus = getattr(_status.CapabilityStatus, "UNAVAILABLE", None)
		self.assertIsNotNone(unavailableStatus)
		unavailable = _status.CapabilityRow(
			"eventMonitoring",
			unavailableStatus,
			"Requires an active NVDA UIA handler.",
		)

		self.assertEqual(
			("capabilityId", "status", "reason"),
			tuple(field.name for field in fields(_status.CapabilityRow)),
		)
		self.assertEqual("eventMonitoring", unavailable.capabilityId)
		self.assertEqual("unavailable", unavailable.status.value)
		self.assertEqual("Requires an active NVDA UIA handler.", unavailable.reason)

	def test_snapshot_requires_the_complete_ordered_runtime_registry(self) -> None:
		rows = tuple(
			_status.CapabilityRow(
				definition.capabilityId,
				_status.CapabilityStatus.ENABLED,
				"Available.",
			)
			for definition in _status.CAPABILITY_REGISTRY
		)

		snapshot = _status.CapabilitySnapshot(rows)

		self.assertEqual(rows, snapshot.rows)
		with self.assertRaisesRegex(ValueError, "complete ordered registry"):
			_ = _status.CapabilitySnapshot(rows[:-1])

	def test_rows_reject_unknown_identity_and_blank_reason(self) -> None:
		unavailableStatus = getattr(_status.CapabilityStatus, "UNAVAILABLE", None)
		self.assertIsNotNone(unavailableStatus)
		with self.assertRaisesRegex(ValueError, "unknown capability"):
			_ = _status.CapabilityRow(
				"not-a-capability",
				unavailableStatus,
				"Unavailable.",
			)
		with self.assertRaisesRegex(ValueError, "reason"):
			_ = _status.CapabilityRow(
				"eventMonitoring",
				unavailableStatus,
				"",
			)


if __name__ == "__main__":
	_ = unittest.main()
