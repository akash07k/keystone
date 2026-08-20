from __future__ import annotations

from datetime import datetime
import unittest

from addon.globalPlugins.keystone.adapters.windows.path_ops import (
	applicationDirectoryName,
	captureDirectoryName,
	fixedOutputRoot,
	sanitizeComponent,
	snapshotOutputRoot,
)


class TestDeterministicPathNames(unittest.TestCase):
	def test_fixed_root_uses_only_absolute_temp_location(self) -> None:
		environment = {"TEMP": r"C:\Users\Tester\AppData\Local\Temp"}
		root = fixedOutputRoot(environment)
		extendedRoot = fixedOutputRoot({"TEMP": r"\\?\C:\Users\Tester\AppData\Local\Temp"})

		self.assertEqual(r"C:\Users\Tester\AppData\Local\Temp\Keystone", str(root))
		self.assertEqual(
			r"\\?\C:\Users\Tester\AppData\Local\Temp\Keystone",
			str(extendedRoot),
		)
		self.assertEqual(root / "snapshots", snapshotOutputRoot(environment))
		for environment in (
			{},
			{"TEMP": "relative"},
			{"TEMP": r"\\server\share"},
			{"TEMP": r"\\?\UNC\server\share\Temp"},
			{"TEMP": r"\\.\C:\Temp"},
		):
			with self.subTest(environment=environment):
				with self.assertRaises(ValueError):
					_ = fixedOutputRoot(environment)

	def test_component_sanitization_is_normalized_bounded_and_windows_safe(self) -> None:
		cases = {
			"": "unknown",
			"   ": "unknown",
			'bad<>:"/\\|?*name': "bad_________name",
			"trail. ": "trail",
			"CON": "_CON",
			"com1.txt": "_com1.txt",
			"e\u0301": "\u00e9",
			"control\u0001name": "control_name",
		}

		for source, expected in cases.items():
			with self.subTest(source=source):
				self.assertEqual(expected, sanitizeComponent(source))
		self.assertEqual("abcdefgh", sanitizeComponent("abcdefghijk", maximumLength=8))
		with self.assertRaises(ValueError):
			_ = sanitizeComponent("name", maximumLength=0)

	def test_application_and_capture_names_are_sortable_and_collision_safe(self) -> None:
		self.assertEqual("reader.exe-42", applicationDirectoryName("reader.exe", 42))
		self.assertEqual("unknown-0", applicationDirectoryName("", 0))
		capturedAt = datetime(2026, 7, 24, 9, 8, 7, 654321)

		self.assertEqual(
			"20260724-090807.654-snapshot",
			captureDirectoryName(capturedAt, "snapshot"),
		)
		self.assertEqual(
			"20260724-090807.654-snapshot-02",
			captureDirectoryName(capturedAt, "snapshot", collisionIndex=2),
		)
		self.assertEqual(
			"Display_adapters-20260724-090807.654-snapshot-02",
			captureDirectoryName(
				capturedAt,
				"snapshot",
				subject="Display/adapters",
				collisionIndex=2,
			),
		)
		with self.assertRaises(ValueError):
			_ = captureDirectoryName(capturedAt, "snapshot", collisionIndex=1)


if __name__ == "__main__":
	_ = unittest.main()
