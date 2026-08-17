from __future__ import annotations

import unittest

from addon.globalPlugins.keystone.adapters.export_names import defaultExportFilename


class DefaultExportFilenameTests(unittest.TestCase):
	def test_uses_the_single_application_executable_stem(self) -> None:
		self.assertEqual(
			"notepad-keystone-events.json",
			defaultExportFilename("notepad.exe", "events", ".json"),
		)

	def test_uses_the_existing_generic_name_without_an_application(self) -> None:
		self.assertEqual(
			"keystone-hierarchy.txt",
			defaultExportFilename(None, "hierarchy", ".txt"),
		)

	def test_sanitizes_a_windows_executable_path(self) -> None:
		self.assertEqual(
			"notepad-keystone-custom-uia.json",
			defaultExportFilename(r"C:\Windows\System32\notepad.exe", "custom-uia", ".json"),
		)

	def test_does_not_use_unknown_as_an_application_name(self) -> None:
		self.assertEqual(
			"keystone-events.json",
			defaultExportFilename("unknown.exe", "events", ".json"),
		)

	def test_includes_a_windows_safe_selected_subject_when_provided(self) -> None:
		self.assertEqual(
			"Display-adapters-reader-keystone-current-inspector-data.json",
			defaultExportFilename(
				"reader.exe",
				"current-inspector-data",
				".json",
				subject="Display/adapters",
			),
		)
