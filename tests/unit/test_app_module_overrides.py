from __future__ import annotations

import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda.app_module_overrides import (
	NvdaAppModuleOverrides,
)


class AppModuleOverrideTests(unittest.TestCase):
	def test_packaged_override_module_explicitly_selects_uia(self) -> None:
		class _BaseAppModule:
			pass

		path = Path(__file__).parents[2] / "addon" / "appModules" / "keystone_uia_override.py"
		with patch.dict(sys.modules, {"appModuleHandler": SimpleNamespace(AppModule=_BaseAppModule)}):
			namespace = runpy.run_path(str(path))

		override = namespace["AppModule"]
		self.assertTrue(override.isGoodUIAWindow(object(), 123))

	def test_enabling_persists_registers_and_reloads_the_selected_executable(self) -> None:
		with tempfile.TemporaryDirectory() as temporary:
			root = Path(temporary)
			registered: list[tuple[str, str]] = []
			reloads: list[bool] = []

			def register(executable: str, module: str) -> None:
				registered.append((executable, module))

			def unregister(_executable: str) -> None:
				pass

			def reload() -> None:
				reloads.append(True)

			handler = SimpleNamespace(
				registerExecutableWithAppModule=register,
				unregisterExecutable=unregister,
				reloadAppModules=reload,
			)
			overrides = NvdaAppModuleOverrides(root)
			with patch(
				"addon.globalPlugins.keystone.adapters.nvda.app_module_overrides.import_module",
				return_value=handler,
			):
				result = overrides.setEnabled("PowerPnt.exe", True)

			self.assertTrue(result.succeeded)
			self.assertEqual([("powerpnt", "keystone_uia_override")], registered)
			self.assertEqual([True], reloads)
			self.assertTrue(overrides.state("powerpnt.exe").enabled)
			document = json.loads(overrides.storagePath.read_text(encoding="utf-8"))
			self.assertEqual({"version": 1, "applications": ["powerpnt"]}, document)

	def test_disabling_unregisters_and_reloads_the_selected_executable(self) -> None:
		with tempfile.TemporaryDirectory() as temporary:
			root = Path(temporary)
			path = root / "keystone" / "app-module-overrides.json"
			path.parent.mkdir()
			_ = path.write_text(
				json.dumps({"version": 1, "applications": ["powerpnt"]}),
				encoding="utf-8",
			)
			overrides = NvdaAppModuleOverrides(root)
			unregistered: list[str] = []
			reloads: list[bool] = []

			def register(_executable: str, _module: str) -> None:
				pass

			def reload() -> None:
				reloads.append(True)

			handler = SimpleNamespace(
				registerExecutableWithAppModule=register,
				unregisterExecutable=unregistered.append,
				reloadAppModules=reload,
			)
			with patch(
				"addon.globalPlugins.keystone.adapters.nvda.app_module_overrides.import_module",
				return_value=handler,
			):
				result = overrides.setEnabled("powerpnt.exe", False)

			self.assertTrue(result.succeeded)
			self.assertEqual(["powerpnt"], unregistered)
			self.assertEqual([True], reloads)
			self.assertFalse(overrides.state("powerpnt.exe").enabled)

	def test_invalid_configuration_disables_changes_without_overwriting_the_document(self) -> None:
		with tempfile.TemporaryDirectory() as temporary:
			root = Path(temporary)
			path = root / "keystone" / "app-module-overrides.json"
			path.parent.mkdir()
			_ = path.write_text("{not json", encoding="utf-8")

			overrides = NvdaAppModuleOverrides(root)
			result = overrides.setEnabled("powerpnt.exe", True)

			self.assertFalse(result.succeeded)
			self.assertEqual("KS.APP_MODULE.INVALID_CONFIGURATION", result.errorCode)
			self.assertEqual("{not json", path.read_text(encoding="utf-8"))

	def test_failed_reload_restores_the_saved_state_and_registration(self) -> None:
		with tempfile.TemporaryDirectory() as temporary:
			root = Path(temporary)
			registered: list[tuple[str, str]] = []
			unregistered: list[str] = []
			reloads = [RuntimeError("reload failed"), None]

			def reload() -> None:
				result = reloads.pop(0)
				if isinstance(result, Exception):
					raise result

			def register(executable: str, module: str) -> None:
				registered.append((executable, module))

			handler = SimpleNamespace(
				registerExecutableWithAppModule=register,
				unregisterExecutable=unregistered.append,
				reloadAppModules=reload,
			)
			overrides = NvdaAppModuleOverrides(root)
			with patch(
				"addon.globalPlugins.keystone.adapters.nvda.app_module_overrides.import_module",
				return_value=handler,
			):
				result = overrides.setEnabled("powerpnt.exe", True)

			self.assertFalse(result.succeeded)
			self.assertEqual("KS.APP_MODULE.RELOAD_FAILED", result.errorCode)
			self.assertEqual([("powerpnt", "keystone_uia_override")], registered)
			self.assertEqual(["powerpnt"], unregistered)
			self.assertFalse(overrides.state("powerpnt.exe").enabled)
			self.assertEqual(
				{"version": 1, "applications": []},
				json.loads(overrides.storagePath.read_text(encoding="utf-8")),
			)
