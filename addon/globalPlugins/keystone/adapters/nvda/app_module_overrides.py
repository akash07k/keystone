from __future__ import annotations

import json
import os
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import cast


_DOCUMENT_VERSION = 1
_MODULE_NAME = "keystone_uia_override"
_STORAGE_NAME = "app-module-overrides.json"


@dataclass(frozen=True, slots=True)
class AppModuleOverrideState:
	executable: str | None
	enabled: bool
	available: bool
	errorCode: str | None = None


@dataclass(frozen=True, slots=True)
class AppModuleOverrideChange:
	succeeded: bool
	executable: str | None
	enabled: bool
	errorCode: str | None = None


class NvdaAppModuleOverrides:
	"""Persist and activate explicit per-app UIA overrides through NVDA's public API."""

	def __init__(self, userConfigurationRoot: Path) -> None:
		super().__init__()
		self.storagePath = Path(userConfigurationRoot) / "keystone" / _STORAGE_NAME
		self._applications: frozenset[str] = frozenset()
		self._loadError: str | None = None
		self._load()

	def state(self, executable: str | None) -> AppModuleOverrideState:
		appName = _appName(executable)
		if self._loadError is not None:
			return AppModuleOverrideState(executable, False, False, self._loadError)
		if appName is None:
			return AppModuleOverrideState(executable, False, False, "KS.APP_MODULE.INVALID_EXECUTABLE")
		return AppModuleOverrideState(executable, appName in self._applications, True)

	def activateStored(self) -> AppModuleOverrideChange:
		if self._loadError is not None:
			return AppModuleOverrideChange(False, None, False, self._loadError)
		if not self._applications:
			return AppModuleOverrideChange(True, None, False)
		handler: object | None = None
		try:
			handler = import_module("appModuleHandler")
			register = getattr(handler, "registerExecutableWithAppModule")
			reload = getattr(handler, "reloadAppModules")
			for appName in self._applications:
				register(appName, _MODULE_NAME)
			reload()
		except (AttributeError, ImportError, RuntimeError):
			return AppModuleOverrideChange(False, None, False, "KS.APP_MODULE.RELOAD_FAILED")
		return AppModuleOverrideChange(True, None, True)

	def setEnabled(self, executable: str | None, enabled: bool) -> AppModuleOverrideChange:
		appName = _appName(executable)
		if self._loadError is not None:
			return AppModuleOverrideChange(False, executable, enabled, self._loadError)
		if appName is None:
			return AppModuleOverrideChange(
				False,
				executable,
				enabled,
				"KS.APP_MODULE.INVALID_EXECUTABLE",
			)
		updated = self._applications | {appName} if enabled else self._applications - {appName}
		if updated == self._applications:
			return AppModuleOverrideChange(True, executable, enabled)
		try:
			self._write(updated)
		except OSError:
			return AppModuleOverrideChange(False, executable, enabled, "KS.APP_MODULE.WRITE_FAILED")
		handler: object | None = None
		try:
			handler = import_module("appModuleHandler")
			if enabled:
				register = getattr(handler, "registerExecutableWithAppModule")
				register(appName, _MODULE_NAME)
			else:
				unregister = getattr(handler, "unregisterExecutable")
				unregister(appName)
			reload = getattr(handler, "reloadAppModules")
			reload()
		except (AttributeError, ImportError, RuntimeError):
			if handler is not None:
				try:
					if enabled:
						unregister = getattr(handler, "unregisterExecutable")
						unregister(appName)
					else:
						register = getattr(handler, "registerExecutableWithAppModule")
						register(appName, _MODULE_NAME)
					reload = getattr(handler, "reloadAppModules")
					reload()
				except (AttributeError, RuntimeError):
					pass
			try:
				self._write(self._applications)
			except OSError:
				pass
			return AppModuleOverrideChange(False, executable, enabled, "KS.APP_MODULE.RELOAD_FAILED")
		self._applications = frozenset(updated)
		return AppModuleOverrideChange(True, executable, enabled)

	def _load(self) -> None:
		try:
			payload = self.storagePath.read_text(encoding="utf-8")
		except FileNotFoundError:
			return
		except OSError:
			self._loadError = "KS.APP_MODULE.READ_FAILED"
			return
		try:
			document: object = json.loads(payload)
		except (KeyError, TypeError, json.JSONDecodeError):
			self._loadError = "KS.APP_MODULE.INVALID_CONFIGURATION"
			return
		if not isinstance(document, dict):
			self._loadError = "KS.APP_MODULE.INVALID_CONFIGURATION"
			return
		document = cast(dict[str, object], document)
		version = document.get("version")
		applications = document.get("applications")
		if version != _DOCUMENT_VERSION or not isinstance(applications, list):
			self._loadError = "KS.APP_MODULE.INVALID_CONFIGURATION"
			return
		applications = cast(list[object], applications)
		names = tuple(_appName(value) for value in applications if isinstance(value, str))
		if len(names) != len(applications) or any(name is None for name in names):
			self._loadError = "KS.APP_MODULE.INVALID_CONFIGURATION"
			return
		self._applications = frozenset(name for name in names if name is not None)

	def _write(self, applications: frozenset[str] | set[str]) -> None:
		document = {
			"version": _DOCUMENT_VERSION,
			"applications": sorted(applications),
		}
		encoded = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
		self.storagePath.parent.mkdir(parents=True, exist_ok=True)
		temporary = self.storagePath.with_name(f".{self.storagePath.name}.{os.getpid()}.tmp")
		try:
			_ = temporary.write_bytes(encoded)
			_ = temporary.replace(self.storagePath)
		finally:
			try:
				temporary.unlink()
			except FileNotFoundError:
				pass


def _appName(executable: object) -> str | None:
	if not isinstance(executable, str):
		return None
	name = executable.strip().casefold()
	if name.endswith(".exe"):
		name = name[:-4]
	if not name or any(character in name for character in ("/", "\\", "\x00")):
		return None
	return name
