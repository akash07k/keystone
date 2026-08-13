from __future__ import annotations

from importlib import import_module
from typing import Protocol, cast

if __package__:
	from .globalPlugins.keystone.adapters.nvda.settings import (
		KEYSTONE_SECTION,
		ConfigRegistrationResult,
		buildConfigSpec,
		initializeLegacyKeystoneBaseSection,
		unregisterLegacyKeystoneBaseSection,
	)
else:
	from globalPlugins.keystone.adapters.nvda.settings import (
		KEYSTONE_SECTION,
		ConfigRegistrationResult,
		buildConfigSpec,
		initializeLegacyKeystoneBaseSection,
		unregisterLegacyKeystoneBaseSection,
	)


class ConfigManagerApi(Protocol):
	def registerSection(
		self,
		sectionName: str,
		sectionSpec: dict[str, str],
		isBaseOnly: bool = False,
	) -> None: ...

	def unregisterSection(self, sectionName: str) -> None: ...


def registerKeystoneSection(api: ConfigManagerApi) -> ConfigRegistrationResult:
	try:
		api.registerSection(KEYSTONE_SECTION, buildConfigSpec(), isBaseOnly=True)
	except (AttributeError, OSError, TypeError, ValueError):
		return ConfigRegistrationResult.unavailable()
	return ConfigRegistrationResult(True)


def unregisterKeystoneSection(api: ConfigManagerApi) -> ConfigRegistrationResult:
	try:
		api.unregisterSection(KEYSTONE_SECTION)
	except (AttributeError, OSError, TypeError, ValueError):
		return ConfigRegistrationResult.unavailable()
	return ConfigRegistrationResult(True)


def registerLegacyKeystoneSection(configManager: object) -> ConfigRegistrationResult:
	result = initializeLegacyKeystoneBaseSection(configManager)
	if not result.available:
		return result
	save = getattr(configManager, "save", None)
	if not callable(save):
		_ = unregisterLegacyKeystoneBaseSection(configManager)
		return ConfigRegistrationResult.unavailable()
	try:
		_ = save()
	except (OSError, RuntimeError, TypeError, ValueError):
		_ = unregisterLegacyKeystoneBaseSection(configManager)
		return ConfigRegistrationResult.unavailable()
	return result


def unregisterLegacyKeystoneSection(configManager: object) -> ConfigRegistrationResult:
	return unregisterLegacyKeystoneBaseSection(configManager)


def _modernConfigSections() -> object | None:
	try:
		return import_module("config.configSections")
	except ModuleNotFoundError as error:
		if error.name == "config.configSections":
			return None
		raise


def onInstall() -> None:
	sections = _modernConfigSections()
	if sections is None:
		config = import_module("config")
		result = registerLegacyKeystoneSection(getattr(config, "conf"))
	else:
		result = registerKeystoneSection(cast(ConfigManagerApi, sections))
	if not result.available:
		raise RuntimeError("Keystone configuration registration failed")


def onUninstall() -> None:
	sections = _modernConfigSections()
	if sections is None:
		config = import_module("config")
		result = unregisterLegacyKeystoneSection(getattr(config, "conf"))
	else:
		result = unregisterKeystoneSection(cast(ConfigManagerApi, sections))
	if not result.available:
		raise RuntimeError("Keystone configuration removal failed")
