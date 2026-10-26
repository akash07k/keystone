from __future__ import annotations

from importlib import import_module
from typing import cast

if __package__:
	from .globalPlugins.keystone.adapters.nvda.settings import (
		ConfigSectionsApi,
		migrateAndRegisterKeystoneSection,
		unregisterKeystoneSection,
	)
else:
	from globalPlugins.keystone.adapters.nvda.settings import (
		ConfigSectionsApi,
		migrateAndRegisterKeystoneSection,
		unregisterKeystoneSection,
	)


def onInstall() -> None:
	sections = cast(ConfigSectionsApi, import_module("config.configSections"))
	config = import_module("config")
	result = migrateAndRegisterKeystoneSection(getattr(config, "conf"), sections)
	if not result.available:
		raise RuntimeError("Keystone configuration migration or registration failed")


def onUninstall() -> None:
	addonHandler = import_module("addonHandler")
	state = getattr(addonHandler, "state")
	stateCategory = getattr(addonHandler, "AddonStateCategory")
	pendingInstalls = state[getattr(stateCategory, "PENDING_INSTALL")]
	if "keystone" in pendingInstalls:
		# The replacement is already registered; the old copy must not remove its shared section.
		return
	sections = cast(ConfigSectionsApi, import_module("config.configSections"))
	result = unregisterKeystoneSection(sections)
	if not result.available:
		raise RuntimeError("Keystone configuration removal failed")
