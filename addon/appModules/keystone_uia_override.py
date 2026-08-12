"""An explicit per-app override that requests UIA from NVDA's normal window chooser."""

# pyright: reportImplicitOverride=false, reportIncompatibleMethodOverride=false, reportMissingImports=false, reportUnknownMemberType=false, reportUntypedBaseClass=false

from __future__ import annotations

import appModuleHandler


class AppModule(appModuleHandler.AppModule):
	"""Let an informed user choose UIA even where NVDA's core policy normally prefers another backend."""

	def isGoodUIAWindow(self, hwnd: int) -> bool:
		_ = hwnd
		return True
