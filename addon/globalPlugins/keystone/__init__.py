from __future__ import annotations

import sys
from collections.abc import Callable
from importlib import import_module
import os
from pathlib import Path
from typing import cast, override

from .adapters.nvda.composition import (
	CompositionRoot as CompositionRoot,
	ProductionComposition,
	buildProductionComposition,
)
from .adapters.nvda.event_sources import NvdaEventSource
from .adapters.windows.raw_uia_events import RawUiaNotification
from .domain.event_monitor import NvdaEventType, RawUiaFamily
from .adapters.wx.settings_panel import KeystoneSettingsPanel as KeystoneSettingsPanel


_AUTOMATED_REVIEW_DELAY_MS = 10_000


class _NvdaGlobalPlugin:
	def __init__(self) -> None:
		super().__init__()

	def terminate(self) -> None:
		pass


if "globalPluginHandler" in sys.modules:
	_NvdaGlobalPlugin = cast(
		type[_NvdaGlobalPlugin],
		getattr(import_module("globalPluginHandler"), "GlobalPlugin"),
	)


def _automatedReviewOutput() -> Path | None:
	direct = os.environ.get("KEYSTONE_AUTOMATED_REVIEW_OUTPUT")
	if direct:
		return Path(direct)
	temporary = os.environ.get("TEMP")
	if not temporary:
		return None
	request = Path(temporary) / "keystone-automated-review.request"
	if not request.is_file():
		return None
	try:
		request.unlink()
	except OSError:
		return None
	return request.with_suffix(".json")


class GlobalPlugin(_NvdaGlobalPlugin):
	"""NVDA host entry point owning one packaged production composition."""

	_eventSource: NvdaEventSource
	scriptCategory = "Keystone"
	__gestures = {
		"kb:NVDA+/": "keystoneCommandLayer",
		"kb:NVDA+shift+/": "keystoneEventMonitor",
	}

	def __init__(
		self,
		*,
		_compositionFactory: Callable[[], ProductionComposition] | None = None,
		_secureDesktop: bool | None = None,
	) -> None:
		super().__init__()
		factory = buildProductionComposition if _compositionFactory is None else _compositionFactory
		self._compositionFactory = factory
		self._secureDesktopAction: object | None = None
		self._secureDesktopCallback = self._onSecureDesktopChange
		self._secureSuspended = False
		self._terminated = False
		composition, self._eventSource = self._buildOwnedComposition()
		self._composition: ProductionComposition | None = composition
		self._registerSecureDesktopCallback()
		secure = self._secureDesktopActive() if _secureDesktop is None else _secureDesktop
		try:
			if secure:
				# Secure preflight: a secure desktop denies every interactive surface before it is
				# created. The composition is transitioned to secure so admission is refused and any
				# assembled resource is released in the established reverse order. Nothing is shown,
				# subscribed, sounded, or exported and the OS focus is left exactly where it was.
				self._secureSuspended = True
				composition.transition("secure")
				return
			composition.start()
			automatedOutput = _automatedReviewOutput()
			if automatedOutput:
				_ = import_module("core").callLater(
					_AUTOMATED_REVIEW_DELAY_MS,
					lambda: composition.runAutomatedRuntimeReview(automatedOutput),
				)
			reviewOutput = os.environ.get("KEYSTONE_LIVE_REVIEW_OUTPUT")
			if reviewOutput:
				_ = import_module("core").callLater(
					1_500,
					lambda: composition.runInstalledReview(Path(reviewOutput)),
				)
		except Exception:
			self._unregisterSecureDesktopCallback()
			self._composition = None
			try:
				composition.close()
			except Exception:
				pass
			raise

	def _buildOwnedComposition(self) -> tuple[ProductionComposition, NvdaEventSource]:
		composition = self._compositionFactory()
		try:
			if not isinstance(composition, ProductionComposition):  # pyright: ignore[reportUnnecessaryIsInstance]
				raise TypeError("composition factory must return ProductionComposition")
			eventSource = NvdaEventSource()
			composition.useEventSource(eventSource)
		except Exception:
			if isinstance(composition, ProductionComposition):  # pyright: ignore[reportUnnecessaryIsInstance]
				try:
					composition.close()
				except Exception:
					pass
			raise
		return composition, eventSource

	def _registerSecureDesktopCallback(self) -> None:
		try:
			action = import_module("winAPI.secureDesktop").post_secureDesktopStateChange
			register = getattr(action, "register")
			unregister = getattr(action, "unregister")
		except (AttributeError, ImportError):
			return
		if not callable(register) or not callable(unregister):
			return
		_ = register(self._secureDesktopCallback)
		self._secureDesktopAction = action

	def _unregisterSecureDesktopCallback(self) -> None:
		action = self._secureDesktopAction
		self._secureDesktopAction = None
		if action is None:
			return
		try:
			unregister = getattr(action, "unregister")
			if callable(unregister):
				_ = unregister(self._secureDesktopCallback)
		except Exception:
			pass

	def _onSecureDesktopChange(self, isSecureDesktop: bool | None = None) -> None:
		if self._terminated:
			return
		composition = self._composition
		if isSecureDesktop is not False:
			self._secureSuspended = True
			if composition is not None:
				try:
					composition.transition("secure" if isSecureDesktop is True else "indeterminate")
				except Exception:
					pass
			return
		if not self._secureSuspended:
			return
		self._secureSuspended = False
		if composition is not None:
			composition.close()
		replacement: ProductionComposition | None = None
		try:
			replacement, eventSource = self._buildOwnedComposition()
			self._eventSource = eventSource
			self._composition = replacement
			replacement.start()
		except Exception:
			self._composition = None
			if replacement is not None:
				try:
					replacement.close()
				except Exception:
					pass
			try:
				import_module("logHandler").log.exception(
					"Keystone could not restart after leaving the secure desktop",
				)
			except Exception:
				pass

	@staticmethod
	def _secureDesktopActive() -> bool:
		"""Report whether NVDA is running on the secure desktop.

		Off-host, and whenever the host does not expose the flag, this defaults to ``False`` so the
		ordinary composition starts. The check reads a single boolean and never touches focus.
		"""

		try:
			globalVars = import_module("globalVars")
			return bool(globalVars.appArgs.secure)
		except (AttributeError, ImportError):
			return False

	@override
	def terminate(self) -> None:
		self._terminated = True
		self._unregisterSecureDesktopCallback()
		composition = self._composition
		self._composition = None
		try:
			if composition is not None:
				composition.close()
		finally:
			super().terminate()

	def script_keystoneCommandLayer(self, _gesture: object) -> None:
		"""Open the Keystone command layer. Press H after the prefix for every command."""
		composition = self._composition
		if composition is not None:
			composition.enterCommandLayer()

	def script_keystoneEventMonitor(self, _gesture: object) -> None:
		"""Open the Keystone Events workspace and start (or re-activate) live event monitoring."""
		composition = self._composition
		if composition is not None:
			try:
				composition.openEventMonitor()
			except Exception:
				pass

	def script_keystoneCustomUiaProperties(self, _gesture: object) -> None:
		"""Manage Custom UIA Properties for applications through an accessible native dialog."""
		composition = self._composition
		if composition is not None:
			try:
				_ = composition.openCustomUiaProperties()
			except Exception:
				pass

	@property
	def eventSource(self) -> NvdaEventSource:
		"""The shipped NVDA object-event source the forwarders feed once a monitor subscribes it."""
		return self._eventSource

	def _forwardEvent(
		self,
		eventType: NvdaEventType,
		obj: object,
		nextHandler: Callable[[], None],
	) -> None:
		"""Forward one NVDA event to the shipped source, then always continue NVDA's event chain.

		The handler stays thin: it does no property, UI, speech, export, or blocking work of its own and
		calls ``nextHandler`` exactly once in ``finally``. Any error from the source is contained so a
		monitoring fault can never interrupt NVDA's browsing pipeline.
		"""
		try:
			_ = self._eventSource.forward(eventType, obj)
		except Exception:
			pass
		finally:
			nextHandler()

	def event_gainFocus(self, obj: object, nextHandler: Callable[[], None]) -> None:
		composition = self._composition
		if composition is not None:
			try:
				composition.observeFocus(obj)
			except Exception:
				pass
		self._forwardEvent(NvdaEventType.FOCUS, obj, nextHandler)

	def event_foreground(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.FOREGROUND, obj, nextHandler)

	def event_nameChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.NAME_CHANGE, obj, nextHandler)

	def event_valueChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.VALUE_CHANGE, obj, nextHandler)

	def event_stateChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.STATE_CHANGE, obj, nextHandler)

	def event_descriptionChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.DESCRIPTION_CHANGE, obj, nextHandler)

	def event_liveRegionChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.LIVE_REGION, obj, nextHandler)

	def event_selection(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.SELECTION, obj, nextHandler)

	def event_caret(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.CARET, obj, nextHandler)

	def event_controllerForChange(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardEvent(NvdaEventType.CONTROLLER, obj, nextHandler)

	def event_becomeNavigatorObject(
		self,
		obj: object,
		nextHandler: Callable[[], None],
		*,
		isFocus: bool = False,
	) -> None:
		try:
			_ = self._eventSource.forward(NvdaEventType.NAVIGATOR_OBJECT, obj, isFocus=isFocus)
		except Exception:
			pass
		finally:
			nextHandler()

	# -- Raw UI Automation-only events -------------------------------------
	#
	# NVDA receives UIA callbacks through UIAHandler, creates or resolves an NVDAObject, and queues the
	# resulting ``event_UIA_*`` event through eventHandler. Each thin global-plugin callback bridges
	# that settled object into the monitor's raw source under the matching family, then always
	# continues NVDA's core event chain. No COM object is created or retained here; the bridge is a
	# no-op unless a monitoring session is open and the family is selected.

	def _forwardRawUia(
		self,
		family: RawUiaFamily,
		obj: object,
		nextHandler: Callable[[], None],
		*,
		notification: RawUiaNotification | None = None,
		activeTextRange: object | None = None,
	) -> None:
		composition = self._composition
		try:
			if composition is not None:
				_ = composition.forwardRawUiaEvent(
					family,
					obj,
					notification=notification,
					activeTextRange=activeTextRange,
				)
		except Exception:
			pass
		finally:
			nextHandler()

	def event_UIA_notification(
		self,
		obj: object,
		nextHandler: Callable[[], None],
		notificationKind: int | None = None,
		notificationProcessing: int | None = None,
		displayString: str | None = None,
		activityId: str | None = None,
	) -> None:
		# NVDA queues these four values with the notification event; the display string is the text
		# the provider asked to have announced, so it is retained as the notification's changed value
		# instead of being dropped on the floor.
		self._forwardRawUia(
			RawUiaFamily.NOTIFICATION,
			obj,
			nextHandler,
			notification=RawUiaNotification(
				notificationKind=notificationKind,
				notificationProcessing=notificationProcessing,
				displayString=displayString,
				activityId=activityId,
			),
		)

	def event_UIA_elementSelected(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.SELECTION, obj, nextHandler)

	def event_UIA_layoutInvalidated(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.LAYOUT, obj, nextHandler)

	def event_UIA_window_windowOpen(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.WINDOW, obj, nextHandler)

	def event_UIA_controllerFor(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.RELATION, obj, nextHandler)

	def event_UIA_dragDropEffect(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.DRAG_DROP, obj, nextHandler)

	def event_UIA_dropTargetEffect(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.DRAG_DROP, obj, nextHandler)

	def event_UIA_systemAlert(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.ALERT, obj, nextHandler)

	def event_UIA_itemStatus(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.ITEM_STATUS, obj, nextHandler)

	def event_UIA_toolTipOpened(self, obj: object, nextHandler: Callable[[], None]) -> None:
		self._forwardRawUia(RawUiaFamily.TOOLTIP, obj, nextHandler)

	def event_UIA_activeTextPositionChanged(
		self,
		obj: object,
		nextHandler: Callable[[], None],
		textRange: object | None = None,
	) -> None:
		# The range is never read here: its contents would need a cross-process call, and only the
		# fact that the provider reported a position is claimed.
		self._forwardRawUia(
			RawUiaFamily.ACTIVE_TEXT_POSITION,
			obj,
			nextHandler,
			activeTextRange=textRange,
		)
