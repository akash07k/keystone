# pyright: reportCallIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda.composition import ProductionComposition
from addon.globalPlugins.keystone.application.settings_service import SettingsService
from addon.globalPlugins.keystone.capability import defaultCapabilitySnapshot
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from tests.contract.test_settings_panel import (
	RecordingCapturePort,
	RecordingSettingsPort,
)


lifecycleModule = import_module("addon.globalPlugins.keystone.application.lifecycle")
hostModule = import_module("addon.globalPlugins.keystone.adapters.nvda.host")
pluginModule = import_module("addon.globalPlugins.keystone")


class _RecordingSound:
	def __init__(self) -> None:
		super().__init__()
		self.invalidations = 0

	def emit(self, request: object) -> None:
		_ = request

	def tick(self) -> None:
		pass

	def invalidate(self, owner: object = None) -> None:
		_ = owner
		self.invalidations += 1


class _RecordingRoot:
	def __init__(self, events: list[str]) -> None:
		super().__init__()
		self._events = events

	def start(self, settings: object) -> None:
		self._events.append("start")

	def transition(self, state: str) -> None:
		self._events.append(f"transition:{state}")

	def close(self) -> None:
		self._events.append("close")


class LifecycleTests(unittest.TestCase):
	def test_admission_allocates_complete_context_owned_by_the_lifecycle(self) -> None:
		service = lifecycleModule.LifecycleService()

		admission = service.admit("settings-panel")

		self.assertTrue(admission.accepted)
		self.assertIsNotNone(admission.context)
		assert admission.context is not None
		self.assertEqual(service.generation, admission.context.generation)
		self.assertIs(admission.context, service.requireCurrent(admission.context))

	def test_secure_transition_rejects_then_invalidates_stops_closes_and_releases_reverse(self) -> None:
		events: list[str] = []
		service = lifecycleModule.LifecycleService()
		service.registerInvalidator("management", lambda: events.append("invalidate"))
		service.registerSource("observer", lambda: events.append("stop-source"))
		service.registerQueue("writer", lambda: events.append("stop-queue"))
		service.registerUi("settings", lambda: events.append("close-ui"))
		service.registerResource("clipboard", lambda: events.append("release-clipboard"))
		service.registerResource("shell", lambda: events.append("release-shell"))
		admission = service.admit("capture")

		service.transition("secure")

		self.assertFalse(service.admit("capture").accepted)
		self.assertFalse(service.precommit(admission))
		self.assertFalse(service.isCurrent(admission.generation))
		self.assertEqual(
			events,
			[
				"invalidate",
				"stop-source",
				"stop-queue",
				"close-ui",
				"release-shell",
				"release-clipboard",
			],
		)

	def test_indeterminate_and_termination_deny_admission_and_late_callbacks(self) -> None:
		for state in ("indeterminate", "terminating"):
			with self.subTest(state=state):
				service = lifecycleModule.LifecycleService()
				admission = service.admit("inspection")
				service.transition(state)
				self.assertFalse(service.precommit(admission))
				self.assertFalse(service.isCurrent(admission.generation))
				self.assertEqual(service.state, "terminated" if state == "terminating" else state)

	def test_resource_release_is_idempotent_and_owned_in_reverse_order(self) -> None:
		events: list[str] = []
		service = lifecycleModule.LifecycleService()
		service.registerResource("first", lambda: events.append("first"))
		service.registerResource("second", lambda: events.append("second"))

		service.transition("terminating")
		service.transition("terminating")

		self.assertEqual(events, ["second", "first"])

	def test_faulty_callbacks_do_not_skip_later_callbacks_or_stages(self) -> None:
		events: list[str] = []
		service = lifecycleModule.LifecycleService()

		def fail() -> None:
			events.append("failed")
			raise RuntimeError("teardown failure")

		service.registerInvalidator("failed-invalidator", fail)
		service.registerInvalidator("later-invalidator", lambda: events.append("invalidate"))
		service.registerSource("source", lambda: events.append("source"))
		service.registerQueue("queue", lambda: events.append("queue"))
		service.registerUi("ui", lambda: events.append("ui"))
		service.registerResource("first-resource", lambda: events.append("first-resource"))
		service.registerResource("failed-resource", fail)
		service.registerResource("last-resource", lambda: events.append("last-resource"))

		service.transition("terminating")

		self.assertEqual(
			[
				"failed",
				"invalidate",
				"source",
				"queue",
				"ui",
				"last-resource",
				"failed",
				"first-resource",
			],
			events,
		)
		self.assertEqual("terminated", service.state)

	def test_secure_then_terminating_runs_every_teardown_callback_once(self) -> None:
		events: list[str] = []
		service = lifecycleModule.LifecycleService()
		service.registerInvalidator("selection.generation", lambda: events.append("invalidate-selection"))
		service.registerSource("monitor.subscriptions", lambda: events.append("stop-subscriptions"))
		service.registerQueue("monitor.queue", lambda: events.append("drain-queue"))
		service.registerUi("inspector.frame", lambda: events.append("close-inspector"))
		service.registerResource("uia.provider", lambda: events.append("release-provider"))
		service.registerResource("audio.port", lambda: events.append("release-audio"))
		selection = service.admit("inspector.selection")
		retarget = service.admit("inspector.retarget")
		export = service.admit("events.export")
		self.assertTrue(all(admission.accepted for admission in (selection, retarget, export)))

		service.transition("secure")
		secureBoundary = list(events)

		self.assertFalse(service.precommit(selection))
		self.assertFalse(service.precommit(retarget))
		self.assertFalse(service.precommit(export))
		self.assertFalse(service.admit("events.drain").accepted)

		service.transition("terminating")
		service.transition("terminating")

		self.assertEqual(
			secureBoundary,
			[
				"invalidate-selection",
				"stop-subscriptions",
				"drain-queue",
				"close-inspector",
				"release-audio",
				"release-provider",
			],
		)
		self.assertEqual(secureBoundary, events)
		self.assertEqual("terminated", service.state)


class SecurePreflightTests(unittest.TestCase):
	def _composition(self, events: list[str], sound: _RecordingSound) -> ProductionComposition:
		return ProductionComposition(
			root=_RecordingRoot(events),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			workflowSound=sound,
		)

	def test_secure_desktop_denies_start_and_creates_no_interactive_surface(self) -> None:
		events: list[str] = []
		sound = _RecordingSound()
		composition = self._composition(events, sound)

		plugin = pluginModule.GlobalPlugin(
			_compositionFactory=lambda: composition,
			_secureDesktop=True,
		)

		# Nothing is started: no panel, source, subscription, audio, or export surface is created.
		self.assertFalse(composition.started)
		self.assertNotIn("start", events)
		self.assertIn("transition:secure", events)
		self.assertFalse(composition.operationalEligible)
		# The optional voice is invalidated exactly once at the secure boundary.
		self.assertEqual(1, sound.invalidations)
		# Terminate remains safe and drives the terminating boundary to a closed composition.
		plugin.terminate()
		plugin.terminate()
		self.assertTrue(composition.closed)

	def test_ordinary_desktop_starts_the_single_owned_composition(self) -> None:
		events: list[str] = []
		composition = self._composition(events, _RecordingSound())

		plugin = pluginModule.GlobalPlugin(
			_compositionFactory=lambda: composition,
			_secureDesktop=False,
		)

		self.assertTrue(composition.started)
		self.assertEqual(["start"], events)
		plugin.terminate()
		self.assertTrue(composition.closed)

	def test_secure_preflight_transition_failure_cleans_up_the_registered_plugin(self) -> None:
		class _Action:
			def __init__(self) -> None:
				super().__init__()
				self.handlers: list[object] = []

			def register(self, handler: object) -> None:
				self.handlers.append(handler)

			def unregister(self, handler: object) -> None:
				self.handlers.remove(handler)

		composition = self._composition([], _RecordingSound())
		action = _Action()

		def imported(name: str) -> object:
			if name == "winAPI.secureDesktop":
				return type("_SecureDesktop", (), {"post_secureDesktopStateChange": action})()
			raise ImportError(name)

		with (
			patch.object(pluginModule, "import_module", side_effect=imported),
			patch.object(composition, "transition", side_effect=RuntimeError("transition failed")),
			self.assertRaisesRegex(RuntimeError, "transition failed"),
		):
			_ = pluginModule.GlobalPlugin(
				_compositionFactory=lambda: composition,
				_secureDesktop=True,
			)

		self.assertEqual([], action.handlers)
		self.assertTrue(composition.closed)

	def test_secure_desktop_transition_failure_is_contained(self) -> None:
		class _Action:
			def __init__(self) -> None:
				super().__init__()
				self.handlers: list[Callable[[bool | None], None]] = []

			def register(self, handler: Callable[[bool | None], None]) -> None:
				self.handlers.append(handler)

			def unregister(self, handler: Callable[[bool | None], None]) -> None:
				self.handlers.remove(handler)

			def notify(self, secure: bool) -> None:
				for handler in tuple(self.handlers):
					handler(secure)

		composition = self._composition([], _RecordingSound())
		action = _Action()

		def imported(name: str) -> object:
			if name == "winAPI.secureDesktop":
				return type("_SecureDesktop", (), {"post_secureDesktopStateChange": action})()
			raise ImportError(name)

		with patch.object(pluginModule, "import_module", side_effect=imported):
			plugin = pluginModule.GlobalPlugin(
				_compositionFactory=lambda: composition,
				_secureDesktop=False,
			)
		with patch.object(composition, "transition", side_effect=RuntimeError("transition failed")):
			action.notify(True)

		self.assertTrue(plugin._secureSuspended)
		self.assertIs(composition, plugin._composition)
		plugin.terminate()
		self.assertEqual([], action.handlers)
		self.assertTrue(composition.closed)


class RecordingScheduler:
	def __init__(self) -> None:
		super().__init__()
		self.calls: list[tuple[str, int, tuple[object, ...]]] = []

	def scheduleImmutable(self, taskId: str, generation: int, values: tuple[object, ...]) -> None:
		self.calls.append((taskId, generation, values))


class HostTests(unittest.TestCase):
	def test_host_schedules_only_immutable_values_and_rejects_stale_generation(self) -> None:
		lifecycle = lifecycleModule.LifecycleService()
		scheduler = RecordingScheduler()
		host = hostModule.NvdaHostAdapter(lifecycle, scheduler)
		admission = lifecycle.admit("status")

		self.assertTrue(host.schedule("status-refresh", admission, ("ready", 4, False)))
		lifecycle.transition("secure")
		self.assertFalse(host.schedule("late-refresh", admission, ("ready",)))
		self.assertEqual(scheduler.calls, [("status-refresh", admission.generation, ("ready", 4, False))])

	def test_host_maps_unknown_secure_state_to_indeterminate(self) -> None:
		lifecycle = lifecycleModule.LifecycleService()
		host = hostModule.NvdaHostAdapter(lifecycle, RecordingScheduler())

		host.desktopChanged(None)

		self.assertEqual(lifecycle.state, "indeterminate")
		self.assertFalse(lifecycle.admit("capture").accepted)


class RecordingPanelRegistry:
	def __init__(self) -> None:
		super().__init__()
		self.added: list[tuple[type[object], object]] = []
		self.removed: list[type[object]] = []

	def add(self, panelClass: type[object], controllerFactory: object) -> None:
		self.added.append((panelClass, controllerFactory))

	def remove(self, panelClass: type[object]) -> None:
		self.removed.append(panelClass)


class CompositionTests(unittest.TestCase):
	def test_global_plugin_inherits_the_nvda_host_base(self) -> None:
		projectRoot = Path(__file__).resolve().parents[2]
		script = """
import sys
import types

class NvdaGlobalPlugin:
\tdef __init__(self):
\t\tself.nvdaBaseInitialized = True

\tdef terminate(self):
\t\tself.nvdaBaseTerminated = True

module = types.ModuleType("globalPluginHandler")
module.GlobalPlugin = NvdaGlobalPlugin
sys.modules["globalPluginHandler"] = module

from addon.globalPlugins.keystone import GlobalPlugin

plugin = GlobalPlugin()
assert isinstance(plugin, NvdaGlobalPlugin)
assert plugin.nvdaBaseInitialized
plugin.terminate()
assert plugin.nvdaBaseTerminated
"""
		result = subprocess.run(
			[sys.executable, "-c", script],
			cwd=projectRoot,
			capture_output=True,
			text=True,
		)
		self.assertEqual(0, result.returncode, result.stderr or result.stdout)

	def test_composition_registers_and_removes_one_exact_panel_identity(self) -> None:
		registry = RecordingPanelRegistry()
		lifecycle = lifecycleModule.LifecycleService()
		capture = RecordingCapturePort()
		settingsPort = RecordingSettingsPort(1)
		settings = SettingsService(settingsPort)
		root = pluginModule.CompositionRoot(
			lifecycle=lifecycle,
			panelRegistry=registry,
			settingsService=settings,
			capabilities=defaultCapabilitySnapshot,
			captureManagement=capture,
		)

		root.start(SettingsSnapshot.defaults(settingsRevision=1))
		controller = registry.added[0][1]()
		controller.refreshCaptures()
		controller.setValue(
			__import__(
				"addon.globalPlugins.keystone.domain.settings",
				fromlist=["SettingId"],
			).SettingId.MAXIMUM_NODES,
			7_000,
		)
		controller.apply()
		root.close()

		self.assertEqual(len(registry.added), 1)
		self.assertIs(registry.added[0][0], pluginModule.KeystoneSettingsPanel)
		self.assertEqual(registry.removed, [pluginModule.KeystoneSettingsPanel])
		self.assertIs(controller._captureManagement, capture)
		self.assertIs(controller._context, capture.requests[0].context)
		self.assertIs(controller._context, settingsPort.requests[0].context)
		self.assertFalse(hasattr(controller, "_clipboard"))
		self.assertFalse(hasattr(controller, "_shell"))
		self.assertFalse(hasattr(controller, "_writer"))

	def test_close_invalidates_management_before_panel_and_resource_release(self) -> None:
		events: list[str] = []
		registry = RecordingPanelRegistry()
		lifecycle = lifecycleModule.LifecycleService()
		lifecycle.registerInvalidator("management", lambda: events.append("invalidate"))
		lifecycle.registerResource("writer", lambda: events.append("release-writer"))
		root = pluginModule.CompositionRoot(
			lifecycle=lifecycle,
			panelRegistry=registry,
			settingsService=SettingsService(RecordingSettingsPort(1)),
			capabilities=defaultCapabilitySnapshot,
			captureManagement=RecordingCapturePort(),
			onPanelClose=lambda: events.append("close-panel"),
		)
		root.start(SettingsSnapshot.defaults(settingsRevision=1))

		root.close()

		self.assertEqual(events, ["invalidate", "close-panel", "release-writer"])


if __name__ == "__main__":
	_ = unittest.main()
