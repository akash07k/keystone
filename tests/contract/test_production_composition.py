# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
import inspect
import json
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins import keystone as pluginModule
from addon.globalPlugins.keystone.adapters.nvda import composition as compositionModule
from addon.globalPlugins.keystone.adapters.nvda import review_hook as reviewHookModule
from addon.globalPlugins.keystone.adapters.nvda.commands import ProductionCommandRuntime
from addon.globalPlugins.keystone.adapters.nvda.composition import (
	ProductionComposition,
	_assembleProductionComposition,
)
from addon.globalPlugins.keystone.application.logging_service import (
	LoggingService,
)
from addon.globalPlugins.keystone.application.output_service import OutputService
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy
from addon.globalPlugins.keystone.encoding.log_formats import LogicalRecord, SequenceAllocator
from addon.globalPlugins.keystone.adapters.nvda.settings import (
	ConfigRegistrationResult,
	SettingsLoadResult,
)
from addon.globalPlugins.keystone.adapters.windows.capability_registry import (
	CapabilityStatusLoader,
	RuntimeCapabilityChecks,
)
from addon.globalPlugins.keystone.adapters.wx.settings_panel import SettingsPanelController
from addon.globalPlugins.keystone.domain.capability_status import (
	CAPABILITY_REGISTRY,
	CapabilityRow,
	CapabilitySnapshot,
	CapabilityStatus,
)
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.ports.effects import (
	CaptureManagementRequest,
	CaptureManagementResult,
	EffectResult,
	FeedbackRequest,
	PortError,
	PortStatus,
	SettingsWriteRequest,
)


class StatusLoader:
	def __init__(self, snapshot: CapabilitySnapshot) -> None:
		super().__init__()
		self.snapshot = snapshot
		self.calls = 0

	def load(self) -> CapabilitySnapshot:
		self.calls += 1
		return self.snapshot


class SettingsAdapter:
	def __init__(self, result: SettingsLoadResult) -> None:
		super().__init__()
		self.result = result
		self.calls = 0

	def readSnapshot(self) -> SettingsLoadResult:
		self.calls += 1
		return self.result

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		raise AssertionError(f"unexpected settings write: {request!r}")


class PanelRegistry:
	def __init__(self, events: list[str] | None = None) -> None:
		super().__init__()
		self.events = events if events is not None else []
		self.added: list[tuple[type[object], Callable[[], SettingsPanelController]]] = []
		self.removed: list[type[object]] = []

	def add(
		self,
		panelClass: type[object],
		controllerFactory: Callable[[], SettingsPanelController],
	) -> None:
		self.events.append("panel-add")
		self.added.append((panelClass, controllerFactory))

	def remove(self, panelClass: type[object]) -> None:
		self.events.append("panel-remove")
		self.removed.append(panelClass)


class PartiallyFailingPanelRegistry(PanelRegistry):
	@override
	def add(
		self,
		panelClass: type[object],
		controllerFactory: Callable[[], SettingsPanelController],
	) -> None:
		super().add(panelClass, controllerFactory)
		raise RuntimeError("partial panel registration")


class ClosedCaptureManagement:
	def manageCaptures(self, request: CaptureManagementRequest) -> CaptureManagementResult:
		return CaptureManagementResult(
			request.operation,
			request.lifecycleGeneration,
			PortStatus("failed", 0),
			None,
			PortError("captureManagementUnavailable"),
			0,
			0,
			0,
			0,
			0,
			0,
			None,
			None,
			None,
		)


def _snapshot(
	*,
	unavailable: frozenset[str] | None = None,
) -> CapabilitySnapshot:
	unavailableIds = unavailable or frozenset()
	rows = tuple(
		CapabilityRow(
			definition.capabilityId,
			(
				CapabilityStatus.UNAVAILABLE
				if definition.capabilityId in unavailableIds
				else CapabilityStatus.ENABLED
			),
			(
				"Runtime prerequisite is unavailable."
				if definition.capabilityId in unavailableIds
				else "Available."
			),
		)
		for definition in CAPABILITY_REGISTRY
	)
	return CapabilitySnapshot(rows)


def _runtimeLoader(
	*,
	secure: bool = False,
	uia: bool = True,
	userInterface: bool = True,
	output: bool = True,
	sound: bool = True,
	screenshot: bool = True,
) -> CapabilityStatusLoader:
	return CapabilityStatusLoader(
		RuntimeCapabilityChecks(
			secureDesktop=lambda: secure,
			uiaHandlerAvailable=lambda: uia,
			userInterfaceAvailable=lambda: userInterface,
			outputDirectoryWritable=lambda: output,
			soundPlaybackAvailable=lambda: sound,
			screenshotAvailable=lambda: screenshot,
		),
	)


def _composition(
	*,
	status: CapabilitySnapshot | None = None,
	settings: SettingsLoadResult | None = None,
	events: list[str] | None = None,
	releases: tuple[tuple[str, Callable[[], None]], ...] = (),
) -> tuple[ProductionComposition, StatusLoader, SettingsAdapter, PanelRegistry]:
	statusLoader = StatusLoader(status or _snapshot())
	settingsAdapter = SettingsAdapter(
		settings
		or SettingsLoadResult(
			"ready",
			SettingsSnapshot.defaults(settingsRevision=1),
		),
	)
	registry = PanelRegistry(events)
	composition = _assembleProductionComposition(
		statusLoader=statusLoader,
		settingsAdapter=settingsAdapter,
		panelRegistry=registry,
		captureManagement=ClosedCaptureManagement(),
		releaseCallbacks=releases,
	)
	return composition, statusLoader, settingsAdapter, registry


class SourceContractTests(unittest.TestCase):
	def test_source_contract_names_only_graph_surfaced_nvda_symbols(self) -> None:
		path = (
			Path(__file__).resolve().parents[1] / "fixtures" / "nvda" / "production-composition-contract.json"
		)
		contract = json.loads(path.read_text(encoding="utf-8"))
		self.assertEqual(1, contract["schemaVersion"])
		self.assertEqual(
			[
				("source/globalPluginHandler.py", "L30", "initialize"),
				("source/globalPluginHandler.py", "L38", "terminate"),
				("source/globalPluginHandler.py", "L47", "reloadGlobalPlugins"),
				("source/gui/settingsDialogs.py", "L6601", "NVDASettingsDialog.categoryClasses"),
			],
			[(item["sourceFile"], item["sourceLocation"], item["symbol"]) for item in contract["symbols"]],
		)


class ProductionCompositionTests(unittest.TestCase):
	def test_production_status_loader_reads_live_secure_and_uia_signals(self) -> None:
		globalVars = SimpleNamespace(appArgs=SimpleNamespace(secure=False))
		uiaHandler = SimpleNamespace(handler=object())
		settingsDialogs = SimpleNamespace(NVDASettingsDialog=object(), SettingsPanel=object())

		def imported(name: str) -> object:
			return {
				"globalVars": globalVars,
				"UIAHandler": uiaHandler,
				"gui.settingsDialogs": settingsDialogs,
			}[name]

		with (
			patch.object(compositionModule, "import_module", side_effect=imported),
			patch.object(compositionModule, "_outputDirectoryWritable", return_value=True),
			patch.object(compositionModule, "_soundPlaybackAvailable", return_value=True),
			patch.object(compositionModule, "_screenshotAvailable", return_value=True),
		):
			loader = compositionModule._productionStatusLoader()
			available = loader.load()
			uiaHandler.handler = None
			withoutUia = loader.load()
			globalVars.appArgs.secure = True
			secure = loader.load()

		self.assertEqual(CapabilityStatus.ENABLED, available.row("eventMonitoring").status)
		self.assertEqual(CapabilityStatus.UNAVAILABLE, withoutUia.row("eventMonitoring").status)
		self.assertEqual(
			"Requires an active NVDA UIA handler.",
			withoutUia.row("eventMonitoring").reason,
		)
		self.assertEqual(
			{CapabilityStatus.UNAVAILABLE},
			{row.status for row in secure.rows},
		)

	def test_default_commands_route_inspector_status_through_shared_now_host(self) -> None:
		class _Output:
			screenshotPort = object()

		class _Host:
			def __init__(self) -> None:
				super().__init__()
				self.announcements: list[tuple[str, str]] = []
				self.scheduled: list[tuple[int, Callable[[], None]]] = []

			def announce(self, message: str, *, priority: str = "normal") -> None:
				self.announcements.append((message, priority))

			def callLater(self, milliseconds: int, callback: Callable[[], None]) -> object:
				handle = (milliseconds, callback)
				self.scheduled.append(handle)
				return handle

			def cancelCall(self, handle: object) -> None:
				if handle in self.scheduled:
					self.scheduled.remove(handle)  # type: ignore[arg-type]

		class _Sounds:
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

		output = _Output()
		host = _Host()
		sounds = _Sounds()
		runtime = object()
		layer = object()
		runtimeCall: dict[str, object] = {}
		layerCall: list[object] = []
		layerKwargs: dict[str, object] = {}

		def runtimeFactory(*args: object, **kwargs: object) -> object:
			runtimeCall["args"] = args
			runtimeCall["kwargs"] = kwargs
			return runtime

		def layerFactory(*args: object, **kwargs: object) -> object:
			layerCall.extend(args)
			layerKwargs.update(kwargs)
			return layer

		composition = ProductionComposition(
			root=SimpleNamespace(
				captureManagement=output,
				lifecycle=compositionModule.LifecycleService(),
			),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=False,
			startupIssueCode=None,
			workflowSound=sounds,
		)
		with (
			patch.object(compositionModule, "OutputService", _Output),
			patch.object(compositionModule, "NvdaCommandHost", return_value=host),
			patch.object(compositionModule, "ProductionCommandRuntime", side_effect=runtimeFactory),
			patch.object(compositionModule, "NvdaCommandLayer", side_effect=layerFactory),
		):
			composition.configureDefaultCommands()

		kwargs = cast(dict[str, object], runtimeCall["kwargs"])
		announce = kwargs["announceInspector"]
		assert callable(announce)
		_ = announce("Focus Inspector retargeted.")
		self.assertEqual(
			[("Focus Inspector retargeted.", "now")],
			host.announcements,
		)
		announceFollowFocus = kwargs["announceFollowFocus"]
		assert callable(announceFollowFocus)
		_ = announceFollowFocus("Inspector now follows browser.exe.")
		firstCallback = host.scheduled[0][1]
		_ = announceFollowFocus("Inspector now follows editor.exe.")
		self.assertEqual(1, len(host.scheduled))
		self.assertEqual(700, host.scheduled[0][0])
		firstCallback()
		self.assertEqual(
			[("Focus Inspector retargeted.", "now")],
			host.announcements,
		)
		host.scheduled.pop()[1]()
		self.assertEqual(
			[
				("Focus Inspector retargeted.", "now"),
				("Inspector now follows editor.exe.", "normal"),
			],
			host.announcements,
		)
		self.assertEqual(runtime, layerCall[0])
		self.assertIs(host, layerCall[2])
		# The one shared sound service is threaded into the command layer so its cues and its
		# lifecycle invalidation ride the single voice.
		self.assertIs(sounds, layerKwargs["sound"])
		# The same shared instance reaches the runtime so live Inspector opens and failures sound
		# through the very same scheduler and audio port - never a second voice.
		self.assertIs(sounds, kwargs["sound"])

	def test_lifecycle_boundaries_invalidate_the_shared_sound(self) -> None:
		class _Sounds:
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

		class _StubRoot:
			def start(self, settings: SettingsSnapshot) -> None:
				_ = settings

			def transition(self, state: str) -> None:
				_ = state

			def close(self) -> None:
				pass

		sounds = _Sounds()
		root = _StubRoot()
		composition = ProductionComposition(
			root=root,  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			workflowSound=sounds,
		)
		composition.start()

		# A secure-desktop transition silences and discards any pending cue synchronously.
		composition.transition("secure")
		self.assertEqual(1, sounds.invalidations)

		# Close is a second terminal boundary; the voice is invalidated again and stays idempotent.
		composition.close()
		self.assertEqual(2, sounds.invalidations)
		composition.close()
		self.assertEqual(2, sounds.invalidations)

	def test_output_commit_feedback_is_concise_and_does_not_speak_internal_folder_identity(
		self,
	) -> None:
		messages: list[str] = []

		def message(value: str) -> None:
			messages.append(value)

		ui = SimpleNamespace(message=message)
		context = CorrelationFactory().admit(generation=3)
		with patch.object(compositionModule, "import_module", return_value=ui):
			result = compositionModule._NvdaFeedbackAdapter().announce(
				FeedbackRequest(
					"output.committed",
					("20260726-155132.603-snapshot",),
					context,
				),
			)

		self.assertEqual("ready", result.status.token)
		self.assertEqual(["Capture output saved."], messages)

	def test_preview_feedback_renders_localized_sentences_from_the_cue_name(self) -> None:
		messages: list[str] = []

		def message(value: str) -> None:
			messages.append(value)

		ui = SimpleNamespace(message=message)
		context = CorrelationFactory().admit(generation=3)
		adapter = compositionModule._NvdaFeedbackAdapter()

		with patch.object(compositionModule, "import_module", return_value=ui):
			started = adapter.announce(FeedbackRequest("sound.preview", ("Layer entered",), context))
			failed = adapter.announce(
				FeedbackRequest("sound.preview.failed", ("Layer entered",), context),
			)

		self.assertEqual("ready", started.status.token)
		self.assertEqual("ready", failed.status.token)
		self.assertEqual(
			[
				"Previewing Layer entered.",
				"The Layer entered sound could not be played. Speech remains available.",
			],
			messages,
		)

	def test_event_monitor_start_feedback_names_the_target_scope_and_raw_setting(self) -> None:
		messages: list[str] = []
		ui = SimpleNamespace(message=messages.append)
		context = CorrelationFactory().admit(generation=3)

		with patch.object(compositionModule, "import_module", return_value=ui):
			result = compositionModule._NvdaFeedbackAdapter().announce(
				FeedbackRequest(
					"events.monitor.started",
					("Document", "element", False),
					context,
				),
			)

		self.assertEqual("ready", result.status.token)
		self.assertEqual(
			["Monitoring active. For Document. Scope: selected element. Raw UIA events excluded."],
			messages,
		)

	def test_wx_sound_host_retains_delayed_callbacks_until_they_fire(self) -> None:
		class Timer:
			def __init__(self, action: Callable[[], None]) -> None:
				super().__init__()
				self._action = action
				self.stopped = 0

			def Stop(self) -> None:
				self.stopped += 1

			def fire(self) -> None:
				self._action()

		class Wx:
			def __init__(self) -> None:
				super().__init__()
				self.timers: list[Timer] = []
				self.callAfterActions: list[Callable[[], None]] = []

			def CallLater(self, _delay: int, action: Callable[[], None]) -> Timer:
				timer = Timer(action)
				self.timers.append(timer)
				return timer

			def CallAfter(self, action: Callable[[], None]) -> None:
				self.callAfterActions.append(action)

		wx = Wx()
		host = compositionModule._WxSoundHost()
		marshal = compositionModule._WxMainThreadMarshal()
		delivered: list[str] = []
		with patch.object(compositionModule, "import_module", return_value=wx):
			host.callLater(30, lambda: delivered.append("delayed"))
			marshal.callLater(0, lambda: delivered.append("immediate"))

		self.assertEqual(1, len(host._timers))
		self.assertEqual(1, len(wx.callAfterActions))
		wx.callAfterActions[0]()
		wx.timers[0].fire()
		self.assertEqual(["immediate", "delayed"], delivered)
		self.assertEqual(set(), host._timers)

	def test_managed_sound_service_stops_retained_callbacks_on_close(self) -> None:
		class Timer:
			def __init__(self, action: Callable[[], None]) -> None:
				super().__init__()
				self._action = action
				self.stopped = 0

			def Stop(self) -> None:
				self.stopped += 1

		class Wx:
			def __init__(self) -> None:
				super().__init__()
				self.timers: list[Timer] = []

			def CallLater(self, _delay: int, action: Callable[[], None]) -> Timer:
				timer = Timer(action)
				self.timers.append(timer)
				return timer

		wx = Wx()
		host = compositionModule._WxSoundHost()
		marshal = compositionModule._WxMainThreadMarshal()
		with patch.object(compositionModule, "import_module", return_value=wx):
			host.callLater(30, lambda: None)
			marshal.callLater(30, lambda: None)

		service = compositionModule._ManagedSoundService(
			feedback=cast(Any, object()),
			audio=cast(Any, object()),
			scheduler=compositionModule.SoundScheduler(),
			host=host,
			enabled=True,
			runtimeLog=None,
			timerOwners=(marshal, host),
		)
		service.close()

		self.assertEqual([1, 1], [timer.stopped for timer in wx.timers])
		self.assertEqual(set(), host._timers)
		self.assertEqual(set(), marshal._timers)

	def test_product_builder_uses_concrete_management_services_and_real_panel(self) -> None:
		status = StatusLoader(_snapshot())
		settings = SettingsAdapter(
			SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
		)
		registry = PanelRegistry()
		configManager = object()
		configModule = SimpleNamespace(conf=configManager)

		with (
			patch.object(compositionModule, "_productionStatusLoader", return_value=status),
			patch.object(compositionModule, "NvdaSettingsAdapter", return_value=settings),
			patch.object(compositionModule, "NvdaPanelRegistry", return_value=registry),
			patch.object(
				compositionModule,
				"initializeKeystoneBaseSection",
				return_value=ConfigRegistrationResult(True),
			),
			patch.object(compositionModule, "import_module", return_value=configModule),
		):
			composition = compositionModule.buildProductionComposition()

		self.assertIsInstance(composition._root._settingsService, compositionModule.SettingsService)
		self.assertIsInstance(composition._root._captureManagement, OutputService)
		self.assertIsInstance(composition._root._lifecycle, compositionModule.LifecycleService)
		self.assertNotIn("Closed", type(composition._root._captureManagement).__name__)
		self.assertTrue(
			all(
				type(service).__module__.startswith("addon.globalPlugins.keystone.")
				for service in (
					composition._root._settingsService,
					composition._root._captureManagement,
					composition._root._lifecycle,
				)
			),
		)

		composition.start()
		self.assertEqual(1, len(registry.added))
		self.assertTrue(composition.operationalEligible)
		controller = registry.added[0][1]()
		captures = controller.refreshCaptures()

		self.assertIsNotNone(captures)
		composition.close()
		self.assertEqual(1, len(registry.removed))

	def test_product_builder_selects_legacy_registration_only_when_new_api_is_absent(self) -> None:
		status = StatusLoader(_snapshot())
		settings = SettingsAdapter(
			SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
		)
		registry = PanelRegistry()
		configManager = object()
		configModule = SimpleNamespace(conf=configManager)

		def importHostModule(name: str) -> object:
			if name == "config.configSections":
				raise ModuleNotFoundError(name=name)
			return configModule

		with (
			patch.object(compositionModule, "_productionStatusLoader", return_value=status),
			patch.object(compositionModule, "NvdaSettingsAdapter", return_value=settings),
			patch.object(compositionModule, "NvdaPanelRegistry", return_value=registry),
			patch.object(
				compositionModule,
				"initializeLegacyKeystoneBaseSection",
				return_value=ConfigRegistrationResult(True),
			) as legacy,
			patch.object(compositionModule, "initializeKeystoneBaseSection") as modern,
			patch.object(compositionModule, "import_module", side_effect=importHostModule),
		):
			_ = compositionModule.buildProductionComposition()

		legacy.assert_called_once_with(configManager)
		modern.assert_not_called()

	def test_product_builder_does_not_silently_default_after_registration_failure(self) -> None:
		configModule = SimpleNamespace(conf=object())

		with (
			patch.object(
				compositionModule,
				"initializeKeystoneBaseSection",
				return_value=ConfigRegistrationResult.unavailable(),
			),
			patch.object(compositionModule, "import_module", return_value=configModule),
			self.assertRaisesRegex(RuntimeError, "registration"),
		):
			_ = compositionModule.buildProductionComposition()

	def test_expected_gui_unavailability_degrades_to_closed_panel_registry(self) -> None:
		status = StatusLoader(_snapshot())
		settings = SettingsAdapter(
			SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
		)
		configModule = type("_ConfigModule", (), {"conf": object()})()
		for unavailable in (
			ImportError("gui runtime unavailable off-host"),
			ModuleNotFoundError("No module named 'gui.settingsDialogs'"),
			AttributeError("module 'gui.settingsDialogs' has no attribute 'NVDASettingsDialog'"),
		):
			with (
				patch.object(compositionModule, "_productionStatusLoader", return_value=status),
				patch.object(compositionModule, "NvdaSettingsAdapter", return_value=settings),
				patch.object(compositionModule, "NvdaPanelRegistry", side_effect=unavailable),
				patch.object(
					compositionModule,
					"initializeKeystoneBaseSection",
					return_value=ConfigRegistrationResult(True),
				),
				patch.object(compositionModule, "import_module", return_value=configModule),
			):
				composition = compositionModule.buildProductionComposition()
			self.assertIsInstance(
				composition._root._panelRegistry,
				compositionModule._ClosedPanelRegistry,
			)
			# Headless installed-source observation must survive a missing GUI panel: starting and
			# closing the composition drives the closed registry's no-op add/remove without error.
			composition.start()
			composition.close()

	def test_unexpected_panel_registry_error_propagates(self) -> None:
		status = StatusLoader(_snapshot())
		settings = SettingsAdapter(
			SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
		)
		configModule = type("_ConfigModule", (), {"conf": object()})()
		for unexpected in (
			RuntimeError("settings panel initialization defect"),
			TypeError("panel category class is not callable"),
		):
			with (
				patch.object(compositionModule, "_productionStatusLoader", return_value=status),
				patch.object(compositionModule, "NvdaSettingsAdapter", return_value=settings),
				patch.object(compositionModule, "NvdaPanelRegistry", side_effect=unexpected),
				patch.object(
					compositionModule,
					"initializeKeystoneBaseSection",
					return_value=ConfigRegistrationResult(True),
				),
				patch.object(compositionModule, "import_module", return_value=configModule),
			):
				with self.assertRaises(type(unexpected)):
					_ = compositionModule.buildProductionComposition()

	def test_valid_capabilities_and_settings_make_one_started_composition_operational(self) -> None:
		composition, status, settings, registry = _composition()

		composition.start()

		self.assertEqual(1, status.calls)
		self.assertEqual(1, settings.calls)
		self.assertTrue(composition.operationalEligible)
		self.assertEqual(1, len(registry.added))
		controller = registry.added[0][1]()
		userInterface = next(
			record for record in controller._capabilities.values() if record.capabilityId == "userInterface"
		)
		self.assertEqual("enabled", userInterface.status)

	def test_direct_runtime_checks_control_normal_composition_startup(self) -> None:
		for secure, expectedOperational, expectedStatus in (
			(False, True, "enabled"),
			(True, False, "unavailable"),
		):
			with self.subTest(secure=secure):
				registry = PanelRegistry()
				composition = _assembleProductionComposition(
					statusLoader=_runtimeLoader(secure=secure),
					settingsAdapter=SettingsAdapter(
						SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
					),
					panelRegistry=registry,
					captureManagement=ClosedCaptureManagement(),
				)

				composition.start()

				self.assertEqual(expectedOperational, composition.operationalEligible)
				controller = registry.added[0][1]()
				self.assertEqual(
					expectedStatus,
					next(
						record
						for record in controller._capabilities.values()
						if record.capabilityId == "userInterface"
					).status,
				)
				composition.close()

	def test_runtime_check_and_base_settings_failures_start_unavailable(self) -> None:
		class FailedStatusLoader:
			def load(self) -> CapabilitySnapshot:
				raise OSError("runtime checks unavailable")

		cases: list[tuple[compositionModule.StatusLoader, SettingsAdapter, str]] = [
			(
				FailedStatusLoader(),
				SettingsAdapter(SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1))),
				"KS.CAPABILITY.RUNTIME_CHECK_FAILED",
			),
			(
				StatusLoader(_snapshot(unavailable=frozenset({"userInterface"}))),
				SettingsAdapter(SettingsLoadResult("failed", None, "KS.SETTINGS.READ_FAILED")),
				"KS.SETTINGS.READ_FAILED",
			),
		]
		for status, settings, expectedCode in cases:
			with self.subTest(expectedCode=expectedCode):
				registry = PanelRegistry()
				composition = _assembleProductionComposition(
					statusLoader=status,
					settingsAdapter=settings,
					panelRegistry=registry,
					captureManagement=ClosedCaptureManagement(),
				)
				composition.start()
				controller = registry.added[0][1]()
				self.assertFalse(composition.operationalEligible)
				self.assertEqual(expectedCode, composition.startupIssueCode)
				statuses = {
					record.capabilityId: record.status for record in controller._capabilities.values()
				}
				if expectedCode == "KS.CAPABILITY.RUNTIME_CHECK_FAILED":
					self.assertEqual({"heldClosed"}, set(statuses.values()))
				else:
					self.assertEqual("unavailable", statuses["userInterface"])
					self.assertEqual("enabled", statuses["eventMonitoring"])
				composition.close()

	def test_duplicate_start_and_repeated_close_preserve_reverse_ownership(self) -> None:
		events: list[str] = []
		composition, _, _, registry = _composition(
			events=events,
			releases=(
				("first", lambda: events.append("release-first")),
				("second", lambda: events.append("release-second")),
			),
		)
		composition.start()

		with self.assertRaisesRegex(RuntimeError, "already started"):
			composition.start()
		composition.close()
		composition.close()

		self.assertEqual(
			["panel-add", "panel-remove", "release-second", "release-first"],
			events,
		)
		self.assertEqual(1, len(registry.removed))

	def test_composition_teardown_releases_the_publication_backend_once(self) -> None:
		class _Backend:
			def __init__(self) -> None:
				super().__init__()
				self.closeCalls = 0

			def close(self) -> None:
				self.closeCalls += 1

		class _Root:
			def close(self) -> None:
				pass

		backend = _Backend()
		with (
			TemporaryDirectory() as temporary,
			patch.object(compositionModule, "LocalPublicationBackend", return_value=backend),
			patch.object(compositionModule, "fixedOutputRoot", return_value=Path(temporary)),
			patch.object(compositionModule, "snapshotOutputRoot", return_value=Path(temporary)),
		):
			services = compositionModule._buildConcreteManagementServices(
				lifecycle=compositionModule.LifecycleService(),
				capabilities=_snapshot(),
				settings=SettingsSnapshot.defaults(settingsRevision=1),
			)
		composition = ProductionComposition(
			root=_Root(),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			releaseCallbacks=services.releaseCallbacks,
		)

		composition.close()
		composition.close()

		self.assertEqual(1, backend.closeCalls)

	def test_secure_transition_invalidates_then_close_remains_idempotent(self) -> None:
		events: list[str] = []
		composition, _, _, _ = _composition(
			events=events,
			releases=(("owned", lambda: events.append("release-owned")),),
		)
		composition.start()

		composition.transition("secure")
		composition.close()

		self.assertEqual(["panel-add", "panel-remove", "release-owned"], events)
		self.assertFalse(composition.operationalEligible)

	def test_terminal_transition_releases_owned_resources_when_command_teardown_fails(self) -> None:
		events: list[str] = []

		class _Root:
			def start(self, settings: SettingsSnapshot) -> None:
				_ = settings
				events.append("root-start")

			def transition(self, state: str) -> None:
				events.append(f"root-transition:{state}")

			def close(self) -> None:
				events.append("root-close")

		class _Layer:
			def invalidate(self) -> None:
				events.append("layer-invalidate")
				raise RuntimeError("layer failure")

		class _Runtime:
			def close(self) -> None:
				events.append("runtime-close")
				raise RuntimeError("runtime failure")

		composition = ProductionComposition(
			root=_Root(),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			releaseCallbacks=(
				("first", lambda: events.append("release-first")),
				("second", lambda: events.append("release-second")),
			),
		)
		composition.configureCommands(cast(object, _Layer()), cast(object, _Runtime()))  # type: ignore[arg-type]
		composition.start()

		composition.transition("terminating")
		composition.close()

		self.assertEqual(
			[
				"root-start",
				"root-transition:terminating",
				"layer-invalidate",
				"runtime-close",
				"release-second",
				"release-first",
			],
			events,
		)
		self.assertTrue(composition.closed)
		self.assertFalse(composition.operationalEligible)

	def test_partial_panel_construction_is_removed_and_releases_reverse(self) -> None:
		events: list[str] = []
		registry = PartiallyFailingPanelRegistry(events)
		composition = _assembleProductionComposition(
			statusLoader=StatusLoader(_snapshot()),
			settingsAdapter=SettingsAdapter(
				SettingsLoadResult("ready", SettingsSnapshot.defaults(settingsRevision=1)),
			),
			panelRegistry=registry,
			captureManagement=ClosedCaptureManagement(),
			releaseCallbacks=(
				("first", lambda: events.append("release-first")),
				("second", lambda: events.append("release-second")),
			),
		)

		with self.assertRaisesRegex(RuntimeError, "partial panel registration"):
			composition.start()
		composition.close()

		self.assertEqual(
			["panel-add", "panel-remove", "release-second", "release-first"],
			events,
		)

	def test_reload_shape_terminates_old_owner_before_new_start(self) -> None:
		events: list[str] = []
		old, _, _, _ = _composition(
			events=events,
			releases=(("old", lambda: events.append("old-release")),),
		)
		new, _, _, _ = _composition(events=events)
		old.start()

		old.close()
		new.start()

		self.assertEqual(
			["panel-add", "panel-remove", "old-release", "panel-add"],
			events,
		)

	def test_interleaved_command_and_monitor_work_tears_down_once_at_secure_then_reloads(
		self,
	) -> None:
		# A cross-subsystem race: the command layer and Inspector runtime are live, a monitor drain
		# and an export are in flight, and a pending cue is armed when the secure desktop arrives.
		# The composition invalidates the shared voice, invalidates the command layer, closes the
		# runtime, releases owned resources in reverse, and refuses further work. A close after the
		# secure boundary is idempotent, and a fresh reload composition starts wholly independently.
		events: list[str] = []

		class _Sound:
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
				events.append("sound-invalidate")

		class _Layer:
			def enter(self) -> None:
				pass

			def invalidate(self) -> None:
				events.append("layer-invalidate")

		class _Runtime:
			def close(self) -> None:
				events.append("runtime-close")

			def openInspectorForReview(self, targetKind: str = "focus") -> None:
				_ = targetKind

		class _Root:
			def __init__(self) -> None:
				super().__init__()
				self.captureManagement = SimpleNamespace()
				self.lifecycle = compositionModule.LifecycleService()

			def start(self, settings: object) -> None:
				events.append("root-start")

			def transition(self, state: str) -> None:
				events.append(f"root-transition:{state}")

			def close(self) -> None:
				events.append("root-close")

		sound = _Sound()
		composition = ProductionComposition(
			root=_Root(),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			releaseCallbacks=(
				("uia-provider", lambda: events.append("release-provider")),
				("audio-port", lambda: events.append("release-audio")),
			),
			workflowSound=sound,
		)
		composition.configureCommands(cast(object, _Layer()), cast(object, _Runtime()))  # type: ignore[arg-type]
		composition.start()
		self.assertTrue(composition.operationalEligible)

		composition.transition("secure")
		secureBoundary = list(events)

		# Late work is refused: the composition is no longer operationally eligible and the command
		# surface has been invalidated (the live layer denies through the shared lifecycle).
		self.assertFalse(composition.operationalEligible)
		self.assertIn("layer-invalidate", secureBoundary)
		self.assertIn("runtime-close", secureBoundary)

		# A close after secure never replays owned-resource release.
		composition.close()
		composition.close()

		self.assertEqual(
			secureBoundary,
			[
				"root-start",
				"root-transition:secure",
				"sound-invalidate",
				"layer-invalidate",
				"runtime-close",
				"release-audio",
				"release-provider",
			],
		)
		self.assertEqual(1, events.count("release-provider"))
		self.assertEqual(1, events.count("release-audio"))
		# The voice is invalidated at each terminal boundary (secure, then close) and stays a no-op
		# for the second close; owned resources still release only once.
		self.assertEqual(2, sound.invalidations)

		# Reload independence: a fresh composition starts and closes on its own ownership.
		reloadEvents: list[str] = []
		reload, _, _, reloadRegistry = _composition(events=reloadEvents)
		reload.start()
		reload.close()
		self.assertEqual(["panel-add", "panel-remove"], reloadEvents)
		self.assertEqual(1, len(reloadRegistry.removed))


class GlobalPluginTests(unittest.TestCase):
	def test_automated_runtime_review_waits_for_post_restart_focus_to_settle(self) -> None:
		self.assertEqual(10_000, pluginModule._AUTOMATED_REVIEW_DELAY_MS)

	def test_automated_runtime_request_is_fixed_consumed_and_noninteractive(self) -> None:
		with TemporaryDirectory() as directory:
			request = Path(directory) / "keystone-automated-review.request"
			_ = request.write_text("", encoding="utf-8")
			with patch.dict(pluginModule.os.environ, {"TEMP": directory}, clear=True):
				output = pluginModule._automatedReviewOutput()

			self.assertEqual(Path(directory) / "keystone-automated-review.json", output)
			self.assertFalse(request.exists())

	def test_automated_runtime_review_publishes_screenshot_evidence_without_opening_ui(self) -> None:
		rawProjection = {
			"rawProjectionRequested": True,
			"rawProjectionApplied": False,
			"rawProjectionStatus": "rejected",
			"rawProjectionMethod": "none",
			"rawProjectionReason": "KS.RAW_UIA.NO_CANDIDATE",
			"rawProjectionEvidenceQuality": "incomplete",
			"rawProjectionEvidencePresent": True,
			"ordinaryUiaSectionPresent": True,
		}
		moduleEvidence = {
			"hostProcessId": 7368,
			"loadedCodeIdentifier": f"sha256:{'a' * 64}",
			"reviewHookModulePath": r"C:\profile\addons\keystone\review_hook.py",
			"reviewHookModuleSha256": "a" * 64,
			"rawUiaModulePath": r"C:\profile\addons\keystone\raw_uia.py",
			"rawUiaModuleSha256": "b" * 64,
			"selectedObjectsModulePath": r"C:\profile\addons\keystone\selected_objects.py",
			"selectedObjectsModuleSha256": "c" * 64,
		}
		with (
			TemporaryDirectory() as directory,
			patch.object(reviewHookModule, "_runtimeScreenshot", return_value=("value", 128)),
			patch.object(reviewHookModule, "_runtimeRawProjection", return_value=rawProjection),
			patch.object(reviewHookModule, "_loadedModuleEvidence", return_value=moduleEvidence),
		):
			output = Path(directory) / "runtime.json"
			payload = reviewHookModule.runAutomatedRuntimeReview(
				output,
				enabledCapabilities=frozenset({"screenCapture", "userInterface"}),
				inspectorRawRetarget={
					"succeeded": True,
					"requested": True,
					"applied": False,
					"sourceGeneration": 2,
				},
			)

			self.assertEqual("pass", payload["status"])
			self.assertEqual(128, payload["screenshotBytes"])
			self.assertEqual(rawProjection["rawProjectionStatus"], payload["rawProjectionStatus"])
			self.assertTrue(payload["rawProjectionEvidencePresent"])
			self.assertEqual(payload, json.loads(output.read_text(encoding="utf-8")))

	def test_automated_runtime_review_fails_closed_without_raw_projection_evidence(self) -> None:
		rawProjection = {
			"rawProjectionRequested": True,
			"rawProjectionApplied": False,
			"rawProjectionStatus": "rejected",
			"rawProjectionMethod": "none",
			"rawProjectionReason": "KS.RAW_UIA.NO_CANDIDATE",
			"rawProjectionEvidenceQuality": "incomplete",
			"rawProjectionEvidencePresent": False,
			"ordinaryUiaSectionPresent": True,
		}
		moduleEvidence = {
			"hostProcessId": 7368,
			"loadedCodeIdentifier": f"sha256:{'a' * 64}",
		}
		with (
			TemporaryDirectory() as directory,
			patch.object(reviewHookModule, "_runtimeScreenshot", return_value=("value", 128)),
			patch.object(reviewHookModule, "_runtimeRawProjection", return_value=rawProjection),
			patch.object(reviewHookModule, "_loadedModuleEvidence", return_value=moduleEvidence),
		):
			payload = reviewHookModule.runAutomatedRuntimeReview(
				Path(directory) / "runtime.json",
				enabledCapabilities=frozenset({"screenCapture", "rawUiaInspection"}),
				inspectorRawRetarget={
					"succeeded": True,
					"requested": True,
					"applied": False,
					"sourceGeneration": 2,
				},
			)

		self.assertEqual("failed", payload["status"])

	def test_secure_desktop_action_tears_down_and_rebuilds_the_owned_composition(self) -> None:
		class _Action:
			def __init__(self) -> None:
				super().__init__()
				self.handlers: list[Callable[[bool | None], None]] = []

			def register(self, handler: Callable[[bool | None], None]) -> None:
				self.handlers.append(handler)

			def unregister(self, handler: Callable[[bool | None], None]) -> None:
				self.handlers.remove(handler)

			def notify(self, value: bool) -> None:
				for handler in tuple(self.handlers):
					handler(value)

		first, _, _, _ = _composition()
		second, _, _, _ = _composition()
		pending = [first, second]
		action = _Action()
		secureDesktop = SimpleNamespace(post_secureDesktopStateChange=action)

		def imported(name: str) -> object:
			if name == "winAPI.secureDesktop":
				return secureDesktop
			raise ImportError(name)

		with patch.object(pluginModule, "import_module", side_effect=imported):
			plugin = pluginModule.GlobalPlugin(
				_compositionFactory=lambda: pending.pop(0),
				_secureDesktop=False,
			)

		self.assertEqual(1, len(action.handlers))
		self.assertTrue(first.started)

		action.notify(True)
		self.assertFalse(first.operationalEligible)
		action.notify(False)

		self.assertTrue(first.closed)
		self.assertTrue(second.started)
		self.assertIs(second, plugin._composition)
		plugin.terminate()
		self.assertTrue(second.closed)
		self.assertEqual([], action.handlers)

	def test_secure_desktop_restart_closes_replacement_when_start_fails(self) -> None:
		events: list[str] = []

		class _FailingRoot:
			def start(self, settings: SettingsSnapshot) -> None:
				_ = settings
				raise RuntimeError("replacement start failed")

			def close(self) -> None:
				events.append("replacement-root-close")

		first, _, _, _ = _composition(
			releases=(("old", lambda: events.append("old-release")),),
		)
		replacement = ProductionComposition(
			root=_FailingRoot(),  # type: ignore[arg-type]
			settings=SettingsSnapshot.defaults(settingsRevision=1),
			operationalEligible=True,
			startupIssueCode=None,
			releaseCallbacks=(("replacement", lambda: events.append("replacement-release")),),
		)
		pending = [first, replacement]
		plugin = pluginModule.GlobalPlugin(
			_compositionFactory=lambda: pending.pop(0),
			_secureDesktop=True,
		)

		with patch.object(first, "close", wraps=first.close) as closeOld:
			plugin._onSecureDesktopChange(False)

		self.assertEqual(1, closeOld.call_count)
		self.assertTrue(replacement.closed)
		self.assertIsNone(plugin._composition)
		self.assertEqual(
			["old-release", "replacement-root-close", "replacement-release"],
			events,
		)

	def test_secure_desktop_restart_closes_replacement_when_build_fails(self) -> None:
		events: list[str] = []
		first, _, _, _ = _composition()
		replacement, _, _, _ = _composition(
			releases=(("replacement", lambda: events.append("replacement-release")),),
		)
		pending = [first, replacement]
		plugin = pluginModule.GlobalPlugin(
			_compositionFactory=lambda: pending.pop(0),
			_secureDesktop=True,
		)

		with patch.object(replacement, "useEventSource", side_effect=RuntimeError("source setup failed")):
			plugin._onSecureDesktopChange(False)

		self.assertTrue(replacement.closed)
		self.assertIsNone(plugin._composition)
		self.assertEqual(["replacement-release"], events)

	def test_installed_custom_uia_observation_uses_the_public_element_attribute(self) -> None:
		element = object()
		target = SimpleNamespace(
			appModule=SimpleNamespace(appName="reader"),
			UIAElement=element,
		)
		reads: list[tuple[str, object]] = []

		class _Source:
			def selectedObject(self, _kind: str) -> object:
				return target

		class _Getter:
			def pollPotentialProperties(self, candidate: object) -> object:
				reads.append(("properties", candidate))
				return SimpleNamespace(status="value")

			def pollPotentialPatterns(self, candidate: object) -> object:
				reads.append(("patterns", candidate))
				return SimpleNamespace(status="empty")

		with (
			patch.object(reviewHookModule, "NvdaSelectedObjectSource", return_value=_Source()),
			patch.object(reviewHookModule, "NvdaCustomUiaGetter", return_value=_Getter()),
		):
			observation = reviewHookModule._customObservation()

		self.assertEqual(
			[("properties", element), ("patterns", element)],
			reads,
		)
		self.assertEqual("value", observation["propertyPolling"])
		self.assertEqual("empty", observation["patternPolling"])

	def test_custom_uia_is_a_named_input_gestures_script(self) -> None:
		composition, _, _, _ = _composition()
		plugin = pluginModule.GlobalPlugin(_compositionFactory=lambda: composition)
		opened: list[object | None] = []

		def openCustomUia(
			*,
			parent: object | None = None,
			currentExecutable: str | None = None,
		) -> None:
			_ = currentExecutable
			opened.append(parent)

		with patch.object(
			composition,
			"openCustomUiaProperties",
			side_effect=openCustomUia,
		):
			plugin.script_keystoneCustomUiaProperties(object())

		description = pluginModule.GlobalPlugin.script_keystoneCustomUiaProperties.__doc__
		self.assertIsNotNone(description)
		self.assertIn("Custom UIA Properties", cast(str, description))
		self.assertEqual([None], opened)
		plugin.terminate()

	def test_no_argument_constructor_builds_and_starts_exactly_one_owned_product(self) -> None:
		signature = inspect.signature(pluginModule.GlobalPlugin)
		self.assertNotIn("composition", signature.parameters)
		composition, _, _, _ = _composition()
		calls = 0

		def factory() -> ProductionComposition:
			nonlocal calls
			calls += 1
			return composition

		plugin = pluginModule.GlobalPlugin(_compositionFactory=factory)

		self.assertEqual(1, calls)
		self.assertTrue(composition.started)
		plugin.terminate()
		plugin.terminate()
		self.assertTrue(composition.closed)

	def test_low_level_factory_must_return_owned_product_composition(self) -> None:
		with self.assertRaisesRegex(TypeError, "ProductionComposition"):
			pluginModule.GlobalPlugin(_compositionFactory=lambda: object())  # type: ignore[arg-type, return-value]

	def test_navigator_event_accepts_the_host_focus_keyword(self) -> None:
		composition, _, _, _ = _composition()
		plugin = pluginModule.GlobalPlugin(_compositionFactory=lambda: composition)
		forwarded: list[tuple[object, object, bool]] = []
		nextCalls: list[str] = []

		class EventSource:
			def forward(self, eventType: object, obj: object, *, isFocus: bool = False) -> None:
				forwarded.append((eventType, obj, isFocus))

		target = object()
		plugin._eventSource = EventSource()  # type: ignore[assignment]
		plugin.event_becomeNavigatorObject(
			target,
			lambda: nextCalls.append("next"),
			isFocus=True,
		)

		self.assertEqual([(pluginModule.NvdaEventType.NAVIGATOR_OBJECT, target, True)], forwarded)
		self.assertEqual(["next"], nextCalls)
		plugin.terminate()

	def test_focus_event_is_offered_to_the_inspector_before_forwarding(self) -> None:
		composition, _, _, _ = _composition()
		plugin = pluginModule.GlobalPlugin(_compositionFactory=lambda: composition)
		observed: list[object] = []
		forwarded: list[tuple[object, object]] = []
		order: list[str] = []

		class EventSource:
			def forward(self, eventType: object, obj: object) -> None:
				forwarded.append((eventType, obj))
				order.append("forward")

		target = object()
		plugin._eventSource = EventSource()  # type: ignore[assignment]

		def observe(obj: object) -> None:
			observed.append(obj)
			order.append("observe")

		with patch.object(
			composition,
			"observeFocus",
			side_effect=observe,
		):
			plugin.event_gainFocus(target, lambda: order.append("next"))

		self.assertEqual([target], observed)
		self.assertEqual([(pluginModule.NvdaEventType.FOCUS, target)], forwarded)
		self.assertEqual(["observe", "forward", "next"], order)
		plugin.terminate()


class RuntimeSettingsApplicationTests(unittest.TestCase):
	"""A committed settings change must reach the services already running."""

	def _composition(self) -> ProductionComposition:
		composition, _statusLoader, _settingsAdapter, _registry = _composition()
		composition.start()
		return composition

	def test_a_committed_change_reaches_the_live_monitor_policy_and_limits(self) -> None:
		composition = self._composition()
		service = composition._buildLiveEventMonitorService()
		before = composition._privacyPolicy()

		composition.applySettings(
			replace(
				SettingsSnapshot.defaults(settingsRevision=9),
				redactProtectedText=True,
				eventRows=25,
				eventDetailCharacters=7,
			),
		)

		policy = composition._privacyPolicy()
		self.assertFalse(before.redactProtectedText)
		self.assertTrue(policy.redactProtectedText)
		self.assertEqual(9, policy.settingsRevision)
		self.assertGreater(policy.policyRevision, before.policyRevision)
		# The service reads both through the composition, so the new values are what it will use.
		self.assertTrue(service._policy().redactProtectedText)
		self.assertEqual(25, service._settings().eventRows)
		self.assertEqual(7, service._settings().eventDetailCharacters)

	def test_a_committed_change_reaches_capture_diff_and_the_inspector(self) -> None:
		composition = self._composition()
		runtime = ProductionCommandRuntime.__new__(ProductionCommandRuntime)
		staged: list[tuple[str, object]] = []

		class _Capture:
			def stageConfiguration(self, settings: SettingsSnapshot, policy: PrivacyPolicy) -> None:
				staged.append(("capture", (settings, policy)))

		class _Diff:
			def stageConfiguration(self, policy: PrivacyPolicy) -> None:
				staged.append(("diff", policy))

		class _Inspector:
			def applySettings(self, settings: SettingsSnapshot) -> None:
				staged.append(("inspector", settings))

		runtime._capture = cast(Any, _Capture())
		runtime._diff = cast(Any, _Diff())
		runtime._inspectorService = cast(Any, _Inspector())
		runtime._settings = SettingsSnapshot.defaults(settingsRevision=1)
		composition._commandRuntime = runtime

		updated = replace(
			SettingsSnapshot.defaults(settingsRevision=9),
			redactProtectedText=True,
			propertyIntervalMilliseconds=2_000,
		)
		composition.applySettings(updated)

		self.assertEqual(["capture", "diff", "inspector"], [name for name, _payload in staged])
		captureSettings, capturePolicy = cast(
			tuple[SettingsSnapshot, PrivacyPolicy],
			staged[0][1],
		)
		self.assertEqual(9, captureSettings.settingsRevision)
		self.assertTrue(capturePolicy.redactProtectedText)
		self.assertEqual(composition._privacyPolicy(), capturePolicy)
		self.assertEqual(capturePolicy, staged[1][1])
		self.assertEqual(2_000, cast(SettingsSnapshot, staged[2][1]).propertyIntervalMilliseconds)
		self.assertEqual(9, runtime._settings.settingsRevision)

	def test_the_policy_revision_only_moves_forward(self) -> None:
		composition = self._composition()
		first = composition._privacyPolicy().policyRevision

		composition.applySettings(replace(SettingsSnapshot.defaults(settingsRevision=40)))
		second = composition._privacyPolicy().policyRevision
		composition.applySettings(replace(SettingsSnapshot.defaults(settingsRevision=41)))
		third = composition._privacyPolicy().policyRevision

		self.assertGreater(second, first)
		self.assertGreater(third, second)

	def test_applying_the_same_revision_does_not_move_the_policy(self) -> None:
		composition = self._composition()
		before = composition._privacyPolicy()

		composition.applySettings(composition._settings)

		self.assertEqual(before, composition._privacyPolicy())

	def test_a_closed_composition_refuses_a_settings_change(self) -> None:
		composition = self._composition()
		before = composition._privacyPolicy()
		composition.close()

		composition.applySettings(replace(SettingsSnapshot.defaults(settingsRevision=4)))

		self.assertEqual(before, composition._privacyPolicy())

	def test_the_relay_carries_a_change_only_while_a_composition_is_attached(self) -> None:
		relay = compositionModule._RuntimeSettingsRelay()
		settings = replace(SettingsSnapshot.defaults(settingsRevision=3), redactProtectedText=True)

		# Before attachment this is a silent no-op rather than a failure.
		relay.applySettings(settings)

		composition = self._composition()
		relay.attach(composition)
		relay.applySettings(settings)

		self.assertTrue(composition._privacyPolicy().redactProtectedText)


class NativeRuntimeLoggingTests(unittest.TestCase):
	def test_committed_settings_emit_a_native_nvda_record(self) -> None:
		records: list[LogicalRecord] = []

		class Sink:
			def emit(self, record: LogicalRecord) -> None:
				records.append(record)

		service = LoggingService(
			nvdaSink=Sink(),
			sequenceAllocator=SequenceAllocator(),
			privacyPolicy=PrivacyPolicy(1, 1, False),
		)
		runtimeLog = compositionModule._RuntimeLog(service, CorrelationFactory().admit(generation=1))
		settings = SettingsSnapshot.defaults(settingsRevision=2)
		runtimeLog.reconfigure(settings, PrivacyPolicy(2, 2, True))

		self.assertEqual(["KS.SETTINGS.GLOBAL_CHANGED"], [record.code for record in records])
		self.assertEqual(2, dict(records[0].fields)["policyRevision"])


if __name__ == "__main__":
	_ = unittest.main()
