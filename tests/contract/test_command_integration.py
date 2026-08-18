from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Literal, cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda.commands import (
	CommandExecutionResult,
	NvdaCommandHost,
	NvdaCommandLayer,
	ProductionCommandRuntime,
)
from addon.globalPlugins.keystone.adapters.windows.publication import (
	CaptureKind,
	CleanupOutcome,
	DiscoverySnapshot,
	PublicationPackage,
	PublicationPolicy,
	PublicationReceipt,
	PublicationResult,
)
from addon.globalPlugins.keystone.application.lifecycle import LifecycleService
from addon.globalPlugins.keystone.application.output_service import OutputService
from addon.globalPlugins.keystone.application.sound_service import WorkflowSounds
from addon.globalPlugins.keystone.domain.commands import COMMAND_BY_KEY, CommandId
from addon.globalPlugins.keystone.domain.correlation import CorrelationContext
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.domain.sounds import (
	CueAtomId,
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	SoundRequest,
)
from addon.globalPlugins.keystone.domain.traversal import TraversalProgress
from addon.globalPlugins.keystone.presentation.commands import (
	commandHelpText,
	keyboardReferenceMarkdown,
)
from addon.globalPlugins.keystone.ports.effects import (
	ClipboardRequest,
	EffectResult,
	FeedbackRequest,
	PortOutcome,
	PortStatus,
	ScreenshotAttempt,
	ScreenshotResult,
	ShellRequest,
)


@dataclass
class _Gesture:
	normalizedIdentifiers: tuple[str, ...]


class _Lifecycle:
	def __init__(self) -> None:
		super().__init__()
		self.generation = 7
		self.current = True
		self.state = "ordinary"

	def isCurrent(self, generation: int) -> bool:
		return self.current and generation == self.generation


class _Host:
	def __init__(self, timeline: list[tuple[str, str]] | None = None) -> None:
		super().__init__()
		self.capture: Callable[[object], bool] | None = None
		self.messages: list[str] = []
		self.announcements: list[tuple[str, str]] = []
		self.help: list[tuple[str, str]] = []
		self.scheduled: list[Callable[[], None]] = []
		self.scheduledMilliseconds: dict[Callable[[], None], int] = {}
		self.timeline = timeline

	def installCapture(self, capture: Callable[[object], bool]) -> object:
		previous = self.capture
		self.capture = capture
		return previous

	def restoreCapture(self, previous: object) -> None:
		self.capture = cast(Callable[[object], bool], previous) if callable(previous) else None

	def announce(self, message: str, *, priority: str = "normal") -> None:
		self.messages.append(message)
		self.announcements.append((message, priority))
		if self.timeline is not None:
			self.timeline.append(("announce", message))

	def showHelp(self, title: str, message: str) -> None:
		self.help.append((title, message))

	def callLater(self, milliseconds: int, callback: Callable[[], None]) -> object:
		self.scheduled.append(callback)
		self.scheduledMilliseconds[callback] = milliseconds
		return callback

	def cancelCall(self, callback: object) -> None:
		if callback in self.scheduled:
			self.scheduled.remove(callback)  # type: ignore[arg-type]
			_ = self.scheduledMilliseconds.pop(cast(Callable[[], None], callback), None)

	def popScheduled(self, milliseconds: int) -> Callable[[], None]:
		for index, callback in enumerate(self.scheduled):
			if self.scheduledMilliseconds.get(callback) == milliseconds:
				_ = self.scheduled.pop(index)
				del self.scheduledMilliseconds[callback]
				return callback
		raise AssertionError(f"no callback scheduled for {milliseconds} ms")


class _ThrowingHost(_Host):
	def __init__(self, *, announce: bool = False, showHelp: bool = False) -> None:
		super().__init__()
		self._throwAnnounce = announce
		self._throwShowHelp = showHelp
		self.announceAttempts: list[tuple[str, str]] = []
		self.helpAttempts: list[tuple[str, str]] = []

	@override
	def announce(self, message: str, *, priority: str = "normal") -> None:
		self.announceAttempts.append((message, priority))
		if self._throwAnnounce:
			raise RuntimeError("announce failed")
		super().announce(message, priority=priority)

	@override
	def showHelp(self, title: str, message: str) -> None:
		self.helpAttempts.append((title, message))
		if self._throwShowHelp:
			raise RuntimeError("show help failed")
		super().showHelp(title, message)


class _Runtime:
	def __init__(self) -> None:
		super().__init__()
		self.executed: list[CommandId] = []
		self.cancelled: list[CommandId] = []
		self.copied: list[CommandId] = []
		self.revealed: list[CommandId] = []

	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		return CommandExecutionResult("completed", committed=True)

	def requestCancellation(self, commandId: CommandId) -> None:
		self.cancelled.append(commandId)

	def copyNewest(self, commandId: CommandId) -> bool:
		self.copied.append(commandId)
		return True

	def revealNewest(self, commandId: CommandId) -> bool:
		self.revealed.append(commandId)
		return True


class _InspectionFeedbackRuntime(_Runtime):
	def __init__(self) -> None:
		super().__init__()
		self._results = {
			CommandId.EVENT_MONITOR: CommandExecutionResult("completed", announcementHandled=True),
			CommandId.EVENT_MONITOR_TOGGLE: CommandExecutionResult("completed", announcementHandled=True),
			CommandId.CUSTOM_UIA_PROPERTIES: CommandExecutionResult("completed"),
		}

	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		return self._results[commandId]


class _TracingRuntime(_Runtime):
	def __init__(self, timeline: list[tuple[str, str]]) -> None:
		super().__init__()
		self._timeline = timeline

	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self._timeline.append(("execute", commandId.value))
		return super().execute(commandId)


class _BlockingRuntime(_Runtime):
	def __init__(self) -> None:
		super().__init__()
		self.entered = threading.Event()
		self.release = threading.Event()
		self.cancellationRequested = threading.Event()

	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		self.entered.set()
		if not self.release.wait(2):
			raise TimeoutError("controlled command was not released")
		return CommandExecutionResult("cancelled")

	@override
	def requestCancellation(self, commandId: CommandId) -> None:
		super().requestCancellation(commandId)
		self.cancellationRequested.set()


class _ReentrantRuntime(_Runtime):
	def __init__(self, result: CommandExecutionResult) -> None:
		super().__init__()
		self.result = result
		self.onExecute: Callable[[], None] | None = None

	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		if self.onExecute is not None:
			self.onExecute()
		return self.result


class _OutputRepository:
	def __init__(self, receipt: PublicationReceipt) -> None:
		super().__init__()
		self._receipt = receipt
		self.newestKinds: list[CaptureKind] = []
		self.contexts: list[CorrelationContext] = []
		self.revalidated: list[PublicationReceipt] = []

	def publish(
		self,
		package: PublicationPackage,
		policyProvider: Callable[[], PublicationPolicy],
		context: CorrelationContext,
	) -> PublicationResult:
		raise AssertionError("copy and reveal actions must not publish")

	def discover(self, context: CorrelationContext) -> DiscoverySnapshot:
		raise AssertionError("copy and reveal actions must not discover")

	def clearAll(self, discoveryRevision: int, context: CorrelationContext) -> CleanupOutcome:
		raise AssertionError("copy and reveal actions must not clear")

	def revalidate(self, receipt: PublicationReceipt, context: CorrelationContext) -> bool:
		self.revalidated.append(receipt)
		self.contexts.append(context)
		return receipt == self._receipt

	def newest(self, captureKind: CaptureKind, context: CorrelationContext) -> PublicationReceipt | None:
		self.newestKinds.append(captureKind)
		self.contexts.append(context)
		return self._receipt


class _OutputFeedback:
	def announce(self, request: FeedbackRequest) -> EffectResult:
		return EffectResult(PortStatus("ready", request.context.generation or 0), PortOutcome("announced"))


class _OutputClipboard:
	def __init__(self) -> None:
		super().__init__()
		self.requests: list[ClipboardRequest] = []

	def copyText(self, request: ClipboardRequest) -> EffectResult:
		self.requests.append(request)
		return EffectResult(PortStatus("ready", request.context.generation or 0), PortOutcome("copied"))


class _OutputShell:
	def __init__(self) -> None:
		super().__init__()
		self.revealed: list[ShellRequest] = []

	def openFolder(self, request: ShellRequest) -> EffectResult:
		return EffectResult(PortStatus("ready", request.statusRevision), PortOutcome("opened"))

	def revealFile(self, request: ShellRequest) -> EffectResult:
		self.revealed.append(request)
		return EffectResult(PortStatus("ready", request.statusRevision), PortOutcome("revealed"))


class _UnusedScreenshot:
	def captureScreenshot(self, attempt: ScreenshotAttempt) -> ScreenshotResult:
		raise AssertionError("copy and reveal actions must not capture screenshots")


class _UnusedSelectedSource:
	def selectedObject(self, targetKind: Literal["foreground", "focus", "navigator"]) -> object:
		raise AssertionError("copy and reveal actions must not read selected objects")


def _outputReceipt() -> PublicationReceipt:
	folderName = "20260728-092500.000-snapshot"
	return PublicationReceipt(
		"publication-a",
		Path(rf"C:\Temp\Keystone\reader.exe-42\{folderName}"),
		folderName,
		("publication-metadata.json", "snapshot.json"),
	)


class CommandLayerTracerTests(unittest.TestCase):
	def test_feedback_and_capture_run_in_separate_ordered_main_loop_callbacks(self) -> None:
		timeline: list[tuple[str, str]] = []
		host = _Host(timeline)
		runtime = _TracingRuntime(timeline)
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		timeline.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual([], timeline)
		self.assertEqual([0], [host.scheduledMilliseconds[item] for item in host.scheduled])

		host.popScheduled(0)()

		self.assertEqual(
			[("announce", "Bounded foreground capture started.")],
			timeline,
		)
		self.assertEqual([], runtime.executed)
		self.assertEqual(1, len(host.scheduled))
		self.assertEqual(10, host.scheduledMilliseconds[host.scheduled[0]])

		host.popScheduled(10)()

		self.assertEqual(
			[
				("announce", "Bounded foreground capture started."),
				("execute", CommandId.FOREGROUND_BOUNDED.value),
			],
			timeline[:2],
		)

	def test_all_capture_commands_handoff_feedback_then_yield_before_execution(self) -> None:
		cases = (
			(("kb:s",), CommandId.FOREGROUND_BOUNDED, "Bounded foreground capture started."),
			(("kb:shift+s",), CommandId.FOREGROUND_UNLIMITED, "Unlimited foreground capture started."),
			(
				("kb:f",),
				CommandId.FOCUS_UNLIMITED,
				"Unlimited focus-object subtree snapshot capture started.",
			),
			(("kb:d",), CommandId.DIFF, "Foreground diff started."),
			(("kb:n",), CommandId.NAVIGATOR_BOUNDED, "Bounded navigator capture started."),
			(("kb:shift+n",), CommandId.NAVIGATOR_UNLIMITED, "Unlimited navigator capture started."),
			(
				("kb:shift+o",),
				CommandId.NAVIGATOR_SUBTREE_UNLIMITED,
				"Unlimited navigator-object subtree capture started.",
			),
		)

		for identifiers, commandId, startMessage in cases:
			with self.subTest(commandId=commandId.value):
				timeline: list[tuple[str, str]] = []
				host = _Host(timeline)
				runtime = _TracingRuntime(timeline)
				layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)
				layer.enter()
				timeline.clear()
				assert host.capture is not None

				self.assertFalse(host.capture(_Gesture(identifiers)))
				self.assertEqual([], timeline)
				host.popScheduled(0)()

				self.assertEqual([("announce", startMessage)], timeline)
				self.assertEqual([], runtime.executed)
				self.assertEqual(1, len(host.scheduled))
				self.assertEqual(10, host.scheduledMilliseconds[host.scheduled[0]])

				host.popScheduled(10)()

				self.assertEqual(
					[
						("announce", startMessage),
						("execute", commandId.value),
					],
					timeline[:2],
				)

	def test_matching_repeat_cancels_after_feedback_before_runtime_callback(self) -> None:
		timeline: list[tuple[str, str]] = []
		host = _Host(timeline)
		runtime = _TracingRuntime(timeline)
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		timeline.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual([], timeline)
		host.popScheduled(0)()
		self.assertEqual(
			[("announce", "Bounded foreground capture started.")],
			timeline,
		)
		self.assertEqual([], runtime.executed)

		layer.enter()
		timeline.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual([], timeline)
		host.popScheduled(0)()
		self.assertEqual(
			[
				(
					"announce",
					"Bounded foreground capture cancellation requested. "
					+ "Keystone will stop after the current provider call reaches a safe boundary.",
				),
				("announce", "Bounded foreground capture cancelled."),
			],
			timeline,
		)

		host.popScheduled(10)()
		self.assertEqual([], runtime.executed)

	def test_hook_captured_layer_feedback_waits_for_main_thread_callback(self) -> None:
		cases = (
			(("kb:escape",), "Keystone command layer cancelled."),
			(("kb:x",), "Unknown Keystone command."),
		)

		for identifiers, expected in cases:
			with self.subTest(expected=expected):
				host = _Host()
				layer = NvdaCommandLayer(_Runtime(), _Lifecycle(), host, nowMilliseconds=lambda: 100)
				layer.enter()
				messageCount = len(host.messages)
				assert host.capture is not None

				self.assertFalse(host.capture(_Gesture(identifiers)))
				self.assertEqual(messageCount, len(host.messages))
				host.popScheduled(0)()

				self.assertEqual(expected, host.messages[-1])

	def test_cross_command_busy_feedback_runs_after_main_thread_handoff(self) -> None:
		timeline: list[tuple[str, str]] = []
		host = _Host(timeline)
		runtime = _TracingRuntime(timeline)
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		timeline.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual([], timeline)

		layer.enter()
		timeline.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:n",))))
		self.assertEqual([], timeline)

		host.popScheduled(0)()
		host.popScheduled(0)()
		self.assertEqual(
			[
				("announce", "Bounded foreground capture started."),
				(
					"announce",
					"Bounded navigator capture is busy because bounded foreground capture is active. "
					+ "The active capture was not cancelled.",
				),
			],
			timeline,
		)
		self.assertEqual([], runtime.executed)
		host.popScheduled(10)()
		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)

	def test_stale_second_stage_is_rejected_by_lifecycle_generation(self) -> None:
		host = _Host()
		runtime = _Runtime()
		lifecycle = _Lifecycle()
		layer = NvdaCommandLayer(runtime, lifecycle, host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.scheduled.pop(0)()
		self.assertEqual([], runtime.executed)
		self.assertEqual(1, len(host.scheduled))

		lifecycle.generation += 1
		host.scheduled.pop(0)()

		self.assertEqual([], runtime.executed)
		self.assertNotIn("Bounded foreground capture completed.", host.messages)

	def test_matching_repeat_cancels_pending_capture_before_runtime_entry(self) -> None:
		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		while host.scheduled:
			host.scheduled.pop(0)()

		self.assertEqual([], runtime.executed)
		self.assertEqual([], runtime.cancelled)
		self.assertEqual(
			[
				"Bounded foreground capture started.",
				"Bounded foreground capture cancellation requested. "
				+ "Keystone will stop after the current provider call reaches a safe boundary.",
				"Bounded foreground capture cancelled.",
			],
			[message for message in host.messages if message.startswith("Bounded foreground capture")],
		)

	def test_prefix_then_s_dispatches_generation_owned_bounded_capture(self) -> None:
		host = _Host()
		runtime = _Runtime()
		lifecycle = _Lifecycle()
		now = 100
		layer = NvdaCommandLayer(runtime, lifecycle, host, nowMilliseconds=lambda: now)

		layer.enter()
		self.assertIsNotNone(host.capture)
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual(1, len(host.scheduled))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)
		self.assertIn("Bounded foreground capture started.", host.messages)
		self.assertIn("Bounded foreground capture completed.", host.messages)
		self.assertIsNone(host.capture)

	def test_help_uses_the_same_registry_and_escape_invalid_timeout_are_spoken(self) -> None:
		host = _Host()
		layer = NvdaCommandLayer(_Runtime(), _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:h",))))
		self.assertEqual([], host.help)
		self.assertEqual(1, len(host.scheduled))
		host.scheduled.pop(0)()
		self.assertEqual(1, len(host.help))
		self.assertIn("KLS, then S", host.help[0][1])
		self.assertIn("Keystone command help opened.", host.messages)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:escape",))))
		host.popScheduled(0)()
		self.assertIn("Keystone command layer cancelled.", host.messages)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:x",))))
		host.popScheduled(0)()
		self.assertIn("Unknown Keystone command.", host.messages)

		layer.enter()
		timeout = host.scheduled[-1]
		timeout()
		self.assertIn("Keystone command layer timed out.", host.messages)

	def test_help_callback_survives_throwing_host_help_and_announcement(self) -> None:
		sound = _RecordingSounds()
		host = _ThrowingHost(announce=True, showHelp=True)
		layer = NvdaCommandLayer(_Runtime(), _Lifecycle(), host, nowMilliseconds=lambda: 100, sound=sound)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:h",))))
		host.popScheduled(0)()

		self.assertEqual([("Keystone commands", commandHelpText())], host.helpAttempts)
		self.assertEqual(
			[
				("Keystone command layer. Press H for help or Escape to cancel.", "normal"),
				("Keystone command help could not be opened.", "normal"),
			],
			host.announceAttempts,
		)
		self.assertEqual([CueEventId.LAYER_ENTERED], sound.events())
		self.assertIsNone(host.capture)
		self.assertEqual([], host.scheduled)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:escape",))))
		host.popScheduled(0)()

		self.assertEqual(
			[CueEventId.LAYER_ENTERED, CueEventId.LAYER_ENTERED, CueEventId.LAYER_EXIT],
			sound.events(),
		)

	def test_enabled_inspection_tools_are_canonical_discoverable_commands(self) -> None:
		self.assertIs(CommandId.EVENT_MONITOR, COMMAND_BY_KEY["e"].commandId)
		self.assertIs(CommandId.EVENT_MONITOR_TOGGLE, COMMAND_BY_KEY["f5"].commandId)
		self.assertIs(CommandId.CUSTOM_UIA_PROPERTIES, COMMAND_BY_KEY["c"].commandId)
		for reference in (commandHelpText(), keyboardReferenceMarkdown()):
			self.assertIn(
				"KLS, then E" if reference == commandHelpText() else "NVDA+/, then E",
				reference,
			)
			self.assertIn("Open Event Monitor", reference)
			self.assertIn(
				"KLS, then F5" if reference == commandHelpText() else "NVDA+/, then F5",
				reference,
			)
			self.assertIn("Start or stop Event Monitor", reference)
			self.assertIn(
				"KLS, then C" if reference == commandHelpText() else "NVDA+/, then C",
				reference,
			)
			self.assertIn("Manage Custom UIA Properties", reference)

		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)
		for key, commandId in (
			("e", CommandId.EVENT_MONITOR),
			("f5", CommandId.EVENT_MONITOR_TOGGLE),
			("c", CommandId.CUSTOM_UIA_PROPERTIES),
		):
			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture((f"kb:{key}",))))
			host.popScheduled(0)()
			host.popScheduled(0)()
			host.popScheduled(0)()
			self.assertIs(commandId, runtime.executed[-1])

	def test_inspection_commands_keep_surface_feedback_and_speak_the_dialog_outcome(self) -> None:
		host = _Host()
		runtime = _InspectionFeedbackRuntime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)
		cases = (
			("e", CommandId.EVENT_MONITOR, ()),
			("f5", CommandId.EVENT_MONITOR_TOGGLE, ()),
			("c", CommandId.CUSTOM_UIA_PROPERTIES, ("Custom UIA Properties opened.",)),
		)

		for key, commandId, expectedMessages in cases:
			with self.subTest(commandId=commandId.value):
				layer.enter()
				host.messages.clear()
				assert host.capture is not None
				self.assertFalse(host.capture(_Gesture((f"kb:{key}",))))
				host.popScheduled(0)()
				host.popScheduled(0)()
				if expectedMessages:
					host.popScheduled(0)()

				self.assertEqual([commandId], runtime.executed[-1:])
				self.assertEqual(expectedMessages, tuple(host.messages))
				self.assertNotIn("Foreground capture completed.", host.messages)

	def test_event_monitor_execution_failure_uses_reachable_command_feedback(self) -> None:
		host = _Host()
		runtime = _FailingRuntime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		host.messages.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:e",))))
		host.popScheduled(0)()
		host.popScheduled(0)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.EVENT_MONITOR], runtime.executed)
		self.assertEqual(["Event Monitor could not be opened."], host.messages)
		self.assertEqual([], host.scheduled)

	def test_modifier_only_gesture_keeps_layer_for_shifted_command(self) -> None:
		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		capture = host.capture
		self.assertFalse(capture(_Gesture(("kb:shift",))))
		self.assertIs(capture, host.capture)
		self.assertNotIn("Unknown Keystone command.", host.messages)
		self.assertFalse(capture(_Gesture(("kb:shift+s",))))
		host.scheduled.pop(0)()
		host.scheduled.pop(0)()

		self.assertEqual([CommandId.FOREGROUND_UNLIMITED], runtime.executed)
		self.assertIsNone(host.capture)

	def test_layout_qualified_shifted_gesture_dispatches_without_leaking(self) -> None:
		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb(laptop):s+shift", "kb:s+shift"))))
		self.assertNotIn("Unknown Keystone command.", host.messages)
		self.assertEqual(1, len(host.scheduled))
		host.scheduled.pop(0)()
		host.scheduled.pop(0)()

		self.assertEqual([CommandId.FOREGROUND_UNLIMITED], runtime.executed)
		self.assertIsNone(host.capture)

	def test_stale_dispatch_does_not_execute_after_lifecycle_invalidation(self) -> None:
		host = _Host()
		runtime = _Runtime()
		lifecycle = _Lifecycle()
		layer = NvdaCommandLayer(runtime, lifecycle, host, nowMilliseconds=lambda: 100)
		layer.enter()
		assert host.capture is not None
		_ = host.capture(_Gesture(("kb:s",)))
		lifecycle.current = False
		host.scheduled.pop(0)()
		self.assertEqual([], runtime.executed)

	def test_owner_thread_work_slice_pumps_nvda_event_queue(self) -> None:
		events: list[bool] = []

		class _Api:
			@staticmethod
			def processPendingEvents(processEventQueue: bool = False) -> None:
				events.append(processEventQueue)

		modules = {"api": _Api()}
		with patch(
			"addon.globalPlugins.keystone.adapters.nvda.commands.import_module",
			side_effect=modules.__getitem__,
		):
			yieldControl = getattr(ProductionCommandRuntime, "_yieldControl")
			yieldControl(10)

		self.assertEqual([True], events)

	def test_nvda_host_uses_supported_non_destructive_now_priority(self) -> None:
		calls: list[tuple[str, object]] = []

		class _Priority:
			NORMAL = object()
			NEXT = object()
			NOW = object()

		class _Speech:
			Spri = _Priority

		class _Ui:
			@staticmethod
			def message(message: str, *, speechPriority: object) -> None:
				calls.append((message, speechPriority))

		modules = {"speech": _Speech(), "ui": _Ui()}
		with patch(
			"addon.globalPlugins.keystone.adapters.nvda.commands.import_module",
			side_effect=modules.__getitem__,
		):
			NvdaCommandHost().announce("Bounded foreground capture started.", priority="now")

		self.assertEqual(
			[("Bounded foreground capture started.", _Priority.NOW)],
			calls,
		)

	def test_s_then_n_overlap_keeps_s_and_prioritizes_command_specific_busy_and_terminal_speech(
		self,
	) -> None:
		host = _Host()
		runtime = _ReentrantRuntime(CommandExecutionResult("partialScreenshot", committed=True))
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		def overlap() -> None:
			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture(("kb:n",))))

		runtime.onExecute = overlap
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)
		self.assertEqual([], runtime.cancelled)
		self.assertIn(
			("Bounded foreground capture started.", "now"),
			host.announcements,
		)
		self.assertIn(
			(
				"Bounded navigator capture is busy because bounded foreground capture is active. "
				+ "The active capture was not cancelled.",
				"now",
			),
			host.announcements,
		)
		self.assertEqual(
			(
				"Bounded foreground capture completed, but the screenshot was unavailable.",
				"now",
			),
			host.announcements[-1],
		)

	def test_s_then_n_before_s_callback_keeps_s_and_clears_active_state(self) -> None:
		host = _Host()
		runtime = _Runtime()
		now = 100
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: now)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertEqual(1, len(host.scheduled))

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:n",))))
		host.popScheduled(0)()
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)
		self.assertEqual([], runtime.cancelled)
		self.assertIn(
			(
				"Bounded navigator capture is busy because bounded foreground capture is active. "
				+ "The active capture was not cancelled.",
				"now",
			),
			host.announcements,
		)
		self.assertEqual(
			("Bounded foreground capture completed.", "now"),
			host.announcements[-1],
		)

		now = 2_000
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		self.assertEqual(
			("Bounded foreground capture started.", "now"),
			host.announcements[-1],
		)

	def test_post_commit_repeats_explain_completion_before_copy_and_reveal(self) -> None:
		host = _Host()
		runtime = _Runtime()
		now = 100
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: now)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		now = 200
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		self.assertEqual(
			"Capture already finished. Newest matching output path copied.",
			host.messages[-1],
		)

		now = 300
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		self.assertEqual(
			"Capture already finished. Newest matching output revealed in Explorer.",
			host.messages[-1],
		)

	def test_matching_repeat_requests_cancellation_while_controlled_command_is_blocked(self) -> None:
		host = _Host()
		runtime = _BlockingRuntime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		command = threading.Thread(target=host.popScheduled(10))
		command.start()
		self.assertTrue(runtime.entered.wait(1))

		layer.enter()
		assert host.capture is not None
		messageCount = len(host.messages)
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		self.assertTrue(runtime.cancellationRequested.is_set())
		self.assertTrue(command.is_alive())
		self.assertEqual(messageCount, len(host.messages))
		host.popScheduled(0)()
		self.assertEqual(
			(
				"Bounded foreground capture cancellation requested. "
				"Keystone will stop after the current provider call reaches a safe boundary."
			),
			host.messages[-1],
		)

		runtime.release.set()
		command.join(2)
		self.assertFalse(command.is_alive())
		host.popScheduled(0)()
		self.assertIn("Bounded foreground capture cancelled.", host.messages)


class ProductionRuntimeOutputActionTests(unittest.TestCase):
	def _output(self) -> OutputService:
		lifecycle = LifecycleService()
		return OutputService(
			_OutputRepository(_outputReceipt()),
			_OutputFeedback(),
			_OutputClipboard(),
			_OutputShell(),
			actionIdFactory=lambda: "action-a",
			lifecycleGeneration=lifecycle.generation,
		)

	def test_inspection_tool_commands_invoke_their_composed_entry_points(self) -> None:
		lifecycle = LifecycleService()
		eventMonitorCalls: list[bool] = []
		customUiaParents: list[object] = []
		runtime = ProductionCommandRuntime(
			lifecycle,
			SettingsSnapshot.defaults(settingsRevision=1),
			self._output(),
			_UnusedScreenshot(),
			openCustomUia=lambda parent, _executable: customUiaParents.append(parent),
			openEventMonitor=lambda: eventMonitorCalls.append(True),
			selectedSource=_UnusedSelectedSource(),
		)

		eventMonitor = runtime.execute(CommandId.EVENT_MONITOR)
		customUia = runtime.execute(CommandId.CUSTOM_UIA_PROPERTIES)
		self.assertEqual("completed", eventMonitor.outcome)
		self.assertTrue(eventMonitor.announcementHandled)
		self.assertEqual("completed", customUia.outcome)
		self.assertFalse(customUia.announcementHandled)
		self.assertEqual([True], eventMonitorCalls)
		self.assertEqual([None], customUiaParents)

	def test_event_monitor_toggle_reports_its_result_without_duplicate_feedback(self) -> None:
		lifecycle = LifecycleService()
		activeAfterToggle = [True]
		runtime = ProductionCommandRuntime(
			lifecycle,
			SettingsSnapshot.defaults(settingsRevision=1),
			self._output(),
			_UnusedScreenshot(),
			openCustomUia=lambda _parent, _executable: None,
			openEventMonitor=lambda: None,
			toggleEventMonitor=lambda: activeAfterToggle[0],
			eventMonitorActive=lambda: True,
			selectedSource=_UnusedSelectedSource(),
		)

		started = runtime.execute(CommandId.EVENT_MONITOR_TOGGLE)
		activeAfterToggle[0] = False
		stopped = runtime.execute(CommandId.EVENT_MONITOR_TOGGLE)

		self.assertEqual("eventMonitorStarted", started.outcome)
		self.assertTrue(started.announcementHandled)
		self.assertEqual("eventMonitorStopped", stopped.outcome)
		self.assertTrue(stopped.announcementHandled)

	def test_copy_and_reveal_newest_use_the_real_output_service(self) -> None:
		lifecycle = LifecycleService()
		receipt = _outputReceipt()
		repository = _OutputRepository(receipt)
		clipboard = _OutputClipboard()
		shell = _OutputShell()
		output = OutputService(
			repository,
			_OutputFeedback(),
			clipboard,
			shell,
			actionIdFactory=lambda: "action-a",
			lifecycleGeneration=lifecycle.generation,
		)

		def openCustomUia(_parent: object, _executable: str | None) -> None:
			return

		runtime = ProductionCommandRuntime(
			lifecycle,
			SettingsSnapshot.defaults(settingsRevision=1),
			output,
			_UnusedScreenshot(),
			openCustomUia=openCustomUia,
			openEventMonitor=lambda: None,
			selectedSource=_UnusedSelectedSource(),
		)

		self.assertTrue(runtime.copyNewest(CommandId.FOREGROUND_BOUNDED))
		self.assertTrue(runtime.revealNewest(CommandId.DIFF))

		path = str(receipt.path)
		self.assertEqual([path], [request.text for request in clipboard.requests])
		self.assertEqual([path], [request.targetId for request in shell.revealed])
		self.assertEqual(["snapshot", "diff"], repository.newestKinds)
		self.assertEqual(2, len(repository.revalidated))
		self.assertTrue(all(context.generation == lifecycle.generation for context in repository.contexts))

	def test_capture_progress_announcement_failure_does_not_abort_progress(self) -> None:
		lifecycle = LifecycleService()
		progressSounds: list[CommandId] = []

		def failAnnouncement(_message: str) -> None:
			raise RuntimeError("speech unavailable")

		runtime = ProductionCommandRuntime(
			lifecycle,
			SettingsSnapshot.defaults(settingsRevision=1),
			self._output(),
			_UnusedScreenshot(),
			openCustomUia=lambda _parent, _executable: None,
			openEventMonitor=lambda: None,
			selectedSource=_UnusedSelectedSource(),
			announceCaptureProgress=failAnnouncement,
			emitCaptureProgressSound=progressSounds.append,
		)

		report = runtime._captureProgressReporter(  # pyright: ignore[reportPrivateUsage]
			CommandId.FOREGROUND_BOUNDED,
			"full",
		)
		report(TraversalProgress(1, 5_000, 1))

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], progressSounds)


class _RecordingSounds:
	"""A ``WorkflowSounds`` seam that records requests instead of playing them.

	Every assertion about wiring reduces to "which typed event, owned by which generation, in
	which order" — never to audio. The recorder never raises, so a passing test proves the
	surface reached the seam, not that anything sounded.
	"""

	def __init__(self) -> None:
		super().__init__()
		self.requests: list[SoundRequest] = []
		self.ticks = 0
		self.invalidations: list[SoundOwner | None] = []

	def emit(self, request: SoundRequest) -> None:
		self.requests.append(request)

	def tick(self) -> None:
		self.ticks += 1

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		self.invalidations.append(owner)

	def events(self) -> list[CueEventId]:
		return [request.event for request in self.requests]

	def captureRequests(self) -> list[SoundRequest]:
		return [request for request in self.requests if request.owner.kind == SoundOwnerKind.CAPTURE]


class _FailingSounds:
	"""A seam whose every operation raises, proving sound failures never reach speech or flow."""

	def emit(self, request: SoundRequest) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and command flow")

	def tick(self) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and command flow")

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and command flow")


class _OutcomeRuntime(_Runtime):
	def __init__(
		self,
		outcome: str,
		*,
		committed: bool = True,
		announcementHandled: bool = False,
	) -> None:
		super().__init__()
		self._outcome = outcome
		self._committed = committed
		self._announcementHandled = announcementHandled

	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		return CommandExecutionResult(
			self._outcome,
			committed=self._committed,
			announcementHandled=self._announcementHandled,
		)


class _FailingRuntime(_Runtime):
	@override
	def execute(self, commandId: CommandId) -> CommandExecutionResult:
		self.executed.append(commandId)
		raise RuntimeError("command execution failed")


class _EmptyOutputRuntime(_Runtime):
	@override
	def copyNewest(self, commandId: CommandId) -> bool:
		self.copied.append(commandId)
		return False

	@override
	def revealNewest(self, commandId: CommandId) -> bool:
		self.revealed.append(commandId)
		return False


class SoundWiringContract(unittest.TestCase):
	def _layer(
		self,
		sound: WorkflowSounds | None,
		*,
		runtime: _Runtime | None = None,
	) -> tuple[_Host, NvdaCommandLayer]:
		host = _Host()
		layer = NvdaCommandLayer(
			runtime or _Runtime(),
			_Lifecycle(),
			host,
			nowMilliseconds=lambda: 100,
			sound=sound,
		)
		return host, layer

	def test_already_announced_inspector_failure_skips_generic_command_feedback(self) -> None:
		runtime = _OutcomeRuntime("failed", committed=False, announcementHandled=True)
		host, layer = self._layer(None, runtime=runtime)

		layer.enter()
		host.messages.clear()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:i",))))
		host.popScheduled(0)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.INSPECT_FOCUS], runtime.executed)
		self.assertEqual([], host.messages)
		self.assertEqual([], host.scheduled)

	def _deniedLayer(
		self,
		sound: WorkflowSounds | None,
		*,
		state: str,
	) -> tuple[_Host, NvdaCommandLayer]:
		host = _Host()
		lifecycle = _Lifecycle()
		lifecycle.current = False
		lifecycle.state = state
		layer = NvdaCommandLayer(
			_Runtime(),
			lifecycle,
			host,
			nowMilliseconds=lambda: 100,
			sound=sound,
		)
		return host, layer

	def test_secure_desktop_denial_speaks_then_sounds_the_cue(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._deniedLayer(sound, state="secure")
		layer.enter()
		# Speech-first: the denial is spoken, then the secure-desktop cue sounds on the system
		# generation. The layer never armed, so no capture was installed.
		self.assertIn("Keystone commands are unavailable in the current NVDA state.", host.messages)
		self.assertEqual([CueEventId.SECURE_DESKTOP_DENIAL], sound.events())
		request = sound.requests[-1]
		self.assertEqual(SoundOwnerKind.SYSTEM, request.owner.kind)
		self.assertEqual(7, request.owner.generation)
		self.assertIsNone(host.capture)

	def test_non_secure_denial_speaks_without_the_secure_cue(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._deniedLayer(sound, state="indeterminate")
		layer.enter()
		# An indeterminate or terminating denial speaks the same message but sounds no secure cue.
		self.assertIn("Keystone commands are unavailable in the current NVDA state.", host.messages)
		self.assertEqual([], sound.events())

	def test_secure_denial_sound_failure_stays_isolated_from_speech(self) -> None:
		host, layer = self._deniedLayer(_FailingSounds(), state="secure")
		layer.enter()
		# The denial is still spoken even though the secure cue's emit raises.
		self.assertIn("Keystone commands are unavailable in the current NVDA state.", host.messages)

	def test_secure_denial_without_a_seam_speaks_only(self) -> None:
		host, layer = self._deniedLayer(None, state="secure")
		layer.enter()
		# Without a seam the denial is still spoken; nothing is scheduled.
		self.assertIn("Keystone commands are unavailable in the current NVDA state.", host.messages)

	def test_layer_entry_emits_layer_entered_owned_by_incrementing_layer_generation(self) -> None:
		sound = _RecordingSounds()
		_host, layer = self._layer(sound)
		layer.enter()
		layer.enter()
		self.assertEqual([CueEventId.LAYER_ENTERED, CueEventId.LAYER_ENTERED], sound.events())
		first, second = sound.requests
		self.assertEqual(SoundOwnerKind.LAYER, first.owner.kind)
		self.assertEqual(SoundOwnerKind.LAYER, second.owner.kind)
		self.assertLess(first.owner.generation, second.owner.generation)

	def test_escape_exit_emits_layer_exit_for_the_same_layer_generation(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound)
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:escape",))))
		host.popScheduled(0)()
		self.assertEqual([CueEventId.LAYER_ENTERED, CueEventId.LAYER_EXIT], sound.events())
		entered, exited = sound.requests
		self.assertEqual(SoundOwnerKind.LAYER, exited.owner.kind)
		self.assertEqual(entered.owner.generation, exited.owner.generation)

	def test_unknown_key_emits_coalescing_layer_invalid_key(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound)
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:x",))))
		host.popScheduled(0)()
		self.assertEqual([CueEventId.LAYER_ENTERED, CueEventId.LAYER_INVALID_KEY], sound.events())
		invalid = sound.requests[-1]
		self.assertEqual(SoundOwnerKind.LAYER, invalid.owner.kind)
		self.assertIsNotNone(invalid.coalescingKey)

	def test_layer_timeout_emits_layer_timeout(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound)
		layer.enter()
		host.scheduled[-1]()
		self.assertEqual([CueEventId.LAYER_ENTERED, CueEventId.LAYER_TIMEOUT], sound.events())
		self.assertEqual(SoundOwnerKind.LAYER, sound.requests[-1].owner.kind)

	def test_help_emits_command_help_opened_owned_by_command(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound)
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:h",))))
		host.popScheduled(0)()
		self.assertEqual([CueEventId.LAYER_ENTERED, CueEventId.COMMAND_HELP_OPENED], sound.events())
		self.assertEqual(SoundOwnerKind.COMMAND, sound.requests[-1].owner.kind)

	def test_bounded_capture_emits_start_then_success_under_one_capture_owner(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound)
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()
		self.assertEqual(
			[CueEventId.LAYER_ENTERED, CueEventId.START_BOUNDED_FULL, CueEventId.CAPTURE_SUCCESS],
			sound.events(),
		)
		start, success = sound.captureRequests()
		self.assertEqual(SoundOwnerKind.CAPTURE, start.owner.kind)
		self.assertEqual(start.owner, success.owner)
		self.assertTrue(start.startsProgress)
		self.assertEqual(CueAtomId.BOUNDED_FULL_FAMILY, success.familyAtom)

	def test_capture_progress_uses_the_active_capture_owner_and_family(self) -> None:
		sound = _RecordingSounds()
		_host, layer = self._layer(sound)
		layer._beginCaptureSound(CommandId.FOREGROUND_BOUNDED)  # pyright: ignore[reportPrivateUsage]

		layer.emitCaptureProgressSound(CommandId.FOREGROUND_BOUNDED)

		capture = sound.captureRequests()
		self.assertEqual(
			[CueEventId.START_BOUNDED_FULL, CueEventId.CAPTURE_PROGRESS],
			[request.event for request in capture],
		)
		self.assertEqual(capture[0].owner, capture[1].owner)
		self.assertEqual(CueAtomId.BOUNDED_FULL_FAMILY, capture[1].familyAtom)

	def test_diff_no_change_emits_start_diff_then_fixed_diff_family_terminal(self) -> None:
		sound = _RecordingSounds()
		host, layer = self._layer(sound, runtime=_OutcomeRuntime("noChange", committed=False))
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:d",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()
		self.assertEqual(
			[CueEventId.START_DIFF, CueEventId.DIFF_NO_CHANGE],
			[request.event for request in sound.captureRequests()],
		)
		self.assertEqual(CueAtomId.DIFF_FAMILY, sound.requests[-1].familyAtom)

	def test_cancelled_pending_capture_emits_start_requested_cancelled_under_one_owner(self) -> None:
		sound = _RecordingSounds()
		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100, sound=sound)
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		while host.scheduled:
			host.scheduled.pop(0)()
		captures = sound.captureRequests()
		self.assertEqual(
			[
				CueEventId.START_BOUNDED_FULL,
				CueEventId.CAPTURE_CANCELLATION_REQUESTED,
				CueEventId.CAPTURE_CANCELLED,
			],
			[request.event for request in captures],
		)
		self.assertEqual(1, len({request.owner.generation for request in captures}))
		self.assertEqual([], runtime.executed)

	def test_copy_and_reveal_repeats_emit_command_owned_confirmations(self) -> None:
		sound = _RecordingSounds()
		host = _Host()
		now = 100
		layer = NvdaCommandLayer(_Runtime(), _Lifecycle(), host, nowMilliseconds=lambda: now, sound=sound)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		now = 200
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()

		now = 300
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()

		confirmations = [
			request
			for request in sound.requests
			if request.event in {CueEventId.OUTPUT_PATH_COPY, CueEventId.EXPLORER_REVEAL}
		]
		self.assertEqual(
			[CueEventId.OUTPUT_PATH_COPY, CueEventId.EXPLORER_REVEAL],
			[request.event for request in confirmations],
		)
		self.assertTrue(all(request.owner.kind == SoundOwnerKind.COMMAND for request in confirmations))
		self.assertIsNotNone(confirmations[0].coalescingKey)

	def test_repeat_with_no_committed_output_stays_silent(self) -> None:
		sound = _RecordingSounds()
		host = _Host()
		now = 100
		layer = NvdaCommandLayer(
			_EmptyOutputRuntime(),
			_Lifecycle(),
			host,
			nowMilliseconds=lambda: now,
			sound=sound,
		)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		now = 200
		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()

		self.assertEqual("No matching committed output is available.", host.messages[-1])
		self.assertNotIn(CueEventId.OUTPUT_PATH_COPY, sound.events())
		self.assertNotIn(CueEventId.EXPLORER_REVEAL, sound.events())

	def test_layer_invalidate_clears_every_sound_owner(self) -> None:
		sound = _RecordingSounds()
		_host, layer = self._layer(sound)
		layer.enter()
		layer.invalidate()
		self.assertEqual([None], sound.invalidations)

	def test_sound_sink_failure_never_disturbs_speech_or_capture(self) -> None:
		host = _Host()
		runtime = _Runtime()
		layer = NvdaCommandLayer(
			runtime,
			_Lifecycle(),
			host,
			nowMilliseconds=lambda: 100,
			sound=_FailingSounds(),
		)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)
		self.assertIn("Bounded foreground capture started.", host.messages)
		self.assertIn("Bounded foreground capture completed.", host.messages)

	def test_throwing_announcement_keeps_capture_cue_cleanup_and_command_flow(self) -> None:
		sound = _RecordingSounds()
		host = _ThrowingHost(announce=True)
		runtime = _Runtime()
		layer = NvdaCommandLayer(runtime, _Lifecycle(), host, nowMilliseconds=lambda: 100, sound=sound)

		layer.enter()
		assert host.capture is not None
		self.assertFalse(host.capture(_Gesture(("kb:s",))))
		host.popScheduled(0)()
		host.popScheduled(10)()
		host.popScheduled(0)()

		self.assertEqual([CommandId.FOREGROUND_BOUNDED], runtime.executed)
		self.assertEqual(
			[CueEventId.LAYER_ENTERED, CueEventId.START_BOUNDED_FULL, CueEventId.CAPTURE_SUCCESS],
			sound.events(),
		)
		layer.emitCaptureProgressSound(CommandId.FOREGROUND_BOUNDED)
		self.assertEqual(
			[CueEventId.LAYER_ENTERED, CueEventId.START_BOUNDED_FULL, CueEventId.CAPTURE_SUCCESS],
			sound.events(),
		)
		self.assertEqual([], host.scheduled)

	def test_speech_is_byte_identical_whether_or_not_a_sound_seam_is_present(self) -> None:
		def run(sound: WorkflowSounds | None) -> list[tuple[str, str]]:
			host = _Host()
			layer = NvdaCommandLayer(_Runtime(), _Lifecycle(), host, nowMilliseconds=lambda: 100, sound=sound)

			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture(("kb:s",))))
			host.popScheduled(0)()
			host.popScheduled(10)()
			host.popScheduled(0)()

			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture(("kb:h",))))
			host.popScheduled(0)()

			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture(("kb:escape",))))
			host.popScheduled(0)()

			layer.enter()
			assert host.capture is not None
			self.assertFalse(host.capture(_Gesture(("kb:x",))))
			host.popScheduled(0)()

			return host.announcements

		silent = run(None)
		self.assertNotEqual([], silent)
		self.assertEqual(silent, run(_RecordingSounds()))
		self.assertEqual(silent, run(_FailingSounds()))


if __name__ == "__main__":
	_ = unittest.main()
