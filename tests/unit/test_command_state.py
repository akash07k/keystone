from __future__ import annotations

import unittest
from typing import cast
from unittest.mock import call, patch

from addon.globalPlugins.keystone.domain.commands import (
	CommandId,
	CommandLayerState,
	CommandRepeatState,
	COMMAND_DEFINITIONS,
)
from addon.globalPlugins.keystone.presentation import commands as commandPresentation
from addon.globalPlugins.keystone.presentation.commands import (
	commandGestureText,
	commandHelpText,
	presentCaptureLimit,
	presentCaptureProgress,
	presentCommandOutcome,
	presentCommandStart,
)


class CommandStateTests(unittest.TestCase):
	def test_command_clocks_and_generations_require_nonnegative_integers(self) -> None:
		repeat = CommandRepeatState()
		_ = repeat.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=0)
		layer = CommandLayerState()
		token = layer.enter(lifecycleGeneration=0, nowMilliseconds=0)
		for invalid in (-1, True, 1.5, "1", None):
			with self.subTest(requestClock=invalid), self.assertRaises(ValueError):
				_ = repeat.request(CommandId.DIFF, nowMilliseconds=cast(int, invalid))
			with self.subTest(finishClock=invalid), self.assertRaises(ValueError):
				repeat.finish(
					CommandId.FOREGROUND_BOUNDED,
					nowMilliseconds=cast(int, invalid),
					committed=True,
				)
			with self.subTest(layerGeneration=invalid), self.assertRaises(ValueError):
				_ = layer.isCurrent(
					token,
					lifecycleGeneration=cast(int, invalid),
					nowMilliseconds=0,
				)
			with self.subTest(layerClock=invalid), self.assertRaises(ValueError):
				_ = layer.isCurrent(
					token,
					lifecycleGeneration=0,
					nowMilliseconds=cast(int, invalid),
				)

	def test_registry_is_the_complete_mnemonic_layer(self) -> None:
		self.assertEqual(
			(
				("s", CommandId.FOREGROUND_BOUNDED),
				("shift+s", CommandId.FOREGROUND_UNLIMITED),
				("f", CommandId.FOCUS_UNLIMITED),
				("d", CommandId.DIFF),
				("n", CommandId.NAVIGATOR_BOUNDED),
				("shift+n", CommandId.NAVIGATOR_UNLIMITED),
				("shift+o", CommandId.NAVIGATOR_SUBTREE_UNLIMITED),
				("i", CommandId.INSPECT_FOCUS),
				("o", CommandId.INSPECT_NAVIGATOR),
				("e", CommandId.EVENT_MONITOR),
				("f5", CommandId.EVENT_MONITOR_TOGGLE),
				("c", CommandId.CUSTOM_UIA_PROPERTIES),
				("h", CommandId.HELP),
			),
			tuple((definition.key, definition.commandId) for definition in COMMAND_DEFINITIONS),
		)
		helpText = commandHelpText()
		for definition in COMMAND_DEFINITIONS:
			self.assertIn(
				commandGestureText(definition.commandId).replace("NVDA+/", "KLS", 1),
				helpText,
			)
			self.assertIn(definition.label, helpText)

	def test_matching_active_command_cancels_but_different_command_is_busy(self) -> None:
		state = CommandRepeatState(repeatWindowMilliseconds=2_000)
		self.assertEqual("run", state.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=100).action)
		self.assertEqual("busy", state.request(CommandId.DIFF, nowMilliseconds=200).action)
		self.assertEqual(
			"cancel",
			state.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=300).action,
		)

	def test_each_capture_command_has_an_independent_copy_reveal_cycle(self) -> None:
		state = CommandRepeatState(repeatWindowMilliseconds=2_000)
		_ = state.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=0)
		state.finish(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=1_000, committed=True)
		self.assertEqual("run", state.request(CommandId.DIFF, nowMilliseconds=1_100).action)
		state.finish(CommandId.DIFF, nowMilliseconds=1_200, committed=True)
		self.assertEqual("copy", state.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=1_300).action)
		self.assertEqual("copy", state.request(CommandId.DIFF, nowMilliseconds=1_400).action)
		self.assertEqual("reveal", state.request(CommandId.FOREGROUND_BOUNDED, nowMilliseconds=1_500).action)
		self.assertEqual("reveal", state.request(CommandId.DIFF, nowMilliseconds=1_600).action)

	def test_expired_or_failed_cycle_runs_again(self) -> None:
		state = CommandRepeatState(repeatWindowMilliseconds=500)
		_ = state.request(CommandId.NAVIGATOR_BOUNDED, nowMilliseconds=0)
		state.finish(CommandId.NAVIGATOR_BOUNDED, nowMilliseconds=100, committed=False)
		self.assertEqual("run", state.request(CommandId.NAVIGATOR_BOUNDED, nowMilliseconds=200).action)
		state.finish(CommandId.NAVIGATOR_BOUNDED, nowMilliseconds=300, committed=True)
		self.assertEqual("run", state.request(CommandId.NAVIGATOR_BOUNDED, nowMilliseconds=801).action)

	def test_layer_generation_rejects_stale_timeout_and_dispatch(self) -> None:
		state = CommandLayerState(timeoutMilliseconds=1_000)
		first = state.enter(lifecycleGeneration=4, nowMilliseconds=100)
		second = state.enter(lifecycleGeneration=4, nowMilliseconds=200)
		self.assertFalse(state.isCurrent(first, lifecycleGeneration=4, nowMilliseconds=300))
		self.assertTrue(state.isCurrent(second, lifecycleGeneration=4, nowMilliseconds=300))
		self.assertFalse(state.isGeneration(first))
		self.assertTrue(state.isGeneration(second))
		self.assertFalse(state.isCurrent(second, lifecycleGeneration=5, nowMilliseconds=300))
		self.assertFalse(state.isCurrent(second, lifecycleGeneration=4, nowMilliseconds=1_201))

	def test_terminal_presentations_are_distinct_and_complete(self) -> None:
		tokens = (
			"started",
			"progress",
			"completed",
			"cancellationRequested",
			"cancelled",
			"truncated",
			"partialScreenshot",
			"failed",
			"baselineCreated",
			"noChange",
		)
		messages = tuple(presentCommandOutcome(token) for token in tokens)
		self.assertEqual(len(messages), len(set(messages)))
		self.assertTrue(all(message.strip() for message in messages))

	def test_completed_and_failed_messages_identify_the_requested_command(self) -> None:
		self.assertEqual(
			"Bounded navigator capture completed.",
			presentCommandOutcome("completed", commandId=CommandId.NAVIGATOR_BOUNDED),
		)
		self.assertEqual(
			"Focus Inspector opened.",
			presentCommandOutcome("completed", commandId=CommandId.INSPECT_FOCUS),
		)
		self.assertEqual(
			"Custom UIA Properties opened.",
			presentCommandOutcome("completed", commandId=CommandId.CUSTOM_UIA_PROPERTIES),
		)
		self.assertEqual(
			"Navigator Inspector could not be opened.",
			presentCommandOutcome("failed", commandId=CommandId.INSPECT_NAVIGATOR),
		)
		self.assertEqual(
			"Event Monitor could not be opened.",
			presentCommandOutcome("failed", commandId=CommandId.EVENT_MONITOR),
		)
		self.assertEqual(
			"Custom UIA Properties could not be opened.",
			presentCommandOutcome("failed", commandId=CommandId.CUSTOM_UIA_PROPERTIES),
		)

	def test_outcomes_translate_each_raw_message_once_and_preserve_localized_detail(self) -> None:
		translations = {
			"Bounded foreground capture": "Localized capture",
			"{command} completed.": "{command} complete.",
			"Diff baseline created.": "Localized baseline created.",
		}
		with patch.object(
			commandPresentation,
			"gettext",
			side_effect=translations.__getitem__,
		) as gettext:
			self.assertEqual(
				"Localized capture complete.",
				presentCommandOutcome("completed", commandId=CommandId.FOREGROUND_BOUNDED),
			)
			self.assertEqual(
				[call("Bounded foreground capture"), call("{command} completed.")],
				gettext.call_args_list,
			)
			gettext.reset_mock()
			self.assertEqual(
				"Localized baseline created. Already localized detail.",
				presentCommandOutcome("baselineCreated", "Already localized detail."),
			)
			self.assertEqual([call("Diff baseline created.")], gettext.call_args_list)

	def test_capture_start_and_terminal_messages_identify_target_and_limit_mode(self) -> None:
		self.assertEqual(
			"Bounded foreground capture started.",
			presentCommandStart(CommandId.FOREGROUND_BOUNDED),
		)
		self.assertEqual(
			"Unlimited navigator capture started.",
			presentCommandStart(CommandId.NAVIGATOR_UNLIMITED),
		)
		self.assertEqual(
			"Unlimited focus-object subtree snapshot capture started.",
			presentCommandStart(CommandId.FOCUS_UNLIMITED),
		)
		self.assertEqual(
			"Bounded navigator capture completed, but the screenshot was unavailable.",
			presentCommandOutcome(
				"partialScreenshot",
				commandId=CommandId.NAVIGATOR_BOUNDED,
			),
		)
		self.assertEqual(
			"Unlimited foreground capture cancelled.",
			presentCommandOutcome(
				"cancelled",
				commandId=CommandId.FOREGROUND_UNLIMITED,
			),
		)

	def test_capture_limit_presentation_names_the_reached_text_budget(self) -> None:
		self.assertEqual(
			"Text limit of 20,000 characters reached.",
			presentCaptureLimit("textScalars", 20_000),
		)

	def test_capture_progress_presentation_reports_safe_counts_and_elapsed_time(self) -> None:
		self.assertEqual(
			"30 nodes captured, 14 pending, 2 seconds.",
			presentCaptureProgress(30, 14, 2_002),
		)
		self.assertEqual(
			"Preparing snapshot: 30 nodes captured, 2 seconds.",
			presentCaptureProgress(30, 0, 2_002, "preparing"),
		)


if __name__ == "__main__":
	_ = unittest.main()
