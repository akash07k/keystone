# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
import unittest

from addon.globalPlugins.keystone.adapters.wx.inspector_frame import (
	EventsWorkspaceDefinition,
	InspectorWorkspaceDefinition,
	_statusWord,
	_statusWords,
)
from addon.globalPlugins.keystone.domain.commands import COMMAND_DEFINITIONS, CommandId
from addon.globalPlugins.keystone.domain.inspector import PropertyStatus
from addon.globalPlugins.keystone.presentation.commands import (
	commandGestureText,
	commandHelpText,
	commandLabelText,
)

_PHASE_LEAK = re.compile(r"\bphase\s+\d+\b", re.IGNORECASE)
_ACCESS_KEY = re.compile(r"&[A-Za-z0-9]")

# Fields whose value NVDA speaks as a control's accessible name. Accessible names must never carry
# the ampersand access-key marker, which belongs only on the visible label.
_WORKSPACE_ACCESSIBLE_NAMES = (
	"title",
	"sourceSummaryName",
	"hierarchyName",
	"propertyNotebookName",
	"followFocusOfflineHelp",
)
_WORKSPACE_ACCESS_KEY_LABELS = (
	"retargetFocusLabel",
	"retargetNavigatorLabel",
	"followFocusLabel",
	"rawUiaLabel",
	"appModuleOverrideLabel",
	"openSnapshotLabel",
)

_EVENTS_ACCESSIBLE_NAMES = (
	"eventListName",
	"monitoringGroupName",
	"historyActionsName",
	"scopeName",
	"detailsName",
	"clearConfirmTitle",
)
_EVENTS_ACCESS_KEY_LABELS = (
	"restartLabel",
	"startLabel",
	"stopLabel",
	"exportLabel",
	"clearLabel",
	"filterLabel",
	"followNewestLabel",
	"includeRawLabel",
)


class AccessibleNameContractTests(unittest.TestCase):
	def _allValues(self) -> list[str]:
		workspace = InspectorWorkspaceDefinition()
		events = EventsWorkspaceDefinition()
		values: list[str] = []
		for definition, names in (
			(workspace, (*_WORKSPACE_ACCESSIBLE_NAMES, *_WORKSPACE_ACCESS_KEY_LABELS)),
			(events, (*_EVENTS_ACCESSIBLE_NAMES, *_EVENTS_ACCESS_KEY_LABELS)),
		):
			values.extend(getattr(definition, name) for name in names)
		values.extend(workspace.tabNames)
		values.extend(events.columnHeadings)
		return values

	def test_every_definition_string_is_present_and_never_leaks_internal_phase_labels(self) -> None:
		for value in self._allValues():
			self.assertIsInstance(value, str)
			self.assertTrue(value.strip(), "every accessible name and label must be non-empty")
			self.assertIsNone(
				_PHASE_LEAK.search(value),
				f"user-facing string must not expose an internal phase label: {value!r}",
			)

	def test_accessible_names_carry_no_access_key_marker(self) -> None:
		workspace = InspectorWorkspaceDefinition()
		events = EventsWorkspaceDefinition()
		for definition, names in (
			(workspace, _WORKSPACE_ACCESSIBLE_NAMES),
			(events, _EVENTS_ACCESSIBLE_NAMES),
		):
			for name in names:
				value = getattr(definition, name)
				self.assertNotIn("&", value, f"accessible name {name} must not contain an access key")
		for tab in workspace.tabNames:
			self.assertNotIn("&", tab)
		for heading in events.columnHeadings:
			self.assertNotIn("&", heading)

	def test_actionable_controls_expose_exactly_one_access_key(self) -> None:
		workspace = InspectorWorkspaceDefinition()
		events = EventsWorkspaceDefinition()
		for definition, names in (
			(workspace, _WORKSPACE_ACCESS_KEY_LABELS),
			(events, _EVENTS_ACCESS_KEY_LABELS),
		):
			for name in names:
				value = getattr(definition, name)
				self.assertEqual(
					1,
					len(_ACCESS_KEY.findall(value)),
					f"actionable label {name} must expose exactly one keyboard access key: {value!r}",
				)


class FocusAndKeyboardFlowTests(unittest.TestCase):
	def test_property_category_list_has_the_four_visible_categories(self) -> None:
		tabs = InspectorWorkspaceDefinition().tabNames
		self.assertEqual(("Core", "UIA", "Annotations", "Advanced"), tabs)

	def test_event_list_declares_one_heading_per_reported_column(self) -> None:
		headings = EventsWorkspaceDefinition().columnHeadings
		self.assertEqual(4, len(headings))
		self.assertEqual(len(headings), len(set(headings)), "column headings must be distinct")


class NonvisualStateContractTests(unittest.TestCase):
	def test_every_property_status_has_a_spoken_word(self) -> None:
		words = _statusWords()
		for status in PropertyStatus:
			self.assertIn(status, words)
			self.assertTrue(_statusWord(status).strip())

	def test_status_words_are_distinct_so_state_is_never_ambiguous(self) -> None:
		spoken = [_statusWord(status) for status in PropertyStatus]
		self.assertEqual(len(spoken), len(set(spoken)))


class CompleteSpeechContractTests(unittest.TestCase):
	def test_command_help_speaks_every_command_gesture_and_action(self) -> None:
		helpText = commandHelpText()
		for definition in COMMAND_DEFINITIONS:
			gesture = commandGestureText(definition.commandId).replace("NVDA+/", "KLS", 1)
			label = commandLabelText(definition.commandId)
			self.assertIn(gesture, helpText, f"help must announce the keystroke for {definition.commandId}")
			self.assertIn(label, helpText, f"help must announce the action for {definition.commandId}")

	def test_command_help_covers_the_whole_registry(self) -> None:
		helpText = commandHelpText()
		self.assertEqual(len(COMMAND_DEFINITIONS), len(set(CommandId)))
		spokenLines = [line for line in helpText.splitlines() if line.strip().startswith("KLS, then")]
		self.assertEqual(len(COMMAND_DEFINITIONS), len(spokenLines))


if __name__ == "__main__":
	_ = unittest.main()
