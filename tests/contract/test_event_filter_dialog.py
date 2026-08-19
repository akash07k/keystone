# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnusedCallResult=false
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
import unittest

from addon.globalPlugins.keystone.adapters.wx.inspector_frame import (
	EventFilterDialog,
	_nvdaEventTypeLabel,
	_rawUiaFamilyLabel,
)
from addon.globalPlugins.keystone.domain.event_monitor import (
	EventFilter,
	NvdaEventType,
	RawUiaFamily,
)


class _CheckboxList:
	def __init__(self, count: int, checked: tuple[int, ...] = ()) -> None:
		super().__init__()
		self.ItemCount = count
		self._checked = set(checked)
		self.enabled = True

	def CheckItem(self, index: int, checked: bool) -> None:
		if checked:
			self._checked.add(index)
		else:
			self._checked.discard(index)

	def IsItemChecked(self, index: int) -> bool:
		return index in self._checked

	def Enable(self, enabled: bool) -> None:
		self.enabled = enabled


class _Summary:
	def __init__(self) -> None:
		super().__init__()
		self.label = ""

	def SetLabel(self, label: str) -> None:
		self.label = label


class _Dialog:
	def __init__(self) -> None:
		super().__init__()
		self.ended: int | None = None

	def EndModal(self, result: int) -> None:
		self.ended = result


class _Service:
	def __init__(self) -> None:
		super().__init__()
		self.activeFilter = EventFilter.default()
		self.changes: list[EventFilter] = []

	def changeFilter(self, activeFilter: EventFilter, *, preserveRawState: bool = False) -> None:
		_ = preserveRawState
		self.activeFilter = activeFilter
		self.changes.append(activeFilter)


def _dialog(*, rawEnabled: bool = True) -> EventFilterDialog:
	dialog: Any = EventFilterDialog.__new__(EventFilterDialog)
	dialog._service = _Service()
	dialog._rawEnabled = rawEnabled
	dialog._announce = lambda message: dialog._announcements.append(message)
	dialog._announcements = []
	dialog._dialog = _Dialog()
	dialog._nvdaTypes = tuple(NvdaEventType)
	dialog._rawFamilies = tuple(RawUiaFamily)
	dialog._nvdaList = _CheckboxList(len(tuple(NvdaEventType)), checked=(0,))
	dialog._rawList = _CheckboxList(len(tuple(RawUiaFamily)), checked=(0,))
	dialog._summary = _Summary()
	dialog._wx = SimpleNamespace(ID_OK=5100, ID_CANCEL=5101)
	return dialog


class EventFilterDialogTests(unittest.TestCase):
	def test_event_labels_use_explicit_localized_enum_maps(self) -> None:
		self.assertEqual(
			(
				"Focus",
				"Foreground",
				"Name change",
				"Value change",
				"State change",
				"Description change",
				"Live region",
				"Selection",
				"Caret",
				"Controller",
				"Navigator object",
			),
			tuple(_nvdaEventTypeLabel(item) for item in NvdaEventType),
		)
		self.assertEqual(
			(
				"Notification",
				"Selection",
				"Layout",
				"Window",
				"Relation",
				"Drag and drop",
				"Alert",
				"Item status",
				"Tooltip",
				"Active text position",
			),
			tuple(_rawUiaFamilyLabel(item) for item in RawUiaFamily),
		)

	def test_uses_native_checkbox_list_api_and_events(self) -> None:
		source = Path(
			"addon/globalPlugins/keystone/adapters/wx/inspector_frame.py",
		).read_text(encoding="utf-8")

		self.assertIn("_reportList(wx, parent, autoSizeColumn=0)", source)
		self.assertIn("EnableCheckBoxes", source)
		self.assertIn("CheckItem", source)
		self.assertIn("IsItemChecked", source)
		self.assertIn("EVT_LIST_ITEM_CHECKED", source)
		self.assertIn("EVT_LIST_ITEM_UNCHECKED", source)
		self.assertNotIn("wx.CheckListBox", source)

	def test_select_all_clear_and_defaults_mutate_rows_without_rebuilding(self) -> None:
		dialog = _dialog()

		dialog.selectAll()
		self.assertTrue(all(dialog._nvdaList.IsItemChecked(i) for i in range(dialog._nvdaList.ItemCount)))
		self.assertTrue(all(dialog._rawList.IsItemChecked(i) for i in range(dialog._rawList.ItemCount)))

		dialog.clear()
		self.assertFalse(any(dialog._nvdaList.IsItemChecked(i) for i in range(dialog._nvdaList.ItemCount)))
		self.assertFalse(any(dialog._rawList.IsItemChecked(i) for i in range(dialog._rawList.ItemCount)))

		dialog.defaults()
		self.assertTrue(all(dialog._nvdaList.IsItemChecked(i) for i in range(dialog._nvdaList.ItemCount)))
		self.assertFalse(any(dialog._rawList.IsItemChecked(i) for i in range(dialog._rawList.ItemCount)))

	def test_zero_selection_apply_stays_open_and_preserves_active_filter(self) -> None:
		dialog = _dialog()
		dialog.clear()
		before = dialog._service.activeFilter

		self.assertFalse(dialog.apply())

		self.assertEqual(dialog._service.activeFilter, before)
		self.assertEqual(dialog._service.changes, [])
		self.assertIsNone(dialog._dialog.ended)
		self.assertIn("Select at least one event type", dialog._announcements[-1])

	def test_apply_commits_checked_types_and_closes(self) -> None:
		dialog = _dialog()

		self.assertTrue(dialog.apply())

		self.assertEqual(
			dialog._service.activeFilter.nvdaTypes,
			frozenset({tuple(NvdaEventType)[0]}),
		)
		self.assertEqual(
			dialog._service.activeFilter.rawFamilies,
			frozenset({tuple(RawUiaFamily)[0]}),
		)
		self.assertEqual(dialog._dialog.ended, dialog._wx.ID_OK)

	def test_raw_list_enabled_state_tracks_master_switch(self) -> None:
		dialog = _dialog(rawEnabled=False)

		dialog.updateRawEnabled()

		self.assertFalse(dialog._rawList.enabled)
		dialog._rawEnabled = True
		dialog.updateRawEnabled()
		self.assertTrue(dialog._rawList.enabled)

	def test_summary_uses_the_same_readable_labels_as_the_filter_lists(self) -> None:
		dialog = _dialog()

		dialog._updateSummary()

		self.assertEqual(
			"Selected event types: 2: Focus, raw UIA Notification",
			dialog._summary.label,
		)


if __name__ == "__main__":
	unittest.main()
