from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportDeprecated=false, reportMissingSuperCall=false, reportOptionalMemberAccess=false, reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnusedCallResult=false

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from collections.abc import Callable
from typing import cast
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.wx import custom_uia_dialog as module
from addon.globalPlugins.keystone.adapters.wx.custom_uia_dialog import (
	CustomUiaDialogController,
	dialogDefinition,
	showCustomUiaDialog,
)
from addon.globalPlugins.keystone.application.custom_uia_service import (
	CustomUiaChangeResult,
	CustomUiaLoadResult,
)
from addon.globalPlugins.keystone.domain.custom_uia import (
	CustomUiaConfiguration,
	CustomUiaProperty,
	stableKeyForGuid,
)


_GUID = "{12345678-1234-4ABC-8DEF-1234567890AB}"


class _Service:
	def __init__(self, properties: tuple[CustomUiaProperty, ...] = ()) -> None:
		self.configuration = CustomUiaConfiguration(1, properties)

	def load(self) -> CustomUiaLoadResult:
		return CustomUiaLoadResult(self.configuration)

	def save(self, configuration: CustomUiaConfiguration) -> CustomUiaChangeResult:
		self.configuration = configuration
		return CustomUiaChangeResult(True, configuration, restartRequired=True)

	def importFrom(self, _path: object) -> CustomUiaChangeResult:
		return CustomUiaChangeResult(True, self.configuration)

	def exportTo(self, _path: object) -> CustomUiaChangeResult:
		return CustomUiaChangeResult(True, self.configuration)


class _Catalog:
	def gettext(self, message: str) -> str:
		return message


class _Widget:
	def __init__(self, parent: object | None = None, *args: object, **kwargs: object) -> None:
		self.parent = parent
		self.label = kwargs.get("label")
		self.bindings: dict[object, Callable[..., object]] = {}
		self.focused = False
		self.value = kwargs.get("value", "")

	def Bind(self, event: object, handler: Callable[..., object], *_args: object) -> None:
		self.bindings[event] = handler

	def SetFocus(self) -> None:
		self.focused = True

	def SetValue(self, value: object) -> None:
		self.value = value

	def GetValue(self) -> object:
		return self.value

	def Wrap(self, _width: int) -> None:
		pass

	def SetMinSize(self, _size: object) -> None:
		pass

	def CentreOnParent(self) -> None:
		pass


class _ReportList(_Widget):
	def __init__(self, parent: object, *args: object, **kwargs: object) -> None:
		super().__init__(parent, *args, **kwargs)
		self.columns: list[str] = []
		self.rows: list[list[str]] = []
		self.selected = -1
		self.focusedRow = -1

	def InsertColumn(self, _index: int, heading: str) -> None:
		self.columns.append(heading)

	def InsertItem(self, index: int, text: str) -> int:
		self.rows.insert(index, [text])
		return index

	def SetItem(self, index: int, column: int, text: str) -> None:
		while len(self.rows[index]) <= column:
			self.rows[index].append("")
		self.rows[index][column] = text

	def DeleteAllItems(self) -> None:
		self.rows.clear()
		self.selected = -1

	def GetFirstSelected(self) -> int:
		return self.selected

	def Select(self, index: int) -> None:
		self.selected = index

	def Focus(self, index: int) -> None:
		self.focusedRow = index

	def GetItemCount(self) -> int:
		return len(self.rows)

	def PopupMenu(self, _menu: object) -> None:
		pass


class _Sizer:
	def __init__(self, *args: object, **kwargs: object) -> None:
		self.children: list[object] = []

	def Add(self, item: object, *_args: object, **_kwargs: object) -> None:
		self.children.append(item)

	def AddStretchSpacer(self) -> None:
		pass

	def AddGrowableCol(self, *_args: object) -> None:
		pass


class _Dialog(_Widget):
	def __init__(self, state: _State, parent: object | None, *, title: str) -> None:
		super().__init__(parent, title=title)
		self.state = state
		self.title = title
		self.ended: int | None = None
		state.dialogs.append(self)

	def Raise(self) -> None:
		pass

	def ShowModal(self) -> int:
		if self.title == "Custom UIA Properties" and self.state.openEditor:
			add = next(button for button in self.state.buttons if button.label == "&Add...")
			handler = add.bindings[self.state.wx.EVT_BUTTON]
			handler(object())
			self.state.openEditor = False
		if self.title == "Custom UIA Properties" and self.state.exportWhileOpen:
			export = next(button for button in self.state.buttons if button.label == "E&xport...")
			handler = export.bindings[self.state.wx.EVT_BUTTON]
			handler(object())
			self.state.exportWhileOpen = False
		return self.ended if self.ended is not None else self.state.wx.ID_CANCEL

	def EndModal(self, result: int) -> None:
		self.ended = result

	def SetSizerAndFit(self, _sizer: object) -> None:
		pass

	def Destroy(self) -> None:
		pass


@dataclass
class _State:
	wx: object
	staticBoxes: list[_Widget]
	reports: list[_ReportList]
	buttons: list[_Widget]
	dialogs: list[_Dialog]
	openEditor: bool = False
	exportWhileOpen: bool = False


def _host(
	*,
	openEditor: bool = False,
	exportWhileOpen: bool = False,
) -> tuple[object, _State, list[str]]:
	wx = SimpleNamespace()
	state = _State(wx, [], [], [], [], openEditor, exportWhileOpen)
	messages: list[str] = []

	class StaticBox(_Widget):
		def __init__(self, parent: object, *, label: str) -> None:
			super().__init__(parent, label=label)
			state.staticBoxes.append(self)

	class Button(_Widget):
		def __init__(self, parent: object, identifier: int | None = None, *, label: str) -> None:
			_ = identifier
			super().__init__(parent, label=label)
			state.buttons.append(self)

	class TextCtrl(_Widget):
		pass

	class CheckBox(_Widget):
		def IsChecked(self) -> bool:
			return bool(self.value)

	class Choice(_Widget):
		def __init__(self, parent: object, *, choices: tuple[str, ...]) -> None:
			super().__init__(parent)
			self.choices = choices
			self.selection = 0

		def SetSelection(self, selection: int) -> None:
			self.selection = selection

		def GetSelection(self) -> int:
			return self.selection

	class Report(_ReportList):
		def __init__(self, parent: object, *args: object, **kwargs: object) -> None:
			super().__init__(parent, *args, **kwargs)
			state.reports.append(self)

	class Dialog(_Dialog):
		def __init__(self, parent: object | None, *, title: str) -> None:
			super().__init__(state, parent, title=title)

	class Menu:
		def Append(self, _identifier: int, _label: str) -> object:
			return object()

		def AppendSeparator(self) -> None:
			pass

		def Bind(self, _event: object, _handler: object, _item: object) -> None:
			pass

		def Destroy(self) -> None:
			pass

	wx.Dialog = Dialog
	wx.StaticBox = StaticBox
	wx.StaticBoxSizer = _Sizer
	wx.StaticText = _Widget
	wx.TextCtrl = TextCtrl
	wx.CheckBox = CheckBox
	wx.Choice = Choice
	wx.Button = Button
	wx.BoxSizer = _Sizer
	wx.FlexGridSizer = _Sizer
	wx.Menu = Menu
	wx.ListCtrl = Report
	wx.VERTICAL = 1
	wx.HORIZONTAL = 2
	wx.EXPAND = 4
	wx.ALL = 8
	wx.LEFT = 16
	wx.RIGHT = 32
	wx.BOTTOM = 64
	wx.ALIGN_CENTER_VERTICAL = 128
	wx.TE_MULTILINE = 256
	wx.LC_REPORT = 512
	wx.LC_SINGLE_SEL = 1024
	wx.ID_OK = 1
	wx.ID_CANCEL = 2
	wx.ID_ADD = 3
	wx.ID_EDIT = 4
	wx.ID_DELETE = 5
	wx.ID_COPY = 6
	wx.ID_ANY = -1
	wx.WXK_DELETE = 127
	wx.EVT_BUTTON = object()
	wx.EVT_LIST_ITEM_ACTIVATED = object()
	wx.EVT_CONTEXT_MENU = object()
	wx.EVT_KEY_DOWN = object()
	wx.EVT_MENU = object()
	wx.CallAfter = lambda callback, *args: callback(*args)
	gui = SimpleNamespace(mainFrame=None, nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=Report))

	def importHost(name: str) -> object:
		return wx if name == "wx" else gui if name == "gui" else SimpleNamespace(message=messages.append)

	return importHost, state, messages


class CustomUiaDialogTests(unittest.TestCase):
	def test_definition_id_is_managed_from_the_property_guid(self) -> None:
		controller = CustomUiaDialogController(_Service(), currentExecutable="sample.exe")  # type: ignore[arg-type]

		controller.beginAdd(currentExecutable="sample.exe")
		controller.update(canonicalGuid=_GUID)

		self.assertNotIn("stableKey", [control.controlId for control in dialogDefinition().controls])
		self.assertEqual("canonicalGuid", controller.focusedField)
		self.assertEqual(stableKeyForGuid(_GUID), controller.candidate.toProperty().stableKey)

	def test_replacement_is_explicit_and_requires_a_native_warning_confirmation(self) -> None:
		replace = next(control for control in dialogDefinition().controls if control.controlId == "import")
		calls: list[tuple[object, ...]] = []
		catalog = _Catalog()

		def messageBox(*args: object) -> int:
			calls.append(args)
			return 1

		wx = SimpleNamespace(
			YES=1,
			NO=0,
			YES_NO=2,
			NO_DEFAULT=4,
			ICON_WARNING=8,
			MessageBox=messageBox,
		)

		self.assertEqual("Re&place...", replace.label)
		self.assertEqual("Replace definitions", replace.accessibleName)
		self.assertTrue(module._confirmDefinitionReplacement(wx, object(), catalog))
		self.assertEqual(1, len(calls))
		self.assertIn("will be removed", cast(str, calls[0][0]))
		self.assertEqual("Replace Custom UIA definitions", cast(str, calls[0][1]))

	def test_explicit_diagnostic_export_is_localized_and_calls_only_the_injected_action(self) -> None:
		calls: list[str] = []
		controller = CustomUiaDialogController(
			_Service(),  # type: ignore[arg-type]
			currentExecutable="sample.exe",
			exportCustomUiaDiagnostics=lambda: calls.append("diagnostic") or True,
		)
		action = next(
			control for control in dialogDefinition().controls if control.controlId == "exportDiagnostics"
		)

		self.assertEqual("Export Custom UIA Diagnostics...", action.label)
		self.assertTrue(controller.exportCustomUiaDiagnostics())
		self.assertEqual(["diagnostic"], calls)
		self.assertEqual("Custom UIA diagnostics exported", controller.statusText)

	def test_display_name_is_optional_and_falls_back_to_the_programmatic_name(self) -> None:
		field = next(control for control in dialogDefinition().controls if control.controlId == "displayName")
		property = CustomUiaProperty(
			"sample.mode",
			_GUID,
			"Sample.Mode",
			"string",
			"unknown",
			True,
			None,
			"sample.exe",
			None,
			None,
			displayName="Reading mode",
		)
		controller = CustomUiaDialogController(_Service((property,)), currentExecutable="sample.exe")  # type: ignore[arg-type]

		self.assertEqual("Display name", field.accessibleName)
		self.assertIn("If blank", field.helpText)
		controller.edit(0)
		self.assertEqual("Reading mode", controller.candidate.displayName)
		self.assertEqual("sample.mode", controller.candidate.toProperty().stableKey)

	def test_enum_values_use_accessible_line_based_mappings(self) -> None:
		field = next(control for control in dialogDefinition().controls if control.controlId == "enumValues")

		self.assertEqual("Enum values", field.accessibleName)
		self.assertEqual(
			((1, "ViewSlide"), (9, "ViewNormal")),
			module._enumValuesFromText("9 = ViewNormal\n1 = ViewSlide"),
		)
		with self.assertRaises(ValueError):
			_ = module._enumValuesFromText("9 ViewNormal")

	def _show(
		self,
		controller: CustomUiaDialogController,
		*,
		openEditor: bool = False,
		exportWhileOpen: bool = False,
	) -> tuple[_State, list[str]]:
		importer, state, messages = _host(
			openEditor=openEditor,
			exportWhileOpen=exportWhileOpen,
		)
		with patch.object(module, "import_module", side_effect=importer):
			showCustomUiaDialog(
				None,
				controller,
				exportPathProvider=lambda: Path("definitions.json"),
			)
		return state, messages

	def test_manager_uses_a_grouped_autowidth_report_list_without_accessibility_shims(self) -> None:
		property = CustomUiaProperty(
			"sample.mode",
			_GUID,
			"Sample.Mode",
			"string",
			"unknown",
			True,
			None,
			"sample.exe",
			None,
			None,
			displayName="Reading mode",
		)
		controller = CustomUiaDialogController(_Service((property,)), currentExecutable="sample.exe")  # type: ignore[arg-type]

		state, _messages = self._show(controller)

		self.assertEqual(1, len(state.reports))
		report = state.reports[0]
		self.assertEqual(["Definition"], report.columns)
		self.assertEqual([["Reading mode (Enabled)"]], report.rows)
		self.assertEqual(0, report.selected)
		self.assertEqual(0, report.focusedRow)
		self.assertIsInstance(report.parent, _Widget)
		self.assertEqual("Custom UIA property definitions", report.parent.label)
		source = Path("addon/globalPlugins/keystone/adapters/wx/custom_uia_dialog.py").read_text(
			encoding="utf-8",
		)
		self.assertNotIn("setNativeAccessibleName", source)
		self.assertNotIn("wx.ListBox", source)
		self.assertNotIn(".SetName(", source)

	def test_add_editor_is_separate_and_groups_definition_and_filters(self) -> None:
		controller = CustomUiaDialogController(_Service(), currentExecutable="sample.exe")  # type: ignore[arg-type]

		state, _messages = self._show(controller, openEditor=True)

		labels = [box.label for box in state.staticBoxes]
		self.assertEqual(
			["Custom UIA property definitions", "Definition", "Advanced application filters"],
			labels,
		)
		self.assertEqual("Custom UIA Properties", state.dialogs[0].title)
		self.assertEqual("Add Custom UIA Definition", state.dialogs[1].title)
		self.assertIn("&Cancel", [button.label for button in state.buttons])

	def test_controller_deletes_only_a_saved_definition(self) -> None:
		property = CustomUiaProperty(
			"sample.mode",
			_GUID,
			"Sample.Mode",
			"string",
			"unknown",
			True,
			None,
			"sample.exe",
			None,
			None,
		)
		controller = CustomUiaDialogController(_Service((property,)), currentExecutable="sample.exe")  # type: ignore[arg-type]

		result = controller.delete(0)

		self.assertTrue(result.accepted)
		self.assertEqual((), controller.properties)

	def test_export_preserves_the_selected_definition(self) -> None:
		property = CustomUiaProperty(
			"sample.mode",
			_GUID,
			"Sample.Mode",
			"string",
			"unknown",
			True,
			None,
			"sample.exe",
			None,
			None,
		)
		controller = CustomUiaDialogController(_Service((property,)), currentExecutable="sample.exe")  # type: ignore[arg-type]

		state, _messages = self._show(controller, exportWhileOpen=True)

		self.assertEqual(0, state.reports[0].selected)
		self.assertEqual(0, state.reports[0].focusedRow)


if __name__ == "__main__":
	unittest.main()
