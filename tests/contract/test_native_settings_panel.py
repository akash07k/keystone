# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda import composition as compositionModule
from addon.globalPlugins.keystone.adapters.wx.settings_panel import (
	PREVIEW_CUE_ORDER,
	PreviewPort,
	SettingsPanelController,
	panelDefinition,
	panelMessages,
	previewCueChoiceLabels,
)
from addon.globalPlugins.keystone.application.settings_service import SettingsService
from addon.globalPlugins.keystone.capability import (
	CapabilitySnapshot,
	defaultCapabilitySnapshot,
)
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.settings import SETTING_DEFINITIONS, SettingsSnapshot
from addon.globalPlugins.keystone.domain.sounds import CueAtomId
from addon.globalPlugins.keystone.ports.effects import (
	CaptureManagementRequest,
	CaptureManagementResult,
	EffectResult,
	FeedbackRequest,
	PortOutcome,
	PortStatus,
	SettingsReadRequest,
	SettingsWriteRequest,
)


class _BasePanel:
	pass


class _Control:
	def __init__(self, value: object) -> None:
		super().__init__()
		self.value = value
		self.enabled = True
		self.focused = False
		self.selected = False

	def GetValue(self) -> object:
		return self.value

	def SetValue(self, value: object) -> None:
		self.value = value

	def Enable(self, enabled: bool) -> None:
		self.enabled = enabled

	def SetName(self, _name: str) -> None:
		return

	def SetHelpText(self, _helpText: str) -> None:
		return

	def SetFocus(self) -> None:
		self.focused = True

	def SelectAll(self) -> None:
		self.selected = True


class _Choice(_Control):
	def __init__(self, labels: tuple[str, ...], selection: int) -> None:
		super().__init__(labels[selection])
		self.labels = labels
		self.selection = selection

	def GetSelection(self) -> int:
		return self.selection

	def SetSelection(self, selection: int) -> None:
		self.selection = selection
		self.value = self.labels[selection]

	def GetStringSelection(self) -> str:
		assert isinstance(self.value, str)
		return self.value

	def SetStringSelection(self, value: str) -> None:
		if value in self.labels:
			self.SetSelection(self.labels.index(value))


class _SettingsPort:
	def __init__(self, revision: int) -> None:
		super().__init__()
		self.revision = revision

	def readSettings(self, request: SettingsReadRequest) -> EffectResult:
		return EffectResult(PortStatus("ready", self.revision))

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		self.revision += 1
		return EffectResult(PortStatus("ready", self.revision), PortOutcome("settingsUpdated"))


class _CapturePort:
	def __init__(self, recognizedCount: int = 0) -> None:
		super().__init__()
		self.recognizedCount = recognizedCount
		self.requests: list[CaptureManagementRequest] = []

	def manageCaptures(self, request: CaptureManagementRequest) -> CaptureManagementResult:
		self.requests.append(request)
		return CaptureManagementResult(
			operation=request.operation,
			lifecycleGeneration=request.lifecycleGeneration,
			status=PortStatus("ready", 1),
			outcome=PortOutcome("captureStatus"),
			error=None,
			recognizedCount=self.recognizedCount,
			suspiciousCount=0,
			deletedCount=0,
			skippedCount=0,
			failedCount=0,
			confirmationRevision=2,
			copyActionId=None,
			openActionId=None,
			revealActionId=None,
		)


def _controller(
	*,
	capturePort: _CapturePort | None = None,
	settingsPort: _SettingsPort | None = None,
	capabilities: CapabilitySnapshot = defaultCapabilitySnapshot,
	preview: PreviewPort | None = None,
) -> SettingsPanelController:
	generation = 1
	return SettingsPanelController(
		snapshot=SettingsSnapshot.defaults(settingsRevision=1),
		settingsService=SettingsService(settingsPort or _SettingsPort(1)),
		capabilities=capabilities,
		captureManagement=capturePort or _CapturePort(),
		lifecycleGeneration=generation,
		context=CorrelationFactory().admit(generation=generation),
		preview=preview,
	)


def _nativePanel(
	controller: SettingsPanelController,
) -> object:
	nativeClass = compositionModule._nativePanelClass(_BasePanel, lambda: controller)
	panel = nativeClass()
	panel._keystoneController = controller
	return panel


def _controlsForCandidate(controller: SettingsPanelController) -> dict[str, _Control]:
	controls: dict[str, _Control] = {}
	for definition in SETTING_DEFINITIONS:
		value = controller.candidate().value(definition.settingId)
		controls[definition.settingId.value] = _Control(value)
	return controls


class NativeButtonRenderingTests(unittest.TestCase):
	def test_native_checkbox_uses_the_resolved_capability_help(self) -> None:
		class CheckBox:
			instance: CheckBox | None = None

			def __init__(self, _parent: object, *, label: str) -> None:
				super().__init__()
				type(self).instance = self
				self.label = label
				self.value = False
				self.enabled = False
				self.name = ""
				self.helpText = ""

			def SetValue(self, value: bool) -> None:
				self.value = value

			def Enable(self, enabled: bool) -> None:
				self.enabled = enabled

			def SetName(self, name: str) -> None:
				self.name = name

			def SetHelpText(self, helpText: str) -> None:
				self.helpText = helpText

		class Helper:
			def addItem(self, _item: object) -> None:
				return

		class StaticText:
			def __init__(self, _parent: object, *, label: str) -> None:
				super().__init__()

			def Wrap(self, _width: int) -> None:
				return

		class Panel:
			def scaleSize(self, value: int) -> int:
				return value

		definition = next(
			control for control in panelDefinition().controls if control.controlId == "forceRawUia"
		)
		definition = replace(
			definition,
			helpText="Raw UI Automation inspection is enabled.",
		)
		builder = compositionModule._NativePanelBuilder(Panel(), object())
		builder._helper = Helper()
		wx = SimpleNamespace(CheckBox=CheckBox, StaticText=StaticText)

		with patch.object(compositionModule, "import_module", return_value=wx):
			builder.addCheckBox(definition, True, True)

		checkbox = CheckBox.instance
		assert checkbox is not None
		self.assertEqual("Raw UI Automation inspection is enabled.", checkbox.helpText)
		self.assertEqual(
			"Force raw UI Automation for Keystone inspection. " + "Raw UI Automation inspection is enabled.",
			checkbox.name,
		)

	def test_native_builder_uses_the_resolved_capability_label(self) -> None:
		class Button:
			instance: Button | None = None

			def __init__(self, _parent: object, *, label: str) -> None:
				super().__init__()
				type(self).instance = self
				self.label = label
				self.enabled = False
				self.name = ""
				self.helpText = ""

			def Enable(self, enabled: bool) -> None:
				self.enabled = enabled

			def Bind(self, _event: object, _handler: Callable[[object], None]) -> None:
				return

			def SetName(self, name: str) -> None:
				self.name = name

			def SetHelpText(self, helpText: str) -> None:
				self.helpText = helpText

		class Helper:
			def addItem(self, _item: object) -> None:
				return

		class StaticText:
			def __init__(self, _parent: object, *, label: str) -> None:
				super().__init__()

			def Wrap(self, _width: int) -> None:
				return

		class Panel:
			def scaleSize(self, value: int) -> int:
				return value

		controller = _controller()
		state = next(state for state in controller.controlStates() if state.controlId == "rawUiaDetails")
		definition = next(
			control for control in panelDefinition().controls if control.controlId == "rawUiaDetails"
		)
		builder = compositionModule._NativePanelBuilder(Panel(), object())
		builder._helper = Helper()
		wx = SimpleNamespace(Button=Button, StaticText=StaticText, EVT_BUTTON=object())

		with patch.object(compositionModule, "import_module", return_value=wx):
			builder.addButton(
				replace(definition, label=state.label, helpText=state.explanation),
				state.enabled,
			)

		button = Button.instance
		assert button is not None
		self.assertEqual("Raw UI Automation held closed; Capab&ility Details...", button.label)
		self.assertEqual(
			"Raw UI Automation held closed; Capability Details.... "
			+ "Raw UI Automation inspection is held closed; open details for status, reason, and safe fallback.",
			button.name,
		)


class NativeActionDispatchTests(unittest.TestCase):
	def test_capability_details_open_selectable_copyable_browsable_content(self) -> None:
		controller = _controller()
		panel = _nativePanel(controller)
		ui = SimpleNamespace(messages=[], browsed=[])
		ui.message = lambda message: ui.messages.append(message)
		ui.browseableMessage = lambda *args, **kwargs: ui.browsed.append((args, kwargs))
		owned: list[str] = []
		panel._showCapabilityDetails = lambda details: owned.append(details)
		definition = next(
			control for control in panelDefinition().controls if control.controlId == "rawUiaDetails"
		)

		with patch.object(
			compositionModule,
			"import_module",
			side_effect=lambda name: ui if name == "ui" else None,
		):
			panel.onKeystoneAction(definition)

		self.assertEqual([], ui.messages)
		self.assertEqual([], ui.browsed)
		self.assertEqual(1, len(owned))
		self.assertIn("rawUiaInspection", owned[0])
		self.assertIn("heldClosed", owned[0])

	def test_capability_details_dialog_is_parented_selectable_copyable_and_escape_closable(self) -> None:
		panel = _nativePanel(_controller())

		class Dialog:
			instance: Dialog | None = None

			def __init__(self, parent: object, *, title: str) -> None:
				super().__init__()
				type(self).instance = self
				self.parent = parent
				self.title = title
				self.escapeId: int | None = None
				self.affirmativeId: int | None = None
				self.destroyed = False

			def SetEscapeId(self, value: int) -> None:
				self.escapeId = value

			def SetAffirmativeId(self, value: int) -> None:
				self.affirmativeId = value

			def SetSizer(self, _sizer: object) -> None:
				return

			def SetSize(self, _size: tuple[int, int]) -> None:
				return

			def CentreOnParent(self) -> None:
				return

			def ShowModal(self) -> int:
				return 9

			def EndModal(self, _value: int) -> None:
				return

			def Destroy(self) -> None:
				self.destroyed = True

		class TextCtrl:
			instance: TextCtrl | None = None

			def __init__(self, parent: object, *, value: str, style: int) -> None:
				super().__init__()
				type(self).instance = self
				self.parent = parent
				self.value = value
				self.style = style
				self.selected = False
				self.copied = False
				self.focused = False

			def SetName(self, _name: str) -> None:
				return

			def SelectAll(self) -> None:
				self.selected = True

			def Copy(self) -> None:
				self.copied = True

			def SetFocus(self) -> None:
				self.focused = True

		class Button:
			instances: list[Button] = []

			def __init__(self, _parent: object, _buttonId: int | None = None, *, label: str) -> None:
				super().__init__()
				self.label = label
				self.handler: Callable[[object], None] | None = None
				type(self).instances.append(self)

			def Bind(self, _event: object, handler: Callable[[object], None]) -> None:
				self.handler = handler

			def SetDefault(self) -> None:
				return

		class BoxSizer:
			def __init__(self, _orientation: int) -> None:
				super().__init__()

			def Add(self, *_args: object) -> None:
				return

			def AddStretchSpacer(self) -> None:
				return

		wx = SimpleNamespace(
			Dialog=Dialog,
			TextCtrl=TextCtrl,
			Button=Button,
			BoxSizer=BoxSizer,
			TE_MULTILINE=1,
			TE_READONLY=2,
			ID_CLOSE=3,
			EVT_BUTTON=object(),
			VERTICAL=4,
			HORIZONTAL=5,
			EXPAND=8,
			ALL=16,
			RIGHT=32,
			LEFT=64,
			BOTTOM=128,
		)

		with patch.object(compositionModule, "import_module", return_value=wx):
			panel._showCapabilityDetails("Capability: rawUiaInspection")

		dialog = Dialog.instance
		text = TextCtrl.instance
		assert dialog is not None and text is not None
		self.assertIs(dialog.parent, panel)
		self.assertEqual(wx.TE_MULTILINE | wx.TE_READONLY, text.style)
		self.assertEqual(wx.ID_CLOSE, dialog.escapeId)
		self.assertEqual(wx.ID_CLOSE, dialog.affirmativeId)
		self.assertTrue(text.focused)
		self.assertTrue(dialog.destroyed)
		self.assertEqual(2, len(Button.instances))
		self.assertNotEqual(Button.instances[0].label, Button.instances[1].label)
		assert Button.instances[0].handler is not None
		Button.instances[0].handler(object())
		self.assertTrue(text.selected)
		self.assertTrue(text.copied)

	def test_zero_captures_announces_no_change_without_confirmation(self) -> None:
		controller = _controller(capturePort=_CapturePort(recognizedCount=0))
		panel = _nativePanel(controller)
		confirmations: list[tuple[object, ...]] = []
		panel._confirm = lambda *args: confirmations.append(args) or False
		ui = SimpleNamespace(messages=[], message=lambda message: ui.messages.append(message))
		definition = next(
			control for control in panelDefinition().controls if control.controlId == "clearPublishedCaptures"
		)

		with patch.object(
			compositionModule,
			"import_module",
			side_effect=lambda name: ui if name == "ui" else None,
		):
			panel.onKeystoneAction(definition)

		self.assertEqual([], confirmations)
		self.assertEqual([panelMessages().noCapturesBody], ui.messages)

	def test_positive_capture_count_still_uses_confirmation(self) -> None:
		controller = _controller(capturePort=_CapturePort(recognizedCount=1))
		panel = _nativePanel(controller)
		confirmations: list[tuple[object, ...]] = []
		panel._confirm = lambda *args: confirmations.append(args) or False
		definition = next(
			control for control in panelDefinition().controls if control.controlId == "clearPublishedCaptures"
		)

		panel.onKeystoneAction(definition)

		self.assertEqual(1, len(confirmations))


class _MessageDialog:
	instance: _MessageDialog | None = None
	modalResult = 2

	def __init__(self, *_args: object, **_kwargs: object) -> None:
		super().__init__()
		type(self).instance = self
		self.labels: tuple[str, str] | None = None
		self.style = _kwargs.get("style")

	def SetOKCancelLabels(self, ok: str, cancel: str) -> None:
		self.labels = (ok, cancel)

	def ShowModal(self) -> int:
		return type(self).modalResult

	def Destroy(self) -> None:
		return


class _RichMessageDialog:
	instance: _RichMessageDialog | None = None

	def __init__(
		self,
		parent: object,
		message: str,
		title: str,
		*,
		style: int,
	) -> None:
		super().__init__()
		type(self).instance = self
		self.parent = parent
		self.message = message
		self.title = title
		self.style = style
		self.details: str | None = None
		self.escapeId: int | None = None
		self.destroyed = False

	def ShowDetailedText(self, details: str) -> None:
		self.details = details

	def SetEscapeId(self, escapeId: int) -> None:
		self.escapeId = escapeId

	def ShowModal(self) -> int:
		return 1

	def Destroy(self) -> None:
		self.destroyed = True


class NativeDialogTests(unittest.TestCase):
	def test_rejected_or_failed_save_shows_error_and_blocks_dialog_close(self) -> None:
		for expectedCode, expectedMessage, settingsPort, maximumNodes in (
			("KS.SETTINGS.VALIDATION_REJECTED", "Correct the listed values", _SettingsPort(1), 1),
			(
				"KS.SETTINGS.REVISION_MISMATCH",
				"could not complete the save",
				_SettingsPort(2),
				6_000,
			),
		):
			with self.subTest(errorCode=expectedCode):
				controller = _controller(settingsPort=settingsPort)
				panel = _nativePanel(controller)
				controls = _controlsForCandidate(controller)
				controls["maximumNodes"].value = maximumNodes
				panel._keystoneBuilder = SimpleNamespace(
					controls=controls,
					choiceTokens={},
				)
				presentations: list[object] = []
				panel._showValidation = lambda presentation: presentations.append(presentation)

				with (
					patch.object(
						compositionModule,
						"import_module",
						return_value=SimpleNamespace(Choice=_Choice),
					),
					self.assertRaisesRegex(ValueError, "not saved"),
				):
					panel.onSave()

				self.assertEqual(1, len(presentations))
				presentation = presentations[0]
				self.assertEqual("Keystone settings not saved", presentation.title)
				self.assertIn(expectedMessage, presentation.message)
				self.assertIn(expectedCode, presentation.details)

	def test_confirmation_uses_native_cancel_id_and_unique_mnemonics(self) -> None:
		panel = _nativePanel(_controller())
		wx = SimpleNamespace(
			MessageDialog=_MessageDialog,
			OK=1,
			CANCEL=2,
			CANCEL_DEFAULT=4,
			ICON_WARNING=8,
			ID_OK=1,
			ID_CANCEL=2,
		)
		_MessageDialog.modalResult = wx.ID_CANCEL

		with patch.object(compositionModule, "import_module", return_value=wx):
			self.assertFalse(
				panel._confirm(
					panelMessages().restoreDefaultsTitle,
					panelMessages().restoreDefaultsConfirmation,
					panelMessages().restoreDefaultsAction,
				),
			)
		dialog = _MessageDialog.instance
		assert dialog is not None and dialog.labels is not None
		assert dialog is not None and dialog.labels is not None
		self.assertEqual(wx.OK | wx.CANCEL | wx.CANCEL_DEFAULT | wx.ICON_WARNING, dialog.style)
		self.assertEqual(1, dialog.labels[0].count("&"))
		self.assertEqual(1, dialog.labels[1].count("&"))
		yesMnemonic = dialog.labels[0].split("&", 1)[1][0].casefold()
		noMnemonic = dialog.labels[1].split("&", 1)[1][0].casefold()
		self.assertNotEqual(yesMnemonic, noMnemonic)
		_MessageDialog.modalResult = wx.ID_OK
		with patch.object(compositionModule, "import_module", return_value=wx):
			self.assertTrue(
				panel._confirm(
					panelMessages().restoreDefaultsTitle,
					panelMessages().restoreDefaultsConfirmation,
					panelMessages().restoreDefaultsAction,
				),
			)

	def test_validation_dialog_uses_top_level_wx_rich_message_api(self) -> None:
		panel = _nativePanel(_controller())
		wx = SimpleNamespace(
			RichMessageDialog=_RichMessageDialog,
			OK=1,
			ICON_ERROR=2,
			ID_OK=3,
		)
		presentation = SimpleNamespace(
			message="One setting needs your attention.",
			title="Keystone settings not saved",
			details="1. Maximum nodes per bounded capture",
		)

		def importFake(name: str) -> object:
			if name == "wx":
				return wx
			raise AssertionError(f"unexpected module import: {name}")

		with patch.object(compositionModule, "import_module", side_effect=importFake):
			panel._showValidation(presentation)

		dialog = _RichMessageDialog.instance
		assert dialog is not None
		self.assertIs(dialog.parent, panel)
		self.assertEqual(presentation.message, dialog.message)
		self.assertEqual(presentation.title, dialog.title)
		self.assertEqual(presentation.details, dialog.details)
		self.assertEqual(wx.OK | wx.ICON_ERROR, dialog.style)
		self.assertEqual(wx.ID_OK, dialog.escapeId)
		self.assertTrue(dialog.destroyed)

	def test_invalid_candidate_opens_summary_details_and_selects_first_field(self) -> None:
		controller = _controller()
		panel = _nativePanel(controller)
		controls = _controlsForCandidate(controller)
		controls["maximumNodes"].value = 1
		panel._keystoneBuilder = SimpleNamespace(
			controls=controls,
			choiceTokens={},
		)
		presentations: list[object] = []
		panel._showValidation = lambda presentation: presentations.append(presentation)
		ui = SimpleNamespace(message=lambda _message: None)
		wx = SimpleNamespace(Choice=_Choice)

		with patch.object(
			compositionModule,
			"import_module",
			side_effect=lambda name: wx if name == "wx" else ui if name == "ui" else None,
		):
			self.assertFalse(panel.isValid())

		self.assertEqual(1, len(presentations))
		presentation = presentations[0]
		self.assertEqual("Keystone settings not saved", presentation.title)
		self.assertIn("Maximum nodes per bounded capture", presentation.message)
		self.assertIn("KS.SETTINGS.VALIDATION_REJECTED", presentation.details)
		self.assertTrue(controls["maximumNodes"].focused)
		self.assertTrue(controls["maximumNodes"].selected)


class _RecordingPreviewPort:
	def __init__(self) -> None:
		super().__init__()
		self.previews: list[tuple[CueAtomId, int, FeedbackRequest, FeedbackRequest]] = []
		self.stops = 0
		self.enabledCalls: list[bool] = []

	def preview(
		self,
		atom: CueAtomId,
		*,
		generation: int,
		announcement: FeedbackRequest,
		unavailable: FeedbackRequest,
	) -> object:
		self.previews.append((atom, generation, announcement, unavailable))
		return None

	def stopPreview(self) -> None:
		self.stops += 1

	def setEnabled(self, enabled: bool) -> None:
		self.enabledCalls.append(enabled)


class NativePreviewTests(unittest.TestCase):
	def test_native_builder_maps_preview_choice_to_atom_tokens(self) -> None:
		class Panel:
			def scaleSize(self, value: int) -> int:
				return value

		class StaticText:
			def __init__(self, _parent: object, *, label: str) -> None:
				super().__init__()
				self.label = label

			def Wrap(self, _width: int) -> None:
				return

		class Helper:
			def __init__(self) -> None:
				super().__init__()
				self.control: _Choice | None = None

			def addLabeledControl(
				self,
				_label: str,
				_controlType: type[_Choice],
				*,
				choices: tuple[str, ...],
			) -> _Choice:
				self.control = _Choice(choices, 0)
				return self.control

			def addItem(self, _item: object) -> None:
				return

		definition = next(
			control for control in panelDefinition().controls if control.controlId == "soundPreviewCue"
		)
		labels = previewCueChoiceLabels()
		helper = Helper()
		builder = compositionModule._NativePanelBuilder(Panel(), object())
		builder._helper = helper
		wx = SimpleNamespace(Choice=_Choice, StaticText=StaticText)

		with patch.object(compositionModule, "import_module", return_value=wx):
			builder.addChoice(definition, labels[2], labels, True)

		assert helper.control is not None
		self.assertEqual(2, helper.control.GetSelection())
		self.assertEqual(
			tuple(atom.value for atom in PREVIEW_CUE_ORDER),
			builder.choiceTokens["soundPreviewCue"],
		)

	def test_preview_button_auditions_selected_cue_through_injected_port(self) -> None:
		preview = _RecordingPreviewPort()
		controller = _controller(preview=preview)
		panel = _nativePanel(controller)
		labels = previewCueChoiceLabels()
		panel._keystoneBuilder = SimpleNamespace(
			controls={"soundPreviewCue": _Choice(labels, 4)},
			choiceTokens={"soundPreviewCue": tuple(atom.value for atom in PREVIEW_CUE_ORDER)},
		)
		definition = next(
			control for control in panelDefinition().controls if control.controlId == "previewSound"
		)

		panel.onKeystoneAction(definition)

		self.assertEqual(1, len(preview.previews))
		atom, generation, announcement, unavailable = preview.previews[0]
		self.assertEqual(PREVIEW_CUE_ORDER[4], atom)
		self.assertEqual(1, generation)
		self.assertEqual("sound.preview", announcement.messageId)
		self.assertEqual("sound.preview.failed", unavailable.messageId)


if __name__ == "__main__":
	_ = unittest.main()
