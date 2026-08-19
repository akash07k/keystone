# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from dataclasses import fields, replace
from importlib import import_module
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.application.settings_service import SettingsService
from addon.globalPlugins.keystone.capability import (
	CapabilitySnapshot,
	CapabilityState,
	defaultCapabilitySnapshot,
)
from addon.globalPlugins.keystone.domain.correlation import (
	CorrelationContext,
	CorrelationFactory,
)
from addon.globalPlugins.keystone.domain.settings import SettingId, SettingsSnapshot
from addon.globalPlugins.keystone.domain.sounds import CueAtomId
from addon.globalPlugins.keystone.domain.status import EvidenceState, EvidenceStateCounts, OutcomeSummary
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
from addon.globalPlugins.keystone.presentation.status_presenter import (
	StateCountPresentation,
	presentStatus,
	resolveStateCount,
)

if TYPE_CHECKING:
	from addon.globalPlugins.keystone.adapters.wx.settings_panel import NativeControlDefinition


panelModule = import_module("addon.globalPlugins.keystone.adapters.wx.settings_panel")
_CONTEXTS: dict[int, CorrelationContext] = {}


def _context(generation: int) -> CorrelationContext:
	if generation not in _CONTEXTS:
		_CONTEXTS[generation] = CorrelationFactory().admit(generation=generation)
	return _CONTEXTS[generation]


class InjectedCatalog:
	def __init__(self) -> None:
		super().__init__()
		self.calls: list[tuple[object, ...]] = []

	def gettext(self, message: str) -> str:
		self.calls.append(("gettext", message))
		return f"translated:{message}"

	def pgettext(self, context: str, message: str) -> str:
		self.calls.append(("pgettext", context, message))
		return f"translated:{context}:{message}"

	def ngettext(self, singular: str, plural: str, count: int) -> str:
		self.calls.append(("ngettext", singular, plural, count))
		selected = singular if count == 1 else plural
		return f"translated:{selected}"


class LocalizationTests(unittest.TestCase):
	def test_partial_outcomes_retain_canonical_tokens(self) -> None:
		correlation = _context(3)
		counts = EvidenceStateCounts(
			tuple((state, 1 if state is EvidenceState.FAILED else 0) for state in EvidenceState),
		)
		partial = presentStatus(
			OutcomeSummary(
				"completedPartial",
				counts,
				successfulAreas=("accessibilityEvidence",),
				failedAreas=("screenshot",),
				errorCode="KS.SCREENSHOT.ENCODE_FAILED",
				diagnosticId="diagnostic-1",
			),
			correlation,
		)

		self.assertEqual("KS.SCREENSHOT.ENCODE_FAILED", partial.detail.errorCode)
		self.assertEqual(EvidenceState.FAILED, partial.counts[-2].canonicalToken)

	def test_state_counts_use_catalog_pluralization_and_keep_canonical_state(self) -> None:
		catalog = InjectedCatalog()
		counts = EvidenceStateCounts(
			tuple((state, 1 if state is EvidenceState.VALUE else 2) for state in EvidenceState),
		)
		model = presentStatus(OutcomeSummary("completed", counts), None)

		singular = resolveStateCount(model.counts[0], catalog)
		plural = resolveStateCount(model.counts[1], catalog)

		self.assertIn("1", singular)
		self.assertIn("2", plural)
		self.assertEqual(EvidenceState.VALUE, model.counts[0].canonicalToken)
		self.assertEqual(EvidenceState.EMPTY, model.counts[1].canonicalToken)
		self.assertIn(("ngettext", "{count} item", "{count} items", 1), catalog.calls)
		self.assertIn(("ngettext", "{count} item", "{count} items", 2), catalog.calls)

	def test_state_count_plural_templates_preserve_valid_singular_and_plural_text(self) -> None:
		class CountCatalog:
			@staticmethod
			def gettext(message: str) -> str:
				return message

			@staticmethod
			def pgettext(context: str, message: str) -> str:
				return message

			@staticmethod
			def ngettext(singular: str, plural: str, count: int) -> str:
				return singular if count == 1 else plural

		catalog = CountCatalog()
		singular = StateCountPresentation(
			EvidenceState.VALUE,
			"evidenceState.value",
			EvidenceState.VALUE,
			1,
		)
		plural = StateCountPresentation(
			EvidenceState.EMPTY,
			"evidenceState.empty",
			EvidenceState.EMPTY,
			2,
		)

		self.assertEqual("1 item: Available", resolveStateCount(singular, catalog))
		self.assertEqual("2 items: Empty", resolveStateCount(plural, catalog))

	def test_state_count_plural_templates_degrade_safely_when_malformed(self) -> None:
		class MalformedCatalog:
			def __init__(self, template: str) -> None:
				super().__init__()
				self._template = template

			@staticmethod
			def gettext(message: str) -> str:
				return message

			@staticmethod
			def pgettext(context: str, message: str) -> str:
				return message

			def ngettext(self, singular: str, plural: str, count: int) -> str:
				return self._template

		count = StateCountPresentation(
			EvidenceState.VALUE,
			"evidenceState.value",
			EvidenceState.VALUE,
			2,
		)
		for template in (
			"{missing} records",
			"{} records",
			"{count[0]} records",
			"{count!r} records",
			"{count",
		):
			with self.subTest(template=template):
				self.assertEqual("2 items: Available", resolveStateCount(count, MalformedCatalog(template)))

	def test_complete_panel_inventory_uses_the_injected_catalog(self) -> None:
		catalog = InjectedCatalog()

		definition = panelModule.panelDefinition(catalog)
		messages = panelModule.panelMessages(catalog)
		panel = panelModule.KeystoneSettingsPanel(_controller(catalog=catalog), catalog=catalog)

		self.assertTrue(all(group.startswith("translated:") for group in definition.groups))
		self.assertTrue(all(control.group.startswith("translated:") for control in definition.controls))
		self.assertTrue(all(control.label.startswith("translated:") for control in definition.controls))
		self.assertTrue(all(control.helpText.startswith("translated:") for control in definition.controls))
		self.assertTrue(
			all(getattr(messages, field.name).startswith("translated:") for field in fields(messages)),
		)
		self.assertTrue(panel.title.startswith("translated:"))
		self.assertTrue(panel.panelDescription.startswith("translated:"))
		self.assertIn("translated:", panelModule.clearCapturesConfirmation(2, catalog))


class RecordingSettingsPort:
	def __init__(self, revision: int) -> None:
		super().__init__()
		self.revision = revision
		self.requests: list[SettingsWriteRequest] = []

	def readSettings(self, request: SettingsReadRequest) -> EffectResult:
		return EffectResult(PortStatus("ready", self.revision))

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		self.requests.append(request)
		self.revision += 1
		return EffectResult(PortStatus("ready", self.revision), PortOutcome("settingsUpdated"))


class RecordingCapturePort:
	def __init__(self) -> None:
		super().__init__()
		self.requests: list[CaptureManagementRequest] = []

	def manageCaptures(self, request: CaptureManagementRequest) -> CaptureManagementResult:
		self.requests.append(request)
		return CaptureManagementResult(
			operation=request.operation,
			lifecycleGeneration=request.lifecycleGeneration,
			status=PortStatus("ready", 4),
			outcome=PortOutcome("captureStatus"),
			error=None,
			recognizedCount=2,
			suspiciousCount=1,
			deletedCount=2 if request.operation == "clearAll" else 0,
			skippedCount=0,
			failedCount=0,
			confirmationRevision=9,
			copyActionId=None,
			openActionId=None,
			revealActionId=None,
		)


class RecordingPanelBuilder:
	def __init__(self) -> None:
		super().__init__()
		self.groups: list[str] = []
		self.controls: list[str] = []
		self.buttonLabels: dict[str, str] = {}
		self.checkboxHelpTexts: dict[str, str] = {}

	def beginGroup(self, label: str) -> None:
		self.groups.append(label)

	def addSpin(
		self,
		definition: NativeControlDefinition,
		value: int,
		minimum: int,
		maximum: int,
	) -> None:
		self.controls.append(definition.controlId)

	def addCheckBox(self, definition: NativeControlDefinition, value: bool, enabled: bool) -> None:
		self.controls.append(definition.controlId)
		self.checkboxHelpTexts[definition.controlId] = definition.helpText

	def addChoice(
		self,
		definition: NativeControlDefinition,
		value: str,
		choices: tuple[str, ...],
		enabled: bool,
	) -> None:
		self.controls.append(definition.controlId)

	def addButton(self, definition: NativeControlDefinition, enabled: bool) -> None:
		self.controls.append(definition.controlId)
		self.buttonLabels[definition.controlId] = definition.label


class PanelDefinitionTests(unittest.TestCase):
	def test_native_inventory_has_fixed_group_and_focus_order(self) -> None:
		definition = panelModule.panelDefinition()

		self.assertEqual(
			(
				"All Keystone settings are global. Named, application, and temporary NVDA "
				"configuration profiles do not override them. Changes apply to new work."
			),
			panelModule.KeystoneSettingsPanel.panelDescription,
		)
		self.assertEqual(
			definition.groups,
			(
				"Capture limits",
				"Privacy",
				"Output and screenshots",
				"Inspector and events",
				"Sounds",
				"Restore defaults",
			),
		)
		self.assertEqual(
			definition.focusOrder,
			(
				"maximumNodes",
				"maximumDepth",
				"captureTimeSeconds",
				"maximumTextCharacters",
				"progressIntervalSeconds",
				"redactProtectedText",
				"jsonFullTabIndentation",
				"clearPublishedCaptures",
				"eventDetailCharacters",
				"eventRows",
				"offlineFileMegabytes",
				"propertyIntervalMilliseconds",
				"swapPropertyActions",
				"forceRawUia",
				"rawUiaDetails",
				"soundsEnabled",
				"soundPreviewCue",
				"previewSound",
				"soundDetails",
				"restoreDefaults",
			),
		)
		self.assertTrue(all(control.native for control in definition.controls))
		self.assertTrue(all(control.label and control.helpText for control in definition.controls))
		self.assertFalse(definition.usesCustomColors)
		self.assertFalse(definition.usesNestedScroller)

	def test_every_actionable_control_has_one_english_mnemonic(self) -> None:
		mnemonics: dict[str, str] = {}
		for control in panelModule.panelDefinition().controls:
			self.assertEqual(1, control.label.count("&"), control.controlId)
			index = control.label.index("&")
			self.assertLess(index + 1, len(control.label), control.controlId)
			mnemonic = control.label[index + 1].casefold()
			self.assertTrue(mnemonic.isascii() and mnemonic.isalpha(), control.controlId)
			self.assertNotIn(mnemonic, mnemonics, control.controlId)
			mnemonics[mnemonic] = control.controlId

	def test_builder_renders_every_group_and_native_control(self) -> None:
		definition = panelModule.panelDefinition()
		builder = RecordingPanelBuilder()

		panelModule.KeystoneSettingsPanel(_controller()).makeSettings(builder)

		self.assertEqual(definition.groups, tuple(builder.groups))
		self.assertEqual(definition.focusOrder, tuple(builder.controls))

	def test_held_closed_and_dependent_controls_stay_visible_disabled(self) -> None:
		controller = _controller()

		states = {state.controlId: state for state in controller.controlStates()}

		self.assertTrue(states["forceRawUia"].visible)
		self.assertFalse(states["forceRawUia"].enabled)
		self.assertTrue(states["forceRawUia"].explanation)


class CapabilityDetailLabelTests(unittest.TestCase):
	def test_raw_uia_checkbox_help_tracks_capability_status(self) -> None:
		for status, enabled in (
			("enabled", True),
			("unavailable", False),
			("heldClosed", False),
			("disabled", False),
			("unclaimed", False),
		):
			with self.subTest(status=status):
				controller = _controller(
					capabilities=_capabilities(rawUiaStatus=status, soundStatus="heldClosed"),
				)
				states = {state.controlId: state for state in controller.controlStates()}
				builder = RecordingPanelBuilder()
				panelModule.KeystoneSettingsPanel(controller).makeSettings(builder)

				expectedStatus = {"heldClosed": "held closed"}.get(status, status)
				expectedHelp = f"Raw UI Automation inspection is {expectedStatus}."
				self.assertEqual(enabled, states["forceRawUia"].enabled)
				self.assertEqual(expectedHelp, states["forceRawUia"].explanation)
				self.assertEqual(expectedHelp, builder.checkboxHelpTexts["forceRawUia"])

	def test_unavailable_raw_uia_preserves_saved_preference_on_apply(self) -> None:
		snapshot = replace(SettingsSnapshot.defaults(settingsRevision=1), forceRawUia=True)
		settingsPort = RecordingSettingsPort(1)
		controller = _controller(
			snapshot=snapshot,
			settingsPort=settingsPort,
			capabilities=_capabilities(rawUiaStatus="unavailable", soundStatus="heldClosed"),
		)
		rawUiaState = {state.controlId: state for state in controller.controlStates()}["forceRawUia"]
		controller.setValue(SettingId.EVENT_ROWS, 25)

		result = controller.apply()

		self.assertTrue(rawUiaState.value)
		self.assertFalse(rawUiaState.enabled)
		self.assertEqual("updated", result.status.value)
		self.assertTrue(result.snapshot.forceRawUia)
		self.assertTrue(dict(settingsPort.requests[0].values)["forceRawUia"])

	def test_enabled_raw_uia_and_sound_feedback_labels_match_the_snapshot(self) -> None:
		controller = _controller(
			capabilities=_capabilities(rawUiaStatus="enabled", soundStatus="enabled"),
		)
		states = {state.controlId: state for state in controller.controlStates()}
		builder = RecordingPanelBuilder()

		panelModule.KeystoneSettingsPanel(controller).makeSettings(builder)

		self.assertEqual(
			"Raw UI Automation enabled; Capab&ility Details...",
			states["rawUiaDetails"].label,
		)
		self.assertEqual(
			"Sound feedback enabled; Capabilit&y Details...",
			states["soundDetails"].label,
		)
		self.assertEqual(
			"Raw UI Automation inspection is enabled; open details for status, reason, and safe fallback.",
			states["rawUiaDetails"].explanation,
		)
		self.assertEqual(
			"Sound feedback is enabled; complete localized speech remains active.",
			states["soundDetails"].explanation,
		)
		self.assertEqual(states["rawUiaDetails"].label, builder.buttonLabels["rawUiaDetails"])
		self.assertEqual(states["soundDetails"].label, builder.buttonLabels["soundDetails"])

	def test_unavailable_capabilities_label_both_details_buttons_unavailable(self) -> None:
		controller = _controller(
			capabilities=_capabilities(rawUiaStatus="unavailable", soundStatus="unavailable"),
		)
		states = {state.controlId: state for state in controller.controlStates()}

		self.assertEqual(
			"Raw UI Automation unavailable; Capab&ility Details...",
			states["rawUiaDetails"].label,
		)
		self.assertEqual(
			"Sound feedback unavailable; Capabilit&y Details...",
			states["soundDetails"].label,
		)

	def test_held_closed_capabilities_label_both_details_buttons_held_closed(self) -> None:
		states = {state.controlId: state for state in _controller().controlStates()}

		self.assertEqual(
			"Raw UI Automation held closed; Capab&ility Details...",
			states["rawUiaDetails"].label,
		)
		self.assertEqual(
			"Sound feedback held closed; Capabilit&y Details...",
			states["soundDetails"].label,
		)


class SettingsSemanticsTests(unittest.TestCase):
	def test_invalid_apply_writes_nothing_and_identifies_first_control(self) -> None:
		settingsPort = RecordingSettingsPort(1)
		controller = _controller(settingsPort=settingsPort)
		controller.setValue(SettingId.MAXIMUM_NODES, 1)
		controller.setValue(SettingId.MAXIMUM_DEPTH, 0)

		result = controller.apply()

		self.assertEqual(result.status.value, "rejected")
		self.assertEqual(result.issues[0].settingId, SettingId.MAXIMUM_NODES)
		self.assertEqual(len(result.issues), 2)
		self.assertEqual(settingsPort.requests, [])

	def test_restore_changes_controls_only_until_apply_and_cancel_discards(self) -> None:
		settingsPort = RecordingSettingsPort(3)
		snapshot = SettingsSnapshot.defaults(settingsRevision=3)
		controller = _controller(snapshot=snapshot, settingsPort=settingsPort)
		controller.setValue(SettingId.MAXIMUM_NODES, 9_000)
		changed = controller.restoreDefaults(confirmed=True)

		self.assertIn(SettingId.MAXIMUM_NODES, changed)
		self.assertEqual(settingsPort.requests, [])
		controller.setValue(SettingId.MAXIMUM_DEPTH, 75)
		controller.cancel()
		self.assertEqual(controller.candidate(), snapshot.asCandidate())
		self.assertEqual(settingsPort.requests, [])

	def test_apply_commits_one_complete_candidate(self) -> None:
		settingsPort = RecordingSettingsPort(6)
		controller = _controller(
			snapshot=SettingsSnapshot.defaults(settingsRevision=6),
			settingsPort=settingsPort,
		)
		controller.setValue(SettingId.MAXIMUM_NODES, 7_000)

		result = controller.apply()

		self.assertEqual(result.status.value, "updated")
		self.assertEqual(len(settingsPort.requests), 1)
		self.assertEqual(len(settingsPort.requests[0].values), 14)
		self.assertEqual(settingsPort.requests[0].startingRevision, 6)


class ManagementSemanticsTests(unittest.TestCase):
	def test_refresh_and_confirmed_capture_clear_use_exact_current_revision(self) -> None:
		capturePort = RecordingCapturePort()
		controller = _controller(capturePort=capturePort, generation=8)

		status = controller.refreshCaptures()
		controller.clearPublishedCaptures(confirmed=False)
		cleared = controller.clearPublishedCaptures(confirmed=True)

		self.assertEqual(status.recognizedCount, 2)
		self.assertEqual(cleared.deletedCount, 2)
		self.assertEqual(
			capturePort.requests,
			[
				CaptureManagementRequest("refresh", _context(8), 8),
				CaptureManagementRequest("clearAll", _context(8), 8, confirmationRevision=9),
			],
		)


def _controller(
	*,
	snapshot: SettingsSnapshot | None = None,
	settingsPort: RecordingSettingsPort | None = None,
	capturePort: RecordingCapturePort | None = None,
	capabilities: CapabilitySnapshot = defaultCapabilitySnapshot,
	generation: int = 1,
	catalog: InjectedCatalog | None = None,
	preview: object | None = None,
	settingsApplied: object | None = None,
):
	current = snapshot or SettingsSnapshot.defaults(settingsRevision=1)
	port = settingsPort or RecordingSettingsPort(current.settingsRevision)
	return panelModule.SettingsPanelController(
		snapshot=current,
		settingsService=SettingsService(port),
		capabilities=capabilities,
		captureManagement=capturePort or RecordingCapturePort(),
		lifecycleGeneration=generation,
		context=_context(generation),
		catalog=catalog,
		preview=preview,
		settingsApplied=settingsApplied,
	)


def _capabilities(*, rawUiaStatus: str, soundStatus: str) -> CapabilitySnapshot:
	return _CapabilitySnapshot(
		tuple(
			CapabilityState(
				record.capabilityId,
				(
					rawUiaStatus
					if record.capabilityId == "rawUiaInspection"
					else soundStatus
					if record.capabilityId == "audioFeedback"
					else record.status
				),
				record.gateId,
				record.reasonCode,
				record.fallbackCode,
			)
			for record in defaultCapabilitySnapshot.records
		),
	)


class _CapabilitySnapshot:
	def __init__(self, records: tuple[CapabilityState, ...]) -> None:
		super().__init__()
		self.records = records


class RecordingSettingsAppliedPort:
	def __init__(self, order: list[str] | None = None) -> None:
		super().__init__()
		self.applied: list[SettingsSnapshot] = []
		self._order = order

	def applySettings(self, settings: SettingsSnapshot) -> None:
		self.applied.append(settings)
		if self._order is not None:
			self._order.append("settings")


class FailingSettingsAppliedPort:
	def applySettings(self, _settings: SettingsSnapshot) -> None:
		raise RuntimeError("runtime settings application failed")


class RecordingLogger:
	def __init__(self) -> None:
		super().__init__()
		self.exceptionMessages: list[str] = []

	def exception(self, message: str) -> None:
		self.exceptionMessages.append(message)


class SettingsActivationTests(unittest.TestCase):
	def test_applying_settings_reaches_the_running_add_on(self) -> None:
		order: list[str] = []
		settingsApplied = RecordingSettingsAppliedPort(order)
		controller = _controller(settingsApplied=settingsApplied)
		controller.setValue(SettingId.EVENT_ROWS, 25)
		controller.setValue(SettingId.REDACT_PROTECTED_TEXT, True)

		result = controller.apply()

		self.assertEqual("updated", result.status.value)
		self.assertEqual(["settings"], order)
		self.assertEqual([25], [applied.eventRows for applied in settingsApplied.applied])
		self.assertEqual([True], [applied.redactProtectedText for applied in settingsApplied.applied])
		self.assertEqual(2, settingsApplied.applied[0].settingsRevision)

	def test_post_save_application_failure_is_logged_without_failing_the_save(self) -> None:
		logger = RecordingLogger()
		controller = _controller(settingsApplied=FailingSettingsAppliedPort())
		controller.setValue(SettingId.EVENT_ROWS, 25)

		with patch.object(panelModule, "import_module", return_value=SimpleNamespace(log=logger)):
			result = controller.apply()

		self.assertEqual("updated", result.status.value)
		self.assertEqual(2, result.snapshot.settingsRevision)
		self.assertEqual(25, result.snapshot.eventRows)
		self.assertEqual(["Keystone settings application after save failed"], logger.exceptionMessages)


class RecordingPreviewPort:
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


class SoundPreviewControlTests(unittest.TestCase):
	def _states(self, controller: Any) -> dict[str, Any]:
		return {state.controlId: state for state in controller.controlStates()}

	def test_sound_controls_default_selected_enabled_and_disclose_volume(self) -> None:
		controller = _controller()
		states = self._states(controller)

		self.assertEqual(states["soundsEnabled"].value, True)
		self.assertTrue(states["soundsEnabled"].enabled)
		self.assertIn(
			"NVDA or system volume",
			states["soundsEnabled"].explanation,
		)
		self.assertEqual(
			states["soundPreviewCue"].value,
			panelModule.previewCueName(panelModule.PREVIEW_CUE_ORDER[0]),
		)
		self.assertTrue(states["soundPreviewCue"].enabled)
		self.assertTrue(states["previewSound"].enabled)

	def test_preview_inventory_lists_every_cue_once_in_manifest_order(self) -> None:
		self.assertEqual(panelModule.PREVIEW_CUE_ORDER, tuple(CueAtomId))
		labels = panelModule.previewCueChoiceLabels()
		self.assertEqual(len(labels), len(tuple(CueAtomId)))
		self.assertEqual(
			labels,
			tuple(panelModule.previewCueName(atom) for atom in CueAtomId),
		)

	def test_selecting_a_cue_updates_the_reported_choice_value(self) -> None:
		controller = _controller()
		chosen = panelModule.PREVIEW_CUE_ORDER[3]

		controller.setPreviewCue(chosen)

		self.assertEqual(controller.previewCue(), chosen)
		self.assertEqual(
			self._states(controller)["soundPreviewCue"].value,
			panelModule.previewCueName(chosen),
		)

	def test_preview_speaks_first_and_calls_port_owning_dialog_generation(self) -> None:
		preview = RecordingPreviewPort()
		controller = _controller(generation=4, preview=preview)
		chosen = panelModule.PREVIEW_CUE_ORDER[5]
		name = panelModule.previewCueName(chosen)

		controller.setPreviewCue(chosen)
		controller.previewSelectedCue()

		self.assertEqual(len(preview.previews), 1)
		atom, generation, announcement, unavailable = preview.previews[0]
		self.assertEqual(atom, chosen)
		self.assertEqual(generation, 4)
		self.assertEqual(announcement.messageId, "sound.preview")
		self.assertEqual(announcement.arguments, (name,))
		self.assertEqual(announcement.context.generation, 4)
		self.assertEqual(unavailable.messageId, "sound.preview.failed")
		self.assertEqual(unavailable.arguments, (name,))
		self.assertEqual(unavailable.context.generation, 4)

	def test_close_stops_active_preview_and_blocks_further_audition(self) -> None:
		preview = RecordingPreviewPort()
		controller = _controller(preview=preview)

		controller.close()

		self.assertEqual(preview.stops, 1)
		controller.previewSelectedCue()
		self.assertEqual(len(preview.previews), 0)
		states = self._states(controller)
		self.assertFalse(states["soundPreviewCue"].enabled)
		self.assertFalse(states["previewSound"].enabled)

	def test_preview_without_a_port_is_a_safe_noop(self) -> None:
		controller = _controller(preview=None)

		controller.previewSelectedCue()  # must not raise

	def test_apply_drives_live_service_enablement_from_committed_preference(self) -> None:
		preview = RecordingPreviewPort()
		controller = _controller(preview=preview)

		controller.setValue(SettingId.SOUNDS_ENABLED, False)
		result = controller.apply()

		self.assertEqual(result.status.value, "updated")
		self.assertEqual(preview.enabledCalls, [False])


if __name__ == "__main__":
	_ = unittest.main()
