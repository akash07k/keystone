from __future__ import annotations

from dataclasses import dataclass, replace
from importlib import import_module
from typing import Protocol, cast

from ...application.settings_service import SettingsService
from ...capability import CapabilitySnapshot, PlainValue
from ...domain.correlation import CorrelationContext, requireCompleteCorrelation
from ...domain.settings import (
	SETTING_DEFINITIONS,
	SaveResult,
	SettingId,
	SettingsCandidate,
	SettingsSnapshot,
	ValidationResult,
	restoreDefaultCandidate,
)
from ...domain.sounds import CueAtomId
from ...ports.effects import (
	CaptureManagementPort,
	CaptureManagementRequest,
	CaptureManagementResult,
	FeedbackRequest,
)
from ...presentation.commands import NvdaTranslationCatalog, TranslationCatalog


@dataclass(frozen=True, slots=True)
class NativeControlDefinition:
	controlId: str
	group: str
	label: str
	helpText: str
	kind: str
	native: bool = True


@dataclass(frozen=True, slots=True)
class SettingsPanelDefinition:
	groups: tuple[str, ...]
	controls: tuple[NativeControlDefinition, ...]
	focusOrder: tuple[str, ...]
	usesCustomColors: bool = False
	usesNestedScroller: bool = False


@dataclass(frozen=True, slots=True)
class PanelMessages:
	title: str
	panelDescription: str
	restoreDefaultsConfirmation: str
	noCapturesBody: str
	clearCapturesTitle: str
	restoreDefaultsTitle: str
	capabilityDetailsTitle: str
	validationTitle: str
	clearCapturesAction: str
	restoreDefaultsAction: str
	cancelLabel: str
	capabilityDetailsCopy: str
	capabilityDetailsClose: str


@dataclass(frozen=True, slots=True)
class ValidationDialogPresentation:
	title: str
	message: str
	details: str


@dataclass(frozen=True, slots=True)
class ControlState:
	controlId: str
	visible: bool
	enabled: bool
	value: PlainValue
	explanation: str
	label: str


class PreviewPort(Protocol):
	def preview(
		self,
		atom: CueAtomId,
		*,
		generation: int,
		announcement: FeedbackRequest,
		unavailable: FeedbackRequest,
	) -> object: ...

	def stopPreview(self) -> None: ...

	def setEnabled(self, enabled: bool) -> None: ...


_DEFAULT_CATALOG = NvdaTranslationCatalog()
_FOCUS_ORDER = (
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
)


def _catalog(catalog: TranslationCatalog | None) -> TranslationCatalog:
	return _DEFAULT_CATALOG if catalog is None else catalog


# The preview choice lists every atomic cue in the closed manifest order (identical to the
# CueAtomId declaration order enforced by domain.sounds). Display names come from the approved
# bundled asset inventory; they localize independently of the stable atom identifiers.
_PREVIEW_CUE_NAMES: tuple[tuple[CueAtomId, str], ...] = (
	(CueAtomId.LAYER_ENTERED, "Layer entered"),
	(CueAtomId.LAYER_INVALID_KEY, "Layer invalid key"),
	(CueAtomId.LAYER_TIMEOUT, "Layer timeout"),
	(CueAtomId.LAYER_EXPLICIT_EXIT, "Layer explicit exit"),
	(CueAtomId.BOUNDED_FULL_FAMILY, "Bounded full family"),
	(CueAtomId.UNLIMITED_FULL_FAMILY, "Unlimited full family"),
	(CueAtomId.DIFF_FAMILY, "Diff family"),
	(CueAtomId.BOUNDED_NAVIGATOR_FAMILY, "Bounded navigator family"),
	(CueAtomId.UNLIMITED_NAVIGATOR_FAMILY, "Unlimited navigator family"),
	(CueAtomId.START_STATE, "Start state"),
	(CueAtomId.PROGRESS_STATE, "Progress state"),
	(CueAtomId.CANCELLATION_REQUESTED, "Cancellation requested"),
	(CueAtomId.CANCELLED_OUTCOME, "Cancelled outcome"),
	(CueAtomId.SUCCESS_OUTCOME, "Success outcome"),
	(CueAtomId.TRUNCATED_SUCCESS_OUTCOME, "Truncated-success outcome"),
	(CueAtomId.PARTIAL_SCREENSHOT_OUTCOME, "Partial-screenshot outcome"),
	(CueAtomId.NO_CHANGE_OUTCOME, "No-change outcome"),
	(CueAtomId.BASELINE_CREATED_OUTCOME, "Baseline-created outcome"),
	(CueAtomId.FAILURE_OUTCOME, "Failure outcome"),
	(CueAtomId.FOCUS_INSPECTOR_FAMILY, "Focus Inspector family"),
	(CueAtomId.NAVIGATOR_INSPECTOR_FAMILY, "Navigator Inspector family"),
	(CueAtomId.INSPECTOR_REFRESH, "Inspector refresh"),
	(CueAtomId.INSPECTOR_READY, "Inspector ready"),
	(CueAtomId.INSPECTOR_CLOSE, "Inspector close"),
	(CueAtomId.EVENT_MONITOR_START, "Event monitor start"),
	(CueAtomId.EVENT_MONITOR_STOP, "Event monitor stop"),
	(CueAtomId.PENDING_QUEUE_DROP, "Pending-queue drop"),
	(CueAtomId.RETAINED_ROW_DROP, "Retained-row drop"),
	(CueAtomId.EVENT_EXPORT_FAMILY, "Event export family"),
	(CueAtomId.OUTPUT_PATH_COPIED, "Output-path copied"),
	(CueAtomId.EXPLORER_REVEAL, "Explorer reveal"),
	(CueAtomId.COMMAND_HELP_OPENED, "Command help opened"),
	(CueAtomId.QUICK_PROPERTY_BROWSABLE_MESSAGE, "Quick-property browsable message"),
	(CueAtomId.QUICK_PROPERTY_COPY, "Quick-property copy"),
	(CueAtomId.SHARED_WARNING, "Shared warning"),
)
PREVIEW_CUE_ORDER: tuple[CueAtomId, ...] = tuple(atom for atom, _name in _PREVIEW_CUE_NAMES)
_PREVIEW_CUE_NAME_BY_ATOM: dict[CueAtomId, str] = dict(_PREVIEW_CUE_NAMES)

if PREVIEW_CUE_ORDER != tuple(CueAtomId):
	raise RuntimeError("preview cue inventory must list every atom once in manifest order")


def previewCueName(atom: CueAtomId, catalog: TranslationCatalog | None = None) -> str:
	return _catalog(catalog).pgettext("sound cue name", _PREVIEW_CUE_NAME_BY_ATOM[atom])


def previewCueChoiceLabels(catalog: TranslationCatalog | None = None) -> tuple[str, ...]:
	active = _catalog(catalog)
	return tuple(active.pgettext("sound cue name", name) for _atom, name in _PREVIEW_CUE_NAMES)


def _capabilityStatusLabel(status: str, catalog: TranslationCatalog) -> str:
	message = {
		"enabled": "enabled",
		"unavailable": "unavailable",
		"heldClosed": "held closed",
		"disabled": "disabled",
		"unclaimed": "unclaimed",
	}.get(status, "unavailable")
	return catalog.pgettext(
		"settings capability status",
		message,
	)


def _rawUiaHelp(status: str, catalog: TranslationCatalog) -> str:
	return catalog.pgettext(
		"settings help",
		"Raw UI Automation inspection is {status}.",
	).format(status=_capabilityStatusLabel(status, catalog))


def _capabilityDetailsLabel(
	controlId: str,
	status: str,
	catalog: TranslationCatalog,
) -> str:
	statusLabel = _capabilityStatusLabel(status, catalog)
	if controlId == "rawUiaDetails":
		template = catalog.pgettext(
			"settings action",
			"Raw UI Automation {status}; Capab&ility Details...",
		)
	elif controlId == "soundDetails":
		template = catalog.pgettext(
			"settings action",
			"Sound feedback {status}; Capabilit&y Details...",
		)
	else:
		raise ValueError(f"unknown capability details control {controlId!r}")
	return template.format(status=statusLabel)


def _capabilityDetailsHelp(
	controlId: str,
	status: str,
	catalog: TranslationCatalog,
) -> str:
	statusLabel = _capabilityStatusLabel(status, catalog)
	if controlId == "rawUiaDetails":
		template = catalog.pgettext(
			"settings help",
			"Raw UI Automation inspection is {status}; open details for status, reason, and safe fallback.",
		)
	elif controlId == "soundDetails":
		template = catalog.pgettext(
			"settings help",
			"Sound feedback is {status}; complete localized speech remains active.",
		)
	else:
		raise ValueError(f"unknown capability details control {controlId!r}")
	return template.format(status=statusLabel)


def _groups(catalog: TranslationCatalog) -> tuple[str, ...]:
	return (
		catalog.pgettext("settings group", "Capture limits"),
		catalog.pgettext("settings group", "Privacy"),
		catalog.pgettext("settings group", "Output and screenshots"),
		catalog.pgettext("settings group", "Inspector and events"),
		catalog.pgettext("settings group", "Sounds"),
		catalog.pgettext("settings group", "Restore defaults"),
	)


def _controlDefinitions(
	catalog: TranslationCatalog,
	groups: tuple[str, ...],
) -> tuple[NativeControlDefinition, ...]:
	capture, privacy, output, inspector, sounds, restore = groups
	return (
		NativeControlDefinition(
			"maximumNodes",
			capture,
			catalog.pgettext("settings control", "Maximum &nodes per bounded capture"),
			catalog.pgettext("settings help", "Limits emitted nodes."),
			"spin",
		),
		NativeControlDefinition(
			"maximumDepth",
			capture,
			catalog.pgettext("settings control", "Ma&ximum tree depth per bounded capture"),
			catalog.pgettext("settings help", "Limits hierarchy depth."),
			"spin",
		),
		NativeControlDefinition(
			"captureTimeSeconds",
			capture,
			catalog.pgettext("settings control", "Capture time budget in &seconds"),
			catalog.pgettext("settings help", "Limits elapsed collection time."),
			"spin",
		),
		NativeControlDefinition(
			"maximumTextCharacters",
			capture,
			catalog.pgettext("settings control", "Maximum c&haracters per text range"),
			catalog.pgettext("settings help", "Limits each captured text range."),
			"spin",
		),
		NativeControlDefinition(
			"progressIntervalSeconds",
			capture,
			catalog.pgettext("settings control", "Progress announcement fre&quency in seconds"),
			catalog.pgettext("settings help", "Controls bounded progress announcements."),
			"spin",
		),
		NativeControlDefinition(
			"redactProtectedText",
			privacy,
			catalog.pgettext(
				"settings control",
				"&Redact protected-field text in Keystone evidence",
			),
			catalog.pgettext(
				"settings help",
				"Warning: Protected-field redaction is off by default. When off, new Keystone evidence may contain sensitive text, including password-field values, in captures, exports, event history, and the NVDA log. Screenshots are always unredacted.",
			),
			"checkbox",
		),
		NativeControlDefinition(
			"jsonFullTabIndentation",
			output,
			catalog.pgettext("settings control", "Use full tab indentation in &JSON output files"),
			catalog.pgettext("settings help", "Screenshots remain unredacted."),
			"checkbox",
		),
		NativeControlDefinition(
			"clearPublishedCaptures",
			output,
			catalog.pgettext("settings action", "Clear &All Published Captures..."),
			catalog.pgettext(
				"settings help",
				"Deletes only validated Keystone-owned captures after confirmation.",
			),
			"button",
		),
		NativeControlDefinition(
			"eventDetailCharacters",
			inspector,
			catalog.pgettext("settings control", "Maximum event &detail characters"),
			catalog.pgettext("settings help", "Zero removes only display truncation."),
			"spin",
		),
		NativeControlDefinition(
			"eventRows",
			inspector,
			catalog.pgettext("settings control", "Maximum retained event ro&ws"),
			catalog.pgettext("settings help", "Process safety limits remain active."),
			"spin",
		),
		NativeControlDefinition(
			"offlineFileMegabytes",
			inspector,
			catalog.pgettext("settings control", "Maximum offline file si&ze in megabytes"),
			catalog.pgettext(
				"settings help",
				"Unavailable verification keeps this value visible and disabled.",
			),
			"spin",
		),
		NativeControlDefinition(
			"propertyIntervalMilliseconds",
			inspector,
			catalog.pgettext(
				"settings control",
				"&Property shortcut multi-press interval in milliseconds",
			),
			catalog.pgettext("settings help", "Sets the shortcut multi-press interval."),
			"spin",
		),
		NativeControlDefinition(
			"swapPropertyActions",
			inspector,
			catalog.pgettext(
				"settings control",
				"Swap dou&ble-press and triple-press property actions",
			),
			catalog.pgettext("settings help", "Swaps copy and browsable-detail actions."),
			"checkbox",
		),
		NativeControlDefinition(
			"forceRawUia",
			inspector,
			catalog.pgettext(
				"settings control",
				"Force raw &UI Automation for Keystone inspection",
			),
			catalog.pgettext("settings help", "Raw UI Automation inspection is unavailable."),
			"checkbox",
		),
		NativeControlDefinition(
			"rawUiaDetails",
			inspector,
			catalog.pgettext(
				"settings action",
				"Raw UI Automation unavailable; Capab&ility Details...",
			),
			catalog.pgettext(
				"settings help",
				"Raw UI Automation inspection is unavailable; open details for status, reason, and safe fallback.",
			),
			"button",
		),
		NativeControlDefinition(
			"soundsEnabled",
			sounds,
			catalog.pgettext("settings control", "Enable Keystone s&ounds"),
			catalog.pgettext(
				"settings help",
				"Sounds supplement complete speech and use NVDA or system volume. Keystone has no separate volume control.",
			),
			"checkbox",
		),
		NativeControlDefinition(
			"soundPreviewCue",
			sounds,
			catalog.pgettext("settings control", "Sound &cue to preview"),
			catalog.pgettext(
				"settings help",
				"Auditions any single Keystone cue without changing speech, focus, or command outcomes.",
			),
			"choice",
		),
		NativeControlDefinition(
			"previewSound",
			sounds,
			catalog.pgettext("settings action", "Preview selected cu&e"),
			catalog.pgettext(
				"settings help",
				"Plays the selected cue once at the current NVDA or system volume.",
			),
			"button",
		),
		NativeControlDefinition(
			"soundDetails",
			sounds,
			catalog.pgettext(
				"settings action",
				"Sound feedback unavailable; Capabilit&y Details...",
			),
			catalog.pgettext(
				"settings help",
				"Sound feedback is unavailable; complete localized speech remains active.",
			),
			"button",
		),
		NativeControlDefinition(
			"restoreDefaults",
			restore,
			catalog.pgettext("settings action", "Restore all Keystone de&faults..."),
			catalog.pgettext(
				"settings help",
				"Changes controls only; Apply or OK is required to save.",
			),
			"button",
		),
	)


def panelDefinition(catalog: TranslationCatalog | None = None) -> SettingsPanelDefinition:
	activeCatalog = _catalog(catalog)
	groups = _groups(activeCatalog)
	return SettingsPanelDefinition(groups, _controlDefinitions(activeCatalog, groups), _FOCUS_ORDER)


def panelMessages(catalog: TranslationCatalog | None = None) -> PanelMessages:
	activeCatalog = _catalog(catalog)
	return PanelMessages(
		activeCatalog.pgettext("settings panel title", "Keystone"),
		activeCatalog.pgettext(
			"settings panel description",
			"All Keystone settings are global. Named, application, and temporary NVDA configuration profiles do not override them. Changes apply to new work.",
		),
		activeCatalog.pgettext(
			"restore defaults confirmation",
			"This will replace unsaved values in: Capture limits, Privacy, Output and screenshots, Inspector and events, and Sounds. Nothing is saved until you choose Apply or OK.",
		),
		activeCatalog.pgettext(
			"capture cleanup status",
			"Keystone found 0 recognized published capture folders. No files were changed.",
		),
		activeCatalog.pgettext("confirmation title", "Clear Captures"),
		activeCatalog.pgettext("confirmation title", "Restore Defaults"),
		activeCatalog.pgettext("capability details title", "Capability Details"),
		activeCatalog.pgettext("settings validation title", "Keystone settings not saved"),
		activeCatalog.pgettext("confirmation action", "Clear Ca&ptures"),
		activeCatalog.pgettext("confirmation action", "Restore &Defaults"),
		activeCatalog.pgettext("confirmation action", "&Cancel"),
		activeCatalog.pgettext("capability details action", "&Copy"),
		activeCatalog.pgettext("capability details action", "C&lose"),
	)


def clearCapturesConfirmation(count: int, catalog: TranslationCatalog | None = None) -> str:
	activeCatalog = _catalog(catalog)
	# Translators: {count} is a nonnegative count of validated Keystone-owned capture folders.
	template = activeCatalog.ngettext(
		"Keystone found {count} recognized published capture folder. Clear it now? Only validated Keystone-owned captures will be deleted. Suspicious or unrecognized entries will be left untouched. Event exports are not affected.",
		"Keystone found {count} recognized published capture folders. Clear them now? Only validated Keystone-owned captures will be deleted. Suspicious or unrecognized entries will be left untouched. Event exports are not affected.",
		count,
	)
	return template.format(count=count)


class SettingsAppliedPort(Protocol):
	"""Applies every other committed setting to the running add-on."""

	def applySettings(self, settings: SettingsSnapshot) -> None: ...


def _logUnexpectedSettingsApplicationFailure() -> None:
	try:
		import_module("logHandler").log.exception("Keystone settings application after save failed")
	except Exception:
		pass


class NativePanelBuilder(Protocol):
	def beginGroup(self, label: str) -> None: ...

	def addSpin(
		self,
		definition: NativeControlDefinition,
		value: int,
		minimum: int,
		maximum: int,
	) -> None: ...

	def addCheckBox(self, definition: NativeControlDefinition, value: bool, enabled: bool) -> None: ...

	def addChoice(
		self,
		definition: NativeControlDefinition,
		value: str,
		choices: tuple[str, ...],
		enabled: bool,
	) -> None: ...

	def addButton(self, definition: NativeControlDefinition, enabled: bool) -> None: ...


class KeystoneSettingsPanel:
	title = panelMessages().title
	panelDescription = panelMessages().panelDescription

	def __init__(
		self,
		controller: SettingsPanelController,
		*,
		catalog: TranslationCatalog | None = None,
	) -> None:
		super().__init__()
		self.controller = controller
		self._catalog = _catalog(catalog)
		messages = panelMessages(self._catalog)
		self.title = messages.title
		self.panelDescription = messages.panelDescription

	def makeSettings(self, builder: NativePanelBuilder) -> None:
		states = {state.controlId: state for state in self.controller.controlStates()}
		definitions = {definition.settingId.value: definition for definition in SETTING_DEFINITIONS}
		panel = panelDefinition(self._catalog)
		for group in panel.groups:
			builder.beginGroup(group)
			for control in panel.controls:
				if control.group != group:
					continue
				state = states[control.controlId]
				setting = definitions.get(control.controlId)
				if control.kind == "spin" and setting is not None:
					assert isinstance(state.value, int) and not isinstance(state.value, bool)
					assert setting.minimum is not None and setting.maximum is not None
					builder.addSpin(control, state.value, setting.minimum, setting.maximum)
				elif control.kind == "checkbox":
					builder.addCheckBox(
						replace(control, label=state.label, helpText=state.explanation),
						bool(state.value),
						state.enabled,
					)
				elif control.kind == "choice" and control.controlId == "soundPreviewCue":
					assert isinstance(state.value, str)
					builder.addChoice(
						control,
						state.value,
						previewCueChoiceLabels(self._catalog),
						state.enabled,
					)
				else:
					builder.addButton(
						replace(control, label=state.label, helpText=state.explanation),
						state.enabled,
					)


class SettingsPanelController:
	def __init__(
		self,
		*,
		snapshot: SettingsSnapshot,
		settingsService: SettingsService,
		capabilities: CapabilitySnapshot,
		captureManagement: CaptureManagementPort,
		lifecycleGeneration: int,
		context: CorrelationContext,
		catalog: TranslationCatalog | None = None,
		preview: PreviewPort | None = None,
		settingsApplied: SettingsAppliedPort | None = None,
	) -> None:
		super().__init__()
		if lifecycleGeneration < 0:
			raise ValueError("lifecycle generation must be nonnegative")
		_ = requireCompleteCorrelation(context)
		if context.generation != lifecycleGeneration:
			raise ValueError("panel generation must match correlation context")
		self._snapshot = snapshot
		self._candidate = snapshot.asCandidate()
		self._settingsService = settingsService
		self._capabilities = {record.capabilityId: record for record in capabilities.records}
		self._captureManagement = captureManagement
		self._lifecycleGeneration = lifecycleGeneration
		self._context = context
		self._catalog = _catalog(catalog)
		self._preview = preview
		self._settingsApplied = settingsApplied
		self._previewCue: CueAtomId = PREVIEW_CUE_ORDER[0]
		self._captureResult: CaptureManagementResult | None = None
		self._open = True

	def candidate(self) -> SettingsCandidate:
		return self._candidate

	def setValue(self, settingId: SettingId, value: object) -> None:
		if self._open:
			self._candidate = self._candidate.withValue(settingId, value)

	def previewCue(self) -> CueAtomId:
		return self._previewCue

	def setPreviewCue(self, atom: CueAtomId) -> None:
		if self._open:
			self._previewCue = atom

	def previewSelectedCue(self) -> None:
		# An explicit dialog audition: it owns the settings-dialog generation, speaks first, and cannot
		# start once the panel has closed. The sound port itself keeps the audition off the operation queue.
		if not self._open or self._preview is None:
			return
		name = previewCueName(self._previewCue, self._catalog)
		announcement = FeedbackRequest("sound.preview", (name,), self._context)
		unavailable = FeedbackRequest("sound.preview.failed", (name,), self._context)
		_ = self._preview.preview(
			self._previewCue,
			generation=self._lifecycleGeneration,
			announcement=announcement,
			unavailable=unavailable,
		)

	def _capabilityEnabled(self, capabilityId: str) -> bool:
		state = self._capabilities.get(capabilityId)
		return state is not None and state.status == "enabled"

	def capabilityDetails(self, controlId: str) -> str:
		capabilityId = {
			"rawUiaDetails": "rawUiaInspection",
			"soundDetails": "audioFeedback",
		}.get(controlId)
		if capabilityId is None:
			raise ValueError(f"unknown capability details control {controlId!r}")
		state = self._capabilities[capabilityId]
		template = self._catalog.pgettext(
			"capability technical details",
			"Capability: {capabilityId}\nStatus: {status}\nReason: {reason}",
		)
		return template.format(
			capabilityId=state.capabilityId,
			status=state.status,
			reason=state.reasonCode,
		)

	def validationDialog(self, validation: ValidationResult) -> ValidationDialogPresentation:
		if validation.isValid:
			raise ValueError("valid settings do not have a validation dialog")
		labels = {
			control.controlId: control.label.replace("&", "")
			for control in panelDefinition(self._catalog).controls
		}
		reasons = {
			"integerRequired": self._catalog.pgettext(
				"settings validation reason",
				"Enter a whole number.",
			),
			"outsideAllowedRange": self._catalog.pgettext(
				"settings validation reason",
				"The value is outside the allowed range.",
			),
			"booleanRequired": self._catalog.pgettext(
				"settings validation reason",
				"Choose an available checked or unchecked state.",
			),
			"capabilityUnavailable": self._catalog.pgettext(
				"settings validation reason",
				"This capability is unavailable and cannot be enabled.",
			),
			"choiceRequired": self._catalog.pgettext(
				"settings validation reason",
				"Choose one of the available values.",
			),
			"positiveRevisionRequired": self._catalog.pgettext(
				"settings validation reason",
				"The settings revision is invalid.",
			),
			"staleRevision": self._catalog.pgettext(
				"settings validation reason",
				"The settings changed before this save could complete.",
			),
		}
		first = validation.issues[0]
		firstId = str(first.settingId)
		firstLabel = labels.get(firstId, firstId)
		summaryTemplate = self._catalog.pgettext(
			"settings validation summary",
			"Keystone settings were not saved. Correct the listed values, starting with {fieldLabel}. No settings were changed.",
		)
		rows = tuple(
			"{}. {}: {}".format(
				index,
				labels.get(str(issue.settingId), str(issue.settingId)),
				reasons.get(issue.reasonCode, issue.reasonCode),
			)
			for index, issue in enumerate(validation.issues, start=1)
		)
		detailRows = tuple(
			f"{index}. Setting: {issue.settingId}; reason: {issue.reasonCode}"
			for index, issue in enumerate(validation.issues, start=1)
		)
		details = "\n".join(
			(
				"Code: KS.SETTINGS.VALIDATION_REJECTED",
				f"Correlation: {self._context.applicableId.value}",
				*detailRows,
			),
		)
		return ValidationDialogPresentation(
			panelMessages(self._catalog).validationTitle,
			"\n\n".join((summaryTemplate.format(fieldLabel=firstLabel), "\n".join(rows))),
			details,
		)

	def saveFailureDialog(self, result: SaveResult) -> ValidationDialogPresentation:
		if result.status.value == "rejected":
			return self.validationDialog(ValidationResult(self._candidate, result.issues))
		if result.status.value != "failed" or result.errorCode is None:
			raise ValueError("save failure dialog requires a rejected or failed save result")
		message = self._catalog.pgettext(
			"settings save failure summary",
			"Keystone settings were not saved because the settings service could not complete the save. No settings were changed.",
		)
		details = "\n".join(
			(
				f"Code: {result.errorCode}",
				f"Correlation: {self._context.applicableId.value}",
			),
		)
		return ValidationDialogPresentation(
			panelMessages(self._catalog).validationTitle,
			message,
			details,
		)

	def controlStates(self) -> tuple[ControlState, ...]:
		controls = panelDefinition(self._catalog).controls
		rawAvailable = self._capabilityEnabled("rawUiaInspection")
		offlineAvailable = self._capabilityEnabled("offlineAnalysis")
		values = {
			definition.settingId.value: self._candidate.value(definition.settingId)
			for definition in SETTING_DEFINITIONS
		}
		states: list[ControlState] = []
		for control in controls:
			value = cast(PlainValue, values.get(control.controlId))
			enabled = self._open
			explanation = control.helpText
			label = control.label
			if control.controlId == "forceRawUia":
				enabled = self._open and rawAvailable
				explanation = _rawUiaHelp(
					self._capabilities["rawUiaInspection"].status,
					self._catalog,
				)
			elif control.controlId == "offlineFileMegabytes":
				enabled = self._open and offlineAvailable
			elif control.controlId == "rawUiaDetails":
				status = self._capabilities["rawUiaInspection"].status
				label = _capabilityDetailsLabel(control.controlId, status, self._catalog)
				explanation = _capabilityDetailsHelp(control.controlId, status, self._catalog)
			elif control.controlId == "soundDetails":
				status = self._capabilities["audioFeedback"].status
				label = _capabilityDetailsLabel(control.controlId, status, self._catalog)
				explanation = _capabilityDetailsHelp(control.controlId, status, self._catalog)
			elif control.controlId == "soundPreviewCue":
				value = previewCueName(self._previewCue, self._catalog)
			elif control.controlId == "previewSound":
				# A cue is always selected (defaulting to the first), so the button is disabled
				# only while the panel is not open.
				enabled = self._open
			states.append(ControlState(control.controlId, True, enabled, value, explanation, label))
		return tuple(states)

	def apply(self) -> SaveResult:
		result = self._settingsService.save(self._snapshot, self._candidate, self._context)
		if result.status.value == "updated":
			self._snapshot = result.snapshot
			self._candidate = result.snapshot.asCandidate()
			# The committed global preference drives the live service so later workflow cues honor it;
			# preview itself stays available because it is an explicit user action, not a workflow cue.
			if self._preview is not None:
				self._preview.setEnabled(bool(result.snapshot.soundsEnabled))
			self._applyCommittedSettings(result.snapshot)
		return result

	def _applyCommittedSettings(self, settings: SettingsSnapshot) -> None:
		if self._settingsApplied is not None:
			try:
				self._settingsApplied.applySettings(settings)
			except Exception:
				_logUnexpectedSettingsApplicationFailure()

	def cancel(self) -> None:
		self._candidate = self._snapshot.asCandidate()

	def restoreDefaults(self, *, confirmed: bool) -> tuple[SettingId, ...]:
		if not confirmed or not self._open:
			return ()
		restored = restoreDefaultCandidate(self._snapshot)
		changed = tuple(
			definition.settingId
			for definition in SETTING_DEFINITIONS
			if self._candidate.value(definition.settingId) != restored.value(definition.settingId)
		)
		self._candidate = restored
		return changed

	def refreshCaptures(self) -> CaptureManagementResult | None:
		if not self._open:
			return None
		result = self._captureManagement.manageCaptures(
			CaptureManagementRequest("refresh", self._context, self._lifecycleGeneration),
		)
		if self.acceptCaptureResult(result):
			self._captureResult = result
			return result
		return None

	def acceptCaptureResult(self, result: CaptureManagementResult) -> bool:
		return self._open and result.lifecycleGeneration == self._lifecycleGeneration

	def clearPublishedCaptures(self, *, confirmed: bool) -> CaptureManagementResult | None:
		if not confirmed or not self._open or self._captureResult is None:
			return None
		result = self._captureManagement.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				self._context,
				self._lifecycleGeneration,
				confirmationRevision=self._captureResult.confirmationRevision,
			),
		)
		if self.acceptCaptureResult(result):
			self._captureResult = result
			return result
		return None

	def close(self) -> None:
		self._open = False
		self._captureResult = None
		if self._preview is not None:
			self._preview.stopPreview()
