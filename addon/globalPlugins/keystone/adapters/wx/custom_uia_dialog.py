# pyright: reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from importlib import import_module
from pathlib import Path
from typing import Protocol

from ...application.custom_uia_service import CustomUiaChangeResult, CustomUiaService
from ...domain.custom_uia import (
	ALLOWED_PRIVACY,
	ALLOWED_PROPERTY_TYPES,
	CustomUiaConfiguration,
	CustomUiaIssue,
	CustomUiaProperty,
	stableKeyForGuid,
)
from ...presentation.commands import NvdaTranslationCatalog
from ..export_names import defaultExportFilename


def _optionalNvdaControls() -> object | None:
	"""Return NVDA's ``gui.nvdaControls`` when hosted, otherwise ``None`` for off-host doubles."""

	try:
		gui = import_module("gui")
	except Exception:
		return None
	return getattr(gui, "nvdaControls", None)


def _reportList(wx: object, parent: object) -> object:
	"""Create the approved native report list parented directly to ``parent``.

	On the NVDA host this is ``AutoWidthColumnListCtrl`` so long values keep an auto-sized column;
	off-host it degrades to ``wx.ListCtrl`` with the same report/single-selection style.
	"""

	nvdaControls = _optionalNvdaControls()
	factory = getattr(nvdaControls, "AutoWidthColumnListCtrl", None) if nvdaControls is not None else None
	style = wx.LC_REPORT | wx.LC_SINGLE_SEL
	if factory is not None:
		return factory(parent, autoSizeColumn=0, style=style)
	return wx.ListCtrl(parent, style=style)


@dataclass(frozen=True, slots=True)
class DialogControlDefinition:
	controlId: str
	label: str
	accessibleName: str
	helpText: str
	kind: str
	advanced: bool = False


@dataclass(frozen=True, slots=True)
class CustomUiaDialogDefinition:
	title: str
	description: str
	controls: tuple[DialogControlDefinition, ...]
	focusOrder: tuple[str, ...]


class TranslationCatalog(Protocol):
	def gettext(self, message: str) -> str: ...


_DEFAULT_CATALOG = NvdaTranslationCatalog()


def _responsiveRowSizer(wx: object) -> object:
	"""Wrap action controls instead of clipping translated labels in a narrow dialog."""

	wrapSizer = getattr(wx, "WrapSizer", None)
	if callable(wrapSizer):
		return wrapSizer(wx.HORIZONTAL)
	return wx.BoxSizer(wx.HORIZONTAL)


def _fromDip(window: object, value: int) -> int:
	"""Use wx logical pixels when the host supports DPI conversion."""

	convert = getattr(window, "FromDIP", None)
	if not callable(convert):
		return value
	result = convert(value)
	return result if isinstance(result, int) else value


def _enumValuesFromText(text: str) -> tuple[tuple[int, str], ...]:
	values: dict[int, str] = {}
	for rawLine in text.splitlines():
		line = rawLine.strip()
		if not line:
			continue
		numberText, separator, nameText = line.partition("=")
		numberText = numberText.strip()
		name = nameText.strip()
		if not separator or not numberText or not name or not numberText.lstrip("-").isdigit():
			raise ValueError("enum values must use number = name")
		number = int(numberText)
		if number in values:
			raise ValueError("enum values must not repeat a number")
		values[number] = name
	return tuple(sorted(values.items()))


@dataclass(frozen=True, slots=True)
class CustomUiaCandidate:
	stableKey: str = ""
	canonicalGuid: str = ""
	name: str = ""
	displayName: str = ""
	propertyType: str = "string"
	enumValues: str = ""
	privacy: str = "unknown"
	enabled: bool = True
	description: str = ""
	executableTarget: str = ""
	frameworkFilter: str = ""
	windowClassFilter: str = ""

	def toProperty(self) -> CustomUiaProperty:
		return CustomUiaProperty(
			self.stableKey or stableKeyForGuid(self.canonicalGuid),
			self.canonicalGuid,
			self.name,
			self.propertyType,
			self.privacy,
			self.enabled,
			self.description or None,
			self.executableTarget,
			self.frameworkFilter or None,
			self.windowClassFilter or None,
			displayName=self.displayName or None,
			enumValues=_enumValuesFromText(self.enumValues),
		)

	@classmethod
	def fromProperty(cls, property: CustomUiaProperty) -> CustomUiaCandidate:
		return cls(
			stableKey=property.stableKey,
			canonicalGuid=property.canonicalGuid,
			name=property.name,
			displayName=property.displayName or "",
			propertyType=property.propertyType,
			enumValues="\n".join(f"{number} = {name}" for number, name in property.enumValues),
			privacy=property.privacy,
			enabled=property.enabled,
			description=property.description or "",
			executableTarget=property.executableTarget,
			frameworkFilter=property.frameworkFilter or "",
			windowClassFilter=property.windowClassFilter or "",
		)


_CONTROLS = (
	DialogControlDefinition(
		"properties",
		"&Definitions:",
		"Custom UIA property definitions",
		"Application-scoped definitions. Select one to edit, enable, or disable.",
		"list",
	),
	DialogControlDefinition(
		"add",
		"&Add",
		"Add definition",
		"Add a definition for the current application.",
		"button",
	),
	DialogControlDefinition("edit", "&Edit", "Edit definition", "Edit the selected definition.", "button"),
	DialogControlDefinition(
		"delete",
		"&Delete",
		"Delete definition",
		"Delete the selected definition.",
		"button",
	),
	DialogControlDefinition(
		"enable",
		"E&nable",
		"Enable definition",
		"Enable the selected definition.",
		"button",
	),
	DialogControlDefinition(
		"disable",
		"D&isable",
		"Disable definition",
		"Disable the selected definition.",
		"button",
	),
	DialogControlDefinition(
		"canonicalGuid",
		"Property &GUID:",
		"Property GUID",
		"Braced GUID identifying the custom property. Use the provider's documented GUID, not a potential-property runtime ID.",
		"text",
	),
	DialogControlDefinition(
		"name",
		"Programmatic &name:",
		"Programmatic name",
		"Provider's non-localized UI Automation programmatic name. A saved definition does not discover a property.",
		"text",
	),
	DialogControlDefinition(
		"displayName",
		"&Display name:",
		"Display name",
		"Optional reader-facing name shown in Keystone. If blank, Keystone shows the programmatic name.",
		"text",
	),
	DialogControlDefinition(
		"propertyType",
		"Property &type:",
		"Property type",
		"Allowed scalar UI Automation property type.",
		"choice",
	),
	DialogControlDefinition(
		"enumValues",
		"Enum &values:",
		"Enum values",
		"One number = name mapping per line. Required for Enum; leave blank for other property types.",
		"multiline",
	),
	DialogControlDefinition(
		"privacy",
		"&Privacy:",
		"Privacy classification",
		"Unknown, sensitive, or protected. Public is not allowed.",
		"choice",
	),
	DialogControlDefinition(
		"enabled",
		"&Enabled",
		"Enabled",
		"Whether this definition should register after the next NVDA restart.",
		"checkBox",
	),
	DialogControlDefinition(
		"description",
		"&Description:",
		"Description",
		"Optional user-facing description.",
		"multiline",
	),
	DialogControlDefinition(
		"executableTarget",
		"E&xecutable:",
		"Executable target",
		"Current application executable base name.",
		"text",
	),
	DialogControlDefinition(
		"frameworkFilter",
		"&Framework filter:",
		"Framework filter, advanced",
		"Optional exact framework identifier that narrows application matching.",
		"text",
		True,
	),
	DialogControlDefinition(
		"windowClassFilter",
		"&Window class filter:",
		"Window class filter, advanced",
		"Optional exact window class that narrows application matching.",
		"text",
		True,
	),
	DialogControlDefinition(
		"save",
		"&Save",
		"Save definition",
		"Validate and save this definition.",
		"button",
	),
	DialogControlDefinition(
		"import",
		"Re&place...",
		"Replace definitions",
		"Replace all saved definitions with custom-uia.json after confirmation.",
		"button",
	),
	DialogControlDefinition(
		"export",
		"E&xport...",
		"Export definitions",
		"Export custom-uia.json.",
		"button",
	),
	DialogControlDefinition(
		"exportDiagnostics",
		"Export Custom UIA Diagnostics...",
		"Export Custom UIA Diagnostics",
		"Capture developer diagnostics in a separate privacy-safe export.",
		"button",
	),
	DialogControlDefinition("close", "&Close", "Close", "Close the Custom UIA Properties dialog.", "button"),
)
_FIELD_IDS = (
	"canonicalGuid",
	"name",
	"displayName",
	"propertyType",
	"enumValues",
	"privacy",
	"enabled",
	"description",
	"executableTarget",
	"frameworkFilter",
	"windowClassFilter",
)


def dialogDefinition(catalog: TranslationCatalog | None = None) -> CustomUiaDialogDefinition:
	resolver = _DEFAULT_CATALOG if catalog is None else catalog
	controls = tuple(
		replace(
			control,
			label=resolver.gettext(control.label),
			accessibleName=resolver.gettext(control.accessibleName),
			helpText=resolver.gettext(control.helpText),
		)
		for control in _CONTROLS
	)
	return CustomUiaDialogDefinition(
		resolver.gettext("Custom UIA Properties"),
		resolver.gettext(
			"Manage application-scoped custom UI Automation property definitions. "
			+ "Effective changes require an NVDA restart.",
		),
		controls,
		tuple(control.controlId for control in controls),
	)


def _activateModal(dialog: object, initialControl: object) -> None:
	dialog.Raise()
	initialControl.SetFocus()


def _showActivatedModal(wx: object, dialog: object, initialControl: object) -> int:
	wx.CallAfter(_activateModal, dialog, initialControl)
	return int(dialog.ShowModal())


def _popupOwner() -> object | None:
	try:
		owner = getattr(import_module("gui"), "mainFrame", None)
	except ImportError:
		return None
	if not callable(getattr(owner, "prePopup", None)) or not callable(getattr(owner, "postPopup", None)):
		return None
	return owner


def _showModalWithPopupOwner(
	wx: object,
	dialog: object,
	initialControl: object,
	owner: object | None,
) -> int:
	if owner is None:
		return _showActivatedModal(wx, dialog, initialControl)
	owner.prePopup()
	try:
		return _showActivatedModal(wx, dialog, initialControl)
	finally:
		owner.postPopup()


_FIELD_LABELS = {
	"stableKey": "Definition ID",
	"canonicalGuid": "Property GUID",
	"name": "Programmatic name",
	"displayName": "Display name",
	"enumValues": "Enum values",
	"type": "Property type",
	"propertyType": "Property type",
	"privacy": "Privacy",
	"enabled": "Enabled",
	"description": "Description",
	"executableTarget": "Executable target",
	"frameworkFilter": "Framework filter",
	"windowClassFilter": "Window class filter",
	"document": "Configuration document",
	"properties": "Property definitions",
	"schemaVersion": "Schema version",
}
_VALIDATION_MESSAGES = {
	"KSERR_CUIA_KEY_INVALID": "Use an identifier that starts with a letter or number and contains only letters, numbers, dot, underscore, or hyphen.",
	"KSERR_CUIA_GUID_INVALID": "Enter a non-zero braced GUID, for example {12345678-1234-1234-1234-1234567890AB}.",
	"KSERR_CUIA_STRING_LIMIT": "Enter a value within the allowed length.",
	"KSERR_CUIA_UNSAFE_TEXT": "Remove unsupported control or directional characters.",
	"KSERR_CUIA_TYPE_INVALID": "Choose a supported property type.",
	"KSERR_CUIA_ENUM_VALUES_INVALID": "For Enum, enter unique number = name mappings. Leave this field blank for other property types.",
	"KSERR_CUIA_PRIVACY_INVALID": "Choose unknown, sensitive, or protected.",
	"KSERR_CUIA_ENABLED_INVALID": "Choose whether this definition is enabled.",
	"KSERR_CUIA_ENTRY_INVALID": "Enter a valid value.",
	"KSERR_CUIA_EXPANSION_FORBIDDEN": "Use a literal value without environment-variable expansion.",
	"KSERR_CUIA_CATALOG_CONFLICT": "This definition conflicts with a built-in property.",
	"KSERR_CUIA_GUID_CONFLICT": "This property GUID is already used by another definition.",
	"KSERR_CUIA_KEY_CONFLICT": "This definition ID is already used by another definition.",
}


class CustomUiaDialogController:
	def __init__(
		self,
		service: CustomUiaService,
		*,
		currentExecutable: str,
		catalog: TranslationCatalog | None = None,
		exportCustomUiaDiagnostics: Callable[[], bool] | None = None,
	) -> None:
		super().__init__()
		self._service = service
		self._catalog = _DEFAULT_CATALOG if catalog is None else catalog
		self._exportCustomUiaDiagnostics = exportCustomUiaDiagnostics
		self._currentExecutable = currentExecutable
		self._configuration = service.load().configuration
		self._selectedIndex: int | None = None
		self.candidate = CustomUiaCandidate(executableTarget=currentExecutable)
		self.statusText = self._catalog.gettext("Ready")
		self.focusedField: str | None = None

	@property
	def properties(self) -> tuple[CustomUiaProperty, ...]:
		return self._configuration.properties

	@property
	def currentExecutable(self) -> str:
		return self._currentExecutable

	@property
	def catalog(self) -> TranslationCatalog:
		return self._catalog

	def beginAdd(self, *, currentExecutable: str) -> None:
		self._selectedIndex = None
		self.candidate = CustomUiaCandidate(executableTarget=currentExecutable)
		self.statusText = self._catalog.gettext("Ready")
		self.focusedField = "canonicalGuid"

	def edit(self, index: int) -> None:
		property = self._configuration.properties[index]
		self._selectedIndex = index
		self.candidate = CustomUiaCandidate.fromProperty(property)
		self.statusText = self._catalog.gettext("Editing definition")
		self.focusedField = "canonicalGuid"

	def update(self, **changes: object) -> None:
		allowed = set(_FIELD_IDS)
		unknown = set(changes) - allowed
		if unknown:
			raise ValueError("unknown custom UIA dialog field")
		self.candidate = replace(self.candidate, **changes)

	def setEnabled(self, index: int, enabled: bool) -> CustomUiaChangeResult:
		property = replace(self._configuration.properties[index], enabled=enabled)
		properties = list(self._configuration.properties)
		properties[index] = property
		result = self._service.save(CustomUiaConfiguration(1, tuple(properties)))
		return self._accept(result)

	def delete(self, index: int) -> CustomUiaChangeResult:
		properties = list(self._configuration.properties)
		del properties[index]
		result = self._service.save(CustomUiaConfiguration(1, tuple(properties)))
		return self._accept(result)

	def save(self) -> CustomUiaChangeResult:
		try:
			candidate = self.candidate.toProperty()
		except ValueError:
			self.focusedField = "enumValues"
			self.statusText = self._catalog.gettext(
				"Enum values: Enter one unique number = name mapping per line.",
			)
			return CustomUiaChangeResult(
				False,
				None,
				(CustomUiaIssue("enumValues", "KSERR_CUIA_ENUM_VALUES_INVALID"),),
			)
		properties = list(self._configuration.properties)
		if self._selectedIndex is None:
			properties.append(candidate)
		else:
			properties[self._selectedIndex] = candidate
		result = self._service.save(CustomUiaConfiguration(1, tuple(properties)))
		return self._accept(result)

	def importFrom(self, path: Path) -> CustomUiaChangeResult:
		return self._accept(self._service.importFrom(path))

	def importCancelled(self) -> None:
		self._setCancelledStatus("Import cancelled.")

	def exportTo(self, path: Path) -> CustomUiaChangeResult:
		result = self._service.exportTo(path)
		self.statusText = (
			self._catalog.gettext("Configuration exported") if result.accepted else self._errorText(result)
		)
		self.focusedField = None
		return result

	def exportCancelled(self) -> None:
		self._setCancelledStatus("Export cancelled.")

	def exportCustomUiaDiagnostics(self) -> bool:
		"""Invoke only the explicit diagnostic-export seam, never normal capture."""
		if self._exportCustomUiaDiagnostics is None:
			self.statusText = self._catalog.gettext("Custom UIA diagnostics are unavailable")
			self.focusedField = None
			return False
		try:
			exported = self._exportCustomUiaDiagnostics()
		except Exception:
			exported = False
		self.statusText = self._catalog.gettext(
			"Custom UIA diagnostics exported" if exported else "Could not export Custom UIA diagnostics",
		)
		self.focusedField = None
		return exported

	def _setCancelledStatus(self, message: str) -> None:
		self.statusText = self._catalog.gettext(message)
		self.focusedField = None

	def _accept(self, result: CustomUiaChangeResult) -> CustomUiaChangeResult:
		if result.accepted and result.configuration is not None:
			self._configuration = result.configuration
			self._selectedIndex = None
			self.statusText = self._catalog.gettext(
				"Definition saved. Restart NVDA to apply it."
				if result.restartRequired
				else "No changes to save",
			)
			self.focusedField = None
		else:
			self.focusedField = self._fieldFromResult(result)
			self.statusText = self._errorText(result)
		return result

	@staticmethod
	def _fieldFromResult(result: CustomUiaChangeResult) -> str | None:
		if not result.issues:
			return None
		field = result.issues[0].field
		if "." in field:
			field = field.rsplit(".", 1)[1]
		return "propertyType" if field == "type" else field

	def _errorText(self, result: CustomUiaChangeResult) -> str:
		if result.issues:
			issue = result.issues[0]
			field = issue.field.rsplit(".", 1)[-1]
			label = self._catalog.gettext(_FIELD_LABELS.get(field, "Configuration"))
			message = self._catalog.gettext(
				_VALIDATION_MESSAGES.get(issue.code, "Could not validate this value."),
			)
			return f"{label}: {message}"
		return f"{self._catalog.gettext('Configuration')}: {result.errorCode or 'KSERR_CUIA_FAILED'}"


def _copyDefinition(wx: object, property: CustomUiaProperty) -> bool:
	"""Copy the complete selected definition without introducing an accessibility shim."""
	text = "\n".join(
		(
			f"Property GUID: {property.canonicalGuid}",
			f"Programmatic name: {property.name}",
			f"Display name: {property.displayName or ''}",
			f"Enum values: {', '.join(f'{number} = {name}' for number, name in property.enumValues)}",
			f"Property type: {property.propertyType}",
			f"Privacy: {property.privacy}",
			f"Enabled: {property.enabled}",
			f"Description: {property.description or ''}",
			f"Executable: {property.executableTarget}",
			f"Framework filter: {property.frameworkFilter or ''}",
			f"Window class filter: {property.windowClassFilter or ''}",
		),
	)
	clipboard = getattr(wx, "TheClipboard", None)
	dataObject = getattr(wx, "TextDataObject", None)
	if clipboard is None or not callable(dataObject):
		return False
	try:
		if not clipboard.Open():
			return False
		clipboard.SetData(dataObject(text))
		return True
	finally:
		close = getattr(clipboard, "Close", None)
		if callable(close):
			_ = close()


def _confirmDefinitionReplacement(wx: object, parent: object, catalog: TranslationCatalog) -> bool:
	return (
		wx.MessageBox(
			catalog.gettext(
				"Replace all saved Custom UIA definitions with the selected file? "
				+ "Definitions not in the file will be removed.",
			),
			catalog.gettext("Replace Custom UIA definitions"),
			wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
			parent,
		)
		== wx.YES
	)


def _showCustomUiaManager(
	parent: object,
	controller: CustomUiaDialogController,
	*,
	importPathProvider: Callable[[], Path | None] | None,
	exportPathProvider: Callable[[], Path | None] | None,
) -> None:
	"""Present the definition manager separately from the Add/Edit form."""
	wx = import_module("wx")
	owner = _popupOwner()
	catalog = controller.catalog
	dialog = wx.Dialog(
		parent if parent is not None else owner,
		title=catalog.gettext("Custom UIA Properties"),
	)
	root = wx.BoxSizer(wx.VERTICAL)
	description = wx.StaticText(
		dialog,
		label=catalog.gettext(
			"Manage application-scoped custom UI Automation property definitions. "
			+ "Effective changes require an NVDA restart.",
		),
	)
	description.Wrap(_fromDip(dialog, 700))
	root.Add(description, 0, wx.EXPAND | wx.ALL, 12)
	box_widget = wx.StaticBox(dialog, label=catalog.gettext("Custom UIA property definitions"))
	box = wx.StaticBoxSizer(box_widget, wx.VERTICAL)
	definitions = _reportList(wx, box_widget)
	definitions.InsertColumn(0, catalog.gettext("Definition"))
	box.Add(definitions, 1, wx.EXPAND | wx.ALL, 8)
	root.Add(box, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
	actions = _responsiveRowSizer(wx)
	add = wx.Button(dialog, label=catalog.gettext("&Add..."))
	importButton = wx.Button(dialog, label=catalog.gettext("Re&place..."))
	exportButton = wx.Button(dialog, label=catalog.gettext("E&xport..."))
	diagnosticExportButton = wx.Button(
		dialog,
		label=catalog.gettext("Export Custom UIA Diagnostics..."),
	)
	for control in (add, importButton, exportButton, diagnosticExportButton):
		actions.Add(control, 0, wx.RIGHT, 8)
	root.Add(actions, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
	dialog.SetSizerAndFit(root)
	dialog.SetMinSize((_fromDip(dialog, 660), _fromDip(dialog, 420)))
	dialog.CentreOnParent()

	def selectedIndex() -> int | None:
		index = int(definitions.GetFirstSelected())
		return index if 0 <= index < len(controller.properties) else None

	def definitionText(property: CustomUiaProperty) -> str:
		state = catalog.gettext("Enabled") if property.enabled else catalog.gettext("Disabled")
		return f"{property.userVisibleName} ({state})"

	def refresh(*, select: int | None = None) -> None:
		definitions.DeleteAllItems()
		for index, property in enumerate(controller.properties):
			_ = definitions.InsertItem(index, definitionText(property))
		if select is not None and 0 <= select < len(controller.properties):
			definitions.Select(select)
			definitions.Focus(select)

	def setStatus() -> None:
		getStatusBar = getattr(parent, "GetStatusBar", None)
		statusBar = getStatusBar() if callable(getStatusBar) else None
		setStatusText = getattr(statusBar, "SetStatusText", None)
		if callable(setStatusText):
			_ = setStatusText(controller.statusText)

	def announceOutcome() -> None:
		setStatus()
		import_module("ui").message(controller.statusText)

	def editDefinition(index: int | None) -> None:
		if index is None:
			controller.beginAdd(currentExecutable=controller.currentExecutable)
		else:
			controller.edit(index)
		editor = wx.Dialog(
			dialog,
			title=catalog.gettext("Add Custom UIA Definition")
			if index is None
			else catalog.gettext("Edit Custom UIA Definition"),
		)
		editorRoot = wx.BoxSizer(wx.VERTICAL)
		definitionBox = wx.StaticBox(editor, label=catalog.gettext("Definition"))
		definitionSizer = wx.StaticBoxSizer(definitionBox, wx.VERTICAL)
		fields = wx.FlexGridSizer(cols=2, hgap=8, vgap=8)
		fields.AddGrowableCol(1, 1)
		controls: dict[str, object] = {}
		for fieldId in _FIELD_IDS[:9]:
			controlDefinition = next(item for item in _CONTROLS if item.controlId == fieldId)
			label = wx.StaticText(definitionBox, label=catalog.gettext(controlDefinition.label))
			if controlDefinition.kind == "choice":
				choices = ALLOWED_PROPERTY_TYPES if fieldId == "propertyType" else ALLOWED_PRIVACY
				control = wx.Choice(definitionBox, choices=choices)
				control.SetSelection(choices.index(getattr(controller.candidate, fieldId)))
			elif controlDefinition.kind == "checkBox":
				control = wx.CheckBox(definitionBox, label=catalog.gettext(controlDefinition.label))
				control.SetValue(bool(getattr(controller.candidate, fieldId)))
				label = wx.StaticText(definitionBox, label="")
			else:
				style = wx.TE_MULTILINE if controlDefinition.kind == "multiline" else 0
				control = wx.TextCtrl(
					definitionBox,
					value=getattr(controller.candidate, fieldId),
					style=style,
				)
			fields.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
			fields.Add(control, 1, wx.EXPAND)
			controls[fieldId] = control
		definitionSizer.Add(fields, 1, wx.EXPAND | wx.ALL, 8)
		editorRoot.Add(definitionSizer, 1, wx.EXPAND | wx.ALL, 8)
		advancedBox = wx.StaticBox(editor, label=catalog.gettext("Advanced application filters"))
		advancedSizer = wx.StaticBoxSizer(advancedBox, wx.VERTICAL)
		advanced = wx.FlexGridSizer(cols=2, hgap=8, vgap=8)
		advanced.AddGrowableCol(1, 1)
		for fieldId in _FIELD_IDS[9:]:
			controlDefinition = next(item for item in _CONTROLS if item.controlId == fieldId)
			advanced.Add(
				wx.StaticText(advancedBox, label=catalog.gettext(controlDefinition.label)),
				0,
				wx.ALIGN_CENTER_VERTICAL,
			)
			control = wx.TextCtrl(advancedBox, value=getattr(controller.candidate, fieldId))
			advanced.Add(control, 1, wx.EXPAND)
			controls[fieldId] = control
		advancedSizer.Add(advanced, 1, wx.EXPAND | wx.ALL, 8)
		editorRoot.Add(advancedSizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)
		buttons = wx.BoxSizer(wx.HORIZONTAL)
		save = wx.Button(editor, wx.ID_OK, label=catalog.gettext("&Save"))
		cancel = wx.Button(editor, wx.ID_CANCEL, label=catalog.gettext("&Cancel"))
		buttons.AddStretchSpacer()
		buttons.Add(cancel, 0, wx.RIGHT, 8)
		buttons.Add(save, 0)
		editorRoot.Add(buttons, 0, wx.EXPAND | wx.ALL, 12)
		editor.SetSizerAndFit(editorRoot)
		editor.SetMinSize((_fromDip(editor, 660), _fromDip(editor, 420)))

		def onSave(_event: object) -> None:
			changes: dict[str, object] = {}
			for fieldId, control in controls.items():
				if fieldId in ("propertyType", "privacy"):
					choices = ALLOWED_PROPERTY_TYPES if fieldId == "propertyType" else ALLOWED_PRIVACY
					selection = int(control.GetSelection())
					changes[fieldId] = choices[selection] if 0 <= selection < len(choices) else ""
				else:
					changes[fieldId] = control.GetValue()
			controller.update(**changes)
			result = controller.save()
			setStatus()
			if not result.accepted:
				field = controls.get(controller.focusedField or "")
				if field is not None:
					field.SetFocus()
				import_module("ui").message(controller.statusText)
			if result.accepted:
				editor.EndModal(wx.ID_OK)

		save.Bind(wx.EVT_BUTTON, onSave)
		wx.CallAfter(controls["canonicalGuid"].SetFocus)
		if editor.ShowModal() == wx.ID_OK:
			refresh(
				select=min(
					index if index is not None else len(controller.properties) - 1,
					len(controller.properties) - 1,
				),
			)
			announceOutcome()
		editor.Destroy()

	def onAdd(_event: object) -> None:
		editDefinition(None)

	def onEdit(_event: object) -> None:
		index = selectedIndex()
		if index is None:
			controller.statusText = catalog.gettext("Select a definition to edit")
			announceOutcome()
			return
		editDefinition(index)

	def onToggle(enabled: bool) -> None:
		index = selectedIndex()
		if index is None:
			controller.statusText = catalog.gettext("Select a definition first")
			announceOutcome()
			return
		_ = controller.setEnabled(index, enabled)
		refresh(select=index)
		announceOutcome()

	def onDelete(_event: object) -> None:
		index = selectedIndex()
		if index is None:
			controller.statusText = catalog.gettext("Select a definition to delete")
			announceOutcome()
			return
		_ = controller.delete(index)
		refresh(select=min(index, len(controller.properties) - 1))
		announceOutcome()

	def onCopy(_event: object | None = None) -> None:
		index = selectedIndex()
		if index is None:
			controller.statusText = catalog.gettext("No Custom UIA definition is selected to copy.")
			announceOutcome()
			return
		controller.statusText = (
			catalog.gettext("Definition copied")
			if _copyDefinition(wx, controller.properties[index])
			else catalog.gettext("Could not copy definition")
		)
		announceOutcome()

	def onContext(event: object) -> None:
		_ = event
		menu = wx.Menu()

		def onEnable(_event: object) -> None:
			onToggle(True)

		def onDisable(_event: object) -> None:
			onToggle(False)

		for identifier, label, handler in (
			(wx.ID_ADD, catalog.gettext("Add definition"), onAdd),
			(wx.ID_EDIT, catalog.gettext("Edit selected definition"), onEdit),
			(wx.ID_ANY, catalog.gettext("Enable selected definition"), onEnable),
			(wx.ID_ANY, catalog.gettext("Disable selected definition"), onDisable),
			(wx.ID_DELETE, catalog.gettext("Delete selected definition"), onDelete),
		):
			item = menu.Append(identifier, label)
			menu.Bind(wx.EVT_MENU, handler, item)
		menu.AppendSeparator()
		copy = menu.Append(wx.ID_COPY, catalog.gettext("Copy selected definition"))
		menu.Bind(wx.EVT_MENU, onCopy, copy)
		definitions.PopupMenu(menu)
		menu.Destroy()

	def chooseImport() -> Path | None:
		if importPathProvider is not None:
			return importPathProvider()
		chooser = wx.FileDialog(
			dialog,
			message=catalog.gettext("Replace Custom UIA Properties"),
			wildcard=catalog.gettext("JSON files (*.json)|*.json"),
			style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
		)
		try:
			return Path(chooser.GetPath()) if chooser.ShowModal() == wx.ID_OK else None
		finally:
			chooser.Destroy()

	def chooseExport() -> Path | None:
		if exportPathProvider is not None:
			return exportPathProvider()
		chooser = wx.FileDialog(
			dialog,
			message=catalog.gettext("Export Custom UIA Properties"),
			defaultFile=defaultExportFilename(
				controller.currentExecutable,
				"custom-uia",
				".json",
			),
			wildcard=catalog.gettext("JSON files (*.json)|*.json"),
			style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
		)
		try:
			return Path(chooser.GetPath()) if chooser.ShowModal() == wx.ID_OK else None
		finally:
			chooser.Destroy()

	def onImport(_event: object) -> None:
		path = chooseImport()
		if path is None:
			controller.importCancelled()
		elif not _confirmDefinitionReplacement(wx, dialog, catalog):
			controller.importCancelled()
		else:
			_ = controller.importFrom(path)
		refresh(select=0 if controller.properties else None)
		announceOutcome()

	def onExport(_event: object) -> None:
		index = selectedIndex()
		path = chooseExport()
		if path is None:
			controller.exportCancelled()
		else:
			_ = controller.exportTo(path)
		refresh(select=index)
		announceOutcome()

	def onDiagnosticExport(_event: object) -> None:
		_ = controller.exportCustomUiaDiagnostics()
		announceOutcome()

	def onKey(event: object) -> None:
		key = int(event.GetKeyCode())
		if key == wx.WXK_DELETE:
			onDelete(event)
			return
		if bool(event.ControlDown()) and key in (ord("C"), ord("c")):
			onCopy()
			return
		event.Skip()

	add.Bind(wx.EVT_BUTTON, onAdd)
	importButton.Bind(wx.EVT_BUTTON, onImport)
	exportButton.Bind(wx.EVT_BUTTON, onExport)
	diagnosticExportButton.Bind(wx.EVT_BUTTON, onDiagnosticExport)
	definitions.Bind(wx.EVT_LIST_ITEM_ACTIVATED, onEdit)
	definitions.Bind(wx.EVT_CONTEXT_MENU, onContext)
	definitions.Bind(wx.EVT_KEY_DOWN, onKey)
	refresh(select=0 if controller.properties else None)

	def show() -> None:
		try:
			_ = _showModalWithPopupOwner(wx, dialog, definitions, owner)
		finally:
			dialog.Destroy()

	wx.CallAfter(show)


def showCustomUiaDialog(
	parent: object,
	controller: CustomUiaDialogController,
	*,
	importPathProvider: Callable[[], Path | None] | None = None,
	exportPathProvider: Callable[[], Path | None] | None = None,
) -> None:
	"""Show the native list-first Custom UIA manager."""
	_showCustomUiaManager(
		parent,
		controller,
		importPathProvider=importPathProvider,
		exportPathProvider=exportPathProvider,
	)
