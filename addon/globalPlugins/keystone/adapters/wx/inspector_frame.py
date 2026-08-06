# pyright: reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import builtins
from collections.abc import Callable, Iterable
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
import time
from typing import Any, Literal, cast

from ...application.inspector_service import (
	AnnotationNavigationStatus,
	FollowFocusEvent,
	FollowFocusOutcome,
	InspectorCopyKind,
	InspectorRegion,
	InspectorService,
)
from ...domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	ChildState,
	PaneCursor,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	QuickPropertyAction,
	StructuredPropertyNode,
)
from ...application.event_monitor_service import EventActionOutcome, EventMonitorService
from ...application.sound_service import WorkflowSounds
from ..export_names import defaultExportFilename
from ...domain.event_monitor import (
	ChangeEvidence,
	EventCopyFormat,
	EventFilter,
	EventHistory,
	EventRow,
	HistoryItem,
	MonitorScopeKind,
	NvdaEventType,
	RawUiaFamily,
	ScopeUnavailableReason,
	SessionBoundary,
)
from ...domain.sounds import (
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	soundRequestFor,
)
from ...domain.snapshot_bundle import (
	BundleAdmissionLimitExceeded,
	BundleAdmissionLimits,
	LOCAL_SELECTED_BUNDLE_LIMITS,
)


type InspectorTargetKind = Literal["focus", "navigator"]
type WindowOwnershipCheck = Callable[[int, int, int], bool]

_ACTIVATION_RETRY_DELAYS_MS = (50, 100, 200)
_lastSnapshotDirectory: Path | None = None


@dataclass(frozen=True, slots=True)
class InspectorRetargetOutcome:
	succeeded: bool
	rawRequested: bool = False
	rawApplied: bool = False
	rawReason: str | None = None


@dataclass(frozen=True, slots=True)
class AppModuleOverrideState:
	executable: str | None
	enabled: bool
	available: bool


@dataclass(frozen=True, slots=True)
class AppModuleOverrideOutcome:
	succeeded: bool
	executable: str | None
	enabled: bool
	errorCode: str | None = None


def _ignoreAnnouncement(_message: str) -> None:
	pass


def _rawUiaFallbackMessage(reason: str | None) -> str:
	if reason == "KS.RAW_UIA.NO_NATIVE_PROVIDER":
		# Translators: Explicit raw UIA was unavailable because Windows reported no native provider.
		return gettext(
			"Raw UIA is unavailable because this target has no native UIA provider; using the NVDA-selected target.",
		)
	# Translators: Explicit raw UIA was unavailable, so the normal NVDA target remains in use.
	return gettext("Raw UIA unavailable for this target; using NVDA-selected target.")


def _rawUiaFallbackSummary(reason: str | None) -> str:
	if reason == "KS.RAW_UIA.NO_NATIVE_PROVIDER":
		# Translators: Raw UIA summary when Windows reports no native provider for the target.
		return gettext(
			"unavailable because this target has no native UIA provider; using NVDA-selected target",
		)
	# Translators: Raw UIA summary when the requested projection was unavailable.
	return gettext("unavailable for this target; using NVDA-selected target")


def gettext(message: str) -> str:
	"""Translate a plain message through NVDA's installed catalog, unchanged when off-host."""

	translator = cast("Callable[[str], str] | None", getattr(builtins, "_", None))
	if translator is None:
		return message
	return translator(message)


def pgettext(context: str, message: str) -> str:
	"""Translate a message disambiguated by context, unchanged when off-host."""

	translator = cast("Callable[[str, str], str] | None", getattr(builtins, "pgettext", None))
	if translator is None:
		return message
	return translator(context, message)


def ngettext(singular: str, plural: str, count: int) -> str:
	"""Select the singular or plural translation for count, unchanged when off-host."""

	translator = cast("Callable[[str, str, int], str] | None", getattr(builtins, "ngettext", None))
	if translator is None:
		return singular if count == 1 else plural
	return translator(singular, plural, count)


def _nvdaEventTypeLabel(eventType: NvdaEventType) -> str:
	labels = {
		NvdaEventType.FOCUS: pgettext("events filter type", "Focus"),
		NvdaEventType.FOREGROUND: pgettext("events filter type", "Foreground"),
		NvdaEventType.NAME_CHANGE: pgettext("events filter type", "Name change"),
		NvdaEventType.VALUE_CHANGE: pgettext("events filter type", "Value change"),
		NvdaEventType.STATE_CHANGE: pgettext("events filter type", "State change"),
		NvdaEventType.DESCRIPTION_CHANGE: pgettext("events filter type", "Description change"),
		NvdaEventType.LIVE_REGION: pgettext("events filter type", "Live region"),
		NvdaEventType.SELECTION: pgettext("events filter type", "Selection"),
		NvdaEventType.CARET: pgettext("events filter type", "Caret"),
		NvdaEventType.CONTROLLER: pgettext("events filter type", "Controller"),
		NvdaEventType.NAVIGATOR_OBJECT: pgettext("events filter type", "Navigator object"),
	}
	return labels[eventType]


def _rawUiaFamilyLabel(family: RawUiaFamily) -> str:
	labels = {
		RawUiaFamily.NOTIFICATION: pgettext("events filter type", "Notification"),
		RawUiaFamily.SELECTION: pgettext("events filter type", "Selection"),
		RawUiaFamily.LAYOUT: pgettext("events filter type", "Layout"),
		RawUiaFamily.WINDOW: pgettext("events filter type", "Window"),
		RawUiaFamily.RELATION: pgettext("events filter type", "Relation"),
		RawUiaFamily.DRAG_DROP: pgettext("events filter type", "Drag and drop"),
		RawUiaFamily.ALERT: pgettext("events filter type", "Alert"),
		RawUiaFamily.ITEM_STATUS: pgettext("events filter type", "Item status"),
		RawUiaFamily.TOOLTIP: pgettext("events filter type", "Tooltip"),
		RawUiaFamily.ACTIVE_TEXT_POSITION: pgettext("events filter type", "Active text position"),
	}
	return labels[family]


def _optionalNvdaControls() -> object | None:
	"""Return NVDA's ``gui.nvdaControls`` module when hosted, otherwise ``None``.

	The approved list control is NVDA's ``AutoWidthColumnListCtrl``. It only exists inside the NVDA
	host, so this stays behind the host boundary and lets the off-host contract doubles fall back to
	a plain report list without importing anything NVDA-only.
	"""

	try:
		gui = import_module("gui")
	except Exception:
		return None
	return getattr(gui, "nvdaControls", None)


def _reportList(wx: object, parent: object, *, autoSizeColumn: int = 0) -> object:
	"""Create the approved native report list parented directly to ``parent``.

	On the NVDA host this is ``AutoWidthColumnListCtrl`` so long values keep an auto-sized column;
	off-host it degrades to ``wx.ListCtrl`` with the same report/single-selection style.
	"""

	nvdaControls = _optionalNvdaControls()
	factory = getattr(nvdaControls, "AutoWidthColumnListCtrl", None) if nvdaControls is not None else None
	style = wx.LC_REPORT | wx.LC_SINGLE_SEL
	if factory is not None:
		return factory(parent, autoSizeColumn=autoSizeColumn, style=style)
	return wx.ListCtrl(parent, style=style)


def _staticGroup(wx: object, parent: object, label: str) -> tuple[object, object]:
	"""Build the one accessibility grouping pattern the user validated on this host.

	A ``wx.StaticBox`` is created on ``parent`` and wrapped in a ``wx.StaticBoxSizer``; the caller
	then creates the child list or tree with the returned ``StaticBox`` as its direct parent. That
	direct parenting -- not the sizer alone -- is what makes NVDA speak the group name for the
	enclosed collection, so every labelled list and tree is built through this helper.
	"""

	box = wx.StaticBox(parent, label=label)
	sizer = wx.StaticBoxSizer(box, wx.VERTICAL)
	return box, sizer


def _responsiveRowSizer(wx: object) -> object:
	"""Wrap action controls instead of clipping translated labels in a narrow window."""

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


def _layout(window: object) -> None:
	"""Lay out controls after their notebook page has an actual size."""

	layout = getattr(window, "Layout", None)
	if callable(layout):
		_ = layout()


def _layoutTree(window: object) -> None:
	"""Apply every nested sizer once wx has assigned the shared window its final size."""

	getSizer = getattr(window, "GetSizer", None)
	sizer = getSizer() if callable(getSizer) else None
	sizerLayout = getattr(sizer, "Layout", None)
	if callable(sizerLayout):
		_ = sizerLayout()
	_layout(window)
	getChildren = getattr(window, "GetChildren", None)
	if callable(getChildren):
		children = getChildren()
		if isinstance(children, Iterable):
			for child in children:
				_layoutTree(child)


def _bindMenuItem(menu: object, wx: object, item: object, handler: Callable[[object], None]) -> None:
	"""Bind a transient command on its transient menu rather than accumulating control bindings."""

	bind = getattr(menu, "Bind", None)
	if callable(bind):
		_ = bind(wx.EVT_MENU, handler, item)


def _setControlLabel(control: object, label: str) -> None:
	getLabel = getattr(control, "GetLabel", None)
	current = getLabel() if callable(getLabel) else getattr(control, "label", None)
	if current != label:
		control.SetLabel(label)


def _setControlEnabled(control: object, enabled: bool) -> None:
	isEnabled = getattr(control, "IsEnabled", None)
	current = isEnabled() if callable(isEnabled) else getattr(control, "enabled", None)
	if current is not enabled:
		control.Enable(enabled)


def _setControlSelection(control: object, selection: int) -> None:
	getSelection = getattr(control, "GetSelection", None)
	current = getSelection() if callable(getSelection) else None
	if current != selection:
		control.SetSelection(selection)


def _logUnexpectedSound(message: str = "Keystone Inspector sound emission failed") -> None:
	try:
		import_module("logHandler").log.exception(message)
	except Exception:
		pass


def _nativeWindowOwnership(
	inspectorWindowHandle: int,
	selectedProcessId: int,
	selectedWindowHandle: int,
) -> bool:
	if min(inspectorWindowHandle, selectedProcessId, selectedWindowHandle) <= 0:
		return False
	try:
		user32 = ctypes.windll.user32
		inspectorProcessId = wintypes.DWORD()
		nativeSelectedProcessId = wintypes.DWORD()
		if not user32.GetWindowThreadProcessId(
			inspectorWindowHandle,
			ctypes.byref(inspectorProcessId),
		) or not user32.GetWindowThreadProcessId(
			selectedWindowHandle,
			ctypes.byref(nativeSelectedProcessId),
		):
			return False
		if not (int(inspectorProcessId.value) == int(nativeSelectedProcessId.value) == selectedProcessId):
			return False
		if selectedWindowHandle == inspectorWindowHandle or user32.IsChild(
			inspectorWindowHandle,
			selectedWindowHandle,
		):
			return True
		root = int(user32.GetAncestor(selectedWindowHandle, 2))
		if root == inspectorWindowHandle:
			return True
		visited: set[int] = set()
		while root > 0 and root not in visited:
			visited.add(root)
			root = int(user32.GetWindow(root, 4))
			if root == inspectorWindowHandle:
				return True
	except (AttributeError, OSError, TypeError, ValueError):
		return False
	return False


@dataclass(frozen=True, slots=True)
class InspectorTargetEvidence:
	targetKind: InspectorTargetKind
	executable: str
	processId: int
	windowHandle: int
	backend: str
	rawRequested: bool
	rawApplied: bool
	rawReason: str | None

	def lines(self) -> tuple[str, ...]:
		target = "Focus" if self.targetKind == "focus" else "Navigator object"
		raw = (
			"not requested"
			if not self.rawRequested
			else "applied"
			if self.rawApplied
			else _rawUiaFallbackSummary(self.rawReason)
		)
		return (
			f"Target: {target}",
			f"Application: {self.executable}",
			f"Process ID: {self.processId}",
			f"Window handle: {self.windowHandle}",
			f"Backend: {self.backend}",
			f"Raw UIA: {raw}",
		)


class InspectorFrameController:
	def __init__(
		self,
		targetProvider: Callable[[InspectorTargetKind, bool], InspectorTargetEvidence],
		openCustomUia: Callable[[object], None],
		isCurrent: Callable[[], bool],
		announce: Callable[[str], None] | None = None,
	) -> None:
		super().__init__()
		self._targetProvider = targetProvider
		self._openCustomUia = openCustomUia
		self._isCurrent = isCurrent
		self._announce = announce or _ignoreAnnouncement
		self.targetKind: InspectorTargetKind = "focus"
		self.rawRequested = False
		self.evidence: InspectorTargetEvidence | None = None
		self.closed = False
		self._bundleExporter: Callable[[str, str], bytes] | None = None
		self._bundleOutline: tuple[str, ...] = ()

	def retarget(
		self,
		targetKind: InspectorTargetKind | None = None,
		*,
		rawRequested: bool | None = None,
		announce: bool = False,
	) -> InspectorTargetEvidence:
		if self.closed or not self._isCurrent():
			raise RuntimeError("Inspector invocation is no longer current")
		if targetKind is not None:
			self.targetKind = targetKind
		if rawRequested is not None:
			self.rawRequested = rawRequested
		self.evidence = self._targetProvider(self.targetKind, self.rawRequested)
		if announce:
			# Translators: Name of the focus target when the Inspector reports a retarget.
			focusWord = pgettext("inspector target", "Focus")
			# Translators: Name of the navigator-object target when the Inspector reports a retarget.
			navigatorWord = pgettext("inspector target", "Navigator")
			target = focusWord if self.targetKind == "focus" else navigatorWord
			# Translators: Inspector retarget announcement. {target} is Focus or Navigator.
			message = gettext("{target} Inspector retargeted.").format(target=target)
			if self.evidence.rawRequested and not self.evidence.rawApplied:
				message += " " + _rawUiaFallbackMessage(self.evidence.rawReason)
			self._announce(message)
		return self.evidence

	def openCustomUia(self, parent: object) -> None:
		if self.closed or not self._isCurrent():
			raise RuntimeError("Inspector invocation is no longer current")
		self._openCustomUia(parent)

	def openBundle(
		self,
		exporter: Callable[[str, str], bytes],
		outline: tuple[str, ...] = (),
	) -> None:
		if self.closed or not self._isCurrent():
			raise RuntimeError("Inspector invocation is no longer current")
		self._bundleExporter = exporter
		self._bundleOutline = outline

	def exportSelectedNode(self, nodeId: str, exportFormat: str = "json") -> bytes:
		if self.closed or not self._isCurrent():
			raise RuntimeError("Inspector invocation is no longer current")
		if self._bundleExporter is None:
			raise RuntimeError("no capture bundle is open in the Inspector")
		return self._bundleExporter(nodeId, exportFormat)

	@property
	def bundleOutline(self) -> tuple[str, ...]:
		return self._bundleOutline

	def close(self) -> None:
		self.closed = True


def _statusWords() -> dict[PropertyStatus, str]:
	return {
		# Translators: Inspector property status meaning the property has a concrete value.
		PropertyStatus.VALUE: pgettext("inspector property status", "Value"),
		# Translators: Inspector property status meaning the property is present but empty.
		PropertyStatus.EMPTY: pgettext("inspector property status", "Empty"),
		# Translators: Inspector property status meaning the target does not support this property.
		PropertyStatus.UNSUPPORTED: pgettext("inspector property status", "Unsupported"),
		# Translators: Inspector property status meaning the property does not apply to this target.
		PropertyStatus.NOT_APPLICABLE: pgettext("inspector property status", "Not applicable"),
		# Translators: Inspector property status meaning the value could not be obtained.
		PropertyStatus.UNAVAILABLE: pgettext("inspector property status", "Unavailable"),
		# Translators: Inspector property status meaning the value was hidden for privacy.
		PropertyStatus.REDACTED: pgettext("inspector property status", "Redacted"),
		# Translators: Inspector property status meaning the value was shortened to a safe length.
		PropertyStatus.TRUNCATED: pgettext("inspector property status", "Truncated"),
		# Translators: Inspector property status meaning the value may be out of date.
		PropertyStatus.STALE: pgettext("inspector property status", "Stale"),
		# Translators: Inspector property status meaning the request was rejected by a safety limit.
		PropertyStatus.REJECTED: pgettext("inspector property status", "Rejected"),
		# Translators: Inspector property status meaning retrieval failed with an error.
		PropertyStatus.FAILED: pgettext("inspector property status", "Failed"),
	}


def _statusWord(status: PropertyStatus) -> str:
	return _statusWords().get(status, status.value)


def _statusCell(status: PropertyStatus) -> str:
	return "" if status is PropertyStatus.VALUE else _statusWord(status)


def _annotationStatusWord(status: AnnotationStatus) -> str:
	return {
		AnnotationStatus.NO_DATA: pgettext("inspector annotation status", "No data"),
		AnnotationStatus.UNSUPPORTED: pgettext("inspector annotation status", "Unsupported"),
		AnnotationStatus.UNAVAILABLE: pgettext("inspector annotation status", "Unavailable"),
		AnnotationStatus.TRUNCATED: pgettext("inspector annotation status", "Truncated"),
		AnnotationStatus.STALE: pgettext("inspector annotation status", "Stale"),
		AnnotationStatus.FAILED: pgettext("inspector annotation status", "Failed"),
		AnnotationStatus.VALUE: pgettext("inspector annotation status", "Value"),
	}[status]


def _monotonicMilliseconds() -> int:
	return time.monotonic_ns() // 1_000_000


# How far up the parent chain a focused window is followed before giving up on naming it. Controls
# sit at most a few panels deep inside a workspace page, so this never walks far.
_FOCUS_ANCESTOR_LIMIT = 8


def _parentWindow(window: object) -> object | None:
	getParent = getattr(window, "GetParent", None)
	if not callable(getParent):
		return None
	try:
		return getParent()
	except Exception:
		return None


def _focusedWindow(event: object) -> object | None:
	"""Resolve the window that actually holds focus for one child-focus event.

	``wxChildFocusEvent`` reports the direct child of the window the handler is bound to, which for a
	control nested inside a notebook page is the notebook rather than the control. The live focus is
	authoritative, so it is asked first and the event is only the fallback.
	"""

	try:
		windowClass = getattr(import_module("wx"), "Window", None)
		finder = getattr(windowClass, "FindFocus", None)
		focused = finder() if callable(finder) else None
	except Exception:
		focused = None
	if focused is not None:
		return focused
	getWindow = getattr(event, "GetWindow", None)
	if not callable(getWindow):
		return None
	try:
		return getWindow()
	except Exception:
		return None


def _wasSkipped(event: object) -> bool:
	"""Whether a handler passed the key on rather than claiming it."""

	getter = getattr(event, "GetSkipped", None)
	if callable(getter):
		try:
			return bool(getter())
		except Exception:
			pass
	return bool(getattr(event, "skipped", False))


def _matchesAccessKey(label: str, keyCode: int) -> bool:
	"""Match a translated wx mnemonic label against an Alt-modified key code."""

	try:
		pressed = chr(keyCode).casefold()
	except ValueError:
		return False
	index = 0
	while index < len(label):
		if label[index] != "&":
			index += 1
			continue
		index += 1
		if index >= len(label):
			return False
		if label[index] == "&":
			index += 1
			continue
		return label[index].casefold() == pressed
	return False


def _isControlEnabled(control: object | None) -> bool:
	"""Use wx's enabled state, with a lightweight fallback for contract doubles."""

	if control is None:
		return False
	isEnabled = getattr(control, "IsEnabled", None)
	if callable(isEnabled):
		return bool(isEnabled())
	return bool(getattr(control, "enabled", True))


def _toggleControl(control: object | None) -> bool | None:
	"""Toggle an enabled checkbox-like control, or leave a non-checkbox untouched."""

	if not _isControlEnabled(control):
		return None
	getValue = getattr(control, "GetValue", None)
	setValue = getattr(control, "SetValue", None)
	if not callable(getValue) or not callable(setValue):
		return None
	enabled = not bool(getValue())
	_ = setValue(enabled)
	return enabled


def _controlKeyFor(
	controls: dict[str, object],
	window: object | None,
	extra: tuple[tuple[str, object], ...] = (),
) -> str | None:
	"""Name the control a focused window belongs to, following its parents when it is nested."""

	current = window
	for _depth in range(_FOCUS_ANCESTOR_LIMIT):
		if current is None:
			return None
		for key, control in extra:
			if control is current:
				return key
		for key, control in controls.items():
			if control is current:
				return key
		current = _parentWindow(current)
	return None


@dataclass(frozen=True, slots=True)
class InspectorWorkspaceDefinition:
	"""Visible labels and the two intentional native names for the Inspector workspace."""

	title: str = field(default_factory=lambda: pgettext("inspector window", "Keystone Inspector"))
	targetGroupName: str = field(
		default_factory=lambda: pgettext("inspector region", "Inspection target"),
	)
	sourceSummaryName: str = field(default_factory=lambda: _workspaceSourceSummaryName())
	hierarchyName: str = field(default_factory=lambda: _workspaceHierarchyName())
	propertyNotebookName: str = field(default_factory=lambda: _workspacePropertyNotebookName())
	retargetFocusLabel: str = field(default_factory=lambda: _workspaceRetargetFocusLabel())
	retargetNavigatorLabel: str = field(default_factory=lambda: _workspaceRetargetNavigatorLabel())
	followFocusLabel: str = field(default_factory=lambda: _workspaceFollowFocusLabel())
	rawUiaLabel: str = field(default_factory=lambda: _workspaceRawUiaLabel())
	appModuleOverrideLabel: str = field(default_factory=lambda: _workspaceAppModuleOverrideLabel())
	customUiaLabel: str = field(default_factory=lambda: _workspaceCustomUiaLabel())
	openSnapshotLabel: str = field(default_factory=lambda: _workspaceOpenSnapshotLabel())
	followFocusOfflineHelp: str = field(default_factory=lambda: _workspaceFollowFocusOfflineHelp())

	@property
	def tabNames(self) -> tuple[str, ...]:
		return tuple(category.label for category in _PRESENTATION_CATEGORIES)


def _workspaceName() -> str:
	# Translators: Accessible name of the tab strip that switches between Inspector workspaces.
	return pgettext("inspector region", "Keystone workspaces")


def _workspaceSourceSummaryName() -> str:
	# Translators: Accessible name of the region summarising the current Inspector source.
	return pgettext("inspector region", "Current Inspector source")


def _workspaceHierarchyName() -> str:
	# Translators: Accessible name of the tree region showing the accessible object hierarchy.
	return pgettext("inspector region", "Accessible object hierarchy")


def _workspacePropertyNotebookName() -> str:
	# Translators: Accessible name of the notebook grouping property categories.
	return pgettext("inspector region", "Property categories")


def _workspaceRetargetFocusLabel() -> str:
	# Translators: Button label retargeting the Inspector to the focus object. Ampersand marks the access key.
	return pgettext("inspector control", "Retarget to &Focus")


def _workspaceRetargetNavigatorLabel() -> str:
	# Translators: Button label retargeting the Inspector to the navigator object. Ampersand marks the access key.
	return pgettext("inspector control", "Retarget to &Navigator")


def _workspaceFollowFocusLabel() -> str:
	# Translators: Toggle label that makes the Inspector follow focus changes. Ampersand marks the access key.
	return pgettext("inspector control", "Follow F&ocus")


def _workspaceRawUiaLabel() -> str:
	# Translators: Toggle label requesting the raw UIA view. Ampersand marks the access key.
	return pgettext("inspector control", "Use Raw &UIA")


def _workspaceAppModuleOverrideLabel() -> str:
	# Translators: Toggle label requesting UIA for the inspected application. Ampersand marks the access key.
	return pgettext("inspector control", "Force &UIA for application")


def _workspaceCustomUiaLabel() -> str:
	# Translators: Button label opening Custom UIA Properties. Ampersand marks the access key.
	return pgettext("inspector control", "Manage &Custom UIA Properties...")


def _workspaceOpenSnapshotLabel() -> str:
	# Translators: Button label opening a saved snapshot for offline inspection. Ampersand marks access key.
	return pgettext("inspector control", "Open Sna&pshot...")


def _workspaceFollowFocusOfflineHelp() -> str:
	# Translators: Help text explaining Follow Focus cannot run on a saved offline snapshot.
	return pgettext("inspector control", "Follow Focus is unavailable for offline snapshots.")


type WorkspaceId = Literal["inspector", "events"]


def _presentationCategoryLabel(message: str) -> str:
	"""Return an extractable localized category label while keeping ``message`` as a stable key."""

	if message == "Core":
		# Translators: Visible Inspector property category.
		return pgettext("inspector property category", "Core")
	if message == "UIA":
		# Translators: Visible Inspector property category.
		return pgettext("inspector property category", "UIA")
	if message == "Annotations":
		# Translators: Visible Inspector property category.
		return pgettext("inspector property category", "Annotations")
	if message == "Advanced":
		# Translators: Visible Inspector property category.
		return pgettext("inspector property category", "Advanced")
	raise ValueError(f"Unknown Inspector property category: {message}")


@dataclass(frozen=True, slots=True)
class _PresentationCategory:
	"""A visible Inspector category which groups the stable data categories."""

	message: str
	categories: tuple[PropertyCategory, ...]

	@property
	def label(self) -> str:
		return _presentationCategoryLabel(self.message)


_PRESENTATION_CATEGORIES: tuple[_PresentationCategory, ...] = (
	_PresentationCategory("Core", (PropertyCategory.CORE, PropertyCategory.QUICK)),
	_PresentationCategory(
		"UIA",
		(
			PropertyCategory.UIA,
			PropertyCategory.SUPPORTED_UIA_PATTERNS,
			PropertyCategory.OTHER_API,
		),
	),
	_PresentationCategory("Annotations", (PropertyCategory.ANNOTATIONS,)),
	_PresentationCategory(
		"Advanced",
		(
			PropertyCategory.IA2_MSAA,
			PropertyCategory.JAB,
			PropertyCategory.DEVELOPER_INFO,
			PropertyCategory.ALL_PROPERTIES,
			PropertyCategory.DIAGNOSTICS,
		),
	),
)


@dataclass(frozen=True, slots=True)
class KeystoneWindowDefinition:
	"""Names for the one modeless window and the top-level workspaces inside it."""

	title: str = field(default_factory=lambda: pgettext("inspector window", "Keystone Inspector"))
	workspacesName: str = field(default_factory=lambda: _workspaceName())
	inspectorLabel: str = field(
		# Translators: Name of the top-level Inspector workspace page.
		default_factory=lambda: pgettext("keystone workspace", "Inspector"),
	)
	eventsLabel: str = field(
		# Translators: Name of the top-level Events workspace page.
		default_factory=lambda: pgettext("keystone workspace", "Event Monitor"),
	)

	def labelFor(self, workspaceId: WorkspaceId) -> str:
		return self.inspectorLabel if workspaceId == "inspector" else self.eventsLabel


@dataclass(slots=True)
class _RegisteredWorkspace:
	build: Callable[[object], None]
	restoreFocus: Callable[[], None]
	dismissed: Callable[[], None]
	closed: Callable[[], None]
	handleKey: Callable[[object], None]
	refreshStatus: Callable[[], None] = lambda: None
	page: object | None = None


class KeystoneWindow:
	"""The one modeless Keystone Inspector window holding both top-level workspaces.

	Inspector and Events are pages of a single notebook here, not separate frames, so the user keeps
	one window, one place in the alt-tab order, and one close action. Ctrl+I and Ctrl+E select a
	workspace from anywhere in the window and hand focus back to whatever that workspace last had
	focused, which is what makes switching cheap enough to do mid-investigation.
	"""

	def __init__(self, *, windowOwnership: WindowOwnershipCheck | None = None) -> None:
		super().__init__()
		self._windowOwnership = windowOwnership or _nativeWindowOwnership
		self._definition = KeystoneWindowDefinition()
		self._frame: object | None = None
		self._owner: object | None = None
		self._notebook: object | None = None
		self._statusBar: object | None = None
		self._order: list[WorkspaceId] = []
		self._workspaces: dict[WorkspaceId, _RegisteredWorkspace] = {}
		self._activationGeneration = 0
		self._activationTimer: object | None = None
		self._activeId: WorkspaceId | None = None

	def setStatus(self, text: str) -> None:
		"""Write one line to the single native frame status bar shared by both workspaces."""

		statusBar = self._statusBar
		if statusBar is None:
			return
		setStatusText = getattr(statusBar, "SetStatusText", None)
		if callable(setStatusText):
			_ = setStatusText(text)

	@property
	def definition(self) -> KeystoneWindowDefinition:
		return self._definition

	@property
	def frame(self) -> object | None:
		return self._frame

	@property
	def isOpen(self) -> bool:
		return self._frame is not None

	@property
	def activeWorkspace(self) -> WorkspaceId | None:
		return self._currentWorkspaceId()

	def _currentWorkspaceId(self) -> WorkspaceId | None:
		"""Read which workspace is actually on screen, not which one was last selected here.

		The notebook can change page without going through :meth:`activate` -- Ctrl+Tab, a click on a
		tab, or an arrow key -- so the live selection is authoritative. A keyboard command routed on
		a remembered value would reach a workspace the user cannot see.
		"""

		notebook = self._notebook
		if notebook is None:
			return self._activeId
		try:
			index = int(notebook.GetSelection())
		except (AttributeError, TypeError, ValueError):
			return self._activeId
		if 0 <= index < len(self._order):
			self._activeId = self._order[index]
		return self._activeId

	@property
	def workspaceOrder(self) -> tuple[WorkspaceId, ...]:
		return tuple(self._order)

	def register(
		self,
		workspaceId: WorkspaceId,
		*,
		build: Callable[[object], None],
		restoreFocus: Callable[[], None],
		dismissed: Callable[[], None],
		closed: Callable[[], None],
		handleKey: Callable[[object], None],
		refreshStatus: Callable[[], None] = lambda: None,
	) -> None:
		"""Claim one top-level page. Registering again replaces the callbacks, never the page order."""

		if workspaceId not in self._workspaces:
			self._order.append(workspaceId)
		self._workspaces[workspaceId] = _RegisteredWorkspace(
			build,
			restoreFocus,
			dismissed,
			closed,
			handleKey,
			refreshStatus,
		)
		if self._frame is not None:
			self._buildPage(import_module("wx"), workspaceId)

	def refreshActiveStatus(self) -> None:
		"""Let only the workspace currently on screen write the shared status bar.

		Both pages are built at open and each renders its own status, so the visible workspace must
		reassert its line whenever the page changes -- initial open, Ctrl+I/Ctrl+E, or a native tab.
		"""

		workspaceId = self._currentWorkspaceId()
		registration = self._workspaces.get(workspaceId) if workspaceId is not None else None
		if registration is not None:
			registration.refreshStatus()

	def ownsWindow(self, processId: int, windowHandle: int) -> bool:
		frame = self._frame
		if frame is None:
			return False
		try:
			keystoneWindowHandle = int(frame.GetHandle())
		except (AttributeError, TypeError, ValueError):
			return False
		return self._windowOwnership(keystoneWindowHandle, processId, windowHandle)

	def open(self) -> None:
		"""Build the frame and every registered page once; later calls only fill in new pages."""

		wx = import_module("wx")
		if self._frame is None:
			self._buildFrame(wx)
		for workspaceId in tuple(self._order):
			self._buildPage(wx, workspaceId)

	def activate(self, workspaceId: WorkspaceId) -> None:
		"""Show the window, select ``workspaceId``, and restore that workspace's own focus."""

		self.open()
		frame = self._frame
		if frame is None:
			return
		wx = import_module("wx")
		self._selectPage(workspaceId)
		self.refreshActiveStatus()
		generation = self._nextActivationGeneration()
		owner = self._owner
		if owner is None:
			frame.Show()
			frame.Raise()
		else:
			owner.prePopup()
			try:
				frame.Show()
				frame.Raise()
			finally:
				owner.postPopup()
		self._scheduleLayout(wx, workspaceId)
		self._scheduleFocus(wx, frame, generation, workspaceId)

	def dismiss(self) -> None:
		"""Destroy the window and let every workspace drop the controls that lived inside it."""

		frame = self._frame
		_ = self._nextActivationGeneration()
		self._frame = None
		self._owner = None
		self._notebook = None
		self._activeId = None
		for registration in self._workspaces.values():
			registration.page = None
			registration.dismissed()
		if frame is not None:
			frame.Destroy()

	def handleKey(self, event: object) -> bool:
		"""Select a workspace on Ctrl+I or Ctrl+E; return whether the key was consumed."""

		if not bool(event.ControlDown()) or bool(event.AltDown()) or bool(event.ShiftDown()):
			return False
		keyCode = int(event.GetKeyCode())
		requested: WorkspaceId | None = None
		if keyCode in (ord("I"), ord("i")):
			requested = "inspector"
		elif keyCode in (ord("E"), ord("e")):
			requested = "events"
		if requested is None or requested not in self._workspaces:
			return False
		self.activate(requested)
		return True

	# -- internals ---------------------------------------------------------

	def _buildFrame(self, wx: Any) -> None:
		self._owner = self._popupOwner()
		frame = wx.Frame(self._owner, title=self._definition.title, style=wx.DEFAULT_FRAME_STYLE)
		panel = wx.Panel(frame)
		root = wx.BoxSizer(wx.VERTICAL)
		notebook = wx.Notebook(panel)
		notebook.SetName(self._definition.workspacesName)
		root.Add(notebook, 1, wx.EXPAND | wx.ALL, 8)
		close = wx.Button(panel, wx.ID_CLOSE, label=gettext("&Close"))
		buttons = wx.BoxSizer(wx.HORIZONTAL)
		buttons.AddStretchSpacer()
		buttons.Add(close, 0)
		root.Add(buttons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)
		panel.SetSizer(root)
		frame.SetSize((_fromDip(frame, 1120), _fromDip(frame, 760)))
		frame.SetMinSize((_fromDip(frame, 820), _fromDip(frame, 560)))
		frame.Centre()
		self._frame = frame
		self._notebook = notebook
		createStatusBar = getattr(frame, "CreateStatusBar", None)
		if callable(createStatusBar):
			statusBar = createStatusBar()
			self._statusBar = statusBar
			setStatusText = getattr(statusBar, "SetStatusText", None)
			if callable(setStatusText):
				_ = setStatusText(gettext("Ready"))

		def onClose(_event: object) -> None:
			self.closeWorkspaces()

		def onKey(event: object) -> None:
			self._routeKey(event)

		def onPageChanged(event: object) -> None:
			_ = self._currentWorkspaceId()
			self.refreshActiveStatus()
			skip = getattr(event, "Skip", None)
			if callable(skip):
				_ = skip()

		frame.Bind(wx.EVT_CLOSE, onClose)
		frame.Bind(wx.EVT_CHAR_HOOK, onKey)
		notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, onPageChanged)
		close.Bind(wx.EVT_BUTTON, onClose)

	def _routeKey(self, event: object) -> None:
		"""Give the window keys to its active workspace, leaving native Close behavior untouched."""

		if self.handleKey(event):
			return
		workspaceId = self._currentWorkspaceId()
		registration = self._workspaces.get(workspaceId) if workspaceId is not None else None
		if registration is not None:
			registration.handleKey(event)
			if not _wasSkipped(event):
				return
		if registration is None:
			skip = getattr(event, "Skip", None)
			if callable(skip):
				_ = skip()

	def closeWorkspaces(self) -> None:
		"""Let each workspace close itself, then make sure the window is gone."""

		for registration in tuple(self._workspaces.values()):
			registration.closed()
		self.dismiss()

	def _buildPage(self, wx: Any, workspaceId: WorkspaceId) -> None:
		registration = self._workspaces.get(workspaceId)
		notebook = self._notebook
		if registration is None or notebook is None or registration.page is not None:
			return
		page = wx.Panel(notebook)
		registration.page = page
		notebook.AddPage(page, self._definition.labelFor(workspaceId))
		registration.build(page)
		_layout(page)
		_layout(notebook)
		if self._frame is not None:
			_layout(self._frame)

	def _selectPage(self, workspaceId: WorkspaceId) -> None:
		notebook = self._notebook
		if notebook is None or workspaceId not in self._workspaces:
			return
		index = self._order.index(workspaceId)
		notebook.SetSelection(index)
		self._activeId = workspaceId

	def _scheduleLayout(self, wx: object, workspaceId: WorkspaceId) -> None:
		"""Lay out the selected page after wx assigns its final notebook-page dimensions."""

		def layoutPage() -> None:
			registration = self._workspaces.get(workspaceId)
			notebook = self._notebook
			frame = self._frame
			if registration is None or registration.page is None or notebook is None or frame is None:
				return
			sendSizeEvent = getattr(registration.page, "SendSizeEvent", None)
			if callable(sendSizeEvent):
				_ = sendSizeEvent()
			_layoutTree(frame)

		wx.CallAfter(layoutPage)

	def _popupOwner(self) -> object | None:
		gui = import_module("gui")
		owner = getattr(gui, "mainFrame", None)
		if owner is None:
			return None
		if not callable(getattr(owner, "prePopup", None)) or not callable(
			getattr(owner, "postPopup", None),
		):
			return None
		return owner

	def _nextActivationGeneration(self) -> int:
		self._activationGeneration += 1
		timer = self._activationTimer
		self._activationTimer = None
		if timer is not None:
			stop = getattr(timer, "Stop", None)
			if callable(stop):
				_ = stop()
		return self._activationGeneration

	def _scheduleFocus(
		self,
		wx: Any,
		frame: object,
		generation: int,
		workspaceId: WorkspaceId,
	) -> None:
		def focus(attempt: int = 0) -> None:
			if self._frame is not frame or self._activationGeneration != generation:
				return
			frame.Raise()
			registration = self._workspaces.get(workspaceId)
			if registration is not None:
				registration.restoreFocus()
			isActive = getattr(frame, "IsActive", None)
			if not callable(isActive) or bool(isActive()):
				self._activationTimer = None
				return
			if attempt < len(_ACTIVATION_RETRY_DELAYS_MS):
				self._activationTimer = wx.CallLater(
					_ACTIVATION_RETRY_DELAYS_MS[attempt],
					lambda: focus(attempt + 1),
				)
				return
			self._activationTimer = None
			requestAttention = getattr(frame, "RequestUserAttention", None)
			if callable(requestAttention):
				_ = requestAttention()

		wx.CallAfter(focus)


class InspectorWorkspace:
	"""One singleton native workspace that renders and drives an ``InspectorService``.

	The service owns every Inspector decision: the ancestor-only hierarchy, the eleven independent
	property panes, loaded-only search, semantic copy, quick-property cycles, Follow Focus, and the
	generation counters that make deferred callbacks safe. This class is the thin owner-thread native
	binding: it builds the wx controls once, renders the service's immutable views into them, routes
	keyboard commands back into the service, submits explicit speech only where the contract requires
	it (never for ordinary tree, list, or tab movement), and tears everything down in lifecycle order
	so no stale callback can touch a control, the clipboard, or speech after close.
	"""

	def __init__(
		self,
		service: InspectorService,
		*,
		retarget: Callable[
			[InspectorTargetKind, bool],
			InspectorRetargetOutcome | None,
		]
		| None = None,
		followRetarget: Callable[[FollowFocusEvent], bool | None] | None = None,
		openSnapshot: Callable[[Path, BundleAdmissionLimits | None], None] | None = None,
		openEventMonitor: Callable[[], None] | None = None,
		openCustomUia: Callable[[object], None] | None = None,
		appModuleOverrideState: Callable[[], AppModuleOverrideState] | None = None,
		setAppModuleOverride: Callable[[bool], AppModuleOverrideOutcome] | None = None,
		announce: Callable[[str], None] | None = None,
		announceFollowFocus: Callable[[str], None] | None = None,
		copyToClipboard: Callable[[str], bool] | None = None,
		copySubtreeSnapshot: Callable[[str], bytes] | None = None,
		exportSubtreeSnapshot: Callable[[str, Path], None] | None = None,
		isCurrent: Callable[[], bool] | None = None,
		windowOwnership: WindowOwnershipCheck | None = None,
		clock: Callable[[], int] | None = None,
		sound: WorkflowSounds | None = None,
		window: KeystoneWindow | None = None,
	) -> None:
		super().__init__()
		self._service = service
		self._sound = sound
		self._retarget = retarget
		self._followRetarget = followRetarget
		self._openSnapshot = openSnapshot
		self._openEventMonitor = openEventMonitor
		self._openCustomUia = openCustomUia
		self._appModuleOverrideState = appModuleOverrideState
		self._setAppModuleOverride = setAppModuleOverride
		self._announce = announce or _ignoreAnnouncement
		self._announceFollowFocus = announceFollowFocus or self._announce
		self._copyToClipboard = copyToClipboard
		self._copySubtreeSnapshotCallback = copySubtreeSnapshot
		self._exportSubtreeSnapshotCallback = exportSubtreeSnapshot
		self._isCurrent = isCurrent or (lambda: True)
		self._windowOwnership = windowOwnership or _nativeWindowOwnership
		self._clock = clock or _monotonicMilliseconds
		self._definition = InspectorWorkspaceDefinition()
		self._frame: object | None = None
		self._owner: object | None = None
		self._controls: dict[str, object] = {}
		self._propertyControls: list[object] = []
		self._snapshotDirectory = _lastSnapshotDirectory
		self._presentationCategoryIndex = 0
		self._presentationRows: dict[str, PropertyRow] = {}
		self._presentationAnnotations: dict[str, AnnotationRecord] = {}
		self._presentationItems: dict[object, str] = {}
		self._detailBox: object | None = None
		self._detailSizer: object | None = None
		self._detailPanel: object | None = None
		self._detailKind = ""
		self._detailListRows: list[tuple[str, str, str]] = []
		self._detailListKeys: list[tuple[PropertyCategory, str]] = []
		self._detailSelectedKey: tuple[PropertyCategory, str] | str | None = None
		self._renderedPresentationCategory: str | None = None
		self._detailAnnotationRecords: list[AnnotationRecord | None] = []
		self._detailTreeNodes: list[dict[str, object]] = []
		self._detailTreeRootItem: object | None = None
		self._treeItems: dict[str, object] = {}
		self._treePlaceholders: dict[str, object] = {}
		self._activationGeneration = 0
		self._activationTimer: object | None = None
		self._renderingHierarchy = False
		self._quickTimers: dict[int, object] = {}
		self._findText = ""
		self._findData: object | None = None
		self._findDialog: object | None = None
		self._lastFocusKey = "hierarchy"
		self._window = window or KeystoneWindow(windowOwnership=self._windowOwnership)
		self._window.register(
			"inspector",
			build=self._buildInto,
			restoreFocus=self._restoreFocus,
			dismissed=self._releaseControls,
			closed=self.close,
			handleKey=self.handleKey,
			refreshStatus=self._refreshStatus,
		)

	def _emitInspectorSound(
		self,
		event: CueEventId,
		*,
		generation: int,
		coalescingKey: str | None = None,
	) -> None:
		# Sound is optional and additive: the workspace has already spoken. A missing seam is a
		# no-op, and any failure to build or schedule the request must never disturb speech, the
		# clipboard, or the frame.
		sound = self._sound
		if sound is None:
			return
		owner = SoundOwner(SoundOwnerKind.INSPECTOR, generation)
		try:
			sound.emit(soundRequestFor(event, owner, coalescingKey=coalescingKey))
		except Exception:
			_logUnexpectedSound()

	@property
	def service(self) -> InspectorService:
		return self._service

	@property
	def definition(self) -> InspectorWorkspaceDefinition:
		return self._definition

	@property
	def window(self) -> KeystoneWindow:
		"""The one window this workspace shares with the other top-level workspace."""

		return self._window

	def ownsWindow(self, processId: int, windowHandle: int) -> bool:
		return self._window.ownsWindow(processId, windowHandle)

	# -- lifecycle: build, activate, teardown ------------------------------

	def show(self) -> None:
		"""Open the shared window on first use, then select and re-render this workspace."""

		alreadyBuilt = bool(self._controls)
		self._window.open()
		if alreadyBuilt:
			self._renderAll()
		self._window.activate("inspector")

	def _buildInto(self, panel: object) -> None:
		"""Render every Inspector control into the page the shared window owns."""

		self._build(panel)

	def _restoreFocus(self) -> None:
		"""Return focus to the control this workspace last had focused, defaulting to the hierarchy."""
		if self._lastFocusKey == "properties":
			self._focusActivePane()
			return
		target = self._controls.get(self._lastFocusKey) or self._controls.get("hierarchy")
		if target is not None:
			target.SetFocus()

	def _onChildFocus(self, event: object) -> None:
		"""Remember whatever the user moved focus to, however they moved it.

		Tab traversal, a mouse click, and a workspace command all end in the same place: a control
		inside this page holding focus. Recording it here is what lets Ctrl+I return to the control
		the user was actually on rather than the last one Keystone focused for them.
		"""

		key = _controlKeyFor(
			self._controls,
			_focusedWindow(event),
			tuple(("properties", control) for control in self._propertyControls),
		)
		if key is not None:
			self._lastFocusKey = key
			if key == "properties":
				_ = self._service.focusRegion(InspectorRegion.PROPERTIES)
			elif key == "hierarchy":
				_ = self._service.focusRegion(InspectorRegion.HIERARCHY)
		skip = getattr(event, "Skip", None)
		if callable(skip):
			_ = skip()

	def _releaseControls(self) -> None:
		"""Drop every control reference after the shared window destroyed the page."""

		self._cancelQuickTimers()
		self._frame = None
		self._owner = None
		self._controls = {}
		self._propertyControls = []
		self._detailBox = None
		self._detailSizer = None
		self._detailPanel = None
		self._detailKind = ""
		self._detailListRows = []
		self._detailListKeys = []
		self._detailSelectedKey = None
		self._renderedPresentationCategory = None
		self._detailAnnotationRecords = []
		self._detailTreeNodes = []
		self._detailTreeRootItem = None
		self._treeItems = {}
		self._treePlaceholders = {}
		self._findDialog = None
		self._lastFocusKey = "hierarchy"

	def _build(self, panel: object) -> None:
		wx = import_module("wx")
		definition = self._definition
		frame = self._window.frame
		root = wx.BoxSizer(wx.VERTICAL)

		targetBox, targetSizer = _staticGroup(wx, panel, definition.targetGroupName)
		summary = wx.TextCtrl(targetBox, style=wx.TE_READONLY)
		summary.SetName(definition.sourceSummaryName)
		targetSizer.Add(summary, 0, wx.EXPAND | wx.ALL, 4)
		actions = _responsiveRowSizer(wx)
		retargetFocus = wx.Button(targetBox, label=definition.retargetFocusLabel)
		retargetNavigator = wx.Button(targetBox, label=definition.retargetNavigatorLabel)
		followFocus = wx.CheckBox(targetBox, label=definition.followFocusLabel)
		rawUia = wx.CheckBox(targetBox, label=definition.rawUiaLabel)
		appModuleOverride = wx.CheckBox(targetBox, label=definition.appModuleOverrideLabel)
		for control in (retargetFocus, retargetNavigator, followFocus, rawUia, appModuleOverride):
			actions.Add(control, 0, wx.LEFT | wx.RIGHT, 4)
		targetSizer.Add(actions, 0, wx.EXPAND | wx.ALL, 4)
		root.Add(targetSizer, 0, wx.EXPAND | wx.ALL, 8)

		tools = wx.BoxSizer(wx.HORIZONTAL)
		customUia = wx.Button(panel, label=definition.customUiaLabel)
		if self._openCustomUia is None:
			customUia.Enable(False)
		openSnapshot = wx.Button(panel, label=definition.openSnapshotLabel)
		openSnapshot.Enable(self._openSnapshot is not None)
		for control in (customUia, openSnapshot):
			tools.Add(control, 0, wx.LEFT | wx.RIGHT, 4)
		root.Add(tools, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 8)

		splitter = wx.SplitterWindow(panel, style=wx.SP_LIVE_UPDATE)
		hierarchyPanel = wx.Panel(splitter)
		hierarchyLayout = wx.BoxSizer(wx.VERTICAL)
		hierarchyBox, hierarchySizer = _staticGroup(wx, hierarchyPanel, definition.hierarchyName)
		hierarchy = wx.TreeCtrl(
			hierarchyBox,
			style=wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT | wx.TR_DEFAULT_STYLE,
		)
		hierarchySizer.Add(hierarchy, 1, wx.EXPAND | wx.ALL, 4)
		hierarchyLayout.Add(hierarchySizer, 1, wx.EXPAND)
		hierarchyPanel.SetSizer(hierarchyLayout)

		detailPanel = wx.Panel(splitter)
		detailLayout = wx.BoxSizer(wx.VERTICAL)
		detailSplitter = wx.SplitterWindow(detailPanel, style=wx.SP_LIVE_UPDATE)
		categoryPanel = wx.Panel(detailSplitter)
		categoryLayout = wx.BoxSizer(wx.VERTICAL)
		categoryBox, categorySizer = _staticGroup(wx, categoryPanel, definition.propertyNotebookName)
		categoryList = _reportList(wx, categoryBox, autoSizeColumn=0)
		categoryList.InsertColumn(0, definition.propertyNotebookName)
		for index, category in enumerate(_PRESENTATION_CATEGORIES):
			categoryList.InsertItem(index, category.label)
		categoryList.Select(self._presentationCategoryIndex)
		categoryList.Focus(self._presentationCategoryIndex)
		categorySizer.Add(categoryList, 1, wx.EXPAND | wx.ALL, 4)
		categoryLayout.Add(categorySizer, 1, wx.EXPAND)
		categoryPanel.SetSizer(categoryLayout)
		propertyPanel = wx.Panel(detailSplitter)
		propertySizer = wx.BoxSizer(wx.VERTICAL)
		propertyPanel.SetSizer(propertySizer)
		detailSplitter.SplitVertically(categoryPanel, propertyPanel, 240)
		detailSplitter.SetMinimumPaneSize(_fromDip(frame, 160))
		detailLayout.Add(detailSplitter, 1, wx.EXPAND)
		detailPanel.SetSizer(detailLayout)
		splitter.SplitVertically(hierarchyPanel, detailPanel, 300)
		splitter.SetMinimumPaneSize(_fromDip(frame, 180))
		root.Add(splitter, 1, wx.EXPAND | wx.ALL, 8)

		panel.SetSizer(root)

		self._frame = frame
		self._detailPanel = propertyPanel
		self._detailSizer = propertySizer
		self._propertyControls = []
		self._controls = {
			"panel": panel,
			"sourceSummary": summary,
			"retargetFocus": retargetFocus,
			"retargetNavigator": retargetNavigator,
			"followFocus": followFocus,
			"rawUia": rawUia,
			"appModuleOverride": appModuleOverride,
			"customUia": customUia,
			"openSnapshot": openSnapshot,
			"hierarchy": hierarchy,
			"categoryList": categoryList,
		}
		self._bind(wx, hierarchy)
		self._renderAll()

	def _bind(self, wx: object, hierarchy: object) -> None:
		controls = self._controls

		def onRetargetFocus(_event: object) -> None:
			self._doRetarget("focus")

		def onRetargetNavigator(_event: object) -> None:
			self._doRetarget("navigator")

		def onFollowFocus(_event: object) -> None:
			self._toggleFollowFocus(bool(controls["followFocus"].GetValue()))

		def onRawUia(_event: object) -> None:
			state = gettext("enabled") if bool(controls["rawUia"].GetValue()) else gettext("disabled")
			self._setStatus(gettext("Use Raw UIA {state} for the next retarget.").format(state=state))

		def onAppModuleOverride(_event: object) -> None:
			self._toggleAppModuleOverride(bool(controls["appModuleOverride"].GetValue()))

		def onOpenSnapshot(_event: object) -> None:
			self._openSnapshotFromDialog()

		def onOpenCustomUia(_event: object) -> None:
			if self._openCustomUia is not None:
				self._openCustomUia(self._window.frame)

		def onTreeSelection(_event: object) -> None:
			self._onTreeSelection()

		def onTreeExpanding(event: object) -> None:
			self._onTreeExpanding(event)

		def onTreeKey(event: object) -> None:
			self._onTreeKey(event)

		def onHierarchyContext(event: object) -> None:
			self._showInspectorContextMenu(event, "hierarchy")

		def onCategorySelected(_event: object) -> None:
			self._onPresentationCategorySelected()

		def onCategoryKey(event: object) -> None:
			if not self._handleWorkspaceKey(event):
				event.Skip()

		def onCategoryContext(event: object) -> None:
			self._showInspectorContextMenu(event, "category")

		def onChildFocus(event: object) -> None:
			self._onChildFocus(event)

		controls["retargetFocus"].Bind(wx.EVT_BUTTON, onRetargetFocus)
		controls["retargetNavigator"].Bind(wx.EVT_BUTTON, onRetargetNavigator)
		controls["followFocus"].Bind(wx.EVT_CHECKBOX, onFollowFocus)
		controls["rawUia"].Bind(wx.EVT_CHECKBOX, onRawUia)
		controls["appModuleOverride"].Bind(wx.EVT_CHECKBOX, onAppModuleOverride)
		controls["customUia"].Bind(wx.EVT_BUTTON, onOpenCustomUia)
		controls["openSnapshot"].Bind(wx.EVT_BUTTON, onOpenSnapshot)
		hierarchy.Bind(wx.EVT_TREE_SEL_CHANGED, onTreeSelection)
		hierarchy.Bind(wx.EVT_TREE_ITEM_EXPANDING, onTreeExpanding)
		hierarchy.Bind(wx.EVT_KEY_DOWN, onTreeKey)
		hierarchy.Bind(wx.EVT_CONTEXT_MENU, onHierarchyContext)
		controls["categoryList"].Bind(wx.EVT_LIST_ITEM_FOCUSED, onCategorySelected)
		controls["categoryList"].Bind(wx.EVT_CONTEXT_MENU, onCategoryContext)
		controls["categoryList"].Bind(wx.EVT_KEY_DOWN, onCategoryKey)
		controls["panel"].Bind(wx.EVT_CHILD_FOCUS, onChildFocus)

	def _focusOpenSnapshot(self) -> None:
		control = self._controls.get("openSnapshot")
		if control is not None:
			control.SetFocus()
			self._lastFocusKey = "openSnapshot"

	def _confirmExpandedSnapshotOpen(self) -> bool:
		wx = import_module("wx")
		dialog = wx.MessageDialog(
			self._frame,
			gettext(
				(
					"This snapshot exceeds the default 2.5 MiB limit. Retry this one open with a "
					"64 MiB limit? It may use additional memory and take longer to open. "
					"This does not change future snapshot limits."
				),
			),
			pgettext("inspector window", "Open larger snapshot"),
			wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
		)
		try:
			return dialog.ShowModal() == wx.ID_YES
		finally:
			dialog.Destroy()

	def _openSnapshotFromDialog(self) -> None:
		loader = self._openSnapshot
		if loader is None:
			return
		wx = import_module("wx")
		dialog = wx.FileDialog(
			self._frame,
			message=gettext("Choose an index.json snapshot file"),
			wildcard=gettext("Snapshot index (index.json)|index.json"),
			defaultFile="index.json",
			style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
			**({"defaultDir": str(self._snapshotDirectory)} if self._snapshotDirectory is not None else {}),
		)
		try:
			if dialog.ShowModal() != wx.ID_OK:
				self._feedback(gettext("Opening snapshot cancelled."))
				self._focusOpenSnapshot()
				return
			selected = Path(dialog.GetPath())
		finally:
			dialog.Destroy()
		if selected.name != "index.json":
			self._feedback(gettext("Snapshot was not opened because the selected file is not index.json."))
			self._focusOpenSnapshot()
			return
		directory = selected.parent
		global _lastSnapshotDirectory
		_lastSnapshotDirectory = directory
		self._snapshotDirectory = directory
		try:
			loader(directory, None)
		except BundleAdmissionLimitExceeded:
			if not self._confirmExpandedSnapshotOpen():
				self._feedback(gettext("Opening larger snapshot cancelled."))
				self._focusOpenSnapshot()
				return
			try:
				loader(directory, LOCAL_SELECTED_BUNDLE_LIMITS)
			except (BundleAdmissionLimitExceeded, OSError, ValueError):
				self._feedback(gettext("Snapshot was not opened."))
				self._focusOpenSnapshot()
				return
		except (OSError, ValueError):
			self._feedback(gettext("Snapshot was not opened."))
			self._focusOpenSnapshot()
			return
		self._renderAll()
		hierarchy = self._controls.get("hierarchy")
		if hierarchy is not None:
			hierarchy.SetFocus()
			self._lastFocusKey = "hierarchy"
		self._delayedFeedback(gettext("Snapshot opened."))

	def _bindDetailControl(self, wx: object, control: object, *, isTree: bool) -> None:
		"""Bind the category detail's native selection, context menu, and copy key."""

		def onDetailContext(event: object) -> None:
			self._showInspectorContextMenu(event, "details")

		def onDetailKey(event: object) -> None:
			self._onPresentationDetailKey(event)

		def onDetailSelected(event: object) -> None:
			self._onDetailSelected(event, isTree=isTree)

		control.Bind(wx.EVT_CONTEXT_MENU, onDetailContext)
		control.Bind(wx.EVT_KEY_DOWN, onDetailKey)
		control.Bind(
			wx.EVT_TREE_SEL_CHANGED if isTree else wx.EVT_LIST_ITEM_SELECTED,
			onDetailSelected,
		)

	def _nextActivationGeneration(self) -> int:
		self._activationGeneration += 1
		return self._activationGeneration

	def dismiss(self) -> None:
		"""Invalidate deferred work, then destroy the shared window and drop every control."""

		_ = self._nextActivationGeneration()
		self._window.dismiss()
		self._releaseControls()

	def close(self) -> None:
		"""Explicit user/secure close: tear down the frame, then close the service source.

		Closing a workspace that was never opened -- as happens during a plain composition
		teardown that never invoked the Inspector -- is a silent no-op: there is no frame to
		destroy and no open source, so no browsing feedback is spoken.
		"""

		wasOpen = self._frame is not None or self._service.sourceIdentity() is not None
		frameGeneration = self._activationGeneration
		self.dismiss()
		self._service.close()
		if wasOpen:
			# Translators: Inspector message spoken when the Inspector window is closed.
			self._announce(gettext("Inspector closed."))
			self._emitInspectorSound(CueEventId.INSPECTOR_CLOSE, generation=frameGeneration)

	# -- rendering ---------------------------------------------------------

	def _renderAll(self) -> None:
		self._renderSourceSummary()
		self._renderHierarchy()
		self._renderActivePane()
		self._syncFollowFocusControl()
		self._syncAppModuleOverrideControl()

	def _renderSourceSummary(self) -> None:
		summary = self._controls.get("sourceSummary")
		if summary is None:
			return
		identity = self._service.sourceIdentity()
		if identity is None:
			# Translators: Inspector source summary shown when no source is open.
			self._setSourceSummary(summary, gettext("No Inspector source is open."), concise=None)
			return
		# Translators: Label marking a live (running application) Inspector source.
		liveWord = pgettext("inspector source kind", "Live")
		# Translators: Label marking an offline (saved snapshot) Inspector source.
		offlineWord = pgettext("inspector source kind", "Offline")
		kind = liveWord if identity.kind.value == "live" else offlineWord
		# Translators: Inspector source summary naming the source kind and its label.
		parts = [gettext("{kind} source: {label}").format(kind=kind, label=identity.label)]
		if identity.executable:
			# Translators: Inspector source summary line naming the source application executable.
			parts.append(gettext("Application: {executable}").format(executable=identity.executable))
		if identity.processId:
			# Translators: Inspector source summary line naming the source process identifier.
			parts.append(gettext("Process ID: {processId}").format(processId=identity.processId))
		if identity.backend:
			# Translators: Inspector source summary line naming the accessibility backend in use.
			parts.append(gettext("Backend: {backend}").format(backend=identity.backend))
		concise = parts[0]
		if identity.kind.value == "offline" and identity.executable:
			# Translators: Concise offline source title. {executable} is the captured application
			# and {source} is a label such as "Offline source: capture-snapshot".
			concise = gettext("{executable} | {source}").format(
				executable=identity.executable,
				source=concise,
			)
		self._setSourceSummary(summary, ". ".join(parts), concise=concise)

	def _setSourceSummary(self, summary: object, text: str, *, concise: str | None) -> None:
		summary.SetValue(text)
		frame = self._frame
		if frame is None:
			return
		title = self._definition.title
		if concise is not None:
			# Translators: Inspector window title. {title} is Keystone Inspector and {source} is a
			# concise source such as "Live source: notepad.exe".
			title = gettext("{title} — {source}").format(title=title, source=concise)
		frame.SetTitle(title)

	def _renderHierarchy(self) -> None:
		tree = self._controls.get("hierarchy")
		if tree is None:
			return
		self._renderingHierarchy = True
		try:
			tree.DeleteAllItems()
			self._treeItems = {}
			self._treePlaceholders = {}
			root = tree.AddRoot(pgettext("inspector region", "Accessible object hierarchy"))
			selectedItem: object | None = None
			rows = self._service.hierarchy()
			for row in rows:
				facet = row.node.facet
				parentItem = self._treeItems.get(facet.parentId) if facet.parentId is not None else root
				if parentItem is None:
					parentItem = root
				item = self._appendTreeRow(tree, parentItem, row)
				if row.expanded:
					tree.Expand(item)
				if row.selected:
					selectedItem = item
			for row in rows:
				item = self._treeItems[row.nodeId]
				if not self._treeChildItems(row.nodeId):
					self._renderChildPlaceholder(tree, item, row)
			# Expand the visible root so all initial hierarchy rows are reachable.
			tree.Expand(root)
			if selectedItem is not None:
				tree.SelectItem(selectedItem)
		finally:
			self._renderingHierarchy = False

	def _appendTreeRow(self, tree: object, parentItem: object, row: object) -> object:
		item = tree.AppendItem(parentItem, self._hierarchyLabel(row))
		self._treeItems[row.nodeId] = item
		tree.SetItemHasChildren(item, row.node.hasExpander)
		return item

	def _treeChildItems(self, parentNodeId: str) -> tuple[object, ...]:
		return tuple(
			self._treeItems[row.nodeId]
			for row in self._service.hierarchy()
			if row.node.facet.parentId == parentNodeId and row.nodeId in self._treeItems
		)

	def _removeTreePlaceholder(self, nodeId: str) -> None:
		placeholder = self._treePlaceholders.pop(nodeId, None)
		tree = self._controls.get("hierarchy")
		if placeholder is not None and tree is not None:
			tree.Delete(placeholder)

	def _renderChildPlaceholder(self, tree: object, item: object, row: object) -> None:
		state = row.node.childState
		if state is ChildState.HINT or state is ChildState.LOADING:
			# Translators: Placeholder tree item shown while child objects load.
			placeholder = tree.AppendItem(item, pgettext("inspector hierarchy", "Loading children"))
			self._treePlaceholders[row.nodeId] = placeholder
		elif state is ChildState.FAILED:
			# Translators: Placeholder tree item shown when child objects could not be loaded.
			placeholder = tree.AppendItem(item, pgettext("inspector hierarchy", "Children unavailable"))
			self._treePlaceholders[row.nodeId] = placeholder
		elif state is ChildState.TRUNCATED:
			# Translators: Placeholder tree item shown when some child objects were omitted for safety.
			placeholder = tree.AppendItem(item, pgettext("inspector hierarchy", "More children not shown"))
			self._treePlaceholders[row.nodeId] = placeholder
		elif state is ChildState.CANCELLED:
			# Translators: Placeholder tree item shown when a child load was cancelled.
			placeholder = tree.AppendItem(item, pgettext("inspector hierarchy", "Child load cancelled"))
			self._treePlaceholders[row.nodeId] = placeholder
		elif state is ChildState.REJECTED:
			# Translators: Placeholder tree item shown when a child load was rejected by a safety limit.
			placeholder = tree.AppendItem(item, pgettext("inspector hierarchy", "Child load rejected"))
			self._treePlaceholders[row.nodeId] = placeholder

	@staticmethod
	def _hierarchyLabel(row: object) -> str:
		facet = row.node.facet
		name = facet.name if facet.hasName else "Unnamed"
		label = f"{name}, {facet.role}"
		suffix = row.node.exceptionalSuffix
		if suffix:
			label = f"{label}, {suffix}"
		return label

	def _renderActivePane(self, *, restoreStructuredCursor: bool | None = None) -> None:
		self._renderPresentationPane()

	def _presentationCategory(self) -> _PresentationCategory:
		return _PRESENTATION_CATEGORIES[self._presentationCategoryIndex]

	def _onPresentationCategorySelected(self) -> None:
		control = self._controls.get("categoryList")
		if control is None:
			return
		index = int(control.GetFirstSelected())
		if 0 <= index < len(_PRESENTATION_CATEGORIES):
			self._presentationCategoryIndex = index
			_ = self._service.selectCategory(self._presentationCategory().categories[0])
			self._renderPresentationPane()

	def _renderPresentationPane(self) -> None:
		"""Rebuild the single detail pane for the selected category.

		Core, Annotations, and Advanced are flat report lists of Property, Value, and Status; UIA is
		a compact tree whose first section is Custom properties. Each control is built
		as a direct child of the Details static box so NVDA announces the group around it.
		"""

		wx = import_module("wx")
		panel = self._detailPanel
		sizer = self._detailSizer
		if panel is None or sizer is None:
			return
		self._rememberDetailSelection()
		clear = getattr(sizer, "Clear", None)
		if callable(clear):
			_ = clear(True)
		_ = self._controls.pop("detail", None)
		self._propertyControls = []
		self._detailKind = ""
		self._detailListRows = []
		self._detailAnnotationRecords = []
		self._detailTreeNodes = []
		self._detailTreeRootItem = None
		category = self._presentationCategory()
		sameCategory = self._renderedPresentationCategory == category.message
		box, boxSizer = _staticGroup(
			wx,
			panel,
			pgettext("inspector detail group", "{category} properties").format(category=category.label),
		)
		self._detailBox = box
		if category.message == "UIA":
			control = self._buildUiaTree(wx, box, category, sameCategory=sameCategory)
			self._detailKind = "tree"
		else:
			control = self._buildDetailList(wx, box, category, sameCategory=sameCategory)
			self._detailKind = "list"
		boxSizer.Add(control, 1, wx.EXPAND | wx.ALL, 4)
		sizer.Add(boxSizer, 1, wx.EXPAND)
		self._controls["detail"] = control
		self._propertyControls = [control]
		self._bindDetailControl(wx, control, isTree=self._detailKind == "tree")
		primaryPane = self._service.selectCategory(category.categories[0])
		self._renderStatusForPane(primaryPane)
		self._renderedPresentationCategory = category.message
		layout = getattr(panel, "Layout", None)
		if callable(layout):
			_ = layout()

	def _buildDetailList(
		self,
		wx: object,
		parent: object,
		category: _PresentationCategory,
		*,
		sameCategory: bool,
	) -> object:
		control = _reportList(wx, parent, autoSizeColumn=1)
		for index, heading in enumerate(
			(
				# Translators: Column heading for a property name in the Inspector detail list.
				pgettext("inspector detail column", "Property"),
				# Translators: Column heading for a property value in the Inspector detail list.
				pgettext("inspector detail column", "Value"),
				# Translators: Column heading for a property status in the Inspector detail list.
				pgettext("inspector detail column", "Status"),
			),
		):
			control.InsertColumn(index, heading)
		rows, records, keys = self._detailListData(category)
		self._detailListRows = rows
		self._detailAnnotationRecords = records
		self._detailListKeys = keys
		for index, (name, value, status) in enumerate(rows):
			_ = control.InsertItem(index, name)
			control.SetItem(index, 1, value)
			control.SetItem(index, 2, status)
		selectedIndex = self._detailListSelectionIndex(category, sameCategory=sameCategory)
		if selectedIndex is not None:
			control.Select(selectedIndex)
			control.Focus(selectedIndex)
			self._detailSelectedKey = keys[selectedIndex]
		return control

	def _detailListData(
		self,
		category: _PresentationCategory,
	) -> tuple[
		list[tuple[str, str, str]],
		list[AnnotationRecord | None],
		list[tuple[PropertyCategory, str]],
	]:
		rows: list[tuple[str, str, str]] = []
		records: list[AnnotationRecord | None] = []
		keys: list[tuple[PropertyCategory, str]] = []
		for sourceCategory in category.categories:
			pane = self._service.selectCategory(sourceCategory)
			if sourceCategory is PropertyCategory.ANNOTATIONS:
				for record in pane.annotations:
					rows.append(
						(
							self._annotationLabel(record),
							record.summary or record.targetName or "",
							_annotationStatusWord(record.status),
						),
					)
					records.append(record)
					keys.append((sourceCategory, record.key))
				if not pane.annotations and (pane.note or pane.stale):
					rows.append((gettext("Status"), self._paneStatusMessage(pane), gettext("Unavailable")))
					records.append(None)
					keys.append((sourceCategory, "status"))
				continue
			if sourceCategory is PropertyCategory.ALL_PROPERTIES:
				for node in pane.structured:
					self._flattenStructured(node, 0, rows, records, keys, sourceCategory)
				if not pane.structured and (pane.note or pane.stale):
					rows.append((gettext("Status"), self._paneStatusMessage(pane), gettext("Unavailable")))
					records.append(None)
					keys.append((sourceCategory, "status"))
				continue
			for row in pane.rows:
				rows.append(
					(
						row.name,
						row.value if row.value is not None else _statusWord(row.status),
						_statusCell(row.status),
					),
				)
				records.append(None)
				keys.append((sourceCategory, row.fieldKey))
			if not pane.rows and (pane.note or pane.stale):
				rows.append((gettext("Status"), self._paneStatusMessage(pane), gettext("Unavailable")))
				records.append(None)
				keys.append((sourceCategory, "status"))
		return rows, records, keys

	@staticmethod
	def _annotationLabel(record: AnnotationRecord) -> str:
		if record.status is not AnnotationStatus.VALUE:
			return gettext("{type}: {status}").format(
				type=record.typeName,
				status=_annotationStatusWord(record.status),
			)
		if record.summary:
			return gettext("{type}: {summary}").format(type=record.typeName, summary=record.summary)
		if record.targetName:
			return gettext("{type}: {target}").format(type=record.typeName, target=record.targetName)
		return record.typeName

	@staticmethod
	def _paneStatusMessage(pane: object) -> str:
		return (
			cast(str, pane.note)
			if pane.note
			else gettext("Showing stale properties while refreshed values load.")
		)

	def _rememberDetailSelection(self) -> None:
		control = self._controls.get("detail")
		if control is None:
			return
		if self._detailKind == "list":
			index = int(control.GetFirstSelected())
			if 0 <= index < len(self._detailListKeys):
				self._detailSelectedKey = self._detailListKeys[index]
			return
		getSelection = getattr(control, "GetSelection", None)
		getData = getattr(control, "GetItemData", None)
		if not callable(getSelection) or not callable(getData):
			return
		index = getData(getSelection())
		if isinstance(index, int) and 0 <= index < len(self._detailTreeNodes):
			self._detailSelectedKey = cast("str", self._detailTreeNodes[index]["key"])

	def _detailListSelectionIndex(
		self,
		category: _PresentationCategory,
		*,
		sameCategory: bool,
	) -> int | None:
		if not self._detailListKeys:
			return None
		if sameCategory and isinstance(self._detailSelectedKey, tuple):
			try:
				return self._detailListKeys.index(self._detailSelectedKey)
			except ValueError:
				pass
		cursor = self._service.cursor(category.categories[0])
		if cursor.selectedFieldKey is not None:
			for index, (_sourceCategory, key) in enumerate(self._detailListKeys):
				if key == cursor.selectedFieldKey:
					return index
		return 0

	def _flattenStructured(
		self,
		node: StructuredPropertyNode,
		depth: int,
		rows: list[tuple[str, str, str]],
		records: list[AnnotationRecord | None],
		keys: list[tuple[PropertyCategory, str]],
		category: PropertyCategory,
	) -> None:
		name = ("  " * depth) + node.label
		if node.value is not None:
			value = node.value
		elif node.status is not PropertyStatus.VALUE:
			value = _statusWord(node.status)
		else:
			value = ""
		rows.append((name, value, _statusCell(node.status)))
		records.append(None)
		keys.append((category, node.key))
		for child in node.children:
			self._flattenStructured(child, depth + 1, rows, records, keys, category)

	def _buildUiaTree(
		self,
		wx: object,
		parent: object,
		category: _PresentationCategory,
		*,
		sameCategory: bool,
	) -> object:
		tree = wx.TreeCtrl(
			parent,
			style=wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT | wx.TR_DEFAULT_STYLE,
		)
		rootLabel = gettext("UIA properties")
		root = tree.AddRoot(rootLabel)
		rootIndex = self._registerDetailNode(tree, root, rootLabel, "root", None)
		self._detailTreeRootItem = root
		customRows: tuple[PropertyRow, ...] = ()
		standardRows: tuple[PropertyRow, ...] = ()
		patternRows: tuple[PropertyRow, ...] = ()
		providerRows: tuple[PropertyRow, ...] = ()
		for sourceCategory in category.categories:
			pane = self._service.selectCategory(sourceCategory)
			if sourceCategory is PropertyCategory.UIA:
				customRows = tuple(row for row in pane.rows if row.fieldKey.startswith("customUia."))
				inventoryRows = tuple(row for row in pane.rows if row.fieldKey == "propertyInventory")
				standardRows = tuple(
					row
					for row in pane.rows
					if not row.fieldKey.startswith("customUia.") and row.fieldKey != "propertyInventory"
				)
				providerRows += inventoryRows
			elif sourceCategory is PropertyCategory.SUPPORTED_UIA_PATTERNS:
				patternRows = tuple(pane.rows)
			elif sourceCategory is PropertyCategory.OTHER_API:
				providerRows += tuple(row for row in pane.rows if not row.fieldKey.startswith("customUia."))
		availableStandardRows = tuple(
			row
			for row in standardRows
			if row.status
			in (
				PropertyStatus.VALUE,
				PropertyStatus.EMPTY,
				PropertyStatus.TRUNCATED,
				PropertyStatus.REDACTED,
			)
		)
		availableCustomRows = tuple(
			row
			for row in customRows
			if row.status
			in (
				PropertyStatus.VALUE,
				PropertyStatus.EMPTY,
				PropertyStatus.TRUNCATED,
				PropertyStatus.REDACTED,
			)
		)
		unavailableCustomRows = tuple(row for row in customRows if row not in availableCustomRows)
		unavailableStandardRows = tuple(row for row in standardRows if row not in availableStandardRows)
		self._appendUiaSection(
			tree,
			root,
			rootIndex,
			gettext("Custom properties"),
			availableCustomRows,
		)
		self._appendUiaSection(
			tree,
			root,
			rootIndex,
			gettext("Unavailable or unsupported Custom UIA properties"),
			unavailableCustomRows,
		)
		self._appendUiaSection(
			tree,
			root,
			rootIndex,
			gettext("Standard UIA properties"),
			availableStandardRows,
		)
		self._appendUiaSection(
			tree,
			root,
			rootIndex,
			gettext("Unavailable or unsupported Standard UIA properties"),
			unavailableStandardRows,
		)
		self._appendUiaSection(tree, root, rootIndex, gettext("Supported patterns"), patternRows)
		self._appendUiaSection(tree, root, rootIndex, gettext("Provider discovery"), providerRows)
		tree.Expand(root)
		selectedKey = self._detailSelectedKey if sameCategory else "root"
		selectedIndex = next(
			(index for index, node in enumerate(self._detailTreeNodes) if node["key"] == selectedKey),
			0,
		)
		tree.SelectItem(self._detailTreeNodes[selectedIndex]["item"])
		self._detailSelectedKey = cast("str", self._detailTreeNodes[selectedIndex]["key"])
		return tree

	def _appendUiaSection(
		self,
		tree: object,
		root: object,
		rootIndex: int,
		label: str,
		rows: tuple[PropertyRow, ...],
	) -> None:
		section = tree.AppendItem(root, label)
		sectionIndex = self._registerDetailNode(tree, section, label, f"section:{label}", rootIndex)
		for row in rows:
			text = self._propertyRowTreeLabel(row)
			item = tree.AppendItem(section, text)
			_ = self._registerDetailNode(tree, item, text, f"{row.fieldKey}", sectionIndex)
		tree.Expand(section)

	@staticmethod
	def _propertyRowTreeLabel(row: PropertyRow) -> str:
		if row.value is not None:
			return f"{row.name}: {row.value}"
		if row.status is not PropertyStatus.VALUE:
			return f"{row.name}: {_statusWord(row.status)}"
		return row.name

	def _registerDetailNode(
		self,
		tree: object,
		item: object,
		label: str,
		key: str,
		parentIndex: int | None,
	) -> int:
		index = len(self._detailTreeNodes)
		self._detailTreeNodes.append({"label": label, "key": key, "item": item, "children": []})
		setData = getattr(tree, "SetItemData", None)
		if callable(setData):
			_ = setData(item, index)
		if parentIndex is not None:
			self._detailTreeNodes[parentIndex]["children"].append(index)
		return index

	def _onPresentationDetailKey(self, event: object) -> None:
		if self._handleWorkspaceKey(event):
			return
		event.Skip()

	def _onDetailSelected(self, event: object, *, isTree: bool) -> None:
		control = event.GetEventObject()
		if isTree:
			getItem = getattr(event, "GetItem", None)
			item = getItem() if callable(getItem) else control.GetSelection()
			index = control.GetItemData(item)
			if isinstance(index, int) and 0 <= index < len(self._detailTreeNodes):
				key = cast("str", self._detailTreeNodes[index]["key"])
				self._detailSelectedKey = key
				if key not in ("root",) and not key.startswith("section:"):
					self._service.setCursor(
						PropertyCategory.UIA,
						PaneCursor(selectedFieldKey=key, topIndex=0),
					)
			event.Skip()
			return
		index = int(event.GetIndex())
		if not 0 <= index < len(self._detailListKeys):
			event.Skip()
			return
		category, key = self._detailListKeys[index]
		self._detailSelectedKey = (category, key)
		self._service.setCursor(category, PaneCursor(selectedFieldKey=key, topIndex=0))
		record = self._detailAnnotationRecords[index]
		if record is not None:
			_ = self._service.selectAnnotation(record.key)
		event.Skip()

	def _selectedAnnotationRecord(self) -> AnnotationRecord | None:
		if self._detailKind != "list":
			return None
		control = self._controls.get("detail")
		if control is None:
			return None
		index = int(control.GetFirstSelected())
		if 0 <= index < len(self._detailAnnotationRecords):
			return self._detailAnnotationRecords[index]
		return None

	def _showAnnotationTarget(self) -> None:
		record = self._selectedAnnotationRecord()
		if record is None:
			self._feedback(gettext("No annotation target is selected."))
			return
		outcome = self._service.navigateAnnotationTarget(record.key)
		if outcome.status is AnnotationNavigationStatus.NAVIGATED:
			wx = import_module("wx")
			generation = self._activationGeneration

			def renderTarget() -> None:
				if generation != self._activationGeneration or not self._controls:
					return
				self._renderHierarchy()
				self._renderPresentationPane()
				self._focusActivePane()
				self._feedback(gettext("Annotation target shown in Inspector."))

			wx.CallAfter(renderTarget)
			return
		if outcome.status is AnnotationNavigationStatus.STALE:
			self._feedback(gettext("Annotation target is stale; navigation is unavailable."))
			return
		self._feedback(gettext("Annotation target identity is unavailable for navigation."))

	def _renderStatusForPane(self, pane: object) -> None:
		if pane.note:
			self._setStatus(pane.note)
		elif pane.stale:
			self._setStatus(self._paneStatusMessage(pane))

	def _setStatus(self, text: str) -> None:
		if self._window.activeWorkspace != "inspector":
			return
		self._window.setStatus(text)

	def _feedback(self, text: str) -> None:
		self._setStatus(text)
		self._announce(text)

	def _delayedFeedback(self, text: str) -> None:
		"""Announce an outcome after the focus change that caused it has been spoken."""

		self._setStatus(text)
		ui = import_module("ui")
		speech = import_module("speech")
		ui.delayedMessage(text, speechPriority=speech.Spri.NOW)

	def _refreshStatus(self) -> None:
		"""Reassert the Inspector's own status line when this page becomes the visible one."""
		pane = self._service.activePane()
		if pane.note or pane.stale:
			self._renderStatusForPane(pane)
			return
		self._setStatus(gettext("Inspector ready. Browse the hierarchy or choose a property category."))

	def _syncFollowFocusControl(self) -> None:
		control = self._controls.get("followFocus")
		if control is None:
			return
		available = self._service.followFocusAvailable
		control.Enable(available)
		control.SetValue(self._service.followFocusEnabled)
		if not available:
			control.SetHelpText(self._definition.followFocusOfflineHelp)

	def _syncAppModuleOverrideControl(self) -> None:
		control = self._controls.get("appModuleOverride")
		provider = self._appModuleOverrideState
		if control is None:
			return
		state = provider() if provider is not None else AppModuleOverrideState(None, False, False)
		executable = state.executable or gettext("the current application")
		control.SetLabel(f"{self._definition.appModuleOverrideLabel} for {executable}")
		control.SetValue(state.enabled)
		control.Enable(state.available)
		if not state.available:
			# Translators: Help text for an unavailable per-application UIA override.
			control.SetHelpText(
				gettext("An app-module override is available only for a live inspected application."),
			)

	def _confirmAppModuleOverride(self) -> bool:
		wx = import_module("wx")
		provider = self._appModuleOverrideState
		state = provider() if provider is not None else AppModuleOverrideState(None, False, False)
		executable = state.executable or gettext("the current application")
		dialog = wx.MessageDialog(
			self._frame,
			gettext(
				(
					"NVDA's app-specific support for {application} will be disabled and UIA requested. "
					"Keystone will reload app modules immediately and close the Inspector. Continue?"
				),
			).format(application=executable),
			pgettext("inspector window", "Force UIA for application"),
			wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
		)
		try:
			return dialog.ShowModal() == wx.ID_YES
		finally:
			dialog.Destroy()

	def _toggleAppModuleOverride(self, enabled: bool) -> None:
		change = self._setAppModuleOverride
		if change is None:
			self._syncAppModuleOverrideControl()
			return
		if enabled and not self._confirmAppModuleOverride():
			self._syncAppModuleOverrideControl()
			return
		outcome = change(enabled)
		if not outcome.succeeded:
			self._syncAppModuleOverrideControl()
			self._feedback(gettext("NVDA's app module could not be updated."))
			return
		executable = outcome.executable or gettext("the current application")
		state = gettext("enabled") if outcome.enabled else gettext("disabled")
		self._feedback(
			gettext(
				"Force UIA {state} for {application}. "
				+ "App modules reloaded; reopen Inspector to check the available accessibility backend.",
			).format(state=state, application=executable),
		)
		wx = import_module("wx")
		wx.CallAfter(self.close)

	# -- keyboard model ----------------------------------------------------

	def handleKey(self, event: object) -> None:
		"""Route the workspace keyboard contract into the service, then focus the result."""

		if not self._handleWorkspaceKey(event):
			event.Skip()

	def _handleWorkspaceKey(self, event: object) -> bool:
		wx = import_module("wx")
		keyCode = int(event.GetKeyCode())
		control = bool(event.ControlDown())
		alt = bool(event.AltDown())
		shift = bool(event.ShiftDown())
		if alt and not control and not shift:
			if _matchesAccessKey(self._definition.retargetFocusLabel, keyCode):
				self._doRetarget("focus")
				return True
			if _matchesAccessKey(self._definition.retargetNavigatorLabel, keyCode):
				self._doRetarget("navigator")
				return True
			if _matchesAccessKey(self._definition.followFocusLabel, keyCode) and _isControlEnabled(
				self._controls.get("followFocus"),
			):
				followFocus = self._controls["followFocus"]
				enabled = not bool(followFocus.GetValue())
				followFocus.SetValue(enabled)
				self._toggleFollowFocus(enabled)
				return True
			if _matchesAccessKey(self._definition.rawUiaLabel, keyCode):
				if (enabled := _toggleControl(self._controls.get("rawUia"))) is not None:
					state = gettext("enabled") if enabled else gettext("disabled")
					self._setStatus(
						gettext("Use Raw UIA {state} for the next retarget.").format(state=state),
					)
					return True
			if _matchesAccessKey(self._definition.appModuleOverrideLabel, keyCode):
				if (enabled := _toggleControl(self._controls.get("appModuleOverride"))) is not None:
					self._toggleAppModuleOverride(enabled)
					return True
			if (
				_matchesAccessKey(self._definition.customUiaLabel, keyCode)
				and _isControlEnabled(self._controls.get("customUia"))
				and self._openCustomUia is not None
			):
				self._openCustomUia(self._window.frame)
				return True
		if keyCode == wx.WXK_F3 and not control and not alt:
			self._repeatFind(forward=not shift)
			return True
		if control and not alt and not shift and keyCode in (ord("f"), ord("F")):
			self._openSearch()
			return True
		if (
			control
			and not alt
			and not shift
			and keyCode in (ord("o"), ord("O"))
			and _isControlEnabled(self._controls.get("openSnapshot"))
			and self._openSnapshot is not None
		):
			self._openSnapshotFromDialog()
			return True
		if (
			alt
			and not control
			and keyCode in (ord("t"), ord("T"))
			and self._presentationCategory().message == "Annotations"
			and self._lastFocusKey == "properties"
		):
			self._showAnnotationTarget()
			return True
		if control and not alt and not shift and keyCode in (ord("c"), ord("C")):
			if self._lastFocusKey == "hierarchy":
				_ = self._copyPresentationContext("hierarchy")
				return True
			if self._lastFocusKey == "properties":
				_ = self._copyPresentationContext("details")
				return True
			if self._lastFocusKey == "categoryList":
				_ = self._copyPresentationContext("category")
				return True
			return False
		return False

	def _focusActivePane(self) -> None:
		control = self._controls.get("detail")
		if control is not None:
			self._lastFocusKey = "properties"
			control.SetFocus()

	def _focusControl(self, key: str) -> None:
		control = self._controls.get(key)
		if control is not None:
			self._lastFocusKey = key
			control.SetFocus()

	# -- hierarchy interaction ---------------------------------------------

	def _onTreeSelection(self) -> None:
		nodeId = self._selectedTreeNode()
		if nodeId is None or nodeId == self._service.selectedNodeId:
			return
		self._cancelQuickTimers()
		self._service.selectNode(nodeId)
		self._renderActivePane(restoreStructuredCursor=False)
		self._setStatus(
			gettext("Selected hierarchy item: {item}.").format(item=self._facetName(nodeId)),
		)

	def _onTreeExpanding(self, event: object) -> None:
		if self._renderingHierarchy:
			return
		nodeId = self._nodeForItem(event)
		if nodeId is None:
			return
		self._expandTreeNode(nodeId)

	def _onTreeKey(self, event: object) -> None:
		wx = import_module("wx")
		if self._handleWorkspaceKey(event):
			return
		nodeId = self._selectedTreeNode()
		if nodeId is None:
			event.Skip()
			return
		keyCode = int(event.GetKeyCode())
		if keyCode == wx.WXK_RIGHT:
			if self._treeNodeCanExpand(nodeId):
				self._expandTreeNode(nodeId)
				return
		elif keyCode == wx.WXK_LEFT and self._treeNodeIsExpanded(nodeId):
			self._service.collapse(nodeId)
			tree = self._controls.get("hierarchy")
			item = self._treeItems.get(nodeId)
			if tree is not None and item is not None:
				tree.Collapse(item)
			return
		event.Skip()

	def _expandTreeNode(self, nodeId: str) -> None:
		facet = self._facetName(nodeId)
		state = self._service.expand(nodeId)
		self._renderTreeBranch(nodeId)
		if state is ChildState.LOADING:
			# Translators: Inspector status while child objects are being loaded for a facet.
			self._setStatus(gettext("Loading children for {facet}.").format(facet=facet))
		elif state is ChildState.EMPTY:
			# Translators: Inspector status shown when an object has no child objects.
			self._setStatus(gettext("No children."))
		elif state is ChildState.FAILED:
			# Translators: Inspector message when child objects could not be loaded for a facet.
			self._feedback(
				gettext(
					"Children could not be loaded for {facet}. Move to another object and try again.",
				).format(facet=facet),
			)

	def _renderTreeBranch(self, nodeId: str) -> None:
		tree = self._controls.get("hierarchy")
		parentItem = self._treeItems.get(nodeId)
		if tree is None or parentItem is None:
			return
		self._renderingHierarchy = True
		try:
			self._removeTreePlaceholder(nodeId)
			for row in self._service.hierarchy():
				if row.node.facet.parentId == nodeId and row.nodeId not in self._treeItems:
					_ = self._appendTreeRow(tree, parentItem, row)
					if row.expanded:
						_ = tree.Expand(self._treeItems[row.nodeId])
			row = next((row for row in self._service.hierarchy() if row.nodeId == nodeId), None)
			if row is not None and row.node.childState is ChildState.EMPTY:
				tree.SetItemHasChildren(parentItem, False)
			if row is not None and not self._treeChildItems(nodeId):
				self._renderChildPlaceholder(tree, parentItem, row)
			if row is not None and row.expanded:
				tree.Expand(parentItem)
		finally:
			self._renderingHierarchy = False

	def _treeNodeCanExpand(self, nodeId: str) -> bool:
		for row in self._service.hierarchy():
			if row.nodeId == nodeId:
				return row.node.hasExpander and not row.expanded
		return False

	def _treeNodeIsExpanded(self, nodeId: str) -> bool:
		for row in self._service.hierarchy():
			if row.nodeId == nodeId:
				return row.expanded
		return False

	def _selectedTreeNode(self) -> str | None:
		tree = self._controls.get("hierarchy")
		if tree is None:
			return None
		selection = tree.GetSelection()
		for nodeId, item in self._treeItems.items():
			if item == selection:
				return nodeId
		return None

	def _nodeForItem(self, event: object) -> str | None:
		getItem = getattr(event, "GetItem", None)
		item = getItem() if callable(getItem) else None
		if item is not None:
			for nodeId, mapped in self._treeItems.items():
				if mapped == item:
					return nodeId
		return self._selectedTreeNode()

	def _facetName(self, nodeId: str) -> str:
		for row in self._service.hierarchy():
			if row.nodeId == nodeId:
				facet = row.node.facet
				return facet.name if facet.hasName else f"Unnamed {facet.role}"
		return "the selected object"

	# -- loaded-only search ------------------------------------------------

	def _openSearch(self) -> None:
		"""Open the platform Find dialog; it is not part of the Inspector traversal."""
		wx = import_module("wx")
		frame = self._window.frame
		if frame is None:
			return
		dialog = getattr(self, "_findDialog", None)
		if dialog is not None:
			dialog.Raise()
			return
		data = getattr(self, "_findData", None)
		if data is None:
			data = wx.FindReplaceData()
			self._findData = data
		data.SetFindString(self._findText)
		dialog = wx.FindReplaceDialog(frame, data, gettext("Find loaded hierarchy"), wx.FR_NOWHOLEWORD)
		self._findDialog = dialog

		def onFind(event: object) -> None:
			getFindString = getattr(event, "GetFindString", None)
			if callable(getFindString):
				self._findText = str(getFindString())
			flags = int(getattr(event, "GetFlags", lambda: wx.FR_DOWN)())
			self._runSearch(forward=bool(flags & wx.FR_DOWN))

		def onClose(_event: object) -> None:
			self._findDialog = None
			dialog.Destroy()

		dialog.Bind(wx.EVT_FIND, onFind)
		dialog.Bind(wx.EVT_FIND_NEXT, onFind)
		dialog.Bind(wx.EVT_FIND_CLOSE, onClose)
		dialog.Show()

	def _repeatFind(self, *, forward: bool) -> None:
		if not self._findText:
			self._feedback(gettext("Open Find with Control+F before repeating a search."))
			return
		self._runSearch(forward=forward)

	def _runSearch(self, *, forward: bool) -> None:
		outcome = self._service.search(self._findText, forward=forward)
		if outcome.decision == "empty":
			# Translators: Inspector message when the search field is empty.
			self._feedback(gettext("Enter text to search loaded nodes."))
			return
		if outcome.decision == "noMatch":
			# Translators: Inspector message when a search finds no match among loaded nodes.
			self._feedback(
				gettext(
					'No loaded node matches "{query}". Unexpanded branches were not searched.',
				).format(query=outcome.query),
			)
			return
		if outcome.wrapped == "start":
			# Translators: Inspector message when a backward search wraps to the beginning.
			self._feedback(gettext("Search wrapped to the beginning."))
		elif outcome.wrapped == "end":
			# Translators: Inspector message when a forward search wraps to the end.
			self._feedback(gettext("Search wrapped to the end."))
		self._renderHierarchy()
		self._focusControl("hierarchy")

	# -- semantic copy -----------------------------------------------------

	def _copyPresentationContext(self, context: str) -> bool:
		"""Copy the semantic unit under the given region: a whole category, one detail, or a subtree."""

		payload = self._presentationContextText(context)
		if not payload or self._copyToClipboard is None:
			return bool(payload)
		if self._copyToClipboard(payload):
			self._feedback(gettext("Copied to the clipboard."))
		else:
			self._feedback(gettext("Could not copy to the clipboard. Try again."))
		return True

	def _presentationContextText(self, context: str) -> str:
		if context == "category":
			return self._detailCategoryCopyText()
		if context == "details":
			return self._detailSelectionCopyText()
		if context == "hierarchy":
			return self._hierarchyCopyText()
		return ""

	def _exportPresentationContext(self, context: str) -> None:
		payload = self._presentationContextText(context)
		if not payload:
			self._feedback(gettext("Nothing is available to export."))
			return
		wx = import_module("wx")
		identity = self._service.sourceIdentity()
		dialog = wx.FileDialog(
			self._frame,
			message=gettext("Export Inspector data"),
			wildcard=gettext("Text files (*.txt)|*.txt"),
			defaultFile=defaultExportFilename(
				None if identity is None else identity.executable,
				context,
				".txt",
			),
			style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
		)
		try:
			if dialog.ShowModal() != wx.ID_OK:
				self._feedback(gettext("Export cancelled."))
				return
			destination = Path(dialog.GetPath())
		finally:
			dialog.Destroy()
		try:
			with destination.open("w", encoding="utf-8", newline="\n") as stream:
				_ = stream.write(payload)
		except OSError:
			self._feedback(gettext("Could not export Inspector data."))
			return
		self._delayedFeedback(gettext("Inspector data exported."))

	def _copyCurrentNodeJson(self) -> None:
		"""Copy only already-loaded Inspector properties; this never triggers a source read."""

		payload = self._service.copy(InspectorCopyKind.NODE_JSON)
		if not payload:
			self._feedback(gettext("No current Inspector data is available to copy."))
			return
		if self._copyToClipboard is None or not self._copyToClipboard(payload):
			self._feedback(gettext("Could not copy to the clipboard. Try again."))
			return
		self._feedback(gettext("Already loaded, privacy-safe Inspector node data copied as JSON."))

	def _exportCurrentNodeJson(self) -> None:
		payload = self._service.copy(InspectorCopyKind.NODE_JSON)
		if not payload:
			self._feedback(gettext("No current Inspector data is available to export."))
			return
		wx = import_module("wx")
		identity = self._service.sourceIdentity()
		dialog = wx.FileDialog(
			self._frame,
			message=gettext("Export node as JSON"),
			wildcard=gettext("JSON files (*.json)|*.json"),
			defaultFile=defaultExportFilename(
				None if identity is None else identity.executable,
				"current-inspector-data",
				".json",
				subject=(
					self._facetName(nodeId) if (nodeId := self._selectedTreeNode()) is not None else None
				),
			),
			style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
		)
		try:
			if dialog.ShowModal() != wx.ID_OK:
				self._feedback(gettext("JSON export cancelled."))
				return
			destination = Path(dialog.GetPath())
		finally:
			dialog.Destroy()
		try:
			with destination.open("w", encoding="utf-8", newline="\n") as stream:
				_ = stream.write(payload)
		except OSError:
			self._feedback(gettext("Could not export Inspector node data as JSON."))
			return
		self._delayedFeedback(gettext("Already loaded, privacy-safe Inspector node data exported as JSON."))

	def _copySubtreeSnapshot(self) -> None:
		nodeId = self._selectedTreeNode()
		callback = self._copySubtreeSnapshotCallback
		if nodeId is None or callback is None:
			self._feedback(gettext("No hierarchy item is selected for a subtree snapshot."))
			return
		try:
			payload = callback(nodeId)
		except RuntimeError as error:
			if "CANCELLED" in str(error):
				self._feedback(gettext("Subtree snapshot capture cancelled."))
				return
			self._feedback(gettext("Could not create the subtree snapshot."))
			return
		except (LookupError, OSError, ValueError):
			self._feedback(gettext("Could not create the subtree snapshot."))
			return
		if len(payload) > 5 * 1024 * 1024:
			self._feedback(
				gettext(
					"Subtree snapshot JSON is larger than 5 MiB and was not copied. Export the snapshot instead.",
				),
			)
			return
		try:
			text = payload.decode("utf-8", errors="strict")
		except UnicodeDecodeError:
			self._feedback(gettext("Could not create the subtree snapshot."))
			return
		if self._copyToClipboard is None or not self._copyToClipboard(text):
			self._feedback(gettext("Could not copy to the clipboard. Try again."))
			return
		identity = self._service.sourceIdentity()
		label = (
			gettext("Recorded subtree snapshot copied as JSON.")
			if identity is not None and identity.kind.value == "offline"
			else gettext("Fresh captured subtree snapshot copied as JSON.")
		)
		self._feedback(label)

	def _exportSubtreeSnapshot(self) -> None:
		nodeId = self._selectedTreeNode()
		callback = self._exportSubtreeSnapshotCallback
		if nodeId is None or callback is None:
			self._feedback(gettext("No hierarchy item is selected for a subtree snapshot."))
			return
		wx = import_module("wx")
		dialog = wx.DirDialog(
			self._frame,
			message=gettext("Choose a folder for the portable subtree snapshot"),
			style=wx.DD_DEFAULT_STYLE,
		)
		try:
			if dialog.ShowModal() != wx.ID_OK:
				self._feedback(gettext("Subtree snapshot export cancelled."))
				return
			parent = Path(dialog.GetPath())
		finally:
			dialog.Destroy()
		try:
			callback(nodeId, parent)
		except RuntimeError as error:
			if "CANCELLED" in str(error):
				self._feedback(gettext("Subtree snapshot capture cancelled."))
				return
			self._feedback(gettext("Could not export the portable subtree snapshot."))
			return
		except (LookupError, OSError, ValueError):
			self._feedback(gettext("Could not export the portable subtree snapshot."))
			return
		identity = self._service.sourceIdentity()
		label = (
			gettext("Recorded subtree snapshot exported as a portable snapshot directory.")
			if identity is not None and identity.kind.value == "offline"
			else gettext("Fresh captured subtree snapshot exported as a portable snapshot directory.")
		)
		self._delayedFeedback(label)

	def _detailCategoryCopyText(self) -> str:
		label = self._presentationCategory().label
		if self._detailKind == "tree":
			control = self._controls.get("detail")
			if control is not None and self._detailTreeRootItem is not None:
				return self._detailTreeCopyText(control, self._detailTreeRootItem)
			return label
		body = [
			f"  {name}: {value} ({status})" if status else f"  {name}: {value}"
			for name, value, status in self._detailListRows
		]
		return "\n".join([label, *body])

	def _detailSelectionCopyText(self) -> str:
		control = self._controls.get("detail")
		if control is None:
			return ""
		if self._detailKind == "tree":
			getSelection = getattr(control, "GetSelection", None)
			if not callable(getSelection):
				return ""
			return self._detailTreeCopyText(control, getSelection())
		index = int(control.GetFirstSelected())
		if index < 0:
			return ""
		values = [control.GetItemText(index)]
		for column in range(1, int(control.GetColumnCount())):
			values.append(control.GetItem(index, column).GetText())
		return "\t".join(value for value in values if value)

	def _detailTreeCopyText(self, tree: object, item: object) -> str:
		getData = getattr(tree, "GetItemData", None)
		if item is None or not callable(getData):
			return ""
		index = getData(item)
		if not isinstance(index, int) or not 0 <= index < len(self._detailTreeNodes):
			return ""
		lines: list[str] = []

		def walk(nodeIndex: int, depth: int) -> None:
			node = self._detailTreeNodes[nodeIndex]
			lines.append(f"{'  ' * depth}{node['label']}")
			for child in cast("list[int]", node["children"]):
				walk(child, depth + 1)

		walk(index, 0)
		return "\n".join(lines)

	def _hierarchyCopyText(self) -> str:
		rows = self._service.hierarchy()
		selected = next((row.nodeId for row in rows if row.selected), None)
		if selected is None:
			return ""
		identity = self._service.sourceIdentity()
		if identity is not None and identity.kind.value == "offline":
			lines: list[str] = []
			for row in self._service.hierarchySubtree(selected):
				indent = "  " * row.depth
				lines.extend(
					f"{indent}{line}" if line else ""
					for line in self._service.completeNodeText(row.nodeId).splitlines()
				)
				lines.append("")
			return "\n".join(lines).rstrip()
		byId = {row.nodeId: row for row in rows}
		childrenById: dict[str, list[str]] = {}
		for row in rows:
			parentId = row.node.facet.parentId
			if parentId is not None:
				childrenById.setdefault(parentId, []).append(row.nodeId)
		lines: list[str] = []

		def walk(nodeId: str, depth: int) -> None:
			row = byId.get(nodeId)
			if row is None:
				return
			lines.append(f"{'  ' * depth}{self._hierarchyLabel(row)}")
			for child in childrenById.get(nodeId, ()):
				walk(child, depth + 1)

		walk(selected, 0)
		return "\n".join(lines)

	def _showInspectorContextMenu(self, event: object, context: str) -> None:
		wx = import_module("wx")
		control = self._controls.get(
			"hierarchy" if context == "hierarchy" else "categoryList" if context == "category" else "detail",
		)
		if control is None:
			return
		if context == "hierarchy":
			getPosition = getattr(event, "GetPosition", None)
			screenToClient = getattr(control, "ScreenToClient", None)
			hitTest = getattr(control, "HitTest", None)
			if callable(getPosition) and callable(screenToClient) and callable(hitTest):
				position = getPosition()
				if position != (-1, -1):
					item, _flags = cast("tuple[object, object]", hitTest(screenToClient(position)))
					isOk = getattr(item, "IsOk", None)
					if (
						item is not None
						and (not callable(isOk) or bool(isOk()))
						and any(mapped == item for mapped in self._treeItems.values())
					):
						control.SelectItem(item)
		menu = wx.Menu()

		def onCopy(_event: object) -> None:
			_ = self._copyPresentationContext(context)

		def onExport(_event: object) -> None:
			self._exportPresentationContext(context)

		if context == "hierarchy":
			copyMenu = wx.Menu()
			exportMenu = wx.Menu()
			copyText = copyMenu.Append(wx.ID_COPY, gettext("Copy as &text"))
			exportText = exportMenu.Append(wx.ID_ANY, gettext("Export as &text..."))
			currentJson = copyMenu.Append(wx.ID_ANY, gettext("Copy node as &JSON"))
			exportCurrentJson = exportMenu.Append(
				wx.ID_ANY,
				gettext("Export node as &JSON..."),
			)
			subtreeIdentity = self._service.sourceIdentity()
			if subtreeIdentity is not None:
				subtreeLabel = (
					gettext("Copy &recorded subtree snapshot as JSON")
					if subtreeIdentity.kind.value == "offline"
					else gettext("Copy &fresh captured subtree snapshot as JSON")
				)
				exportSubtreeLabel = (
					gettext("Export &recorded subtree as portable snapshot directory...")
					if subtreeIdentity.kind.value == "offline"
					else gettext("Capture and e&xport fresh subtree as portable snapshot directory...")
				)
				subtree = copyMenu.Append(wx.ID_ANY, subtreeLabel)
				exportSubtree = exportMenu.Append(wx.ID_ANY, exportSubtreeLabel)
				_bindMenuItem(copyMenu, wx, subtree, lambda _event: self._copySubtreeSnapshot())
				_bindMenuItem(
					exportMenu,
					wx,
					exportSubtree,
					lambda _event: self._exportSubtreeSnapshot(),
				)
			_bindMenuItem(copyMenu, wx, copyText, onCopy)
			_bindMenuItem(exportMenu, wx, exportText, onExport)
			_bindMenuItem(copyMenu, wx, currentJson, lambda _event: self._copyCurrentNodeJson())
			_bindMenuItem(exportMenu, wx, exportCurrentJson, lambda _event: self._exportCurrentNodeJson())
			menu.AppendSubMenu(copyMenu, gettext("&Copy"))
			menu.AppendSubMenu(exportMenu, gettext("&Export"))
			menu.AppendSeparator()
			inspect = menu.Append(wx.ID_ANY, gettext("Inspect this element"))
			monitor = menu.Append(wx.ID_ANY, gettext("Monitor this element"))

			def onInspect(_event: object) -> None:
				nodeId = self._selectedTreeNode()
				if nodeId is None:
					self._feedback(gettext("No hierarchy item is selected to inspect."))
					return
				self._service.selectNode(nodeId)
				self._renderActivePane(restoreStructuredCursor=False)
				self._focusControl("hierarchy")
				self._feedback(
					gettext("Selected hierarchy item: {item}.").format(item=self._facetName(nodeId)),
				)

			def onMonitor(_event: object) -> None:
				wx.CallAfter(self._monitorSelectedHierarchy)

			_bindMenuItem(menu, wx, inspect, onInspect)
			_bindMenuItem(menu, wx, monitor, onMonitor)
		else:
			item = menu.Append(wx.ID_COPY, gettext("Copy"))
			export = menu.Append(wx.ID_ANY, gettext("Export as text..."))
			_bindMenuItem(menu, wx, item, onCopy)
			_bindMenuItem(menu, wx, export, onExport)
		record = self._selectedAnnotationRecord() if context == "details" else None
		if record is not None and self._service.canNavigateAnnotationTarget(record):
			target = menu.Append(wx.ID_ANY, gettext("Show annotation target in Inspector"))

			def onShowTarget(_event: object) -> None:
				self._showAnnotationTarget()

			_bindMenuItem(menu, wx, target, onShowTarget)
		control.PopupMenu(menu)
		menu.Destroy()

	def _monitorSelectedHierarchy(self) -> None:
		nodeId = self._selectedTreeNode()
		if nodeId is None:
			self._feedback(gettext("No hierarchy item is selected to monitor."))
			return
		self._service.selectNode(nodeId)
		message = gettext("Event Monitor opened for configuration. Choose a scope and start monitoring.")
		if self._openEventMonitor is not None:
			self._openEventMonitor()
			self._announce(message)
			return
		self._window.activate("events")
		self._announce(message)

	# -- retarget and Follow Focus -----------------------------------------

	def _doRetarget(self, targetKind: InspectorTargetKind) -> None:
		if self._retarget is None:
			return
		self._cancelQuickTimers()
		raw = bool(self._controls["rawUia"].GetValue()) if "rawUia" in self._controls else False
		outcome = self._retarget(targetKind, raw)
		if outcome is not None and not outcome.succeeded:
			# Translators: Inspector message when an explicit retarget could not read the selected object.
			self._feedback(gettext("Inspector could not retarget to the selected object."))
			return
		self._renderAll()
		target = self._selectedTargetDescription()
		if targetKind == "focus":
			# Translators: Inspector message after retargeting to focus. {target} names the selected object.
			message = gettext("Inspector retargeted to focus: {target}.").format(target=target)
		else:
			# Translators: Inspector message after retargeting to the navigator object. {target} names it.
			message = gettext("Inspector retargeted to navigator object: {target}.").format(target=target)
		if outcome is not None and outcome.rawRequested:
			if outcome.rawApplied:
				# Translators: Suffix confirming that explicit raw UIA was applied to an Inspector retarget.
				message += " " + gettext("Raw UIA applied.")
			else:
				message += " " + _rawUiaFallbackMessage(outcome.rawReason)
		self._feedback(message)
		refreshGeneration = self._service.sourceGeneration
		self._emitInspectorSound(
			CueEventId.REFRESH_INSPECTOR,
			generation=refreshGeneration,
			coalescingKey=str(refreshGeneration),
		)

	def _selectedTargetDescription(self) -> str:
		for row in self._service.hierarchy():
			if not row.selected:
				continue
			facet = row.node.facet
			name = facet.name if facet.hasName else pgettext("inspector hierarchy", "Unnamed")
			return gettext("{name}, {role}").format(name=name, role=facet.role)
		identity = self._service.sourceIdentity()
		return identity.label if identity is not None else gettext("selected object")

	def _toggleFollowFocus(self, enabled: bool) -> None:
		applied = self._service.setFollowFocus(enabled)
		control = self._controls.get("followFocus")
		if control is not None:
			control.SetValue(applied)
		state = gettext("enabled") if applied else gettext("disabled")
		self._setStatus(gettext("Follow Focus {state}.").format(state=state))

	def considerFollowFocus(self, event: FollowFocusEvent) -> FollowFocusOutcome:
		"""Offer one external focus change to the service; re-root and announce only on retarget."""

		previousIdentity = self._service.sourceIdentity()
		previousApplicationKey = (
			f"{previousIdentity.executable}\x1f{previousIdentity.processId}"
			if previousIdentity is not None
			else None
		)
		outcome = self._service.considerFollowFocus(event)
		if outcome is FollowFocusOutcome.RETARGET:
			self._cancelQuickTimers()
			if self._followRetarget is not None:
				applied = self._followRetarget(event)
				if applied is False:
					# Translators: Inspector message when Follow Focus could not read the new object.
					self._feedback(gettext("Inspector could not follow the new focus object."))
					return outcome
			self._renderAll()
			identity = self._service.sourceIdentity()
			application = identity.executable if identity is not None else event.applicationKey
			if event.applicationKey != previousApplicationKey:
				# Translators: Inspector message when Follow Focus moves the Inspector to a new application.
				message = gettext("Inspector now follows {application}.").format(application=application)
				self._setStatus(message)
				self._announceFollowFocus(message)
			refreshGeneration = self._service.sourceGeneration
			self._emitInspectorSound(
				CueEventId.REFRESH_INSPECTOR,
				generation=refreshGeneration,
				coalescingKey=str(refreshGeneration),
			)
		return outcome

	# -- quick properties --------------------------------------------------

	def quickProperty(self, gestureIdentifier: object, *, nowMilliseconds: int | None = None) -> None:
		"""Handle one layout-tolerant quick-property gesture on the owner thread."""

		now = self._clock() if nowMilliseconds is None else nowMilliseconds
		outcome = self._service.quickProperty(gestureIdentifier, nowMilliseconds=now)
		if outcome is None:
			return
		self._scheduleQuickExpiry(outcome.digit, outcome.deadlineMilliseconds, now)
		if outcome.action is QuickPropertyAction.RESET or outcome.row is None:
			return
		row = outcome.row
		value = row.value if row.value is not None else _statusWord(row.status)
		if outcome.action is QuickPropertyAction.ANNOUNCE:
			self._announce(f"{row.name}: {value}")
		elif outcome.action is QuickPropertyAction.BROWSE:
			self._announce(f"{row.name}. {value}")
			self._emitInspectorSound(
				CueEventId.QUICK_PROPERTY_BROWSABLE,
				generation=self._service.sourceGeneration,
			)
		elif outcome.action is QuickPropertyAction.COPY:
			if self._copyToClipboard is not None and self._copyToClipboard(value):
				# Translators: Inspector message confirming a quick property was copied to the clipboard.
				self._announce(gettext("Copied to the clipboard."))
				self._emitInspectorSound(
					CueEventId.QUICK_PROPERTY_COPY,
					generation=self._service.sourceGeneration,
				)
			else:
				# Translators: Inspector message when copying a quick property to the clipboard failed.
				self._announce(gettext("Could not copy to the clipboard. Try again."))

	def _scheduleQuickExpiry(self, digit: int, deadlineMilliseconds: int, now: int) -> None:
		frame = self._frame
		if frame is None:
			return
		wx = import_module("wx")
		existing = self._quickTimers.pop(digit, None)
		if existing is not None:
			stop = getattr(existing, "Stop", None)
			if callable(stop):
				_ = stop()
		delay = max(0, deadlineMilliseconds - now)
		generation = self._activationGeneration

		def expire() -> None:
			if self._frame is not frame or self._activationGeneration != generation:
				return
			_ = self._quickTimers.pop(digit, None)
			self._service.cancelQuickProperties()

		self._quickTimers[digit] = wx.CallLater(delay, expire)

	def _cancelQuickTimers(self) -> None:
		for timer in self._quickTimers.values():
			stop = getattr(timer, "Stop", None)
			if callable(stop):
				_ = stop()
		self._quickTimers = {}
		self._service.cancelQuickProperties()


def _eventColumnHeadings() -> tuple[str, ...]:
	return (
		# Translators: Column heading for the accessibility event type.
		pgettext("events column", "Event"),
		# Translators: Column heading for the object that raised the event.
		pgettext("events column", "Source"),
		# Translators: Column heading for the value an accessibility event changed.
		pgettext("events column", "Changed value"),
		# Translators: Column heading for the time an accessibility event was observed.
		pgettext("events column", "Time"),
	)


class EventFilterDialog:
	"""Native modal event filter with two accessible checkbox-enabled report lists."""

	def __init__(
		self,
		parent: object,
		service: EventMonitorService,
		*,
		rawEnabled: bool,
		announce: Callable[[str], None],
	) -> None:
		super().__init__()
		wx = import_module("wx")
		self._wx = wx
		self._service = service
		self._rawEnabled = rawEnabled
		self._announce = announce
		self._dialog = wx.Dialog(parent, title=pgettext("events window", "Event Filter"))
		root = wx.BoxSizer(wx.VERTICAL)
		introduction = wx.StaticText(
			self._dialog,
			label=gettext(
				(
					"Choose which accessibility event types to capture. "
					"Changes apply to future events and retain existing rows."
				),
			),
		)
		root.Add(introduction, 0, wx.EXPAND | wx.ALL, 8)

		active = service.activeFilter
		self._nvdaTypes = tuple(NvdaEventType)
		self._rawFamilies = tuple(RawUiaFamily)
		nvdaBox, nvdaSizer = _staticGroup(
			wx,
			self._dialog,
			pgettext("events filter group", "NVDA event types"),
		)
		self._nvdaList = self._createCheckboxList(
			nvdaBox,
			pgettext("events filter group", "NVDA event types"),
			tuple(_nvdaEventTypeLabel(item) for item in self._nvdaTypes),
			frozenset(index for index, item in enumerate(self._nvdaTypes) if item in active.nvdaTypes),
		)
		nvdaSizer.Add(self._nvdaList, 1, wx.EXPAND | wx.ALL, 4)
		rawBox, rawSizer = _staticGroup(
			wx,
			self._dialog,
			pgettext("events filter group", "Raw UIA event types"),
		)
		self._rawList = self._createCheckboxList(
			rawBox,
			pgettext("events filter group", "Raw UIA event types"),
			tuple(_rawUiaFamilyLabel(item) for item in self._rawFamilies),
			frozenset(index for index, item in enumerate(self._rawFamilies) if item in active.rawFamilies),
		)
		rawSizer.Add(self._rawList, 1, wx.EXPAND | wx.ALL, 4)
		root.Add(nvdaSizer, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)
		root.Add(rawSizer, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)

		self._summary = wx.StaticText(self._dialog, label="")
		self._summaryWrapWidth = _fromDip(self._dialog, 520)
		self._summary.Wrap(self._summaryWrapWidth)
		root.Add(self._summary, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)

		bulk = wx.BoxSizer(wx.HORIZONTAL)
		defaults = wx.Button(self._dialog, label=pgettext("events filter action", "&Defaults"))
		selectAll = wx.Button(self._dialog, label=pgettext("events filter action", "Select &All"))
		clear = wx.Button(self._dialog, label=pgettext("events filter action", "&Clear"))
		for control in (defaults, selectAll, clear):
			bulk.Add(control, 0, wx.RIGHT, 8)
		root.Add(bulk, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)

		actions = wx.StdDialogButtonSizer()
		apply = wx.Button(
			self._dialog,
			id=wx.ID_OK,
			label=pgettext("events filter action", "&Apply Event Filter"),
		)
		keep = wx.Button(
			self._dialog,
			id=wx.ID_CANCEL,
			label=pgettext("events filter action", "&Keep Current Filter"),
		)
		actions.AddButton(apply)
		actions.AddButton(keep)
		actions.Realize()
		root.Add(actions, 0, wx.EXPAND | wx.ALL, 8)
		self._dialog.SetSizerAndFit(root)
		self._dialog.SetMinSize((_fromDip(self._dialog, 560), _fromDip(self._dialog, 500)))

		def onDefaults(_event: object) -> None:
			self.defaults()

		def onSelectAll(_event: object) -> None:
			self.selectAll()

		def onClear(_event: object) -> None:
			self.clear()

		def onApply(_event: object) -> None:
			_ = self.apply()

		def onKeep(_event: object) -> None:
			self._dialog.EndModal(wx.ID_CANCEL)

		defaults.Bind(wx.EVT_BUTTON, onDefaults)
		selectAll.Bind(wx.EVT_BUTTON, onSelectAll)
		clear.Bind(wx.EVT_BUTTON, onClear)
		apply.Bind(wx.EVT_BUTTON, onApply)
		keep.Bind(wx.EVT_BUTTON, onKeep)
		for control in (self._nvdaList, self._rawList):
			control.Bind(wx.EVT_LIST_ITEM_CHECKED, self._onChecked)
			control.Bind(wx.EVT_LIST_ITEM_UNCHECKED, self._onChecked)
		self.updateRawEnabled()
		self._updateSummary()
		if int(self._nvdaList.GetItemCount()) > 0:
			self._nvdaList.Select(0)
			self._nvdaList.Focus(0)

	def _createCheckboxList(
		self,
		parent: object,
		name: str,
		labels: tuple[str, ...],
		checked: frozenset[int],
	) -> object:
		wx = self._wx
		control = _reportList(wx, parent, autoSizeColumn=0)
		if hasattr(control, "EnableCheckBoxes"):
			control.EnableCheckBoxes()
		control.InsertColumn(0, name)
		for index, label in enumerate(labels):
			control.InsertItem(index, label)
			if hasattr(control, "CheckItem"):
				control.CheckItem(index, index in checked)
		return control

	def showModal(self) -> int:
		return int(self._dialog.ShowModal())

	def destroy(self) -> None:
		self._dialog.Destroy()

	def defaults(self) -> None:
		self._setAll(self._nvdaList, True)
		self._setAll(self._rawList, False)
		self._updateSummary()
		self._announce(gettext("Default event types selected."))

	def selectAll(self) -> None:
		self._setAll(self._nvdaList, True)
		self._setAll(self._rawList, True)
		self._updateSummary()
		self._announce(gettext("All event types selected."))

	def clear(self) -> None:
		self._setAll(self._nvdaList, False)
		self._setAll(self._rawList, False)
		self._updateSummary()
		self._announce(gettext("Event types cleared."))

	@staticmethod
	def _setAll(control: object, checked: bool) -> None:
		if not hasattr(control, "CheckItem"):
			return
		for index in range(int(control.ItemCount)):
			control.CheckItem(index, checked)

	@staticmethod
	def _checked(control: object, values: tuple[object, ...]) -> tuple[object, ...]:
		if not hasattr(control, "IsItemChecked"):
			return ()
		count = min(int(control.ItemCount), len(values))
		return tuple(values[index] for index in range(count) if control.IsItemChecked(index))

	def apply(self) -> bool:
		nvdaTypes = frozenset(cast(tuple[NvdaEventType, ...], self._checked(self._nvdaList, self._nvdaTypes)))
		rawFamilies = frozenset(
			cast(tuple[RawUiaFamily, ...], self._checked(self._rawList, self._rawFamilies)),
		)
		if not nvdaTypes and (not self._rawEnabled or not rawFamilies):
			message = gettext("Select at least one event type. The current filter was not changed.")
			self._announce(message)
			return False
		self._service.changeFilter(
			EventFilter(nvdaTypes=nvdaTypes, rawFamilies=rawFamilies),
			preserveRawState=True,
		)
		self._dialog.EndModal(self._wx.ID_OK)
		return True

	def updateRawEnabled(self) -> None:
		self._rawList.Enable(self._rawEnabled)
		description = (
			pgettext("events filter state", "Raw UIA event filters enabled.")
			if self._rawEnabled
			else gettext("Enable Include Raw UIA Events to use these filters.")
		)
		setDescription = getattr(self._rawList, "SetToolTip", None)
		if callable(setDescription):
			_ = setDescription(description)

	def _onChecked(self, event: object) -> None:
		self._updateSummary()
		_ = event.Skip()

	def _updateSummary(self) -> None:
		nvda = cast(tuple[NvdaEventType, ...], self._checked(self._nvdaList, self._nvdaTypes))
		raw = cast(tuple[RawUiaFamily, ...], self._checked(self._rawList, self._rawFamilies))
		names = tuple(_nvdaEventTypeLabel(item) for item in nvda) + tuple(
			pgettext("events filter type", "raw UIA {family}").format(
				family=_rawUiaFamilyLabel(item),
			)
			for item in raw
		)
		text = ngettext(
			"Selected event type: {count}",
			"Selected event types: {count}",
			len(names),
		).format(count=len(names))
		if names:
			text = f"{text}: {', '.join(names)}"
		self._summary.SetLabel(text)
		wrap = getattr(self._summary, "Wrap", None)
		if callable(wrap):
			_ = wrap(self._summaryWrapWidth)
		_layout(self._dialog)


@dataclass
class EventsWorkspaceDefinition:
	"""Visible labels for the native Event Monitor workspace."""

	eventListName: str = field(default_factory=lambda: _eventsListName())
	monitoringGroupName: str = field(
		default_factory=lambda: pgettext("events control group", "Monitoring"),
	)
	historyActionsName: str = field(
		default_factory=lambda: pgettext("events control group", "History actions"),
	)
	scopeName: str = field(default_factory=lambda: pgettext("events control group", "Scope"))
	restartLabel: str = field(
		default_factory=lambda: pgettext(
			"events control",
			"&Restart with Current Inspector Selection",
		),
	)
	startLabel: str = field(default_factory=lambda: _eventsStartLabel())
	stopLabel: str = field(default_factory=lambda: _eventsStopLabel())
	exportLabel: str = field(default_factory=lambda: _eventsExportLabel())
	clearLabel: str = field(default_factory=lambda: _eventsClearLabel())
	filterLabel: str = field(default_factory=lambda: _eventsFilterLabel())
	followNewestLabel: str = field(default_factory=lambda: _eventsFollowNewestLabel())
	includeRawLabel: str = field(default_factory=lambda: _eventsIncludeRawLabel())
	detailsName: str = field(default_factory=lambda: _eventsDetailsName())
	clearConfirmTitle: str = field(default_factory=lambda: _eventsClearConfirmTitle())

	@property
	def columnHeadings(self) -> tuple[str, ...]:
		return _eventColumnHeadings()

	@property
	def reportColumnHeadings(self) -> tuple[str, ...]:
		return _eventColumnHeadings()

	@property
	def scopeChoices(self) -> tuple[str, ...]:
		return (
			pgettext("events scope", "Selected element"),
			pgettext("events scope", "Selected subtree"),
			pgettext("events scope", "Application"),
			pgettext("events scope", "Broad"),
		)


def _eventsListName() -> str:
	# Translators: Accessible name of the list of monitored accessibility events.
	return pgettext("events region", "Monitored events")


def _eventsStartLabel() -> str:
	# Translators: Button label starting event monitoring. Ampersand marks the access key.
	return pgettext("events control", "&Start Monitoring")


def _eventsStopLabel() -> str:
	# Translators: Button label stopping event monitoring. Ampersand marks the access key.
	return pgettext("events control", "&Stop Monitoring")


def _eventsExportLabel() -> str:
	# Translators: Button label exporting the retained events to a file. Ampersand marks the access key.
	return pgettext("events control", "&Export...")


def _eventsClearLabel() -> str:
	# Translators: Button label clearing all retained events. Ampersand marks the access key.
	return pgettext("events control", "C&lear")


def _eventsFilterLabel() -> str:
	# Translators: Button label opening the event-type filter dialog. Ampersand marks the access key.
	return pgettext("events control", "Event &Filter...")


def _eventsFollowNewestLabel() -> str:
	# Translators: Toggle label keeping the newest event selected as events arrive. Ampersand marks the access key.
	return pgettext("events control", "Follow &Newest")


def _eventsIncludeRawLabel() -> str:
	# Translators: Toggle label including raw UI Automation events. Ampersand marks the access key.
	return pgettext("events control", "Include Raw &UIA Events")


def _eventsDetailsName() -> str:
	# Translators: Accessible name of the region describing the selected event in full.
	return pgettext("events region", "Selected event details")


def _eventsClearConfirmTitle() -> str:
	# Translators: Title of the confirmation dialog shown before clearing all retained events.
	return pgettext("events window", "Clear Events")


def _changedValueCell(row: EventRow) -> str:
	"""Localize one Changed value cell, keeping every stated outcome distinguishable."""

	if row.changedValue:
		return row.changedValue
	if row.changedValue == "":
		return (
			# Translators: Changed value cell when the size limit left none of the observed value.
			pgettext("events changed value", "(truncated)")
			if row.changedValueTruncated
			# Translators: Changed value cell when the value was read and found empty.
			else pgettext("events changed value", "(empty)")
		)
	return {
		# Translators: Changed value cell when the event reports no value of its own.
		ChangeEvidence.NOT_APPLICABLE: pgettext("events changed value", "Not applicable"),
		# Translators: Changed value cell when the provider exposes no value for this event.
		ChangeEvidence.NOT_EXPOSED: pgettext("events changed value", "Not exposed"),
		# Translators: Changed value cell when the value could not be read from the application.
		ChangeEvidence.UNAVAILABLE: pgettext("events changed value", "Unavailable"),
		# Translators: Changed value cell when the value was withheld for privacy.
		ChangeEvidence.REDACTED: pgettext("events changed value", "(redacted)"),
	}[row.changeEvidence]


def _changeEvidenceWord(evidence: ChangeEvidence) -> str:
	"""Name where a Changed value came from, in the words the details pane speaks."""

	return {
		# Translators: Change evidence naming a value the application itself reported with the event.
		ChangeEvidence.PROVIDER_REPORTED: pgettext("events change evidence", "reported by the provider"),
		# Translators: Change evidence naming a value read from the object right after the event.
		ChangeEvidence.READ_AFTER_EVENT: pgettext("events change evidence", "read after the event"),
		# Translators: Change evidence naming a value compared against the previous observation.
		ChangeEvidence.PRIOR_OBSERVATION_DELTA: pgettext(
			"events change evidence",
			"compared with the previous observation",
		),
		# Translators: Change evidence naming caret position metadata rather than caret text.
		ChangeEvidence.CARET_METADATA: pgettext("events change evidence", "caret position metadata"),
		# Translators: Change evidence stating the event reports no value of its own.
		ChangeEvidence.NOT_APPLICABLE: pgettext("events change evidence", "not applicable"),
		# Translators: Change evidence stating the provider exposes no value for this event.
		ChangeEvidence.NOT_EXPOSED: pgettext("events change evidence", "not exposed"),
		# Translators: Change evidence stating the value could not be read.
		ChangeEvidence.UNAVAILABLE: pgettext("events change evidence", "unavailable"),
		# Translators: Change evidence stating the value was withheld for privacy.
		ChangeEvidence.REDACTED: pgettext("events change evidence", "withheld for privacy"),
	}[evidence]


def _scopeUnavailableMessage(reason: ScopeUnavailableReason, *, restarting: bool) -> str:
	"""Say exactly why a scope was refused, and that monitoring was left where it was."""

	explanations = {
		# Translators: Reason spoken when monitoring cannot start because nothing is selected in the Inspector hierarchy.
		ScopeUnavailableReason.NO_SELECTION: gettext(
			"no object is selected in the Inspector hierarchy",
		),
		# Translators: Reason spoken when the Inspector is showing a saved snapshot instead of a live application.
		ScopeUnavailableReason.SELECTION_OFFLINE: gettext(
			"the Inspector is showing an offline snapshot, which reports no live events",
		),
		# Translators: Reason spoken when the selected Inspector object could no longer be read from its application.
		ScopeUnavailableReason.SELECTION_UNRESOLVED: gettext(
			"the selected object could not be read from its application",
		),
		# Translators: Reason spoken when the selected object reports no usable process.
		ScopeUnavailableReason.NO_PROCESS: gettext(
			"the selected object reports no usable process",
		),
		# Translators: Reason spoken when the selected object exposes no identifier that events can be matched against.
		ScopeUnavailableReason.NO_IDENTITY: gettext(
			"the selected object exposes no identifier that events can be matched against",
		),
		# Translators: Reason spoken when the requested monitoring scope is not supported.
		ScopeUnavailableReason.UNSUPPORTED_SCOPE: gettext(
			"the requested scope is not supported",
		),
	}
	explanation = explanations[reason]
	if restarting:
		# Translators: Spoken when restarting monitoring is refused. {reason} is one explanation phrase.
		return gettext(
			"Monitoring could not restart because {reason}. Monitoring and captured events are unchanged.",
		).format(reason=explanation)
	# Translators: Spoken when starting monitoring is refused. {reason} is one explanation phrase.
	return gettext(
		"Monitoring could not start because {reason}. Select an object in the Inspector and try again.",
	).format(reason=explanation)


class EventsWorkspace:
	"""One singleton native workspace that renders an ``EventMonitorService`` history.

	History lives on the runtime service, not on this frame, so it survives frame close until a manual
	Clear or runtime shutdown. This class is the thin owner-thread native binding: it builds the wx
	controls once, renders the service's immutable history snapshot into an accessible list, routes the
	copy, export, and clear actions back into the service, and tears everything down so no stale
	callback can touch a control, the clipboard, or speech after close.
	"""

	def __init__(
		self,
		service: EventMonitorService,
		*,
		announce: Callable[[str], None] | None = None,
		windowOwnership: WindowOwnershipCheck | None = None,
		sound: WorkflowSounds | None = None,
		window: KeystoneWindow | None = None,
	) -> None:
		super().__init__()
		self._service = service
		self._announce = announce or _ignoreAnnouncement
		self._sound = sound
		self._windowOwnership = windowOwnership or _nativeWindowOwnership
		self._definition = EventsWorkspaceDefinition()
		self._frame: object | None = None
		self._owner: object | None = None
		self._controls: dict[str, object] = {}
		self._rowItems: list[HistoryItem] = []
		self._activationGeneration = 0
		self._followNewest = False
		self._selectedScopeKind = MonitorScopeKind.ELEMENT
		self._broadConfirmed = False
		self._lastFocusKey = "startStop"
		self._startMonitoring: Callable[[MonitorScopeKind], bool] | None = None
		self._stopMonitoring: Callable[[], None] | None = None
		self._restartMonitoring: Callable[[MonitorScopeKind | None], bool] | None = None
		self._showSource: Callable[[EventRow], bool] | None = None
		self._scopeFailure: Callable[[], ScopeUnavailableReason | None] | None = None
		self._announcedFirstVisit = False
		self._window = window or KeystoneWindow(windowOwnership=self._windowOwnership)
		self._window.register(
			"events",
			build=self._buildInto,
			restoreFocus=self._restoreFocus,
			dismissed=self._releaseControls,
			closed=self.close,
			handleKey=self.handleKey,
			refreshStatus=self._refreshStatus,
		)

	@property
	def service(self) -> EventMonitorService:
		return self._service

	@property
	def definition(self) -> EventsWorkspaceDefinition:
		return self._definition

	def configureMonitoring(
		self,
		*,
		start: Callable[..., bool],
		stop: Callable[[], None],
		restart: Callable[[MonitorScopeKind | None], bool] | None = None,
		showSource: Callable[[EventRow], bool] | None = None,
		scopeFailure: Callable[[], ScopeUnavailableReason | None] | None = None,
	) -> None:
		"""Attach the production session actions before the workspace is shown."""

		self._startMonitoring = start
		self._stopMonitoring = stop
		self._restartMonitoring = restart
		self._showSource = showSource
		self._scopeFailure = scopeFailure

	def ownsWindow(self, processId: int, windowHandle: int) -> bool:
		return self._window.ownsWindow(processId, windowHandle)

	@property
	def window(self) -> KeystoneWindow:
		"""The one window this workspace shares with the other top-level workspace."""

		return self._window

	# -- lifecycle: build, activate, teardown ------------------------------

	def show(self) -> None:
		"""Open the shared window on first use, then select and re-render this workspace.

		The opening state is spoken on the first visit after the window opened, not on every switch
		back: Ctrl+E is meant to be cheap enough to press repeatedly.
		"""

		alreadyBuilt = bool(self._controls)
		self._window.open()
		if alreadyBuilt:
			self._renderAll()
		self._window.activate("events")
		if not self._announcedFirstVisit:
			self._announcedFirstVisit = True
			self._announce(self._openingAnnouncement())

	def _openingAnnouncement(self) -> str:
		"""Describe where monitoring actually stands as this visit begins.

		Reopening after a close does not mean monitoring stopped, and the proposed scope is whatever
		the user last chose, so both are read from live state rather than assumed.
		"""

		control = self._focusTargetName()
		if self._service.active:
			scope = self._service.scope
			scopeText = (
				scope.scopeText
				if scope is not None
				# Translators: Events opening state when monitoring is active but names no scope.
				else pgettext("events opening state", "an unreported scope")
			)
			# Translators: Spoken when Events opens while monitoring is running. {scope} is the
			# monitored scope and {control} is the control that takes focus.
			return gettext("Events monitoring active. Scope: {scope}. {control} focused.").format(
				scope=scopeText,
				control=control,
			)
		kinds = tuple(MonitorScopeKind)
		choices = self._definition.scopeChoices
		index = kinds.index(self._selectedScopeKind)
		proposed = choices[index] if index < len(choices) else self._selectedScopeKind.value
		# Translators: Spoken when Events opens while monitoring is stopped. {scope} is the scope
		# that Start would use and {control} is the control that takes focus.
		return gettext("Events stopped. Proposed scope: {scope}. {control} focused.").format(
			scope=proposed,
			control=control,
		)

	def _focusTargetName(self) -> str:
		"""Name the control this visit will land on, so the announcement matches where focus goes."""

		definition = self._definition
		labels = {
			"startStop": definition.stopLabel if self._service.active else definition.startLabel,
			"restart": definition.restartLabel,
			"eventFilter": definition.filterLabel,
			"includeRaw": definition.includeRawLabel,
			"followNewest": definition.followNewestLabel,
			"scopeChoice": definition.scopeName,
			"events": definition.eventListName,
			"eventDetails": definition.detailsName,
			"export": definition.exportLabel,
			"clear": definition.clearLabel,
		}
		return labels.get(self._lastFocusKey, labels["startStop"]).replace("&", "")

	def _buildInto(self, panel: object) -> None:
		"""Render every Events control into the page the shared window owns."""

		self._build(panel)

	def _restoreFocus(self) -> None:
		"""Return focus to the control this workspace last had focused, or Start Monitoring."""

		target = self._controls.get(self._lastFocusKey) or self._controls.get("startStop")
		if target is not None:
			target.SetFocus()

	def _onChildFocus(self, event: object) -> None:
		"""Remember whatever the user moved focus to, however they moved it."""

		key = _controlKeyFor(self._controls, _focusedWindow(event))
		if key is not None:
			self._lastFocusKey = key
		skip = getattr(event, "Skip", None)
		if callable(skip):
			_ = skip()

	def _releaseControls(self) -> None:
		"""Drop every control reference after the shared window destroyed the page."""

		self._frame = None
		self._owner = None
		self._controls = {}
		self._rowItems = []
		self._lastFocusKey = "startStop"
		# The opening state belongs to a window, not to this object: a window that is closed and
		# opened again is a fresh visit and says where monitoring stands, while merely switching
		# back to this workspace stays silent.
		self._announcedFirstVisit = False

	@property
	def isOpen(self) -> bool:
		"""Whether the shared window is currently built and shown."""

		return self._frame is not None

	def refresh(self) -> None:
		"""Re-render the open frame from the service's latest history snapshot; a no-op when closed.

		The owner-thread drain pump calls this after each drain so newly retained rows appear live.
		Nothing is rebuilt or re-activated, so focus and selection are left where the user put them
		unless Follow Newest is on.
		"""

		if self._frame is None:
			return
		self._renderAll()

	def _build(self, panel: object) -> None:
		wx = import_module("wx")
		definition = self._definition
		frame = self._window.frame
		root = wx.BoxSizer(wx.VERTICAL)

		monitoringBox, monitoringSizer = _staticGroup(wx, panel, definition.monitoringGroupName)
		controlsRow = _responsiveRowSizer(wx)
		startStop = wx.Button(monitoringBox, label=definition.startLabel)
		restart = wx.Button(monitoringBox, label=definition.restartLabel)
		eventFilter = wx.Button(monitoringBox, label=definition.filterLabel)
		includeRaw = wx.CheckBox(monitoringBox, label=definition.includeRawLabel)
		includeRaw.SetValue(bool(getattr(self._service, "rawEventsEnabled", False)))
		followNewest = wx.CheckBox(monitoringBox, label=definition.followNewestLabel)
		followNewest.SetValue(self._followNewest)
		for control in (startStop, restart, eventFilter):
			controlsRow.Add(control, 0, wx.LEFT | wx.RIGHT, 4)
		controlsRow.Add(includeRaw, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, 4)
		controlsRow.Add(followNewest, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, 4)
		monitoringSizer.Add(controlsRow, 0, wx.EXPAND | wx.ALL, 4)

		if hasattr(wx, "RadioBox"):
			scopeChoice = wx.RadioBox(
				monitoringBox,
				label=definition.scopeName,
				choices=definition.scopeChoices,
				majorDimension=1,
				style=wx.RA_SPECIFY_ROWS,
			)
		else:
			# Hostless contract doubles predating RadioBox still exercise the rest of the workspace.
			scopeChoice = wx.Button(monitoringBox, label=definition.scopeName)
			scopeChoice.SetSelection = scopeChoice.SetValue
			scopeChoice.GetSelection = scopeChoice.GetValue
		scopeChoice.SetSelection(tuple(MonitorScopeKind).index(self._selectedScopeKind))
		monitoringSizer.Add(scopeChoice, 0, wx.EXPAND | wx.ALL, 4)
		root.Add(monitoringSizer, 0, wx.EXPAND | wx.ALL, 8)

		eventsBox, eventsSizer = _staticGroup(wx, panel, definition.eventListName)
		events = _reportList(wx, eventsBox, autoSizeColumn=2)
		for index, heading in enumerate(definition.reportColumnHeadings):
			events.InsertColumn(index, heading)
		eventsSizer.Add(events, 1, wx.EXPAND | wx.ALL, 4)
		root.Add(eventsSizer, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 8)

		detailsBox, detailsSizer = _staticGroup(wx, panel, definition.detailsName)
		eventDetails = wx.TextCtrl(detailsBox, style=wx.TE_MULTILINE | wx.TE_READONLY)
		detailsSizer.Add(eventDetails, 0, wx.EXPAND | wx.ALL, 4)
		root.Add(detailsSizer, 0, wx.EXPAND | wx.ALL, 8)

		actionsBox, actionsSizer = _staticGroup(wx, panel, definition.historyActionsName)
		actionsRow = _responsiveRowSizer(wx)
		export = wx.Button(actionsBox, label=definition.exportLabel)
		clear = wx.Button(actionsBox, label=definition.clearLabel)
		for control in (export, clear):
			actionsRow.Add(control, 0, wx.LEFT | wx.RIGHT, 4)
		actionsSizer.Add(actionsRow, 0, wx.EXPAND | wx.ALL, 4)
		root.Add(actionsSizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)

		panel.SetSizer(root)

		self._frame = frame
		self._controls = {
			"panel": panel,
			"startStop": startStop,
			"restart": restart,
			"scopeChoice": scopeChoice,
			"events": events,
			"eventDetails": eventDetails,
			"eventFilter": eventFilter,
			"includeRaw": includeRaw,
			"followNewest": followNewest,
			"export": export,
			"clear": clear,
		}
		self._bind(wx)
		self._renderAll()

	def _bind(self, wx: object) -> None:
		controls = self._controls

		def onExport(_event: object) -> None:
			self._export()

		def onClear(_event: object) -> None:
			self._clear()

		def onEventSelected(_event: object) -> None:
			self._renderSelectedDetails()

		def onEventDeselected(_event: object) -> None:
			# A row losing its selection changes what "the selected event" means, so the details
			# pane is re-read rather than left showing an event the user has moved away from.
			self._renderSelectedDetails()

		def onEventContext(event: object) -> None:
			self._showEventContextMenu(event)

		def onEventKey(event: object) -> None:
			if int(event.GetKeyCode()) == wx.WXK_DELETE and not bool(event.ControlDown()):
				self._deleteSelectedEvents()
				return
			event.Skip()

		def onChildFocus(event: object) -> None:
			self._onChildFocus(event)

		def onFilter(_event: object) -> None:
			self._changeFilter()

		def onStartStop(_event: object) -> None:
			self._toggleMonitoring()

		def onRestart(_event: object) -> None:
			self._restartWithCurrentSelection()

		def onScopeChanged(_event: object) -> None:
			self._scopeChanged()

		def onFollowNewest(_event: object) -> None:
			self._followNewest = bool(controls["followNewest"].GetValue())
			if self._followNewest:
				self._focusNewest()
			self._window.setStatus(
				gettext("Follow Newest enabled.")
				if self._followNewest
				else gettext("Follow Newest disabled."),
			)

		def onIncludeRaw(_event: object) -> None:
			self._service.setRawEventsEnabled(bool(controls["includeRaw"].GetValue()))
			self._renderAll()
			self._window.setStatus(
				gettext("Raw UIA events enabled.")
				if bool(controls["includeRaw"].GetValue())
				else gettext("Raw UIA events disabled."),
			)

		controls["startStop"].Bind(wx.EVT_BUTTON, onStartStop)
		controls["restart"].Bind(wx.EVT_BUTTON, onRestart)
		controls["scopeChoice"].Bind(getattr(wx, "EVT_RADIOBOX", wx.EVT_BUTTON), onScopeChanged)
		controls["export"].Bind(wx.EVT_BUTTON, onExport)
		controls["clear"].Bind(wx.EVT_BUTTON, onClear)
		controls["events"].Bind(wx.EVT_LIST_ITEM_SELECTED, onEventSelected)
		controls["events"].Bind(wx.EVT_LIST_ITEM_DESELECTED, onEventDeselected)
		controls["events"].Bind(wx.EVT_CONTEXT_MENU, onEventContext)
		controls["events"].Bind(wx.EVT_KEY_DOWN, onEventKey)
		controls["eventFilter"].Bind(wx.EVT_BUTTON, onFilter)
		controls["includeRaw"].Bind(wx.EVT_CHECKBOX, onIncludeRaw)
		controls["followNewest"].Bind(wx.EVT_CHECKBOX, onFollowNewest)
		controls["panel"].Bind(wx.EVT_CHILD_FOCUS, onChildFocus)

	def handleKey(self, event: object) -> None:
		"""Route the Events keyboard contract; anything else is passed straight on."""

		wx = import_module("wx")
		keyCode = int(event.GetKeyCode())
		control = bool(event.ControlDown())
		alt = bool(event.AltDown())
		shift = bool(event.ShiftDown())
		if not control and not alt and not shift and keyCode == wx.WXK_F5:
			self._toggleMonitoring()
			return
		if alt and not control and not shift:
			if _matchesAccessKey(
				self._definition.startLabel if not self._service.active else self._definition.stopLabel,
				keyCode,
			):
				self._toggleMonitoring()
				return
			if _matchesAccessKey(self._definition.restartLabel, keyCode):
				self._restartWithCurrentSelection()
				return
			if _matchesAccessKey(self._definition.filterLabel, keyCode):
				self._changeFilter()
				return
			if _matchesAccessKey(self._definition.includeRawLabel, keyCode):
				if (enabled := _toggleControl(self._controls.get("includeRaw"))) is not None:
					self._service.setRawEventsEnabled(enabled)
					self._renderAll()
					self._window.setStatus(
						gettext("Raw UIA events enabled.")
						if enabled
						else gettext("Raw UIA events disabled."),
					)
					return
			if _matchesAccessKey(self._definition.followNewestLabel, keyCode):
				if (enabled := _toggleControl(self._controls.get("followNewest"))) is not None:
					self._followNewest = enabled
					if enabled:
						self._focusNewest()
					self._window.setStatus(
						gettext("Follow Newest enabled.") if enabled else gettext("Follow Newest disabled."),
					)
					return
			if _matchesAccessKey(self._definition.exportLabel, keyCode):
				self._export()
				return
			if _matchesAccessKey(self._definition.clearLabel, keyCode):
				self._clear()
				return
		if control and not alt and not shift and keyCode in (ord("C"), ord("c")):
			if self._copyContext():
				return
		event.Skip()

	def _copyContext(self) -> bool:
		"""Copy the selected event as text when the list or its details has focus.

		The copy buttons keep their own formats; this is the one context-sensitive command, so it
		acts only where a selected event is what the user is looking at.
		"""

		if self._lastFocusKey not in ("events", "eventDetails"):
			return False
		if self._selectedEventRow() is None:
			# Translators: Spoken when Ctrl+C is pressed in Events with no event selected.
			self._feedback(gettext("Nothing is selected to copy."))
			return True
		self._copySelected(EventCopyFormat.TEXT)
		return True

	def dismiss(self) -> None:
		"""Destroy the shared window and drop every control without touching retained history."""

		self._activationGeneration += 1
		self._window.dismiss()
		self._releaseControls()

	def close(self) -> None:
		"""Explicit user or secure close: tear down the frame; retained history survives on the service."""

		wasOpen = self._frame is not None
		self.dismiss()
		if wasOpen:
			# Translators: Events message spoken when the Events window is closed.
			self._announce(gettext("Events closed."))

	# -- rendering ---------------------------------------------------------

	def _renderAll(self) -> None:
		snapshot = self._service.historySnapshot()
		self._renderMonitoringControl()
		self._renderEvents(snapshot)
		self._renderSelectedDetails()
		self._renderStatus(snapshot)
		if self._followNewest:
			self._focusNewest()

	def _renderMonitoringControl(self) -> None:
		control = self._controls.get("startStop")
		if control is None:
			return
		if self._service.active:
			_setControlLabel(control, self._definition.stopLabel)
			_setControlEnabled(control, self._stopMonitoring is not None)
		else:
			_setControlLabel(control, self._definition.startLabel)
			_setControlEnabled(control, self._startMonitoring is not None)
		scopeChoice = self._controls.get("scopeChoice")
		if scopeChoice is not None:
			_setControlSelection(scopeChoice, tuple(MonitorScopeKind).index(self._selectedScopeKind))
		restart = self._controls.get("restart")
		if restart is not None:
			_setControlEnabled(restart, self._restartMonitoring is not None)

	def _renderEvents(self, snapshot: EventHistory) -> None:
		events = self._controls.get("events")
		if events is None:
			return
		incoming = list(snapshot.items)
		currentKeys = tuple(self._historyItemKey(item) for item in self._rowItems)
		incomingKeys = tuple(self._historyItemKey(item) for item in incoming)
		if currentKeys == incomingKeys:
			self._rowItems = incoming
			return
		if incomingKeys[: len(currentKeys)] == currentKeys:
			start = len(self._rowItems)
			self._rowItems = incoming
			self._insertEventItems(events, incoming[start:], start=start)
			if start == 0 and incoming and events.GetFirstSelected() < 0:
				events.Select(0)
				events.Focus(0)
			return
		index = events.GetFirstSelected()
		selectedKey = (
			self._historyItemKey(self._rowItems[index]) if 0 <= index < len(self._rowItems) else None
		)
		focusedIndex = events.GetFocusedItem()
		focusedKey = (
			self._historyItemKey(self._rowItems[focusedIndex])
			if 0 <= focusedIndex < len(self._rowItems)
			else None
		)
		events.DeleteAllItems()
		self._rowItems = incoming
		self._insertEventItems(events, incoming, start=0)
		restoredFocus: int | None = None
		for newIndex, item in enumerate(incoming):
			key = self._historyItemKey(item)
			if key == selectedKey:
				events.Select(newIndex)
			if key == focusedKey:
				events.Focus(newIndex)
				restoredFocus = newIndex
		if restoredFocus is not None:
			# Eviction rebuilt the whole list, which leaves it scrolled to the top. Restoring the
			# focused row without revealing it would move the user's row off screen under them.
			events.EnsureVisible(restoredFocus)

	@staticmethod
	def _historyItemKey(item: HistoryItem) -> tuple[str, int, int]:
		return (type(item).__name__, item.session, item.sequence)

	def _insertEventItems(self, events: Any, items: list[HistoryItem], *, start: int) -> None:
		for offset, item in enumerate(items):
			index = start + offset
			cells = self._rowCells(item)
			position = events.InsertItem(index, cells[0])
			for column in range(1, len(cells)):
				events.SetItem(position, column, cells[column])

	@staticmethod
	def _rowCells(item: HistoryItem) -> tuple[str, ...]:
		if isinstance(item, SessionBoundary):
			# Translators: Events list scope cell shown when every application is monitored.
			allApplications = pgettext("events scope", "all applications")
			scope = allApplications if item.broad else item.application
			return (
				item.reason.value,
				scope,
				# Translators: Changed value cell for a session boundary row, which changes no value.
				pgettext("events changed value", "Not applicable"),
				item.startTimeText,
			)
		# Translators: Events list name cell shown when an object name was withheld for privacy.
		redactedName = pgettext("events name", "(redacted)")
		name = redactedName if item.redacted and item.objectName is None else (item.objectName or "")
		return (
			item.eventType,
			", ".join(part for part in (name, item.objectRole, item.detail or "") if part),
			_changedValueCell(item),
			item.timestampText,
		)

	def _renderSelectedDetails(self) -> None:
		control = self._controls.get("eventDetails")
		if control is None:
			return
		row = self._selectedEventRow()
		if row is None:
			self._setEventDetailsText(control, "")
			return
		lines = (
			# Translators: Label for the event type in the selected-event details.
			"{label}: {value}".format(label=pgettext("events detail", "Event"), value=row.eventType),
			# Translators: Label for the object name in the selected-event details.
			"{label}: {value}".format(
				label=pgettext("events detail", "Object"),
				value=row.objectName or "",
			),
			# Translators: Label for the control role in the selected-event details.
			"{label}: {value}".format(label=pgettext("events detail", "Role"), value=row.objectRole),
			# Translators: Label for the application in the selected-event details.
			"{label}: {value}".format(
				label=pgettext("events detail", "Application"),
				value=row.application,
			),
			# Translators: Label for the process ID in the selected-event details.
			"{label}: {value}".format(label=pgettext("events detail", "Process"), value=row.processId),
			# Translators: Label for the accessibility backend in the selected-event details.
			"{label}: {value}".format(
				label=pgettext("events detail", "Backend"),
				value=row.provenance.backend.value,
			),
			# Translators: Label for the concise detail in the selected-event details.
			"{label}: {value}".format(
				label=pgettext("events detail", "Detail"),
				value=row.detail or "",
			),
			"{label}: {value}".format(
				# Translators: Label of the changed value in the selected-event details.
				label=pgettext("events detail", "Changed value"),
				value=_changedValueCell(row),
			),
			"{label}: {value}".format(
				# Translators: Label naming where a changed value came from in the selected-event details.
				label=pgettext("events detail", "Change evidence"),
				value=_changeEvidenceWord(row.changeEvidence),
			),
			# Translators: Label for the observation time in the selected-event details.
			"{label}: {value}".format(
				label=pgettext("events detail", "Time"),
				value=row.timestampText,
			),
		)
		self._setEventDetailsText(control, "\n".join(lines))

	@staticmethod
	def _setEventDetailsText(control: object, text: str) -> None:
		getValue = getattr(control, "GetValue", None)
		current = getValue() if callable(getValue) else getattr(control, "value", None)
		if current != text:
			control.SetValue(text)

	def _refreshStatus(self) -> None:
		"""Reassert the Events status line when this page becomes the visible one."""
		self._renderStatus(self._service.historySnapshot())

	def _renderStatus(self, snapshot: EventHistory) -> None:
		"""Render the status line from live state in the user's language.

		The service keeps its own English status string for logs and diagnostics; what the user
		reads is composed here, where the translation catalog is available.
		"""

		if self._frame is None:
			return
		# Background drains re-render continuously; the shared status bar belongs to whichever page
		# is on screen, so Events only writes it while it is the visible workspace. Page activation
		# uses the window's refreshActiveStatus() to set the selected page's status.
		if self._window.activeWorkspace != "events":
			return
		state = (
			# Translators: Events status word while monitoring is running.
			pgettext("events status", "active")
			if self._service.active
			# Translators: Events status word while monitoring is stopped.
			else pgettext("events status", "stopped")
		)
		scope = self._service.scope
		scopeText = (
			scope.scopeText
			if scope is not None
			# Translators: Events status scope shown before any monitoring session has run.
			else pgettext("events status", "no scope pinned")
		)
		raw = (
			# Translators: Events status phrase when raw UIA events are captured.
			pgettext("events status", "raw UIA included")
			if bool(getattr(self._service, "rawEventsEnabled", False))
			# Translators: Events status phrase when raw UIA events are not captured.
			else pgettext("events status", "raw UIA off")
		)
		# Translators: The Events status line. {state} is active or stopped, {scope} names what is
		# monitored, {raw} reports raw UIA capture, and the counts are exact.
		self._window.setStatus(
			gettext(
				"Monitoring {state}; {scope}; {raw}; events {count}; pending drops {pendingDrops}; retained drops {retainedDrops}.",
			).format(
				state=state,
				scope=scopeText,
				raw=raw,
				count=snapshot.rowCount,
				pendingDrops=snapshot.drops.pendingQueueDrops,
				retainedDrops=snapshot.drops.retainedRowDrops,
			),
		)

	# -- actions -----------------------------------------------------------

	def _feedback(self, message: str) -> None:
		self._window.setStatus(message)
		self._announce(message)

	def _toggleMonitoring(self) -> None:
		if self._service.active:
			if self._stopMonitoring is not None:
				self._stopMonitoring()
			self._renderAll()
			self._feedback(gettext("Monitoring stopped. Retained events remain available."))
			return
		elif self._startMonitoring is not None:
			if self._selectedScopeKind is MonitorScopeKind.BROAD and not self._confirmBroadScope():
				# Answering No to the broad-scope warning is a decision, not a failure to start.
				# Reporting a stale refusal reason here would blame something the user did not do.
				self._announceBroadCancelled()
				self._renderAll()
				return
			started = False
			try:
				started = self._startMonitoring(self._selectedScopeKind)
			except TypeError:
				started = self._startMonitoring()  # type: ignore[call-arg]
			except Exception:
				started = False
			if not started:
				self._announceScopeRefusal(restarting=False)
			else:
				self._renderAll()
				# EventMonitorService has already spoken the canonical start confirmation with the
				# frozen target, scope, and raw-UIA state. Rendering keeps controls and the status bar
				# current without speaking a second, less specific confirmation.
				return
		else:
			self._announceScopeRefusal(restarting=False)
		self._renderAll()

	def _announceBroadCancelled(self) -> None:
		# Translators: Spoken when the user declines the broad monitoring warning.
		self._feedback(gettext("Broad monitoring cancelled. Monitoring is unchanged."))

	def _announceScopeRefusal(self, *, restarting: bool) -> None:
		"""Speak the session's exact refusal reason, never a widened or vague substitute."""

		reason: ScopeUnavailableReason | None = None
		if self._scopeFailure is not None:
			try:
				reason = self._scopeFailure()
			except Exception:
				reason = None
		if reason is not None:
			self._feedback(_scopeUnavailableMessage(reason, restarting=restarting))
			return
		if restarting:
			self._feedback(gettext("Monitoring could not restart with the current Inspector selection."))
			return
		self._feedback(gettext("Monitoring could not start. Check the selected scope and try again."))

	def _scopeChanged(self) -> None:
		control = self._controls.get("scopeChoice")
		if control is None:
			return
		previous = self._selectedScopeKind
		index = int(control.GetSelection())
		kinds = tuple(MonitorScopeKind)
		if not 0 <= index < len(kinds):
			return
		selected = kinds[index]
		if selected is MonitorScopeKind.BROAD and not self._confirmBroadScope():
			control.SetSelection(kinds.index(previous))
			return
		self._selectedScopeKind = selected
		if selected is not MonitorScopeKind.BROAD:
			self._broadConfirmed = False
		self._window.setStatus(
			gettext("Proposed monitoring scope: {scope}.").format(
				scope=self._definition.scopeChoices[kinds.index(selected)].lower(),
			),
		)

	def _confirmBroadScope(self) -> bool:
		if self._broadConfirmed:
			return True
		wx = import_module("wx")
		dialog = wx.MessageDialog(
			self._frame,
			gettext(
				(
					"Broad monitoring observes accessibility events from every non-NVDA process. "
					"Continue with Broad scope?"
				),
			),
			pgettext("events window", "Confirm Broad Monitoring"),
			wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
		)
		try:
			self._broadConfirmed = dialog.ShowModal() == wx.ID_YES
		finally:
			dialog.Destroy()
		return self._broadConfirmed

	def _restartWithCurrentSelection(self) -> None:
		if self._restartMonitoring is None:
			return
		if self._selectedScopeKind is MonitorScopeKind.BROAD and not self._confirmBroadScope():
			self._announceBroadCancelled()
			return
		if self._restartMonitoring(self._selectedScopeKind):
			self._feedback(
				gettext("Monitoring restarted with the current Inspector selection."),
			)
		else:
			self._announceScopeRefusal(restarting=True)
		self._renderAll()

	def _selectedEventRow(self) -> EventRow | None:
		events = self._controls.get("events")
		if events is None:
			return None
		index = events.GetFirstSelected()
		if not 0 <= index < len(self._rowItems):
			return None
		item = self._rowItems[index]
		return item if isinstance(item, EventRow) else None

	def _selectedHistoryItem(self) -> HistoryItem | None:
		events = self._controls.get("events")
		if events is None:
			return None
		index = events.GetFirstSelected()
		return self._rowItems[index] if 0 <= index < len(self._rowItems) else None

	def _deleteSelectedEvents(self) -> None:
		item = self._selectedHistoryItem()
		if item is None:
			self._feedback(gettext("Select an event to delete."))
			return
		if self._service.deleteHistoryItem(item):
			self._renderAll()
			self._feedback(gettext("Event deleted."))

	def _showEventContextMenu(self, event: object) -> None:
		wx = import_module("wx")
		events = self._controls.get("events")
		if events is None:
			return
		getPosition = getattr(event, "GetPosition", None)
		if callable(getPosition):
			position = getPosition()
			if position != (-1, -1):
				screenToClient = getattr(events, "ScreenToClient", None)
				if callable(screenToClient):
					position = screenToClient(position)
				index, _flags = events.HitTest(position)
				if index >= 0:
					events.Select(index)
					events.Focus(index)
		menu = wx.Menu()

		def onCopyText(_event: object) -> None:
			self._copySelected(EventCopyFormat.TEXT)

		def onCopyJson(_event: object) -> None:
			self._copySelected(EventCopyFormat.JSON)

		def onCopyMarkdown(_event: object) -> None:
			self._copySelected(EventCopyFormat.MARKDOWN)

		def onShowSource(_event: object) -> None:
			self._showSelectedSource()

		def onDelete(_event: object) -> None:
			self._deleteSelectedEvents()

		for identifier, label, handler in (
			(wx.ID_COPY, gettext("Copy selected event"), onCopyText),
			(wx.ID_ANY, gettext("Copy event as JSON"), onCopyJson),
			(wx.ID_ANY, gettext("Copy event as Markdown"), onCopyMarkdown),
			(wx.ID_ANY, gettext("Show source in Inspector"), onShowSource),
			(wx.ID_DELETE, gettext("Delete selected event"), onDelete),
		):
			item = menu.Append(identifier, label)
			_bindMenuItem(menu, wx, item, handler)
		events.PopupMenu(menu)
		menu.Destroy()

	def _showSelectedSource(self) -> None:
		row = self._selectedEventRow()
		if row is None:
			self._feedback(gettext("Select an event before showing its source in Inspector."))
			return
		if self._showSource is None or not self._showSource(row):
			self._feedback(gettext("The selected event source is stale or unavailable."))
			return
		self._feedback(gettext("Event source shown in Inspector. Monitoring remains on its frozen target."))

	def _copySelected(self, copyFormat: EventCopyFormat) -> None:
		row = self._selectedEventRow()
		if row is None:
			self._feedback(gettext("No retained event is selected to copy."))
			return
		outcome = self._service.copySelectedEvents((row,), copyFormat)
		self._announceOutcome(outcome, action="copy")

	def _export(self) -> None:
		outcome = self._service.exportEventHistory()
		self._announceOutcome(outcome, action="export")

	def _changeFilter(self) -> None:
		wx = import_module("wx")
		dialog = EventFilterDialog(
			self._frame,
			self._service,
			rawEnabled=self._service.rawEventsEnabled,
			announce=self._announce,
		)
		result: object = None
		try:
			result = dialog.showModal()
		finally:
			dialog.destroy()
		self._renderAll()
		if result == wx.ID_OK:
			# Translators: Events message confirming a committed event filter change.
			applied = gettext("Event filter applied to future events.")
			self._feedback(applied)

	def _focusNewest(self) -> None:
		"""Reveal and select the newest retained row when Follow Newest is enabled."""

		events = self._controls.get("events")
		if events is None:
			return
		count = int(events.GetItemCount())
		if count <= 0:
			return
		newest = count - 1
		events.EnsureVisible(newest)
		events.Focus(newest)
		events.Select(newest)
		# The selection just moved, so the details pane is re-read: leaving it would describe a row
		# that is no longer selected.
		self._renderSelectedDetails()

	def _clear(self) -> None:
		wx = import_module("wx")
		dialog = wx.MessageDialog(
			self._frame,
			ngettext(
				"Clear {count} retained event? Monitoring will continue.",
				"Clear {count} retained events? Monitoring will continue.",
				len(self._service.retainedRows()),
			).format(count=len(self._service.retainedRows())),
			self._definition.clearConfirmTitle,
			wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
		)
		try:
			confirmed = dialog.ShowModal() == wx.ID_YES
		finally:
			dialog.Destroy()
		if not confirmed:
			# Translators: Events message when the user cancels clearing retained events.
			self._feedback(gettext("Clear cancelled."))
			return
		self._service.clear()
		self._renderAll()
		# Translators: Events message confirming all retained events were cleared.
		self._feedback(gettext("Events cleared."))

	def _announceOutcome(self, outcome: EventActionOutcome, *, action: str) -> None:
		verb, actionWord = self._localizedAction(action)
		if outcome.status in ("copied", "published"):
			# Translators: Events message when a copy or export finished. {verb} is Copy or Export.
			message = gettext("{verb} complete.").format(verb=verb)
		elif outcome.status == "empty":
			# Translators: Events message when there is nothing to copy or export. {action} is copy or export.
			message = gettext("No events to {action}.").format(action=actionWord)
		elif outcome.status == "cancelled":
			# Translators: Events message when a copy or export was cancelled. {verb} is Copy or Export.
			message = gettext("{verb} cancelled.").format(verb=verb)
		elif outcome.status == "stale":
			# Translators: Events message when a copy or export was skipped because monitoring changed.
			message = gettext("{verb} skipped because monitoring changed.").format(verb=verb)
		else:
			# Translators: Events message when a copy or export failed. {verb} is Copy or Export.
			message = gettext("{verb} failed.").format(verb=verb)
		self._feedback(message)
		self._emitExportSound(outcome, action=action)

	@staticmethod
	def _localizedAction(action: str) -> tuple[str, str]:
		if action == "export":
			# Translators: Capitalized name of the export action used in Events status messages.
			verb = pgettext("events action", "Export")
			# Translators: Lowercase name of the export action used in "No events to export." messages.
			word = pgettext("events action lowercase", "export")
			return verb, word
		# Translators: Capitalized name of the copy action used in Events status messages.
		verb = pgettext("events action", "Copy")
		# Translators: Lowercase name of the copy action used in "No events to copy." messages.
		word = pgettext("events action lowercase", "copy")
		return verb, word

	def _emitExportSound(self, outcome: EventActionOutcome, *, action: str) -> None:
		# Only the Events export publishes a terminal cue, and only after the outcome has already
		# been spoken. Copy carries no cue; cancelled, empty, and stale exports stay silent. A
		# committed export attempt carries its generation, so a missing generation means there is
		# no owned operation to sound. A missing seam or any failure to build or schedule the
		# request must never disturb speech, the clipboard, the exported file, or the frame.
		if action != "export" or outcome.generation is None:
			return
		if outcome.status == "published":
			event = CueEventId.EVENT_EXPORT_SUCCESS
		elif outcome.status == "failed":
			event = CueEventId.EVENT_EXPORT_FAILURE
		else:
			return
		sound = self._sound
		if sound is None:
			return
		owner = SoundOwner(SoundOwnerKind.EXPORT, outcome.generation)
		try:
			sound.emit(soundRequestFor(event, owner))
		except Exception:
			_logUnexpectedSound()
